"""ICMP ping probe with layered fallbacks.

Order of attempts:
  1. unprivileged ICMP echo via SOCK_DGRAM (works on macOS, and on Linux
     when net.ipv4.ping_group_range covers the current gid)
  2. the system `ping` command (platform-aware flags)
  3. TCP connect fallback to port 443/80 (always works; marked as fallback)
"""
from __future__ import annotations

import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time


class ProbeError(Exception):
    pass


def run(target: str, timeout_ms: int = 5000, params: dict | None = None) -> dict:
    params = params or {}
    host = target.split(":")[0] if ":" in target and not target.count(":") > 1 else target
    timeout = timeout_ms / 1000.0
    count = int(params.get("packets", 1))
    fallback_ports = params.get("tcp_fallback_ports", [443, 80])

    rtt = _try_dgram_icmp(host, timeout)
    if rtt is not None:
        return {"rtt_ms": rtt, "method": "icmp", "latency_ms": rtt,
                "packets_sent": 1, "packets_recv": 1}

    rtt, sent, recv = _try_system_ping(host, timeout_ms, count)
    if rtt is not None:
        return {"rtt_ms": rtt, "method": "icmp_sys", "latency_ms": rtt,
                "packets_sent": sent, "packets_recv": recv}

    rtt = _tcp_fallback(host, timeout, fallback_ports)
    if rtt is not None:
        return {"rtt_ms": rtt, "method": "tcp_fallback", "latency_ms": rtt,
                "packets_sent": 1, "packets_recv": 1,
                "note": "ICMP unavailable; used TCP connect time"}

    raise ProbeError(f"host {host} unreachable (icmp and tcp fallback failed)")


# ---------------------------------------------------------------- raw-ish ICMP
def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _try_dgram_icmp(host: str, timeout: float) -> float | None:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        dst = infos[0][4][0]
        ident = (id(host) & 0x7FFF) or 1234
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname("icmp"))
    except (OSError, socket.gaierror):
        return None
    try:
        payload = b"openeyes" + struct.pack("!d", time.time())
        header = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
        chk = _icmp_checksum(header + payload)
        packet = struct.pack("!BBHHH", 8, 0, chk, ident, 1) + payload
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.sendto(packet, (dst, 0))
        deadline = t0 + timeout
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                return None
            ready, _, _ = select.select([sock], [], [], left)
            if not ready:
                return None
            data, _ = sock.recvfrom(1500)
            if len(data) < 28:
                continue
            ip_header_len = (data[0] & 0x0F) * 4
            icmp_type, _, _, r_ident, _ = struct.unpack(
                "!BBHHH", data[ip_header_len:ip_header_len + 8])
            if icmp_type == 0 and r_ident == ident:
                return round((time.perf_counter() - t0) * 1000, 2)
    except OSError:
        return None
    finally:
        sock.close()


# ---------------------------------------------------------------- system ping
def _try_system_ping(host: str, timeout_ms: int, count: int):
    exe = shutil.which("ping")
    if not exe:
        return None, 0, 0
    if sys.platform == "win32":
        cmd = [exe, "-n", str(count), "-w", str(int(timeout_ms)), host]
    elif sys.platform == "darwin":
        cmd = [exe, "-c", str(count), "-t", str(max(1, int(timeout_ms // 1000))), host]
    else:
        cmd = [exe, "-c", str(count), "-W", str(max(1, int(timeout_ms // 1000))), host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_ms / 1000.0 + 5)
    except (subprocess.TimeoutExpired, OSError):
        return None, 0, 0
    out = proc.stdout or ""
    # average rtt line: rtt min/avg/max/mdev = 1.0/2.0/3.0/0.1 ms (unix)
    m = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms", out)
    if not m:
        # single-packet / Windows style: time=2ms | time<1ms | time=2.3ms
        times = re.findall(r"time[=<]\s*([\d.]+)\s*ms", out)
        if times:
            avg = sum(float(t) for t in times) / len(times)
            return round(avg, 2), count, len(times)
        return None, count, 0
    return round(float(m.group(1)), 2), count, count


# ------------------------------------------------------------------ fallback
def _tcp_fallback(host: str, timeout: float, ports=(443, 80)) -> float | None:
    for port in ports:
        t0 = time.perf_counter()
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return round((time.perf_counter() - t0) * 1000, 2)
        except OSError:
            continue
    return None
