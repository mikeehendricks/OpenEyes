"""TCP port reachability + connect-time probe."""
from __future__ import annotations

import socket
import time


class ProbeError(Exception):
    pass


def run(target: str, timeout_ms: int = 5000, params: dict | None = None) -> dict:
    """Target format: host:port (port defaults to 443)."""
    host, _, port_s = target.rpartition(":")
    if not host:
        host, port_s = target, "443"
    host = host.strip("[]")
    try:
        port = int(port_s)
    except ValueError:
        raise ProbeError(f"invalid port in target '{target}'")
    if not (1 <= port <= 65535):
        raise ProbeError(f"port out of range: {port}")

    timeout = timeout_ms / 1000.0
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ProbeError(f"DNS resolution failed for {host}: {e}")
    dns_ms = round((time.perf_counter() - t0) * 1000, 2)

    family, _, _, _, sockaddr = infos[0]
    t0 = time.perf_counter()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(sockaddr)
    except (socket.timeout, TimeoutError):
        sock.close()
        raise ProbeError(f"TCP connect timeout to {host}:{port}")
    except OSError as e:
        sock.close()
        raise ProbeError(f"TCP connect refused/unreachable {host}:{port}: {e}")
    connect_ms = round((time.perf_counter() - t0) * 1000, 2)
    sock.close()

    return {
        "dns_ms": dns_ms,
        "connect_ms": connect_ms,
        "latency_ms": connect_ms,
        "port": port,
    }
