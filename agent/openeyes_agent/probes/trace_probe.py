"""Traceroute probe wrapping the platform traceroute binary.

Uses `traceroute` on Linux/macOS and `tracert` on Windows. If no binary is
available the probe reports an error (install traceroute to enable it).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys


class ProbeError(Exception):
    pass


def run(target: str, timeout_ms: int = 30000, params: dict | None = None) -> dict:
    host = target.split(":")[0] if ":" in target and target.count(":") == 1 else target
    max_hops = int((params or {}).get("max_hops", 25))
    timeout_s = max(5, timeout_ms / 1000.0)

    if sys.platform == "win32":
        exe = shutil.which("tracert")
        if not exe:
            raise ProbeError("tracert not available on this system")
        cmd = [exe, "-d", "-h", str(max_hops), "-w", "2000", host]
        line_re = re.compile(
            r"^\s*(\d+)\s+(?:([\d.<]+)\s*ms)\s+(?:([\d.<]+)\s*ms)?\s+(?:([\d.<]+)\s*ms)?"
            r"\s+([\d.]+|\S+)")
    else:
        exe = shutil.which("traceroute")
        if not exe:
            raise ProbeError("traceroute not installed (apt install traceroute)")
        cmd = [exe, "-n", "-q", "1", "-w", "2", "-m", str(max_hops), host]
        line_re = re.compile(r"^\s*(\d+)\s+(.+)$")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_s + 10)
    except subprocess.TimeoutExpired:
        raise ProbeError(f"traceroute to {host} timed out after {timeout_s:.0f}s")
    except OSError as e:
        raise ProbeError(f"could not run traceroute: {e}")

    hops: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        if sys.platform == "win32":
            m = line_re.match(line)
            if m:
                rtts = [float(x) for x in m.groups()[1:4]
                        if x and re.match(r"^[\d.]+$", x)]
                hops.append({"hop": int(m.group(1)), "ip": m.group(5),
                             "rtt_ms": sum(rtts) / len(rtts) if rtts else None})
        else:
            m = line_re.match(line)
            if not m:
                continue
            idx, rest = int(m.group(1)), m.group(2)
            if "*" in rest and not re.search(r"[\d.]+\s*ms", rest):
                hops.append({"hop": idx, "ip": "*", "rtt_ms": None})
                continue
            times = re.findall(r"([\d.]+)\s*ms", rest)
            ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]{6,})", rest)
            hops.append({"hop": idx, "ip": ip_m.group(1) if ip_m else "?",
                         "rtt_ms": float(times[0]) if times else None})

    if not hops:
        raise ProbeError(f"traceroute to {host} produced no output")

    complete = hops[-1]["ip"] != "*" and any(
        h["rtt_ms"] is not None for h in hops[-2:])
    total = round(sum(h["rtt_ms"] or 0 for h in hops), 2)
    return {
        "hops": hops,
        "hop_count": len(hops),
        "complete": bool(complete),
        "total_ms": total,
        "latency_ms": hops[-1]["rtt_ms"] if hops[-1]["rtt_ms"] is not None else total,
    }
