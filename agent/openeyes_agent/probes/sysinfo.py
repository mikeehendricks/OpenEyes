"""Cross-platform system info snapshot sent with agent heartbeats."""
from __future__ import annotations

import os
import platform
import socket
import sys


def collect() -> dict:
    info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_release": platform.release(),
        "arch": platform.machine(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
    }
    try:
        if hasattr(os, "getloadavg"):
            load1, load5, load15 = os.getloadavg()
            info["loadavg"] = [round(load1, 2), round(load5, 2), round(load15, 2)]
    except OSError:
        pass
    info["local_ip"] = _local_ip()
    return info


def _local_ip() -> str:
    for probe_host in ("8.8.8.8", "1.1.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect((probe_host, 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            continue
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"
