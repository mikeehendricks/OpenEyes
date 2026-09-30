"""DNS resolution probe.

Resolvers:
  system     – the OS resolver via getaddrinfo
  cloudflare – DNS-over-HTTPS against 1.1.1.1 (JSON API)
  google     – DNS-over-HTTPS against 8.8.8.8 (JSON API)
"""
from __future__ import annotations

import json
import socket
import ssl
import time

DOH_ENDPOINTS = {
    "cloudflare": ("cloudflare-dns.com", "/dns-query"),
    "google": ("dns.google", "/resolve"),
}


class ProbeError(Exception):
    pass


def run(target: str, timeout_ms: int = 5000, params: dict | None = None) -> dict:
    params = params or {}
    resolver = params.get("resolver", "system")
    hostname = target.strip()

    if resolver == "system":
        return _system_resolve(hostname, timeout_ms)
    if resolver in DOH_ENDPOINTS:
        return _doh_resolve(hostname, timeout_ms, resolver)
    raise ProbeError(f"unknown resolver '{resolver}' (system|cloudflare|google)")


def _system_resolve(hostname: str, timeout_ms: int) -> dict:
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ProbeError(f"NXDOMAIN/resolution failed for {hostname}: {e}")
    elapsed = round((time.perf_counter() - t0) * 1000, 2)
    answers = sorted({info[4][0] for info in infos})
    if not answers:
        raise ProbeError(f"no addresses returned for {hostname}")
    return {
        "resolver": "system",
        "resolve_ms": elapsed,
        "latency_ms": elapsed,
        "answers": answers[:8],
        "record_count": len(answers),
    }


def _doh_resolve(hostname: str, timeout_ms: int, provider: str) -> dict:
    host, path = DOH_ENDPOINTS[provider]
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        sock = socket.socket(infos[0][0], socket.SOCK_STREAM)
        sock.settimeout(timeout_ms / 1000.0)
        sock.connect(infos[0][4])
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=host)
        req = (
            f"GET {path}?name={hostname}&type=A HTTP/1.1\r\n"
            f"Host: {host}\r\nAccept: application/dns-json\r\n"
            f"User-Agent: OpenEyes-Agent/1.0\r\nConnection: close\r\n\r\n"
        ).encode()
        tls.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = tls.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        headers = {ln.split(":", 1)[0].strip().lower(): ln.split(":", 1)[1].strip()
                   for ln in head.decode("iso-8859-1").split("\r\n")[1:] if ":" in ln}
        body = rest
        cl = headers.get("content-length")
        if cl and cl.isdigit():
            while len(body) < int(cl):
                chunk = tls.recv(4096)
                if not chunk:
                    break
                body += chunk
        elif b'"Answer"' not in body and b'"Status"' not in body:
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                body += chunk
        tls.close()
    except (OSError, socket.timeout, TimeoutError) as e:
        raise ProbeError(f"DoH query to {provider} failed: {e}")
    elapsed = round((time.perf_counter() - t0) * 1000, 2)
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        raise ProbeError(f"bad DoH response from {provider}")
    status = data.get("Status", 0)
    if status != 0:
        raise ProbeError(f"DoH status {status} for {hostname} via {provider}")
    answers = [a["data"] for a in data.get("Answer", []) if a.get("type") in (1, 28)]
    if not answers:
        raise ProbeError(f"no A/AAAA answers for {hostname} via {provider}")
    return {
        "resolver": provider,
        "resolve_ms": elapsed,
        "latency_ms": elapsed,
        "answers": answers[:8],
        "record_count": len(answers),
    }
