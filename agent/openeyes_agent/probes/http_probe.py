"""HTTP(S) probe with per-phase timing (DNS / connect / TLS / TTFB / total).

Implemented directly on sockets so we can report detailed per-phase
breakdowns using only the Python standard library.
"""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlsplit, urlunsplit

USER_AGENT = "OpenEyes-Agent/1.0"
MAX_BODY_BYTES = 512 * 1024
MAX_REDIRECTS = 3


class ProbeError(Exception):
    pass


def run(target: str, timeout_ms: int = 5000, params: dict | None = None) -> dict:
    params = params or {}
    timeout = timeout_ms / 1000.0
    method = params.get("method", "GET").upper()
    expected_status = params.get("expected_status")

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    url = target
    redirects = 0
    metrics: dict = {}

    while True:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ProbeError(f"unsupported scheme: {parts.scheme}")
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))

        phase = _fetch_one(host, port, path, parts.scheme == "https",
                           timeout, method, params)
        for k, v in phase.items():
            if k not in ("status", "location", "body_bytes"):
                metrics[k] = v
        metrics.setdefault("redirects", 0)

        status = phase["status"]
        if status in (301, 302, 303, 307, 308) and phase.get("location") \
                and params.get("follow_redirects", True) and redirects < MAX_REDIRECTS:
            loc = phase["location"]
            if loc.startswith("/"):
                loc = f"{parts.scheme}://{parts.netloc}{loc}"
            url = loc
            redirects += 1
            metrics["redirects"] = redirects
            continue

        metrics["status_code"] = status
        metrics["bytes"] = phase.get("body_bytes", 0)
        metrics["latency_ms"] = metrics.get("total_ms")
        if expected_status and status != int(expected_status):
            raise ProbeError(f"unexpected status {status} (expected {expected_status})")
        return metrics


def _fetch_one(host: str, port: int, path: str, use_tls: bool,
               timeout: float, method: str, params: dict) -> dict:
    m: dict = {}

    # --- DNS
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ProbeError(f"DNS resolution failed for {host}: {e}")
    m["dns_ms"] = _ms(t0)
    family, _, _, _, sockaddr = infos[0]

    # --- TCP connect
    t0 = time.perf_counter()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(sockaddr)
    except (socket.timeout, TimeoutError) as e:
        sock.close()
        raise ProbeError(f"TCP connect timeout to {host}:{port}: {e}")
    except OSError as e:
        sock.close()
        raise ProbeError(f"TCP connect failed to {host}:{port}: {e}")
    m["connect_ms"] = _ms(t0)

    # --- TLS handshake
    if use_tls:
        ctx = ssl.create_default_context()
        if params.get("insecure_tls"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        t0 = time.perf_counter()
        try:
            sock = ctx.wrap_socket(sock, server_hostname=host)
        except (ssl.SSLError, socket.timeout, OSError) as e:
            sock.close()
            raise ProbeError(f"TLS handshake failed with {host}: {e}")
        m["tls_ms"] = _ms(t0)
        m["tls_version"] = sock.version()

    # --- request
    req = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    t_start = time.perf_counter()
    try:
        sock.sendall(req)
        # --- TTFB: read status line (leftover bytes belong to the body!)
        head, leftover = _read_until_headers(sock, timeout)
        m["ttfb_ms"] = _ms(t_start)

        status, headers = _parse_head(head)
        # --- body
        length = _read_body(sock, headers, timeout, initial=leftover)
        m["total_ms"] = _ms(t_start)
        m["status"] = status
        m["body_bytes"] = length
        loc = headers.get("location")
        if loc:
            m["location"] = loc
        return m
    except (socket.timeout, TimeoutError) as e:
        raise ProbeError(f"timeout while reading from {host}: {e}")
    except OSError as e:
        raise ProbeError(f"connection error with {host}: {e}")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000.0, 2)


def _read_until_headers(sock: socket.socket, timeout: float) -> tuple[bytes, bytes]:
    """Returns (header_block, leftover_body_bytes_already_read)."""
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            raise ProbeError("response headers too large")
    if b"\r\n\r\n" not in buf:
        raise ProbeError("incomplete HTTP headers")
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def _parse_head(head: bytes) -> tuple[int, dict]:
    lines = head.decode("iso-8859-1").split("\r\n")
    if not lines:
        raise ProbeError("empty response")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProbeError(f"bad status line: {lines[0][:60]}")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return int(parts[1]), headers


def _read_body(sock: socket.socket, headers: dict, timeout: float,
               initial: bytes = b"") -> int:
    total = len(initial)
    deadline = time.monotonic() + timeout
    cl = headers.get("content-length")
    if cl and cl.isdigit():
        remaining = min(int(cl), MAX_BODY_BYTES) - total
        while remaining > 0:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            chunk = sock.recv(min(16384, remaining))
            if not chunk:
                break
            total += len(chunk)
            remaining -= len(chunk)
        return total
    # chunked or unknown length: read until close, bounded
    while total < MAX_BODY_BYTES:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        chunk = sock.recv(16384)
        if not chunk:
            break
        total += len(chunk)
    return total
