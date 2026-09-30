"""Unit tests for the agent probes (run against local fixtures)."""
import http.server
import socket
import subprocess
import sys
import threading

import pytest

from openeyes_agent.probes import (dns_probe, http_probe, ping_probe,
                                   sysinfo, tcp_probe, trace_probe)


# ---------------------------------------------------------------- fixture
@pytest.fixture(scope="module")
def local_http():
    """Tiny local HTTP server used as a probe target."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.end_headers()
                return
            body = b"hello openeyes"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _port(addr):
    return int(addr.rsplit(":", 1)[1])


# ------------------------------------------------------------------- http
def test_http_probe_ok(local_http):
    m = http_probe.run(f"http://{local_http}/ok", timeout_ms=4000)
    assert m["status_code"] == 200
    assert m["bytes"] == len(b"hello openeyes")
    assert m["latency_ms"] > 0
    for k in ("dns_ms", "connect_ms", "ttfb_ms", "total_ms"):
        assert k in m and m[k] >= 0


def test_http_probe_follows_redirect(local_http):
    m = http_probe.run(f"http://{local_http}/redir", timeout_ms=4000)
    assert m["status_code"] == 200
    assert m.get("redirects", 0) >= 1


def test_http_probe_no_redirect_when_disabled(local_http):
    m = http_probe.run(f"http://{local_http}/redir", timeout_ms=4000,
                       params={"follow_redirects": False})
    assert m["status_code"] == 302


def test_http_probe_expected_status(local_http):
    with pytest.raises(http_probe.ProbeError):
        http_probe.run(f"http://{local_http}/ok", timeout_ms=4000,
                       params={"expected_status": 404})


def test_http_probe_bad_scheme():
    with pytest.raises(http_probe.ProbeError):
        http_probe.run("ftp://example.com")


def test_http_probe_unreachable():
    # find a free port and leave it closed
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(http_probe.ProbeError):
        http_probe.run(f"http://127.0.0.1:{port}/", timeout_ms=1500)


def test_http_probe_dns_failure():
    with pytest.raises(http_probe.ProbeError):
        http_probe.run("http://no-such-host.invalid/", timeout_ms=2000)


# -------------------------------------------------------------------- tcp
def test_tcp_probe_ok(local_http):
    m = tcp_probe.run(local_http, timeout_ms=3000)
    assert m["connect_ms"] >= 0 and m["port"] == _port(local_http)
    assert m["latency_ms"] == m["connect_ms"]


def test_tcp_probe_default_port_format():
    with pytest.raises(tcp_probe.ProbeError):
        tcp_probe.run("host:notaport", timeout_ms=500)


def test_tcp_probe_refused():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(tcp_probe.ProbeError):
        tcp_probe.run(f"127.0.0.1:{port}", timeout_ms=1500)


# -------------------------------------------------------------------- dns
def test_dns_probe_system_localhost():
    m = dns_probe.run("localhost", timeout_ms=3000)
    assert m["resolver"] == "system"
    assert m["resolve_ms"] >= 0
    assert any(a.startswith(("127.", "::1")) for a in m["answers"])


def test_dns_probe_nxdomain():
    with pytest.raises(dns_probe.ProbeError):
        dns_probe.run("no-such-host.invalid", timeout_ms=3000)


def test_dns_probe_unknown_resolver():
    with pytest.raises(dns_probe.ProbeError):
        dns_probe.run("example.com", params={"resolver": "bogus"})


# ------------------------------------------------------------------- ping
def test_ping_probe_localhost(local_http):
    """Any of the three strategies should reach localhost.

    Inside locked-down CI containers ICMP is often forbidden, so we point the
    TCP fallback at a live local port — on a real host ICMP will simply win.
    """
    port = _port(local_http)
    m = ping_probe.run("127.0.0.1", timeout_ms=3000,
                       params={"tcp_fallback_ports": [port]})
    assert m["rtt_ms"] >= 0
    assert m["method"] in ("icmp", "icmp_sys", "tcp_fallback")
    assert m["latency_ms"] == m["rtt_ms"]


def test_ping_probe_unreachable(monkeypatch):
    """When every strategy fails the probe must raise cleanly."""
    monkeypatch.setattr(ping_probe, "_try_dgram_icmp", lambda h, t: None)
    monkeypatch.setattr(ping_probe, "_try_system_ping", lambda h, ms, c: (None, 0, 0))
    monkeypatch.setattr(ping_probe, "_tcp_fallback", lambda h, t, ports=(443, 80): None)
    with pytest.raises(ping_probe.ProbeError):
        ping_probe.run("192.0.2.1", timeout_ms=500)


def test_ping_probe_real_icmp_when_allowed():
    """Opportunistic: if the OS allows ICMP, a real ping should work."""
    try:
        m = ping_probe.run("127.0.0.1", timeout_ms=2500,
                           params={"tcp_fallback_ports": []})
    except ping_probe.ProbeError:
        pytest.skip("ICMP not permitted in this environment")
    assert m["method"] in ("icmp", "icmp_sys")


# ------------------------------------------------------------------ trace
UNIX_TRACE = """traceroute to example.com (93.184.216.34), 25 hops max
 1  10.0.0.1  1.234 ms
 2  172.16.0.1  5.678 ms
 3  *
 4  93.184.216.34  12.345 ms
"""

WIN_TRACE = """Tracing route to example.com [93.184.216.34]

  1     2 ms     1 ms     1 ms  10.0.0.1
  2     6 ms     5 ms     6 ms  172.16.0.1
  3    13 ms    12 ms    12 ms  93.184.216.34

Trace complete.
"""


def _fake_run(output):
    def inner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=output, stderr="")
    return inner


def test_trace_parser_unix(monkeypatch):
    if sys.platform == "win32":
        pytest.skip("unix variant")
    monkeypatch.setattr(trace_probe.shutil, "which", lambda _: "/usr/bin/traceroute")
    monkeypatch.setattr(trace_probe.subprocess, "run", _fake_run(UNIX_TRACE))
    m = trace_probe.run("example.com", timeout_ms=10000)
    assert m["hop_count"] == 4
    assert m["hops"][2]["ip"] == "*" and m["hops"][2]["rtt_ms"] is None
    assert m["hops"][3]["ip"] == "93.184.216.34"
    assert m["complete"] is True
    assert m["latency_ms"] == 12.345


def test_trace_parser_windows(monkeypatch):
    monkeypatch.setattr(trace_probe.sys, "platform", "win32")
    monkeypatch.setattr(trace_probe.shutil, "which", lambda _: "tracert.exe")
    monkeypatch.setattr(trace_probe.subprocess, "run", _fake_run(WIN_TRACE))
    m = trace_probe.run("example.com", timeout_ms=10000)
    assert m["hop_count"] == 3
    assert m["hops"][0]["rtt_ms"] == pytest.approx(1.3333, rel=1e-3)
    assert m["complete"] is True


def test_trace_missing_binary(monkeypatch):
    monkeypatch.setattr(trace_probe.shutil, "which", lambda _: None)
    with pytest.raises(trace_probe.ProbeError):
        trace_probe.run("example.com")


# ---------------------------------------------------------------- sysinfo
def test_sysinfo_collect():
    info = sysinfo.collect()
    for key in ("hostname", "os", "arch", "python", "cpu_count", "local_ip"):
        assert key in info
    assert info["cpu_count"] >= 1
