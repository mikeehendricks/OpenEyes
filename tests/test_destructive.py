"""Destructive / resilience tests.

* SIGKILL the server while an agent is actively writing -> DB survives,
  server restarts cleanly, agent self-heals and keeps reporting.
* Corrupt the WAL file -> next start recovers (SQLite checksummed WAL).
* Failed binary swap must roll back and never destroy the old executable.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_DIR = os.path.join(ROOT, "server")
AGENT_DIR = os.path.join(ROOT, "agent")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, up=True, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            if up:
                return True
        except OSError:
            if not up:
                return True
        finally:
            s.close()
        time.sleep(0.3)
    return False


def _start_server(port, data_dir):
    return subprocess.Popen(
        [sys.executable, "-m", "openeyes", "--port", str(port),
         "--data-dir", data_dir],
        cwd=SERVER_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.fixture()
def crash_env(tmp_path):
    port = _free_port()
    data_dir = str(tmp_path / "data")
    srv = _start_server(port, data_dir)
    assert _wait_port(port), "server did not start"
    yield {"port": port, "data_dir": data_dir}
    for p in (srv,):
        if p.poll() is None:
            p.terminate()
            p.wait(timeout=5)


def test_sigkill_mid_write_and_recovery(crash_env, tmp_path):
    import urllib.request

    port, data_dir = crash_env["port"], crash_env["data_dir"]
    base = f"http://127.0.0.1:{port}"

    # read first-run credentials straight from disk
    creds = {}
    for line in open(os.path.join(data_dir, "first_run.txt")):
        k, _, v = line.partition(":")
        creds[k.strip()] = v.strip()

    # give ourselves an admin token + one always-healthy fast test
    import sqlite3
    con = sqlite3.connect(os.path.join(data_dir, "openeyes.db"))
    con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('admin_token','dt')")
    con.commit()
    con.close()
    req = urllib.request.Request(
        base + "/api/v1/tests",
        data=json.dumps({"name": "server-tcp", "type": "tcp",
                         "target": f"127.0.0.1:{port}", "interval_sec": 5,
                         "timeout_ms": 2000}).encode(),
        headers={"Content-Type": "application/json", "X-Admin-Token": "dt"})
    urllib.request.urlopen(req, timeout=5).read()

    # start a real agent writing every few seconds
    agent = subprocess.Popen(
        [sys.executable, "-m", "openeyes_agent", "--server", base,
         "--enroll-token", creds["enrollment_token"],
         "--state", str(tmp_path / "state.json")],
        cwd=AGENT_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(6)  # let it enroll + produce results

    def stats():
        with urllib.request.urlopen(base + "/api/v1/me", timeout=5) as r:
            return json.load(r)

    assert stats() == {"authed": False}

    # ---- DESTRUCTIVE: SIGKILL the server (no graceful shutdown, WAL hot)
    os.kill(_server_pid(port), signal.SIGKILL)
    assert _wait_port(port, up=False, timeout=10), "server still alive?!"
    assert agent.poll() is None, "agent must survive a server outage"

    # ---- recovery: restart, DB must open with prior data intact
    srv2 = _start_server(port, data_dir)
    try:
        assert _wait_port(port), "server did not come back"
        import sqlite3
        con = sqlite3.connect(f"file:{data_dir}/openeyes.db?mode=ro", uri=True)
        ok = con.execute("PRAGMA integrity_check").fetchone()[0]
        n_before = con.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        con.close()
        assert ok == "ok"
        assert n_before > 0, "pre-crash results lost"

        # agent self-heals and keeps writing
        deadline = time.time() + 45
        n_after = n_before
        while time.time() < deadline and n_after <= n_before:
            time.sleep(3)
            con = sqlite3.connect(f"file:{data_dir}/openeyes.db?mode=ro", uri=True)
            n_after = con.execute("SELECT COUNT(*) FROM results").fetchone()[0]
            con.close()
        assert n_after > n_before, "agent did not resume after crash"
    finally:
        srv2.terminate()
        srv2.wait(timeout=5)
        agent.terminate()
        agent.wait(timeout=5)


def _server_pid(port):
    out = subprocess.run(["pgrep", "-f", f"openeyes --port {port}"],
                         capture_output=True, text=True).stdout
    return int(out.split()[0])


def test_wal_corruption_recovers(crash_env):
    port, data_dir = crash_env["port"], crash_env["data_dir"]
    # stop the fresh server, then trash the WAL
    _pid = _server_pid(port)
    os.kill(_pid, signal.SIGTERM)
    _wait_port(port, up=False, timeout=10)

    wal = os.path.join(data_dir, "openeyes.db-wal")
    with open(wal, "wb") as fh:
        fh.write(b"\xde\xad\xbe\xef" * 4096)  # garbage WAL

    srv = _start_server(port, data_dir)
    try:
        assert _wait_port(port), "server must recover from corrupt WAL"
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/me",
                                    timeout=5) as r:
            assert json.load(r) == {"authed": False}
    finally:
        srv.terminate()
        srv.wait(timeout=5)


# ------------------------------------------------------- failed update swap
def test_failed_swap_rolls_back(tmp_path, monkeypatch):
    from openeyes_agent import updater

    fake_exe = tmp_path / "agent.bin"
    fake_exe.write_bytes(b"original")
    monkeypatch.setattr(updater, "is_frozen", lambda: True)
    monkeypatch.setattr(updater.sys, "executable", str(fake_exe))
    # make the directory read-only -> both rename and replace fail
    os.chmod(tmp_path, 0o555)
    try:
        new = tmp_path / "incoming.bin"
        # cannot even create the temp file here; craft one elsewhere
        import tempfile
        fd, tmp = tempfile.mkstemp()
        os.write(fd, b"new-version")
        os.close(fd)
        with pytest.raises(updater.UpdateError):
            updater.swap_executable(tmp)
    finally:
        os.chmod(tmp_path, 0o755)
    assert fake_exe.read_bytes() == b"original", "old binary must be intact"
