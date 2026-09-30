"""Tests for the update distribution system + agent self-updater."""
import hashlib
import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
import uvicorn

from openeyes_agent import updater


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    from openeyes.app import create_app

    data_dir = tmp_path_factory.mktemp("upd")
    app = create_app(str(data_dir))
    app.state.store.db.set_meta("admin_token", "test-admin-token")
    port = _free_port()
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    yield {"base": f"http://127.0.0.1:{port}",
           "updates_dir": app.state.updates_dir,
           "db": app.state.store.db}
    server.should_exit = True
    t.join(timeout=5)


def _put(url: str, data: bytes, headers: dict):
    req = urllib.request.Request(url, data=data, method="PUT", headers=headers)
    return urllib.request.urlopen(req, timeout=10)


# ------------------------------------------------------------- version logic
def test_parse_and_compare_versions():
    assert updater.parse_version("1.10.2") == (1, 10, 2)
    assert updater.newer("1.10.0", "1.9.9") is True
    assert updater.newer("1.1.0", "1.1.0") is False
    assert updater.newer("1.0.9", "1.1.0") is False
    assert updater.newer("1.1.0-rc1", "1.0.9") is True
    assert updater.newer("2.0.0", "10.0.0") is False


def test_platform_key_format():
    key = updater.platform_key()
    os_part, _, arch_part = key.partition("-")
    assert os_part in ("linux", "darwin", "windows")
    assert arch_part != ""


# ------------------------------------------------------------- manifest flow
def test_manifest_empty_initially(live):
    url = live["base"] + "/api/v1/update/manifest"
    m = json.loads(urllib.request.urlopen(url).read())
    assert m["agent_version"] is None and m["assets"] == {}
    assert "server_version" in m


def test_publish_download_and_manifest(live):
    payload = b"#!/bin/sh\necho fake-agent-binary-v1.2.0\n"
    sha = hashlib.sha256(payload).hexdigest()
    name = "openeyes-agent-linux-x86_64"

    # unauthorized publish rejected
    with pytest.raises(urllib.error.HTTPError) as ei:
        _put(f"{live['base']}/api/v1/update/assets/{name}", payload,
             {"X-Version": "1.2.0", "X-Platform": "linux-x86_64"})
    assert ei.value.code == 401

    r = _put(f"{live['base']}/api/v1/update/assets/{name}", payload,
             {"X-Version": "1.2.0", "X-Platform": "linux-x86_64",
              "X-Admin-Token": "test-admin-token"})
    assert json.loads(r.read())["sha256"] == sha

    m = json.loads(urllib.request.urlopen(
        live["base"] + "/api/v1/update/manifest").read())
    assert m["agent_version"] == "1.2.0"
    asset = m["assets"]["linux-x86_64"]
    assert asset["sha256"] == sha and asset["size"] == len(payload)

    got = urllib.request.urlopen(live["base"] + asset["url"]).read()
    assert got == payload


def test_asset_name_sanitised(live):
    for bad in ("../etc/passwd", "a/b", "x" * 200):
        req = urllib.request.Request(
            live["base"] + "/api/v1/update/assets/" + urllib.parse.quote(bad),
            headers={"X-Admin-Token": "test-admin-token"})
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(req)
        assert ei.value.code in (400, 404)


def test_missing_headers_rejected(live):
    with pytest.raises(urllib.error.HTTPError) as ei:
        _put(live["base"] + "/api/v1/update/assets/foo.bin", b"x",
             {"X-Admin-Token": "test-admin-token"})
    assert ei.value.code == 400


# --------------------------------------------------------------- agent side
def test_download_and_verify(live):
    m = json.loads(urllib.request.urlopen(
        live["base"] + "/api/v1/update/manifest").read())
    asset = m["assets"]["linux-x86_64"]
    tmp = updater.download_asset(live["base"], asset)
    assert open(tmp, "rb").read().startswith(b"#!/bin/sh")
    import os
    os.unlink(tmp)
    # corrupted checksum must be rejected
    bad = dict(asset, sha256="0" * 64)
    with pytest.raises(updater.UpdateError):
        updater.download_asset(live["base"], bad)


def test_check_and_apply_skips_when_current(live):
    logs = []
    applied = updater.check_and_apply(live["base"], "9.9.9", log=logs.append)
    assert applied is False


def test_check_and_apply_full_cycle(live, tmp_path, monkeypatch):
    fake_exe = tmp_path / "openeyes-agent"
    fake_exe.write_bytes(b"old-binary")
    monkeypatch.setattr(updater, "is_frozen", lambda: True)
    monkeypatch.setattr(updater.sys, "executable", str(fake_exe))

    logs = []
    applied = updater.check_and_apply(live["base"], "1.0.0", log=logs.append)
    assert applied is True
    assert fake_exe.read_bytes().startswith(b"#!/bin/sh")  # replaced
    assert (tmp_path / "openeyes-agent.old").read_bytes() == b"old-binary"


def test_check_and_apply_refuses_when_from_source(live, monkeypatch):
    monkeypatch.setattr(updater, "is_frozen", lambda: False)
    logs = []
    applied = updater.check_and_apply(live["base"], "1.0.0", log=logs.append)
    assert applied is False
    assert any("source" in l for l in logs)


def test_check_and_apply_no_asset_for_platform(live, monkeypatch):
    monkeypatch.setattr(updater, "platform_key", lambda: "beos-m68k")
    logs = []
    applied = updater.check_and_apply(live["base"], "1.0.0", log=logs.append)
    assert applied is False
    assert any("no artifact" in l for l in logs)
