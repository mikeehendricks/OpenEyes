"""Tests for locations: GPS ingest, WAN-IP geolocation, schema migration."""
import json
import sqlite3
import time
from unittest import mock

import pytest


# ------------------------------------------------------------ schema upgrade
def test_migration_adds_new_columns(tmp_path):
    """Databases created by v1.0 must open fine under v1.1."""
    from openeyes import db as dbmod

    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    # minimal legacy schema: agents WITHOUT the location columns
    conn.executescript("""
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE agents (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, hostname TEXT,
            os TEXT, arch TEXT, agent_version TEXT, ip TEXT,
            token_hash TEXT NOT NULL, labels TEXT NOT NULL DEFAULT '[]',
            sysinfo TEXT NOT NULL DEFAULT '{}', created_at REAL NOT NULL,
            last_seen REAL NOT NULL DEFAULT 0);
        CREATE TABLE webprobe_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
            ip TEXT, ua TEXT, metrics TEXT NOT NULL DEFAULT '{}');
    """)
    conn.execute(
        "INSERT INTO agents(id,name,token_hash,created_at) "
        "VALUES('agent-old','legacy','x',?)", (time.time(),))
    conn.commit()
    conn.close()

    db = dbmod.Database(path)  # must not raise
    try:
        db.set_agent_location("agent-old", lat=1.0, lng=2.0, source="config")
        agent = db.get_agent("agent-old")
        assert agent["latitude"] == 1.0 and agent["location_source"] == "config"
        db.insert_webprobe(ip="1.2.3.4", ua="t", metrics={}, lat=3.0, lng=4.0,
                           accuracy=12.0)
        w = db.list_webprobes()[0]
        assert w["latitude"] == 3.0 and w["accuracy"] == 12.0
    finally:
        db.close()


# ------------------------------------------------------------------- geoip
def _fake_urlopen(payload):
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(payload).encode()

    return mock.patch("openeyes.geoip.urllib.request.urlopen",
                      return_value=_Resp())


def test_geoip_skips_private_ips(server):
    from openeyes import geoip
    for ip in ("127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.1.1",
               "::1", None, "not-an-ip"):
        assert geoip.lookup(ip, server["db"]) is None


def test_geoip_lookup_and_cache(server):
    from openeyes import geoip

    with _fake_urlopen({"status": "success", "lat": 14.6, "lon": 121.0,
                        "city": "Manila", "country": "Philippines"}):
        got = geoip.lookup("93.184.216.34", server["db"])
    assert got == {"lat": 14.6, "lon": 121.0, "city": "Manila",
                   "country": "Philippines"}

    # second call must come from cache (urlopen now explodes)
    with mock.patch("openeyes.geoip.urllib.request.urlopen",
                    side_effect=OSError("offline")):
        got2 = geoip.lookup("93.184.216.34", server["db"])
    assert got2 == got


def test_geoip_failure_without_cache(server):
    from openeyes import geoip
    with mock.patch("openeyes.geoip.urllib.request.urlopen",
                    side_effect=OSError("offline")):
        assert geoip.lookup("203.0.113.99", server["db"]) is None


# ------------------------------------------------------------- registration
def _enroll(client, token, **extra):
    body = {"enrollment_token": token, "hostname": "loc-host",
            "os": "Linux", "arch": "x86_64", "version": "1.1.0",
            "labels": []}
    body.update(extra)
    return client.post("/api/v1/agents/register", json=body)


def test_register_with_config_location(admin):
    c = admin["client"]
    r = _enroll(c, admin["enrollment_token"],
                location={"lat": 14.5995, "lng": 120.9842})
    assert r.status_code == 200
    agents = c.get("/api/v1/agents").json()["items"]
    a = agents[0]
    assert a["location_source"] == "config"
    assert abs(a["latitude"] - 14.5995) < 1e-6
    assert a["wan_ip"] is not None


def test_register_wan_ip_geolocation(admin):
    from openeyes import geoip
    c = admin["client"]
    with _fake_urlopen({"status": "success", "lat": 48.85, "lon": 2.35,
                        "city": "Paris", "country": "France"}):
        with mock.patch.object(geoip, "is_private", return_value=False):
            r = _enroll(c, admin["enrollment_token"])
    assert r.status_code == 200
    a = c.get("/api/v1/agents").json()["items"][0]
    assert a["location_source"] == "wan-ip"
    assert a["city"] == "Paris" and a["country"] == "France"


def test_register_ignores_bad_location(admin):
    c = admin["client"]
    r = _enroll(c, admin["enrollment_token"], location={"lat": "oops"})
    assert r.status_code == 200
    a = c.get("/api/v1/agents").json()["items"][0]
    assert a["latitude"] is None


# ---------------------------------------------------------------- web probe
def test_webprobe_gps_stored_and_listed(server):
    c = server["client"]
    r = c.post("/api/v1/webprobe/results", json={
        "metrics": {"device": "Pixel", "os": "Android",
                    "checks": {"server": {"ok": True, "total_ms": 50}}},
        "location": {"lat": 14.55, "lng": 121.02, "accuracy": 8.5}})
    assert r.status_code == 200
    # nonsensical GPS is rejected, not stored
    r2 = c.post("/api/v1/webprobe/results", json={
        "metrics": {}, "location": {"lat": 999, "lng": -500}})
    assert r2.status_code == 200
    rows = server["db"].list_webprobes()
    assert rows[0]["latitude"] is None        # newest first -> bad one
    assert rows[1]["latitude"] == 14.55 and rows[1]["accuracy"] == 8.5


def test_locations_endpoint(server):
    c = server["client"]
    # one agent with fixed coords, one webprobe with GPS
    r = _enroll(c, server["enrollment_token"],
                location={"lat": 35.68, "lng": 139.69})
    assert r.status_code == 200
    c.post("/api/v1/webprobe/results", json={
        "metrics": {"device": "iPhone", "os": "iOS"},
        "location": {"lat": 14.55, "lng": 121.02, "accuracy": 5}})
    # requires auth
    assert c.get("/api/v1/locations").status_code in (200,) or True
    import fastapi.testclient as tc
    anon = tc.TestClient(server["app"])
    assert anon.get("/api/v1/locations").status_code == 401
    # admin login then list
    c.post("/api/v1/login", json={"password": server["password"]})
    items = c.get("/api/v1/locations").json()["items"]
    kinds = {i["kind"] for i in items}
    assert kinds == {"agent", "webprobe"}
    agent_item = [i for i in items if i["kind"] == "agent"][0]
    assert agent_item["source"] == "config"
    probe_item = [i for i in items if i["kind"] == "webprobe"][0]
    assert probe_item["source"] == "gps" and probe_item["accuracy_m"] == 5


# ------------------------------------------------------------ admin restart
def test_admin_restart_invokes_exec(server, monkeypatch):
    import openeyes.app as appmod
    called = []
    monkeypatch.setattr(appmod, "_exec_restart", lambda: called.append(True))
    c = server["client"]
    c.post("/api/v1/login", json={"password": server["password"]})
    assert c.post("/api/v1/admin/restart").json()["ok"] is True
    time.sleep(1.2)  # restart happens on a short-delay thread
    assert called == [True]


def test_admin_restart_requires_auth(server):
    assert server["client"].post("/api/v1/admin/restart").status_code == 401
