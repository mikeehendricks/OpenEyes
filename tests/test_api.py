"""API-level tests for the OpenEyes server."""
import time


def _enroll(client, token, hostname="test-host"):
    return client.post("/api/v1/agents/register", json={
        "enrollment_token": token, "hostname": hostname,
        "os": "Linux", "arch": "x86_64", "version": "1.0.0",
        "labels": ["unit"],
    })


def _make_test(client, **over):
    body = {"name": "Example HTTP", "type": "http",
            "target": "https://example.com", "interval_sec": 60,
            "timeout_ms": 5000, "params": {}, "assign": {"mode": "all"}}
    body.update(over)
    r = client.post("/api/v1/tests", json=body)
    assert r.status_code == 200, r.text
    return r.json()["id"]


# --------------------------------------------------------------------- auth
def test_login_rejects_bad_password(server):
    r = server["client"].post("/api/v1/login", json={"password": "nope"})
    assert r.status_code == 401


def test_login_and_me(server):
    c = server["client"]
    assert c.get("/api/v1/me").json()["authed"] is False
    r = c.post("/api/v1/login", json={"password": server["password"]})
    assert r.status_code == 200
    assert c.get("/api/v1/me").json()["authed"] is True


def test_admin_endpoints_require_auth(server):
    for path in ("/api/v1/tests", "/api/v1/agents", "/api/v1/stats",
                 "/api/v1/alerts", "/api/v1/enrollment-token"):
        assert server["client"].get(path).status_code == 401


def test_admin_token_header_works(admin):
    c = admin["client"]
    token = c.get("/api/v1/admin-token").json()["token"]
    # fresh client without cookie
    import fastapi.testclient as tc
    fresh = tc.TestClient(admin["app"])
    assert fresh.get("/api/v1/stats").status_code == 401
    r = fresh.get("/api/v1/stats", headers={"X-Admin-Token": token})
    assert r.status_code == 200


# ---------------------------------------------------------------- enrolment
def test_enrollment_rejects_bad_token(server):
    r = server["client"].post("/api/v1/agents/register", json={
        "enrollment_token": "wrong", "hostname": "x"})
    assert r.status_code == 403


def test_enrollment_and_agent_config(admin):
    c = admin["client"]
    r = _enroll(c, admin["enrollment_token"])
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"].startswith("agent-")

    test_id = _make_test(c)
    cfg = c.get("/api/v1/agents/me/config",
                headers={"X-Agent-Token": body["agent_token"]})
    assert cfg.status_code == 200
    tests = cfg.json()["tests"]
    assert len(tests) == 1 and tests[0]["id"] == test_id


def test_agent_token_required_for_config(server):
    assert server["client"].get("/api/v1/agents/me/config").status_code == 401
    r = server["client"].get("/api/v1/agents/me/config",
                             headers={"X-Agent-Token": "bogus"})
    assert r.status_code == 401


def test_enrollment_token_rotation(admin):
    c = admin["client"]
    new = c.post("/api/v1/enrollment-token/rotate").json()["token"]
    assert _enroll(c, admin["enrollment_token"]).status_code == 403
    assert _enroll(c, new).status_code == 200


# ------------------------------------------------------------- test CRUD
def test_test_validation(admin):
    c = admin["client"]
    bad = {"name": "x", "type": "smtp", "target": "host", "interval_sec": 60,
           "timeout_ms": 5000, "params": {}, "assign": {"mode": "all"}}
    assert c.post("/api/v1/tests", json=bad).status_code == 400
    bad2 = dict(bad, type="http", target="  ")
    assert c.post("/api/v1/tests", json=bad2).status_code == 400
    bad3 = dict(bad, type="http", target="ok", interval_sec=2)
    assert c.post("/api/v1/tests", json=bad3).status_code == 400


def test_test_patch_and_delete(admin):
    c = admin["client"]
    test_id = _make_test(c)
    r = c.patch(f"/api/v1/tests/{test_id}", json={
        "name": "Renamed", "type": "tcp", "target": "db.internal:5432",
        "interval_sec": 30, "timeout_ms": 3000,
        "params": {"alert_fail_streak": 3}, "assign": {"mode": "all"},
        "enabled": False})
    assert r.status_code == 200
    t = [x for x in c.get("/api/v1/tests").json()["items"] if x["id"] == test_id][0]
    assert t["name"] == "Renamed" and t["enabled"] is False and t["type"] == "tcp"
    assert c.delete(f"/api/v1/tests/{test_id}").status_code == 200
    assert c.delete(f"/api/v1/tests/{test_id}").status_code == 404


# --------------------------------------------------------- assignment rules
def test_assignment_by_label(admin):
    c = admin["client"]
    r1 = _enroll(c, admin["enrollment_token"], "host-a")
    r2 = _enroll(c, admin["enrollment_token"], "host-b")
    _make_test(c, name="all-agents")
    _make_test(c, name="labeled-only",
               assign={"mode": "labels", "labels": ["unit"]})
    _make_test(c, name="other-labels",
               assign={"mode": "labels", "labels": ["datacenter"]})

    def assigned(token):
        return {t["name"] for t in c.get(
            "/api/v1/agents/me/config",
            headers={"X-Agent-Token": token}).json()["tests"]}

    assert assigned(r1.json()["agent_token"]) == {"all-agents", "labeled-only"}
    assert assigned(r2.json()["agent_token"]) == {"all-agents", "labeled-only"}

    # disabled tests disappear
    items = c.get("/api/v1/tests").json()["items"]
    tid = [t["id"] for t in items if t["name"] == "labeled-only"][0]
    body = next(t for t in items if t["id"] == tid)
    body["enabled"] = False
    assert c.patch(f"/api/v1/tests/{tid}", json=body).status_code == 200
    assert "labeled-only" not in assigned(r1.json()["agent_token"])


# ------------------------------------------------------------ results/alerts
def test_results_ingest_and_query(admin):
    c = admin["client"]
    reg = _enroll(c, admin["enrollment_token"]).json()
    test_id = _make_test(c)
    hdr = {"X-Agent-Token": reg["agent_token"]}
    now = time.time()
    r = c.post("/api/v1/agents/me/results", headers=hdr, json={
        "results": [
            {"test_id": test_id, "ts": now - 10, "status": "ok",
             "metrics": {"latency_ms": 120.5, "status_code": 200}},
            {"test_id": test_id, "ts": now, "status": "ok",
             "metrics": {"latency_ms": 98.0, "status_code": 200}},
            {"test_id": "test-doesnotexist", "ts": now, "status": "ok",
             "metrics": {}},
        ]})
    assert r.json()["stored"] == 2  # unknown test silently dropped
    rows = c.get(f"/api/v1/results?test_id={test_id}").json()["items"]
    assert len(rows) == 2
    assert rows[0]["metrics"]["latency_ms"] == 98.0  # newest first
    assert c.get("/api/v1/stats").json()["results"] == 2


def test_alert_engine_failure_and_recovery(admin):
    c = admin["client"]
    reg = _enroll(c, admin["enrollment_token"]).json()
    test_id = _make_test(c, params={"alert_fail_streak": 2})
    hdr = {"X-Agent-Token": reg["agent_token"]}
    now = time.time()
    post = lambda status, err=None: c.post(  # noqa: E731
        "/api/v1/agents/me/results", headers=hdr, json={
            "results": [{"test_id": test_id, "ts": now, "status": status,
                         "metrics": {}, "error": err}]})

    post("fail", "timeout")
    assert len(c.get("/api/v1/alerts").json()["items"]) == 0  # streak=1, no alert
    post("fail", "timeout")
    alerts = c.get("/api/v1/alerts").json()["items"]
    assert len(alerts) == 1 and alerts[0]["kind"] == "failure"
    # duplicate failure does not create a second alert
    post("fail", "still down")
    assert len(c.get("/api/v1/alerts").json()["items"]) == 1
    # recovery resolves it
    post("ok")
    assert len(c.get("/api/v1/alerts").json()["items"]) == 0
    hist = c.get("/api/v1/alerts?include_resolved=true").json()["items"]
    assert len(hist) == 1 and hist[0]["resolved_ts"] is not None


def test_agent_online_flag_and_deletion(admin):
    c = admin["client"]
    reg = _enroll(c, admin["enrollment_token"]).json()
    agents = c.get("/api/v1/agents").json()["items"]
    assert agents and agents[0]["online"] is True
    assert "token_hash" not in agents[0]
    # rotate token -> old token must stop working
    c.post(f"/api/v1/agents/{reg['agent_id']}/rotate-token")
    assert c.get("/api/v1/agents/me/config",
                 headers={"X-Agent-Token": reg["agent_token"]}).status_code == 401
    assert c.delete(f"/api/v1/agents/{reg['agent_id']}").status_code == 200
    assert c.get("/api/v1/agents").json()["items"] == []


# ------------------------------------------------------------------ pages
def test_dashboard_and_probe_pages(admin):
    c = admin["client"]
    r = c.get("/")
    assert r.status_code == 200 and "OpenEyes" in r.text
    r = c.get("/probe")
    assert r.status_code == 200 and "Web Probe" in r.text
    assert c.get("/api/v1/webprobe/beacon").status_code == 200


def test_webprobe_submission(server):
    c = server["client"]
    r = c.post("/api/v1/webprobe/results", json={
        "metrics": {"device": "iPhone", "os": "iOS",
                    "checks": {"server": {"ok": True, "total_ms": 42.0}}}})
    assert r.status_code == 200
    # listing requires admin though
    assert c.get("/api/v1/webprobes").status_code == 401
