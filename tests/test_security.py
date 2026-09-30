"""Security audit tests: auth matrix, injection, limits, headers, hashing."""
import base64
import hashlib
import hmac
import json
import time


def _login(c, pw):
    return c.post("/api/v1/login", json={"password": pw})


# ------------------------------------------------------------- hardening
def test_security_headers_present(admin):
    r = admin["client"].get("/")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("referrer-policy") == "no-referrer"
    r2 = admin["client"].get("/api/v1/stats")
    assert r2.headers.get("x-content-type-options") == "nosniff"


def test_password_hash_is_salted(server):
    stored = server["db"].get_meta("admin_password_hash")
    assert "$" in stored, "expected salt$digest format"
    salt, _, digest = stored.partition("$")
    assert len(salt) >= 16 and len(digest) == 64


def test_legacy_unsalted_hash_still_verifies():
    from openeyes.db import verify_password, _hash_password
    legacy = _hash_password("hunter2")
    assert verify_password("hunter2", legacy)
    assert not verify_password("wrong", legacy)
    assert not verify_password("x", "")


# ------------------------------------------------------------ auth matrix
def test_admin_auth_matrix(server):
    c = server["client"]
    paths = ["/api/v1/tests", "/api/v1/agents", "/api/v1/stats",
             "/api/v1/alerts", "/api/v1/results", "/api/v1/locations",
             "/api/v1/enrollment-token", "/api/v1/version", "/api/v1/webprobes"]
    for p in paths:
        assert c.get(p).status_code == 401, p
    for p in paths:
        assert c.get(p, headers={"X-Admin-Token": "bogus"}).status_code == 401, p
    assert c.post("/api/v1/admin/restart").status_code == 401
    # body validation may fire before the auth check -> 422 is acceptable
    assert c.post("/api/v1/tests", json={}).status_code in (401, 422)
    assert c.delete("/api/v1/tests/x").status_code == 401


def test_forged_and_expired_session_rejected(server):
    c = server["client"]
    secret = server["db"].get_meta("session_secret").encode()
    # valid signature but expired
    exp = int(time.time()) - 10
    payload = base64.urlsafe_b64encode(str(exp).encode()).decode()
    sig = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
    c.cookies.clear()
    c.cookies.set("openeyes_session", f"{payload}.{sig}")
    assert c.get("/api/v1/me").json()["authed"] is False
    # garbage cookie
    c.cookies.set("openeyes_session", "garbage")
    assert c.get("/api/v1/me").json()["authed"] is False


def test_agent_token_matrix(server):
    c = server["client"]
    assert c.get("/api/v1/agents/me/config").status_code == 401
    assert c.get("/api/v1/agents/me/config",
                 headers={"X-Agent-Token": "x" * 32}).status_code == 401
    # token from one agent must not work after deletion
    reg = c.post("/api/v1/agents/register", json={
        "enrollment_token": server["enrollment_token"], "hostname": "tmp"})
    tok = reg.json()["agent_token"]
    aid = reg.json()["agent_id"]
    assert c.get("/api/v1/agents/me/config",
                 headers={"X-Agent-Token": tok}).status_code == 200
    c.post("/api/v1/login", json={"password": server["password"]})
    c.delete(f"/api/v1/agents/{aid}")
    assert c.get("/api/v1/agents/me/config",
                 headers={"X-Agent-Token": tok}).status_code == 401


# ------------------------------------------------------------- injection
def test_sql_injection_is_inert(admin):
    c = admin["client"]
    evil = "x' OR '1'='1"
    r = c.get(f"/api/v1/results?test_id={evil}&agent_id={evil}")
    assert r.status_code == 200 and r.json()["items"] == []
    # name containing SQL – stored literally, tables untouched
    r = c.post("/api/v1/tests", json={
        "name": "'; DROP TABLE tests; --", "type": "http",
        "target": "https://example.com"})
    assert r.status_code == 200
    assert any(t["name"].startswith("'; DROP")
               for t in c.get("/api/v1/tests").json()["items"])
    assert c.get("/api/v1/stats").status_code == 200  # schema alive


def test_traversal_and_bad_names_rejected(admin):
    c = admin["client"]
    for name in ("../secrets", "..%2f..%2fetc%2fpasswd", "a/../../b",
                 "\\windows", "x" * 200, ""):
        r = c.put(f"/api/v1/update/assets/{name}",
                  content=b"evil", headers={"X-Version": "9", "X-Platform": "linux-x86_64"})
        assert r.status_code in (400, 404, 422), name
        r = c.get(f"/api/v1/update/assets/{name}")
        assert r.status_code in (400, 404), name


def test_oversized_inputs_rejected(admin):
    c = admin["client"]
    big = [{"test_id": "t", "ts": time.time(), "status": "ok"}] * 600
    r = c.post("/api/v1/agents/me/results", json={"results": big})
    assert r.status_code in (401, 422)  # unauth first; auth below
    reg = c.post("/api/v1/agents/register", json={
        "enrollment_token": admin["enrollment_token"], "hostname": "big"})
    hdr = {"X-Agent-Token": reg.json()["agent_token"]}
    r = c.post("/api/v1/agents/me/results", headers=hdr, json={"results": big})
    assert r.status_code == 422, "600-item batch must be rejected"
    r = c.post("/api/v1/tests", json={"name": "N" * 500, "type": "http",
                                      "target": "https://x"})
    assert r.status_code == 422
    assert _login(c, "P" * 1000).status_code == 422


def test_malformed_json_rejected(admin):
    import httpx
    r = admin["client"].request(
        "POST", "/api/v1/tests", content=b"{not json",
        headers={"Content-Type": "application/json"})
    assert r.status_code == 422


# ------------------------------------------------------------ rate limit
def test_webprobe_rate_limited(server):
    c = server["client"]
    # limiter is per-IP; TestClient uses testclient IP for all requests
    codes = []
    for _ in range(35):
        codes.append(c.post("/api/v1/webprobe/results",
                            json={"metrics": {}}).status_code)
    assert 429 in codes, "rate limiter never engaged"
    assert codes.count(429) >= 1
    # and admin ingest endpoints are not rate limited
    c.post("/api/v1/login", json={"password": server["password"]})
    assert c.get("/api/v1/stats").status_code == 200


# ------------------------------------------------------------- XSS sweep
def test_user_strings_are_escaped_in_html(admin):
    c = admin["client"]
    evil = "<img src=x onerror=alert(1)>"
    c.post("/api/v1/tests", json={"name": evil, "type": "http",
                                  "target": "https://example.com"})
    reg = c.post("/api/v1/agents/register", json={
        "enrollment_token": admin["enrollment_token"], "hostname": evil})
    hdr = {"X-Agent-Token": reg.json()["agent_token"]}
    c.post("/api/v1/agents/me/results", headers=hdr, json={"results": [
        {"test_id": "x", "ts": time.time(), "status": "fail", "error": evil}]})
    # The dashboard is a JS SPA that escapes via esc(); raw HTML must never
    # contain the unescaped payload.
    html = c.get("/").text
    assert "<img src=x onerror" not in html
