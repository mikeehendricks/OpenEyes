"""OpenEyes server – FastAPI application.

An internet monitoring server:

* agents enroll with a shared token, then authenticate with per-agent tokens
* tests are defined centrally and assigned to agents (all / by id / by label)
* agents poll their config, execute probes, and ship results back
* results feed simple failure-streak / latency alerting and the dashboard
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time
from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel, Field

from . import db as dbmod
from . import geoip

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

SESSION_COOKIE = "openeyes_session"
SESSION_TTL = 12 * 3600
VALID_TEST_TYPES = {"http", "tcp", "ping", "dns", "trace"}
SERVER_VERSION = "1.2.0"
BUILD_NUMBER = 151
ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
WEBPROBE_RATE_PER_MIN = 30
# Injected for tests: actually performed by os.execv in production.
_exec_restart = None  # set inside create_app


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _location_display(lat, lng, city, country) -> str:
    """Human-readable place name; coordinates only as a fallback."""
    if city or country:
        return ", ".join(x for x in (city, country) if x)
    if lat is not None and lng is not None:
        return f"{float(lat):.2f}, {float(lng):.2f}"
    return ""


# --------------------------------------------------------------------------
# Request models (module-level so FastAPI resolves them as bodies)
# --------------------------------------------------------------------------

class LoginBody(BaseModel):
    password: str = Field(max_length=256)


class WebProbeBody(BaseModel):
    metrics: dict = Field(default_factory=dict)
    location: Optional[dict] = None  # {lat, lng, accuracy} from device GPS


class RegisterBody(BaseModel):
    enrollment_token: str = Field(max_length=256)
    hostname: str = Field(default="unknown", max_length=200)
    os: str = Field(default="unknown", max_length=64)
    arch: str = Field(default="unknown", max_length=64)
    version: str = Field(default="0.0.0", max_length=32)
    labels: list[str] = Field(default_factory=list, max_length=32)
    location: Optional[dict] = None  # optional fixed site coords from config


class ResultItem(BaseModel):
    test_id: str = Field(max_length=64)
    ts: float
    status: str = Field(max_length=16)  # ok | fail | error
    metrics: dict = Field(default_factory=dict)
    error: Optional[str] = Field(default=None, max_length=2000)


class ResultsBody(BaseModel):
    results: list[ResultItem] = Field(default_factory=list, max_length=500)
    sysinfo: Optional[dict] = None


class TestBody(BaseModel):
    name: str = Field(max_length=200)
    type: str = Field(max_length=16)
    target: str = Field(max_length=500)
    interval_sec: int = 60
    timeout_ms: int = 5000
    params: dict = Field(default_factory=dict)
    assign: dict = Field(default_factory=lambda: {"mode": "all"})
    enabled: bool = True


class DatabaseWrapper:
    """Holds the Database plus per-agent failure streak state."""

    def __init__(self, path: str):
        self.db = dbmod.Database(path)
        self.streaks: dict[tuple[str, str], int] = {}


def create_app(data_dir: str | None = None,
               restart_args: list[str] | None = None) -> FastAPI:
    global _exec_restart
    data_dir = data_dir or os.environ.get("OPENEYES_DATA_DIR") \
        or os.path.expanduser("~/.openeyes")
    db_path = os.path.join(data_dir, "openeyes.db")
    updates_dir = os.path.join(data_dir, "updates")
    os.makedirs(updates_dir, exist_ok=True)
    store = DatabaseWrapper(db_path)
    db = store.db
    first_run_info = db.bootstrap()

    if _exec_restart is None:
        _args = restart_args if restart_args is not None else sys.argv[1:]

        def _exec_restart():  # pragma: no cover - replaces process image
            os.execv(sys.executable, [sys.executable, "-m", "openeyes"] + _args)

    app = FastAPI(title="OpenEyes", version=SERVER_VERSION)
    app.state.store = store
    app.state.updates_dir = updates_dir

    def _geolocate_agent(agent_id: str, ip: str | None) -> None:
        """Resolve an agent's WAN IP to coordinates (cached, fault-tolerant)."""
        if not ip:
            return
        geo = geoip.lookup(ip, db)
        if geo:
            db.set_agent_location(agent_id, lat=geo["lat"], lng=geo["lon"],
                                  source="wan-ip", city=geo.get("city"),
                                  country=geo.get("country"))

    # --------------------------------------------- hardening: headers + rate
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        return response

    class _RateLimiter:
        """Fixed-window per-IP limiter for the unauthenticated ingest path."""

        def __init__(self, per_minute: int):
            self.limit = per_minute
            self.hits: dict[str, list[float]] = {}

        def allow(self, ip: str) -> bool:
            now = time.time()
            bucket = [t for t in self.hits.get(ip, []) if now - t < 60]
            if len(bucket) >= self.limit:
                self.hits[ip] = bucket
                return False
            bucket.append(now)
            self.hits[ip] = bucket
            if len(self.hits) > 10000:  # memory bound
                self.hits = {k: v for k, v in self.hits.items()
                             if v and now - v[-1] < 120}
            return True

    webprobe_limiter = _RateLimiter(WEBPROBE_RATE_PER_MIN)
    app.state.webprobe_limiter = webprobe_limiter

    # ------------------------------------------------------------- lifecycle
    @app.on_event("shutdown")
    def _shutdown() -> None:
        db.close()

    # ------------------------------------------------------------------ auth
    session_secret = (db.get_meta("session_secret") or "insecure").encode()

    def _make_session() -> str:
        exp = int(time.time()) + SESSION_TTL
        payload = base64.urlsafe_b64encode(str(exp).encode()).decode()
        sig = hmac.new(session_secret, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"

    def _session_valid(cookie: str | None) -> bool:
        if not cookie or "." not in cookie:
            return False
        payload, _, sig = cookie.partition(".")
        expect = hmac.new(session_secret, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            return False
        try:
            exp = int(base64.urlsafe_b64decode(payload.encode()))
        except Exception:
            return False
        return exp > time.time()

    def _is_admin(request: Request) -> bool:
        if _session_valid(request.cookies.get(SESSION_COOKIE)):
            return True
        supplied = request.headers.get("x-admin-token")
        if supplied:
            expected = db.get_meta("admin_token")
            if expected and secrets.compare_digest(supplied, expected):
                return True
        return False

    def _require_admin(request: Request) -> None:
        if not _is_admin(request):
            raise HTTPException(status_code=401, detail="admin auth required")

    def _auth_agent(request: Request) -> dict:
        token = request.headers.get("x-agent-token")
        if not token:
            raise HTTPException(status_code=401, detail="missing agent token")
        th = _hash_token(token)
        for agent in db.list_agents():
            if secrets.compare_digest(agent["token_hash"], th):
                return agent
        raise HTTPException(status_code=401, detail="invalid agent token")

    # ---------------------------------------------------------------- static
    def _read_static(name: str) -> str:
        with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
            return fh.read()

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _read_static("dashboard.html")

    @app.get("/probe", response_class=HTMLResponse)
    def probe_page() -> str:
        return _read_static("probe.html")

    # ------------------------------------------------------------ login flow
    @app.post("/api/v1/login")
    def login(body: LoginBody, response: Response):
        hashed = db.get_meta("admin_password_hash")
        if not hashed or not dbmod.verify_password(body.password, hashed):
            raise HTTPException(status_code=401, detail="invalid password")
        response.set_cookie(SESSION_COOKIE, _make_session(), httponly=True,
                            samesite="lax", max_age=SESSION_TTL)
        return {"ok": True}

    @app.post("/api/v1/logout")
    def logout(response: Response):
        response.delete_cookie(SESSION_COOKIE)
        return {"ok": True}

    @app.get("/api/v1/me")
    def me(request: Request):
        return {"authed": _is_admin(request)}

    # ------------------------------------------------------------- web probe
    @app.post("/api/v1/webprobe/results")
    def webprobe_results(body: WebProbeBody, request: Request):
        ua = request.headers.get("user-agent", "")
        ip = request.client.host if request.client else "?"
        if not webprobe_limiter.allow(ip):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        lat = lng = acc = None
        loc = body.location or {}
        if isinstance(loc, dict) and loc.get("lat") is not None \
                and loc.get("lng") is not None:
            try:
                lat, lng = float(loc["lat"]), float(loc["lng"])
                acc = float(loc.get("accuracy") or 0) or None
                if not (-90 <= lat <= 90 and -180 <= lng <= 180):
                    lat = lng = acc = None  # reject nonsense GPS
            except (TypeError, ValueError):
                lat = lng = acc = None
        db.insert_webprobe(ip=ip, ua=ua, metrics=body.metrics,
                           lat=lat, lng=lng, accuracy=acc)
        return {"ok": True}

    @app.get("/api/v1/webprobes")
    def webprobes(request: Request):
        _require_admin(request)
        items = db.list_webprobes()
        for w in items:
            w["metrics"] = json.loads(w["metrics"] or "{}")
        return {"items": items}

    @app.get("/api/v1/webprobe/beacon")
    def webprobe_beacon(request: Request, cb: str = "", p: str = ""):
        """Tiny same-origin endpoint the browser probe times against."""
        return JSONResponse({"ok": True, "ts": time.time()},
                            headers={"Cache-Control": "no-store",
                                     "Timing-Allow-Origin": "*"})

    # -------------------------------------------------------- agent protocol
    @app.post("/api/v1/agents/register")
    def agent_register(body: RegisterBody, request: Request):
        expected = db.get_meta("enrollment_token")
        if not expected or not secrets.compare_digest(body.enrollment_token, expected):
            raise HTTPException(status_code=403, detail="bad enrollment token")
        ip = request.client.host if request.client else "?"
        agent_token = secrets.token_urlsafe(24)
        agent_id = db.create_agent(
            name=body.hostname, hostname=body.hostname, os_name=body.os,
            arch=body.arch, version=body.version, ip=ip,
            token_hash=_hash_token(agent_token), labels=body.labels,
        )
        # Location: explicit coords from the agent config win; otherwise try
        # to geolocate the WAN IP the agent connected from.
        loc = body.location or {}
        if isinstance(loc, dict) and loc.get("lat") is not None \
                and loc.get("lng") is not None:
            try:
                db.set_agent_location(agent_id, lat=float(loc["lat"]),
                                      lng=float(loc["lng"]), source="config")
            except (TypeError, ValueError):
                pass
        else:
            _geolocate_agent(agent_id, ip)
        return {"agent_id": agent_id, "agent_token": agent_token,
                "poll_interval_sec": 30}

    @app.get("/api/v1/agents/me/config")
    def agent_config(request: Request):
        agent = _auth_agent(request)
        labels = json.loads(agent["labels"] or "[]")
        tests = []
        for t in db.tests_for_agent(agent["id"], labels):
            tests.append({
                "id": t["id"], "name": t["name"], "type": t["type"],
                "target": t["target"], "interval_sec": t["interval_sec"],
                "timeout_ms": t["timeout_ms"],
                "params": json.loads(t["params"] or "{}"),
            })
        db.touch_agent(agent["id"])
        return {"agent_id": agent["id"], "poll_interval_sec": 30, "tests": tests}

    @app.post("/api/v1/agents/me/results")
    def agent_results(body: ResultsBody, request: Request):
        agent = _auth_agent(request)
        agent_id = agent["id"]
        ip = request.client.host if request.client else None
        db.touch_agent(agent_id, ip)
        if body.sysinfo:
            db.update_agent_sysinfo(agent_id, body.sysinfo)
            # device-resolved actual location wins over configured coords
            for key, source in (("location_actual", "device"),
                                ("location", "config")):
                loc = body.sysinfo.get(key) or {}
                if loc.get("lat") is not None and loc.get("lng") is not None:
                    try:
                        db.set_agent_location(
                            agent_id, lat=float(loc["lat"]), lng=float(loc["lng"]),
                            source=source, city=loc.get("city"),
                            country=loc.get("country"))
                        break
                    except (TypeError, ValueError):
                        continue
        # Opportunistic GeoIP when the WAN IP changed and we have no fix yet.
        if ip and agent.get("latitude") is None and not agent.get("location_source"):
            threading.Thread(target=_geolocate_agent, args=(agent_id, ip),
                             daemon=True).start()
        stored = 0
        for r in body.results:
            test = db.get_test(r.test_id)
            if not test:
                continue  # test deleted in the meantime – ignore silently
            db.insert_result(ts=r.ts, test_id=r.test_id, agent_id=agent_id,
                             status=r.status, metrics=r.metrics, error=r.error)
            stored += 1
            _alert_engine(store, test, agent_id, r.status, r.metrics, r.error)
        return {"ok": True, "stored": stored}

    # --------------------------------------------------------- admin: stats
    @app.get("/api/v1/stats")
    def stats(request: Request):
        _require_admin(request)
        return db.stats()

    # --------------------------------------------------------- admin: tests
    def _validate_test(body: TestBody) -> None:
        if body.type not in VALID_TEST_TYPES:
            raise HTTPException(400, f"type must be one of {sorted(VALID_TEST_TYPES)}")
        if not body.target.strip():
            raise HTTPException(400, "target is required")
        if not (5 <= body.interval_sec <= 86400):
            raise HTTPException(400, "interval_sec must be 5..86400")
        if not (100 <= body.timeout_ms <= 300000):
            raise HTTPException(400, "timeout_ms must be 100..300000")
        mode = body.assign.get("mode", "all")
        if mode not in ("all", "agents", "labels"):
            raise HTTPException(400, "assign.mode must be all|agents|labels")

    @app.post("/api/v1/tests")
    def create_test(body: TestBody, request: Request):
        _require_admin(request)
        _validate_test(body)
        test_id = db.create_test(
            name=body.name, type_=body.type, target=body.target,
            interval_sec=body.interval_sec, timeout_ms=body.timeout_ms,
            params=body.params, assign=body.assign,
        )
        if not body.enabled:
            db.update_test(test_id, {"enabled": False})
        return {"id": test_id}

    @app.get("/api/v1/tests")
    def list_tests(request: Request):
        _require_admin(request)
        out = []
        for t in db.list_tests():
            t = dict(t)
            t["params"] = json.loads(t["params"] or "{}")
            t["assign"] = json.loads(t["assign"] or "{}")
            t["enabled"] = bool(t["enabled"])
            out.append(t)
        return {"items": out}

    @app.patch("/api/v1/tests/{test_id}")
    def patch_test(test_id: str, body: TestBody, request: Request):
        _require_admin(request)
        _validate_test(body)
        ok = db.update_test(test_id, {
            "name": body.name, "type": body.type, "target": body.target,
            "interval_sec": body.interval_sec, "timeout_ms": body.timeout_ms,
            "params": body.params, "assign": body.assign, "enabled": body.enabled,
        })
        if not ok:
            raise HTTPException(404, "test not found")
        return {"ok": True}

    @app.delete("/api/v1/tests/{test_id}")
    def delete_test(test_id: str, request: Request):
        _require_admin(request)
        if not db.get_test(test_id):
            raise HTTPException(404, "test not found")
        db.delete_test(test_id)
        return {"ok": True}

    # -------------------------------------------------------- admin: agents
    @app.get("/api/v1/agents")
    def list_agents(request: Request):
        _require_admin(request)
        now = time.time()
        items = []
        for a in db.list_agents():
            a = dict(a)
            a.pop("token_hash", None)
            a["labels"] = json.loads(a["labels"] or "[]")
            a["sysinfo"] = json.loads(a["sysinfo"] or "{}")
            a["online"] = (now - a["last_seen"]) < 120
            a["wan_ip"] = a.pop("ip", None)
            a["location_display"] = _location_display(
                a.get("latitude"), a.get("longitude"), a.get("city"),
                a.get("country"))
            items.append(a)
        return {"items": items}

    @app.get("/api/v1/locations")
    def locations(request: Request):
        _require_admin(request)
        items = []
        now = time.time()
        for a in db.list_agents():
            if a["latitude"] is None or a["longitude"] is None:
                continue
            items.append({"id": a["id"], "name": a["name"], "kind": "agent",
                          "lat": a["latitude"], "lng": a["longitude"],
                          "source": a.get("location_source") or "wan-ip",
                          "wan_ip": a.get("ip"), "city": a.get("city"),
                          "country": a.get("country"),
                          "display": _location_display(
                              a["latitude"], a["longitude"], a.get("city"),
                              a.get("country")),
                          "last_seen": a["last_seen"],
                          "online": (now - a["last_seen"]) < 120})
        for w in db.list_webprobes(limit=200):
            if w["latitude"] is None or w["longitude"] is None:
                continue
            m = json.loads(w["metrics"] or "{}")
            items.append({"id": f"webprobe-{w['id']}",
                          "name": f"{m.get('device') or 'Web Probe'} ({m.get('os') or '?'})",
                          "kind": "webprobe", "lat": w["latitude"],
                          "lng": w["longitude"], "source": "gps",
                          "wan_ip": w["ip"], "city": None, "country": None,
                          "display": _location_display(w["latitude"],
                                                       w["longitude"],
                                                       None, None),
                          "accuracy_m": w.get("accuracy"),
                          "last_seen": w["ts"], "online": False})
        return {"items": items}

    @app.delete("/api/v1/agents/{agent_id}")
    def delete_agent(agent_id: str, request: Request):
        _require_admin(request)
        if not db.get_agent(agent_id):
            raise HTTPException(404, "agent not found")
        db.delete_agent(agent_id)
        return {"ok": True}

    @app.post("/api/v1/agents/{agent_id}/rotate-token")
    def rotate_agent_token(agent_id: str, request: Request):
        _require_admin(request)
        if not db.get_agent(agent_id):
            raise HTTPException(404, "agent not found")
        new_token = secrets.token_urlsafe(24)
        db.set_agent_token(agent_id, _hash_token(new_token))
        return {"agent_token": new_token}

    # ------------------------------------------------------- admin: results
    @app.get("/api/v1/results")
    def results(request: Request, test_id: str | None = None,
                agent_id: str | None = None, since: float | None = None,
                limit: int = 500):
        _require_admin(request)
        limit = max(1, min(limit, 5000))
        rows = db.query_results(test_id=test_id, agent_id=agent_id,
                                since=since, limit=limit)
        for r in rows:
            r["metrics"] = json.loads(r["metrics"] or "{}")
        return {"items": rows}

    @app.get("/api/v1/alerts")
    def alerts(request: Request, include_resolved: bool = False):
        _require_admin(request)
        items = db.list_alerts(include_resolved=include_resolved)
        # decorate with names
        tests = {t["id"]: t["name"] for t in db.list_tests()}
        agents = {a["id"]: a["name"] for a in db.list_agents()}
        for al in items:
            al["test_name"] = tests.get(al["test_id"], al["test_id"])
            al["agent_name"] = agents.get(al["agent_id"], al["agent_id"])
        return {"items": items}

    # ------------------------------------------------ admin: enrollment tok
    @app.get("/api/v1/enrollment-token")
    def get_enrollment_token(request: Request):
        _require_admin(request)
        return {"token": db.get_meta("enrollment_token")}

    @app.post("/api/v1/enrollment-token/rotate")
    def rotate_enrollment_token(request: Request):
        _require_admin(request)
        token = secrets.token_urlsafe(24)
        db.set_meta("enrollment_token", token)
        return {"token": token}

    # -------------------------------------------------- admin: admin token
    @app.get("/api/v1/admin-token")
    def get_admin_token(request: Request):
        _require_admin(request)
        token = db.get_meta("admin_token")
        if not token:
            token = secrets.token_urlsafe(24)
            db.set_meta("admin_token", token)
        return {"token": token}

    # --------------------------------------------------- update distribution
    manifest_path = os.path.join(updates_dir, "manifest.json")

    def _read_manifest() -> dict:
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, encoding="utf-8") as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, OSError):
                pass
        return {"agent_version": None, "published_at": None, "assets": {}}

    def _write_manifest(m: dict) -> None:
        tmp = manifest_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(m, fh, indent=2)
        os.replace(tmp, manifest_path)

    @app.get("/api/v1/version")
    def version(request: Request):
        _require_admin(request)
        m = _read_manifest()
        return {"server_version": SERVER_VERSION,
                "build": BUILD_NUMBER,
                "agent_latest": m.get("agent_version"),
                "manifest": m}

    @app.get("/api/v1/update/manifest")
    def update_manifest():
        """Public: agents poll this to discover new releases."""
        m = _read_manifest()
        m["server_version"] = SERVER_VERSION
        return m

    @app.get("/api/v1/update/assets/{filename}")
    def update_download(filename: str):
        """Public: agents download release artifacts here."""
        if not ASSET_NAME_RE.match(filename):
            raise HTTPException(400, "invalid asset name")
        path = os.path.join(updates_dir, filename)
        if not os.path.isfile(path):
            raise HTTPException(404, "asset not found")
        # belt & braces: never escape the updates dir
        if os.path.realpath(path).startswith(os.path.realpath(updates_dir) + os.sep):
            return FileResponse(path, filename=filename)
        raise HTTPException(400, "invalid asset path")

    @app.put("/api/v1/update/assets/{filename}")
    async def update_publish(filename: str, request: Request):
        """Admin: upload a release artifact.

        Headers: X-Version (agent version), X-Platform
        (e.g. linux-x86_64, darwin-arm64, windows-x86_64).
        The SHA-256 is computed server-side.
        """
        _require_admin(request)
        if not ASSET_NAME_RE.match(filename) or "/" in filename or "\\" in filename:
            raise HTTPException(400, "invalid asset name")
        version = request.headers.get("x-version")
        platform_key = request.headers.get("x-platform")
        if not version or not platform_key:
            raise HTTPException(400, "X-Version and X-Platform headers required")
        body = await request.body()
        if not body:
            raise HTTPException(400, "empty artifact")
        if len(body) > 256 * 1024 * 1024:
            raise HTTPException(413, "artifact too large")
        path = os.path.join(updates_dir, filename)
        tmp = path + ".part"
        with open(tmp, "wb") as fh:
            fh.write(body)
        os.replace(tmp, path)
        sha = hashlib.sha256(body).hexdigest()
        m = _read_manifest()
        m["agent_version"] = version
        m["published_at"] = time.time()
        m.setdefault("assets", {})[platform_key] = {
            "file": filename,
            "url": f"/api/v1/update/assets/{filename}",
            "sha256": sha,
            "size": len(body),
        }
        _write_manifest(m)
        return {"ok": True, "platform": platform_key, "version": version,
                "sha256": sha, "size": len(body)}

    @app.delete("/api/v1/update/assets/{filename}")
    def update_remove(filename: str, request: Request):
        _require_admin(request)
        if not ASSET_NAME_RE.match(filename):
            raise HTTPException(400, "invalid asset name")
        path = os.path.join(updates_dir, filename)
        if os.path.isfile(path):
            os.remove(path)
        m = _read_manifest()
        m["assets"] = {k: v for k, v in m.get("assets", {}).items()
                       if v.get("file") != filename}
        _write_manifest(m)
        return {"ok": True}

    # ---------------------------------------------------------- server admin
    @app.post("/api/v1/admin/restart")
    def admin_restart(request: Request):
        """Graceful in-place restart (systemd or execv keeps it alive)."""
        _require_admin(request)
        threading.Thread(target=_delayed_restart, daemon=True).start()
        return {"ok": True, "detail": "restarting"}

    return app


def _delayed_restart() -> None:  # pragma: no cover - execs the process
    time.sleep(0.4)
    try:
        _exec_restart()
    except Exception:
        os._exit(1)


# --------------------------------------------------------------------------
# Alert engine
# --------------------------------------------------------------------------

def _alert_engine(store: DatabaseWrapper, test: dict, agent_id: str,
                  status: str, metrics: dict, error: str | None) -> None:
    db = store.db
    params = json.loads(test["params"] or "{}") if isinstance(test["params"], str) \
        else test.get("params", {})
    fail_streak_needed = int(params.get("alert_fail_streak", 2))
    latency_threshold = params.get("alert_latency_ms")
    key = (test["id"], agent_id)

    if status == "ok":
        store.streaks[key] = 0
        alert = db.open_alert(test["id"], agent_id)
        if alert:
            db.resolve_alert(alert["id"])
        # latency breach alert auto-resolves with next good result: handled above
        return

    # failure path
    store.streaks[key] = store.streaks.get(key, 0) + 1
    if store.streaks[key] >= fail_streak_needed and not db.open_alert(test["id"], agent_id):
        db.create_alert(test_id=test["id"], agent_id=agent_id, kind="failure",
                        detail=error or f"test failing (streak={store.streaks[key]})")

    # latency breach (only on ok results with slow latency)
    if latency_threshold and status == "ok":
        lat = metrics.get("latency_ms")
        if lat and lat > float(latency_threshold) and not db.open_alert(test["id"], agent_id):
            db.create_alert(test_id=test["id"], agent_id=agent_id, kind="slow",
                            detail=f"latency {lat:.0f}ms > {latency_threshold}ms")
