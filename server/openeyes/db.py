"""OpenEyes server – SQLite persistence layer.

Thread-safe wrapper around sqlite3. The whole server keeps its state in a
single SQLite database file (WAL mode) which makes deployment on Ubuntu a
zero-dependency affair.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from typing import Any, Iterable

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    hostname      TEXT,
    os            TEXT,
    arch          TEXT,
    agent_version TEXT,
    ip            TEXT,
    token_hash    TEXT NOT NULL,
    labels        TEXT NOT NULL DEFAULT '[]',
    sysinfo       TEXT NOT NULL DEFAULT '{}',
    created_at    REAL NOT NULL,
    last_seen     REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tests (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL,
    target       TEXT NOT NULL,
    interval_sec INTEGER NOT NULL DEFAULT 60,
    timeout_ms   INTEGER NOT NULL DEFAULT 5000,
    params       TEXT NOT NULL DEFAULT '{}',
    assign       TEXT NOT NULL DEFAULT '{"mode":"all"}',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    test_id  TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    status   TEXT NOT NULL,
    metrics  TEXT NOT NULL DEFAULT '{}',
    error    TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_lookup ON results (test_id, agent_id, ts);
CREATE INDEX IF NOT EXISTS idx_results_ts ON results (ts);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id     TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    detail      TEXT,
    started_ts  REAL NOT NULL,
    resolved_ts REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts (test_id, agent_id, resolved_ts);
CREATE TABLE IF NOT EXISTS webprobe_results (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    ip      TEXT,
    ua      TEXT,
    metrics TEXT NOT NULL DEFAULT '{}',
    latitude REAL,
    longitude REAL,
    accuracy REAL
);
CREATE TABLE IF NOT EXISTS geoip_cache (
    ip      TEXT PRIMARY KEY,
    lat     REAL,
    lon     REAL,
    city    TEXT,
    country TEXT,
    ts      REAL NOT NULL
);
"""

# Columns that may be missing from databases created by older versions.
MIGRATION_COLUMNS = {
    "agents": [
        ("latitude", "REAL"),
        ("longitude", "REAL"),
        ("location_source", "TEXT"),
        ("city", "TEXT"),
        ("country", "TEXT"),
    ],
    "webprobe_results": [
        ("latitude", "REAL"),
        ("longitude", "REAL"),
        ("accuracy", "REAL"),
    ],
}


def _now() -> float:
    return time.time()


class Database:
    """Small synchronous SQLite facade used by the FastAPI layer."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced by newer versions (runs under lock)."""
        for table, cols in MIGRATION_COLUMNS.items():
            existing = {r[1] for r in
                        self._conn.execute(f"PRAGMA table_info({table})")}
            for name, ctype in cols:
                if name not in existing:
                    self._conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {ctype}")

    # ------------------------------------------------------------------ meta
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key=?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self._conn.commit()

    # -------------------------------------------------------------- bootstrap
    def bootstrap(self) -> dict[str, Any]:
        """Create first-run credentials. Returns info dict for the console."""
        info: dict[str, Any] = {"first_run": False}
        if self.get_meta("admin_password_hash") is None:
            password = secrets.token_urlsafe(12)
            salt = secrets.token_hex(8)
            self.set_meta("admin_password", password)  # stored for first-run display only
            self.set_meta("admin_password_hash", f"{salt}${_hash_password(password, salt)}")
            info["first_run"] = True
            info["admin_password"] = password
        if self.get_meta("enrollment_token") is None:
            info["enrollment_token"] = secrets.token_urlsafe(24)
            self.set_meta("enrollment_token", info["enrollment_token"])
        if self.get_meta("session_secret") is None:
            self.set_meta("session_secret", secrets.token_hex(32))
        self.set_meta("schema_version", str(SCHEMA_VERSION))
        return info

    # ---------------------------------------------------------------- agents
    def create_agent(self, *, name: str, hostname: str, os_name: str, arch: str,
                     version: str, ip: str, token_hash: str,
                     labels: list[str]) -> str:
        agent_id = "agent-" + uuid.uuid4().hex[:12]
        with self._lock:
            self._conn.execute(
                "INSERT INTO agents(id,name,hostname,os,arch,agent_version,ip,"
                "token_hash,labels,created_at,last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (agent_id, name, hostname, os_name, arch, version, ip, token_hash,
                 json.dumps(labels), _now(), _now()),
            )
            self._conn.commit()
        return agent_id

    def set_agent_location(self, agent_id: str, *, lat: float | None,
                           lng: float | None, source: str | None,
                           city: str | None = None,
                           country: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE agents SET latitude=?, longitude=?, location_source=?, "
                "city=COALESCE(?,city), country=COALESCE(?,country) WHERE id=?",
                (lat, lng, source, city, country, agent_id),
            )
            self._conn.commit()

    def get_agent(self, agent_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agents WHERE id=?", (agent_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_agents(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM agents ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def touch_agent(self, agent_id: str, ip: str | None = None) -> None:
        with self._lock:
            if ip:
                self._conn.execute(
                    "UPDATE agents SET last_seen=?, ip=? WHERE id=?",
                    (_now(), ip, agent_id),
                )
            else:
                self._conn.execute(
                    "UPDATE agents SET last_seen=? WHERE id=?", (_now(), agent_id)
                )
            self._conn.commit()

    def update_agent_sysinfo(self, agent_id: str, sysinfo: dict) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE agents SET sysinfo=?, hostname=COALESCE(?,hostname), "
                "last_seen=? WHERE id=?",
                (json.dumps(sysinfo), sysinfo.get("hostname"), _now(), agent_id),
            )
            self._conn.commit()

    def set_agent_token(self, agent_id: str, token_hash: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE agents SET token_hash=? WHERE id=?", (token_hash, agent_id)
            )
            self._conn.commit()

    def delete_agent(self, agent_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))
            self._conn.execute(
                "DELETE FROM results WHERE agent_id=?", (agent_id,)
            )
            self._conn.commit()

    # ----------------------------------------------------------------- tests
    def create_test(self, *, name: str, type_: str, target: str, interval_sec: int,
                    timeout_ms: int, params: dict, assign: dict) -> str:
        test_id = "test-" + uuid.uuid4().hex[:10]
        now = _now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO tests(id,name,type,target,interval_sec,timeout_ms,"
                "params,assign,enabled,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,1,?,?)",
                (test_id, name, type_, target, interval_sec, timeout_ms,
                 json.dumps(params), json.dumps(assign), now, now),
            )
            self._conn.commit()
        return test_id

    def update_test(self, test_id: str, fields: dict) -> bool:
        allowed = {"name", "type", "target", "interval_sec", "timeout_ms",
                   "params", "assign", "enabled"}
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k in ("params", "assign"):
                v = json.dumps(v)
            if k == "enabled":
                v = 1 if v else 0
            sets.append(f"{k}=?")
            vals.append(v)
        if not sets:
            return False
        sets.append("updated_at=?")
        vals.append(_now())
        vals.append(test_id)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE tests SET {', '.join(sets)} WHERE id=?", vals
            )
            self._conn.commit()
            return cur.rowcount > 0

    def get_test(self, test_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tests WHERE id=?", (test_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_tests(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tests ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_test(self, test_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM tests WHERE id=?", (test_id,))
            self._conn.execute("DELETE FROM results WHERE test_id=?", (test_id,))
            self._conn.execute(
                "UPDATE alerts SET resolved_ts=? WHERE test_id=? AND resolved_ts IS NULL",
                (_now(), test_id),
            )
            self._conn.commit()

    def tests_for_agent(self, agent_id: str, labels: list[str]) -> list[dict]:
        out = []
        for t in self.list_tests():
            if not t["enabled"]:
                continue
            assign = json.loads(t["assign"])
            mode = assign.get("mode", "all")
            if mode == "all":
                out.append(t)
            elif mode == "agents" and agent_id in assign.get("agent_ids", []):
                out.append(t)
            elif mode == "labels" and set(assign.get("labels", [])) & set(labels):
                out.append(t)
        return out

    # --------------------------------------------------------------- results
    def insert_result(self, *, ts: float, test_id: str, agent_id: str,
                      status: str, metrics: dict, error: str | None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO results(ts,test_id,agent_id,status,metrics,error) "
                "VALUES(?,?,?,?,?,?)",
                (ts, test_id, agent_id, status, json.dumps(metrics), error),
            )
            self._conn.commit()
            return cur.lastrowid  # type: ignore[return-value]

    def query_results(self, *, test_id: str | None = None, agent_id: str | None = None,
                      since: float | None = None, limit: int = 500) -> list[dict]:
        sql = "SELECT * FROM results WHERE 1=1"
        vals: list[Any] = []
        if test_id:
            sql += " AND test_id=?"
            vals.append(test_id)
        if agent_id:
            sql += " AND agent_id=?"
            vals.append(agent_id)
        if since:
            sql += " AND ts>=?"
            vals.append(since)
        sql += " ORDER BY ts DESC LIMIT ?"
        vals.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, vals).fetchall()
        return [dict(r) for r in rows]

    def latest_result(self, test_id: str, agent_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM results WHERE test_id=? AND agent_id=? "
                "ORDER BY ts DESC LIMIT 1",
                (test_id, agent_id),
            ).fetchone()
        return dict(row) if row else None

    def prune_results(self, keep_days: float = 30.0) -> int:
        cutoff = _now() - keep_days * 86400
        with self._lock:
            cur = self._conn.execute("DELETE FROM results WHERE ts<?", (cutoff,))
            self._conn.commit()
            return cur.rowcount

    # ---------------------------------------------------------------- alerts
    def open_alert(self, test_id: str, agent_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM alerts WHERE test_id=? AND agent_id=? "
                "AND resolved_ts IS NULL",
                (test_id, agent_id),
            ).fetchone()
        return dict(row) if row else None

    def create_alert(self, *, test_id: str, agent_id: str, kind: str,
                     detail: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts(test_id,agent_id,kind,detail,started_ts) "
                "VALUES(?,?,?,?,?)",
                (test_id, agent_id, kind, detail, _now()),
            )
            self._conn.commit()
            return cur.lastrowid  # type: ignore[return-value]

    def resolve_alert(self, alert_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET resolved_ts=? WHERE id=? AND resolved_ts IS NULL",
                (_now(), alert_id),
            )
            self._conn.commit()

    def list_alerts(self, include_resolved: bool = False,
                    limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM alerts"
        if not include_resolved:
            sql += " WHERE resolved_ts IS NULL"
        sql += " ORDER BY started_ts DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (limit,)).fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------- webprobe
    def insert_webprobe(self, *, ip: str, ua: str, metrics: dict,
                        lat: float | None = None, lng: float | None = None,
                        accuracy: float | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO webprobe_results(ts,ip,ua,metrics,latitude,"
                "longitude,accuracy) VALUES(?,?,?,?,?,?,?)",
                (_now(), ip, ua, json.dumps(metrics), lat, lng, accuracy),
            )
            self._conn.commit()

    def list_webprobes(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM webprobe_results ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- geoip
    def get_geoip(self, ip: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM geoip_cache WHERE ip=?", (ip,)
            ).fetchone()
        return dict(row) if row else None

    def set_geoip(self, ip: str, *, lat: float, lon: float,
                  city: str | None, country: str | None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO geoip_cache(ip,lat,lon,city,country,ts) "
                "VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET lat=excluded.lat, "
                "lon=excluded.lon, city=excluded.city, "
                "country=excluded.country, ts=excluded.ts",
                (ip, lat, lon, city, country, _now()),
            )
            self._conn.commit()

    # ------------------------------------------------------------------ misc
    def stats(self) -> dict:
        with self._lock:
            agents = self._conn.execute("SELECT COUNT(*) c FROM agents").fetchone()["c"]
            tests = self._conn.execute("SELECT COUNT(*) c FROM tests").fetchone()["c"]
            results = self._conn.execute("SELECT COUNT(*) c FROM results").fetchone()["c"]
            open_alerts = self._conn.execute(
                "SELECT COUNT(*) c FROM alerts WHERE resolved_ts IS NULL"
            ).fetchone()["c"]
            recent = self._conn.execute(
                "SELECT COUNT(*) c FROM results WHERE ts>?", (_now() - 300,)
            ).fetchone()["c"]
        return {"agents": agents, "tests": tests, "results": results,
                "open_alerts": open_alerts, "results_last_5m": recent}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _hash_password(password: str, salt: str = "") -> str:
    import hashlib
    return hashlib.sha256((salt + password).encode()).hexdigest()


def verify_password(password: str, stored: str) -> bool:
    """Accepts both the salted ('salt$hash') and legacy unsalted formats."""
    if not stored:
        return False
    if "$" in stored:
        salt, _, digest = stored.partition("$")
        return secrets.compare_digest(_hash_password(password, salt), digest)
    return secrets.compare_digest(_hash_password(password), stored)
