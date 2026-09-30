"""OpenEyes agent runtime.

The agent:
  1. enrols against the server (exchanging the enrollment token for a
     per-agent token), persisting the result
  2. polls its assigned test definitions
  3. runs each test on its own interval in a thread pool
  4. batches results and ships them back to the server
"""
from __future__ import annotations

import json
import platform
import queue
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

from . import updater
from .config import AgentConfig, load_state, save_state
from .probes import (dns_probe, geolocate, http_probe, ping_probe, sysinfo,
                     tcp_probe, trace_probe)

AGENT_VERSION = "1.2.0"
ENROLL_MAX_BACKOFF = 60.0
GEO_REFRESH_SEC = 6 * 3600  # re-resolve own location every 6 h
PROBES = {
    "http": http_probe.run,
    "tcp": tcp_probe.run,
    "ping": ping_probe.run,
    "dns": dns_probe.run,
    "trace": trace_probe.run,
}


class ServerError(Exception):
    pass


class Agent:
    def __init__(self, cfg: AgentConfig, log=print):
        self.cfg = cfg
        self.log = log
        self.state = load_state(cfg.state_path)
        self._stop = threading.Event()
        self._results: "queue.Queue[dict]" = queue.Queue()
        self._lock = threading.Lock()
        self._last_run: dict[str, float] = {}
        self._ctx = self._build_ssl_ctx()

    # ------------------------------------------------------------------ http
    def _build_ssl_ctx(self):
        ctx = ssl.create_default_context()
        if self.cfg.insecure_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str, body: dict | None = None,
                 agent_auth: bool = True, timeout: float = 15.0) -> dict:
        url = self.cfg.server(path)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", f"OpenEyes-Agent/{AGENT_VERSION}")
        if agent_auth and self.state.get("agent_token"):
            req.add_header("X-Agent-Token", self.state["agent_token"])
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=self._ctx) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = json.loads(e.read().decode()).get("detail", "")
            except Exception:
                pass
            raise ServerError(f"{method} {path} -> HTTP {e.code} {detail}")
        except urllib.error.URLError as e:
            raise ServerError(f"{method} {path} -> unreachable: {e.reason}")

    # ------------------------------------------------------------- enrolment
    def ensure_enrolled(self) -> bool:
        if self.state.get("agent_id") and self.state.get("agent_token"):
            return True
        if not self.cfg.enrollment_token:
            self.log("No agent credentials and no enrollment token configured.")
            return False
        try:
            body = {
                "enrollment_token": self.cfg.enrollment_token,
                "hostname": platform.node() or "unknown",
                "os": platform.system(),
                "arch": platform.machine(),
                "version": AGENT_VERSION,
                "labels": self.cfg.labels,
            }
            if self.cfg.location:
                body["location"] = self.cfg.location
            resp = self._request("POST", "/api/v1/agents/register", body,
                                 agent_auth=False)
        except ServerError as e:
            self.log(f"Enrollment failed: {e}")
            return False
        self.state["agent_id"] = resp["agent_id"]
        self.state["agent_token"] = resp["agent_token"]
        save_state(self.cfg.state_path, self.state)
        self.log(f"Enrolled as {resp['agent_id']}")
        return True

    def wait_until_enrolled(self) -> bool:
        """Autonomous enrolment: retry with backoff until it works."""
        backoff = 2.0
        while not self._stop.is_set():
            if self.ensure_enrolled():
                return True
            self.log(f"Retrying enrollment in {backoff:.0f}s…")
            self._stop.wait(backoff)
            backoff = min(backoff * 2, ENROLL_MAX_BACKOFF)
        return False

    def _drop_credentials(self) -> None:
        """Forget the per-agent token so the next cycle re-enrols."""
        self.state.pop("agent_token", None)
        self.state.pop("agent_id", None)
        try:
            save_state(self.cfg.state_path, self.state)
        except OSError:
            pass

    # ---------------------------------------------------------------- config
    def fetch_tests(self) -> list[dict]:
        resp = self._request("GET", "/api/v1/agents/me/config")
        return resp.get("tests", [])

    @staticmethod
    def _is_auth_error(err: ServerError) -> bool:
        return "HTTP 401" in str(err)

    # --------------------------------------------------------------- running
    def run_test(self, test: dict) -> dict:
        fn = PROBES.get(test["type"])
        started = time.time()
        if not fn:
            return {"test_id": test["id"], "ts": started, "status": "error",
                    "metrics": {}, "error": f"unknown test type {test['type']}"}
        try:
            metrics = fn(test["target"], test.get("timeout_ms", 5000),
                         test.get("params") or {})
            return {"test_id": test["id"], "ts": started, "status": "ok",
                    "metrics": metrics, "error": None}
        except (http_probe.ProbeError, tcp_probe.ProbeError,
                ping_probe.ProbeError, dns_probe.ProbeError,
                trace_probe.ProbeError) as e:
            return {"test_id": test["id"], "ts": started, "status": "fail",
                    "metrics": {}, "error": str(e)}
        except Exception as e:  # defensive – never crash the agent
            return {"test_id": test["id"], "ts": started, "status": "error",
                    "metrics": {}, "error": f"{type(e).__name__}: {e}"}

    def _collect_sysinfo(self) -> dict:
        """System snapshot + the device's actual geolocated position."""
        now = time.monotonic()
        if getattr(self, "_geo_at", -1e9) + GEO_REFRESH_SEC <= now:
            self._geo_at = now
            self._geo = geolocate.own_location()
            if self._geo:
                self.log("Device location: "
                         f"{self._geo.get('city') or '?'}, "
                         f"{self._geo.get('country') or '?'}")
        info = sysinfo.collect()
        info["agent_version"] = AGENT_VERSION
        if getattr(self, "_geo", None):
            info["location_actual"] = self._geo
        if self.cfg.location:
            info["location"] = self.cfg.location
        return info

    def flush_results(self) -> int:
        batch: list[dict] = []
        while True:
            try:
                batch.append(self._results.get_nowait())
            except queue.Empty:
                break
            if len(batch) >= 200:
                break
        if not batch:
            return 0
        body = {"results": batch}
        # heartbeat: sysinfo + actual device location, refreshed every 6 h
        now = time.monotonic()
        if getattr(self, "_sysinfo_at", -1e9) + GEO_REFRESH_SEC <= now:
            self._sysinfo_at = now
            body["sysinfo"] = self._collect_sysinfo()
        try:
            self._request("POST", "/api/v1/agents/me/results", body)
            return len(batch)
        except ServerError as e:
            self.log(f"Result upload failed, requeueing {len(batch)}: {e}")
            for item in batch:
                self._results.put(item)
            return 0

    # ------------------------------------------------------------------ loop
    def stop(self):
        self._stop.set()

    def run_forever(self):
        """Fully autonomous main loop.

        * enrolment is retried with backoff until it succeeds (the server may
          not be installed/reachable yet)
        * a rotated/revoked agent token triggers automatic re-enrolment
        * self-update runs every `update_check_sec` (default 6h)
        """
        import concurrent.futures
        if not self.wait_until_enrolled():
            return 1
        self.log(f"Agent running against {self.cfg.server_url} "
                 f"(Ctrl+C to stop)")
        tests: list[dict] = []
        last_poll = 0.0
        poll_every = float(self.cfg.poll_interval_sec)
        next_update_check = time.monotonic() + 10.0  # soon after start
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)

        while not self._stop.is_set():
            now = time.monotonic()

            # -------- self update -------------------------------------
            if self.cfg.auto_update and now >= next_update_check:
                next_update_check = now + max(60, self.cfg.update_check_sec)
                if self._try_update():
                    self.flush_results()
                    return 0  # service manager restarts us on the new version

            # -------- config poll --------------------------------------
            if now - last_poll >= poll_every:
                last_poll = now
                try:
                    tests = self.fetch_tests()
                    self.log(f"Synced config: {len(tests)} test(s) assigned")
                except ServerError as e:
                    if self._is_auth_error(e):
                        self.log("Agent token rejected — re-enrolling…")
                        self._drop_credentials()
                        if not self.wait_until_enrolled():
                            return 1
                        tests = []
                    else:
                        self.log(f"Config poll failed: {e}")

            # -------- run due tests ------------------------------------
            for test in tests:
                interval = max(5, int(test.get("interval_sec", 60)))
                due = self._last_run.get(test["id"], 0.0) + interval
                if now >= due:
                    self._last_run[test["id"]] = now
                    executor.submit(self._run_and_queue, test)

            self.flush_results()
            self._stop.wait(1.0)

        self.flush_results()
        executor.shutdown(wait=False)
        return 0

    def _try_update(self) -> bool:
        try:
            return updater.check_and_apply(self.cfg.server_url, AGENT_VERSION,
                                           ssl_ctx=self._ctx, log=self.log)
        except Exception as e:  # never let updating kill the agent
            self.log(f"Update cycle error: {e}")
            return False

    def _run_and_queue(self, test: dict):
        result = self.run_test(test)
        self._results.put(result)
        lat = result["metrics"].get("latency_ms")
        lat_s = f" {lat:.1f}ms" if isinstance(lat, (int, float)) else ""
        self.log(f"[{result['status'].upper():5}] {test['name']}{lat_s}"
                 + (f" - {result['error']}" if result.get("error") else ""))

    def run_once(self):
        """Run every assigned test exactly once, print results, and exit."""
        if not self.ensure_enrolled():
            return 1
        try:
            tests = self.fetch_tests()
        except ServerError as e:
            self.log(f"Config poll failed: {e}")
            return 1
        if not tests:
            self.log("No tests assigned to this agent.")
            return 0
        for test in tests:
            self._run_and_queue(test)
        self.flush_results()
        return 0
