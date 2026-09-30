"""End-to-end test: real uvicorn server + real Agent object + real probes."""
import http.server
import json
import socket
import threading
import time

import pytest
import uvicorn


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    from openeyes.app import create_app

    data_dir = tmp_path_factory.mktemp("e2e")
    app = create_app(str(data_dir))
    port = _free_port()
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"
    yield {"port": port, "app": app, "db": app.state.store.db}
    server.should_exit = True
    t.join(timeout=5)


@pytest.fixture(scope="module")
def target_server():
    """Target that agents probe."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"target ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


def test_full_agent_cycle(live_server, target_server, tmp_path):
    from openeyes_agent.agent import Agent
    from openeyes_agent.config import AgentConfig

    db = live_server["db"]
    base = f"http://127.0.0.1:{live_server['port']}"
    enrollment = db.get_meta("enrollment_token")

    # admin creates two tests: one healthy HTTP target, one guaranteed failure
    ok_test = db.create_test(name="target-http", type_="http",
                             target=target_server, interval_sec=5,
                             timeout_ms=4000, params={}, assign={"mode": "all"})
    bad_test = db.create_test(name="dead-tcp", type_="tcp",
                              target="127.0.0.1:1", interval_sec=5,
                              timeout_ms=1500,
                              params={"alert_fail_streak": 1},
                              assign={"mode": "all"})

    cfg = AgentConfig(server_url=base, enrollment_token=enrollment,
                      state_path=str(tmp_path / "state.json"))
    logs: list[str] = []
    agent = Agent(cfg, log=logs.append)
    assert agent.run_once() == 0

    # state persisted?
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["agent_id"].startswith("agent-") and state["agent_token"]

    # results arrived for both tests?
    rows = db.query_results(test_id=ok_test)
    assert rows and rows[0]["status"] == "ok"
    metrics = json.loads(rows[0]["metrics"])
    assert metrics["status_code"] == 200 and metrics["latency_ms"] > 0

    rows_bad = db.query_results(test_id=bad_test)
    assert rows_bad and rows_bad[0]["status"] == "fail"

    # failure with streak threshold 1 must have raised an alert
    open_alerts = db.list_alerts()
    assert any(a["test_id"] == bad_test for a in open_alerts)

    # re-running uses persisted identity (no second enrollment row)
    n_agents = len(db.list_agents())
    agent2 = Agent(cfg, log=logs.append)
    assert agent2.run_once() == 0
    assert len(db.list_agents()) == n_agents

    # sysinfo heartbeat recorded?
    info = db.list_agents()[0]
    sysinfo = json.loads(info["sysinfo"] or "{}")
    assert sysinfo.get("hostname")


def test_autonomous_reenrollment(live_server, tmp_path):
    """If the server rotates an agent's token, the agent must re-enrol by
    itself using its enrollment token — no user action required."""
    from openeyes_agent.agent import Agent, ServerError
    from openeyes_agent.config import AgentConfig

    db = live_server["db"]
    base = f"http://127.0.0.1:{live_server['port']}"
    enrollment = db.get_meta("enrollment_token")

    cfg = AgentConfig(server_url=base, enrollment_token=enrollment,
                      state_path=str(tmp_path / "state.json"),
                      lat=14.6, lng=121.0)
    agent = Agent(cfg, log=lambda m: None)
    assert agent.ensure_enrolled()
    first_id = agent.state["agent_id"]

    # server-side: rotate this agent's token -> old credentials now invalid
    import secrets as _s
    db.set_agent_token(first_id, "x" * 64)
    try:
        agent.fetch_tests()
        raise AssertionError("expected 401")
    except ServerError as e:
        assert Agent._is_auth_error(e)

    # autonomous recovery: drop creds and re-enrol
    agent._drop_credentials()
    assert agent.ensure_enrolled()
    assert agent.state["agent_id"] != first_id
    # and the new identity works, carrying the configured location
    assert isinstance(agent.fetch_tests(), list)
    new_row = db.get_agent(agent.state["agent_id"])
    assert new_row["location_source"] == "config"
    assert abs(new_row["latitude"] - 14.6) < 1e-6
