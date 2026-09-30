"""Agent configuration + persistent state.

Config file (JSON), e.g. agent.json:

    {
      "server_url": "https://eyes.example.com:8080",
      "enrollment_token": "TOKEN",
      "insecure_tls": false,
      "labels": ["branch-office"]
    }

State (agent_id + per-agent token) is kept in a separate file so config can
be re-deployed without un-enrolling the agent.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class AgentConfig:
    server_url: str = ""
    enrollment_token: str = ""
    insecure_tls: bool = False
    labels: list[str] = field(default_factory=list)
    poll_interval_sec: int = 30
    report_interval_sec: int = 10
    state_path: str = ""
    # Fixed site coordinates reported to the server (optional).
    lat: float | None = None
    lng: float | None = None
    # Self-update behaviour.
    auto_update: bool = True
    update_check_sec: int = 6 * 3600

    @classmethod
    def load(cls, path: str) -> "AgentConfig":
        if not os.path.exists(path):
            raise FileNotFoundError(f"config file not found: {path}")
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        loc = raw.get("location") or {}
        cfg = cls(
            server_url=str(raw.get("server_url", "")).rstrip("/"),
            enrollment_token=str(raw.get("enrollment_token", "")),
            insecure_tls=bool(raw.get("insecure_tls", False)),
            labels=list(raw.get("labels", [])),
            auto_update=bool(raw.get("auto_update", True)),
            update_check_sec=int(raw.get("update_check_sec", 6 * 3600)),
            lat=loc.get("lat"),
            lng=loc.get("lng"),
        )
        if not cfg.server_url:
            raise ValueError("server_url is required in agent config")
        default_state = os.path.join(os.path.dirname(os.path.abspath(path)),
                                     "agent-state.json")
        cfg.state_path = raw.get("state_path", default_state)
        return cfg

    @property
    def location(self) -> dict | None:
        if self.lat is not None and self.lng is not None:
            return {"lat": self.lat, "lng": self.lng}
        return None

    def server(self, path: str) -> str:
        return self.server_url + path


def load_state(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
