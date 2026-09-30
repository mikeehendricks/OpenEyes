"""OpenEyes agent entry point.

Usage examples:

    # enroll + run using a config file
    openeyes-agent --config agent.json

    # enroll + run with flags only (state stored in ~/.openeyes-agent)
    openeyes-agent --server https://eyes.example.com:8080 --enroll-token TOKEN

    # run assigned tests once and exit (good for cron / smoke tests)
    openeyes-agent --server ... --enroll-token TOKEN --once
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys

from .agent import Agent
from .config import AgentConfig, load_state, save_state


def _log(msg: str) -> None:
    print(msg, flush=True)


def build_config(args: argparse.Namespace) -> AgentConfig:
    if args.config:
        cfg = AgentConfig.load(args.config)
    else:
        if not args.server:
            raise SystemExit("error: provide --config FILE or --server URL")
        cfg = AgentConfig(server_url=args.server.rstrip("/"))
        state_dir = os.path.expanduser("~/.openeyes-agent")
        cfg.state_path = os.path.join(state_dir, "state.json")
    if args.server:
        cfg.server_url = args.server.rstrip("/")
    if args.enroll_token:
        cfg.enrollment_token = args.enroll_token
    if args.insecure:
        cfg.insecure_tls = True
    if args.labels:
        cfg.labels = [x.strip() for x in args.labels.split(",") if x.strip()]
    if args.state:
        cfg.state_path = args.state
    if args.lat is not None and args.lng is not None:
        cfg.lat, cfg.lng = args.lat, args.lng
    if args.no_update:
        cfg.auto_update = False
    # If an enrollment token is supplied but we already have credentials for
    # this server, keep them; otherwise start fresh so re-enrollment works.
    state = load_state(cfg.state_path)
    if state.get("agent_token") and not state.get("agent_id"):
        save_state(cfg.state_path, {})
    return cfg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="openeyes-agent",
                                 description="OpenEyes monitoring agent")
    ap.add_argument("--config", help="path to agent.json")
    ap.add_argument("--server", help="server base URL, e.g. https://eyes:8080")
    ap.add_argument("--enroll-token", help="enrollment token from the server")
    ap.add_argument("--labels", help="comma-separated labels")
    ap.add_argument("--state", help="override state file path")
    ap.add_argument("--lat", type=float, default=None,
                    help="fixed site latitude (shows on the Locations map)")
    ap.add_argument("--lng", type=float, default=None,
                    help="fixed site longitude")
    ap.add_argument("--no-update", action="store_true",
                    help="disable agent self-update")
    ap.add_argument("--insecure", action="store_true",
                    help="accept self-signed TLS certificates")
    ap.add_argument("--once", action="store_true",
                    help="run assigned tests once and exit")
    ap.add_argument("--version", action="store_true")
    args = ap.parse_args(argv)

    if args.version:
        from .agent import AGENT_VERSION
        print(f"openeyes-agent {AGENT_VERSION}")
        return 0

    cfg = build_config(args)
    agent = Agent(cfg, log=_log)

    def _sig(*_):
        _log("Shutting down…")
        agent.stop()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    if args.once:
        return agent.run_once()
    return agent.run_forever()


if __name__ == "__main__":
    sys.exit(main())
