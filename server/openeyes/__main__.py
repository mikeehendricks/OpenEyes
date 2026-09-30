"""OpenEyes server entry point.

Usage:
    python -m openeyes [--host 0.0.0.0] [--port 8080] [--data-dir DIR]
"""
from __future__ import annotations

import argparse
import os


def main() -> None:
    ap = argparse.ArgumentParser(prog="openeyes-server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--data-dir", default=None,
                    help="state directory (default ~/.openeyes or $OPENEYES_DATA_DIR)")
    args = ap.parse_args()

    if args.data_dir:
        os.environ["OPENEYES_DATA_DIR"] = args.data_dir

    import uvicorn
    from .app import create_app

    app = create_app()

    # Surface first-run credentials prominently.
    store = app.state.store  # type: ignore[attr-defined]
    db = store.db
    pw = db.get_meta("admin_password")
    if pw:
        data_dir = os.environ.get("OPENEYES_DATA_DIR") or os.path.expanduser("~/.openeyes")
        first_run_file = os.path.join(data_dir, "first_run.txt")
        if not os.path.exists(first_run_file):
            with open(first_run_file, "w", encoding="utf-8") as fh:
                fh.write(f"admin_password: {pw}\n"
                         f"enrollment_token: {db.get_meta('enrollment_token')}\n")
            try:
                os.chmod(first_run_file, 0o600)
            except OSError:
                pass
            # Plain-text password lived only long enough to be persisted above.
            db.set_meta("admin_password", "")
        print("=" * 62)
        print("  OpenEyes first-run credentials")
        print(f"  Admin dashboard password : {pw}")
        print(f"  Agent enrollment token   : {db.get_meta('enrollment_token')}")
        print(f"  (also saved to {first_run_file})")
        print("=" * 62)

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
