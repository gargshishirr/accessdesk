"""Command line: ``accessdesk serve | seed | verify-audit``."""

from __future__ import annotations

import argparse
import os
import sys

from accessdesk import audit
from accessdesk.clock import SystemClock
from accessdesk.config import Settings
from accessdesk.db import Database
from accessdesk.seed import seed_activity, seed_directory
from accessdesk.service import AccessService


def seed(settings: Settings) -> bool:
    """Add the demo people, resources and a few requests to an empty database."""
    db = Database(settings.db_path)
    try:
        if not seed_directory(db):
            return False
        seed_activity(AccessService(db, SystemClock()))
        return True
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="accessdesk", description="Just-in-time access requests.")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="run the web app and API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--no-demo", action="store_true", help="do not add demo data to an empty database")
    commands.add_parser("seed", help="add demo data to an empty database")
    commands.add_parser("verify-audit", help="check the audit hash chain; exit code 1 if it is broken")
    args = parser.parse_args(argv)
    settings = Settings.from_env()

    if args.command == "seed":
        print("Demo data added." if seed(settings) else "Database already has data; nothing added.")
        return 0

    if args.command == "verify-audit":
        db = Database(settings.db_path)
        try:
            with db.connection() as conn:
                result = audit.verify(conn)
        finally:
            db.close()
        if result.ok:
            print(f"OK: {result.events} entries verified. Head hash {result.head_hash}")
            return 0
        print(f"BROKEN at entry {result.first_invalid_seq}: {result.problem}", file=sys.stderr)
        return 1

    import uvicorn

    from accessdesk.web import create_app

    if not args.no_demo and seed(settings):
        print(f"Added demo data to {settings.db_path}.")
    if not os.environ.get("ACCESSDESK_API_KEY"):
        print(f"API key for this run (set ACCESSDESK_API_KEY to fix it): {settings.api_key}", file=sys.stderr)
    uvicorn.run(create_app(settings), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
