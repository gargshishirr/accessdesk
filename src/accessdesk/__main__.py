"""Command line: ``accessdesk serve | seed | verify-audit | directory import/export | backup``."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from accessdesk import audit, directory
from accessdesk.clock import SystemClock
from accessdesk.config import ConfigError, Settings
from accessdesk.db import Database
from accessdesk.seed import seed_activity, seed_directory
from accessdesk.service import AccessService
from accessdesk.web.app import SSO_LATCH


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


def _service(settings: Settings) -> AccessService:
    return AccessService(Database(settings.db_path), SystemClock())


def import_directory(settings: Settings, path: str, *, dry_run: bool = False) -> int:
    service = _service(settings)
    try:
        report = directory.apply(service, directory.load(path), dry_run=dry_run)
    except directory.DirectoryError as exc:
        print(f"Nothing was changed. Fix these problems in {path} first:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    finally:
        service.db.close()
    print(("Dry run, nothing saved. " if dry_run else "") + f"Directory from {path}:")
    for line in report.lines():
        print(f"  {line}")
    return 0


def export_directory(settings: Settings, path: str | None) -> int:
    service = _service(settings)
    try:
        text = json.dumps(directory.export(service), indent=2, ensure_ascii=False) + "\n"
    finally:
        service.db.close()
    if path:
        Path(path).write_text(text, encoding="utf-8")
        print(f"Wrote the directory to {path}.")
    else:
        sys.stdout.write(text)
    return 0


def backup(settings: Settings, target: str) -> int:
    """Copy the database with SQLite's online backup, which is safe while the app is running."""
    if not Path(settings.db_path).exists():
        print(f"There is no database at {settings.db_path}.", file=sys.stderr)
        return 1
    try:
        # Create the file first, readable by its owner only: it holds names, emails and the audit log.
        os.close(os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except FileExistsError:
        print(f"{target} already exists. Choose a new file name.", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"The folder for {target} does not exist. Create it first.", file=sys.stderr)
        return 1
    with closing(sqlite3.connect(settings.db_path)) as source, closing(sqlite3.connect(target)) as copy:
        source.backup(copy)
    print(f"Backed up {settings.db_path} to {target}.")
    return 0


def verify_audit(settings: Settings) -> int:
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


def _used_with_sso(settings: Settings) -> bool:
    service = _service(settings)
    try:
        return service.meta(SSO_LATCH) == "sso"
    finally:
        service.db.close()


def serve(settings: Settings, host: str, port: int, *, demo: bool) -> int:
    import uvicorn

    from accessdesk.web import create_app

    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("accessdesk").setLevel(logging.INFO)
    try:
        app = create_app(settings)
    except ConfigError as exc:
        print(f"AccessDesk cannot start: {exc}", file=sys.stderr)
        return 2

    if settings.directory_file:
        if import_directory(settings, settings.directory_file) != 0:
            app.state.service.db.close()
            return 1
    elif demo and not settings.sso and seed(settings):
        print(f"Added demo data to {settings.db_path}.")

    if settings.oidc is not None:
        print(f"Sign-in: single sign-on with {settings.oidc.issuer}")
        print(f"Redirect URI to register with your identity provider: {settings.redirect_uri}")
        if not settings.api_keys:
            print("The API is off. Set ACCESSDESK_API_KEYS to let other services call it.")
        if not app.state.service.users(active_only=True):
            print(
                "The directory is empty, so nobody can sign in yet. "
                "Load it with: accessdesk directory import FILE"
            )
    else:
        print("Sign-in: DEMO MODE. Anyone can sign in as anyone. Set ACCESSDESK_OIDC_* for real sign-in.")
        if not (os.environ.get("ACCESSDESK_API_KEYS") or os.environ.get("ACCESSDESK_API_KEY")):
            # Demo mode only, and only for a key made up for this run.
            print(
                f"API key for this run (set ACCESSDESK_API_KEYS to fix it): {settings.api_keys[0]}",
                file=sys.stderr,
            )
    uvicorn.run(app, host=host, port=port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="accessdesk", description="Just-in-time access requests.")
    commands = parser.add_subparsers(dest="command", required=True)
    serve_cmd = commands.add_parser("serve", help="run the web app and API")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8000)
    serve_cmd.add_argument("--no-demo", action="store_true", help="do not add demo data to an empty database")
    seed_cmd = commands.add_parser("seed", help="add demo data to an empty database")
    seed_cmd.add_argument("--force", action="store_true", help="even with single sign-on set up")
    commands.add_parser("verify-audit", help="check the audit hash chain; exit code 1 if it is broken")
    directory_cmd = commands.add_parser("directory", help="load or save people, resources and rules")
    directory_commands = directory_cmd.add_subparsers(dest="action", required=True)
    import_cmd = directory_commands.add_parser("import", help="load a directory JSON file")
    import_cmd.add_argument("file")
    import_cmd.add_argument("--dry-run", action="store_true", help="show what would change, save nothing")
    export_cmd = directory_commands.add_parser("export", help="write the directory as JSON")
    export_cmd.add_argument("file", nargs="?", help="where to write it (default: the screen)")
    backup_cmd = commands.add_parser("backup", help="copy the database safely, even while it is in use")
    backup_cmd.add_argument("file", help="the new backup file")
    args = parser.parse_args(argv)

    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"AccessDesk cannot start: {exc}", file=sys.stderr)
        return 2

    if args.command == "seed":
        if (settings.sso or _used_with_sso(settings)) and not args.force:
            print(
                "This AccessDesk uses single sign-on, so demo people and requests are not added. "
                "Use --force if you really want them.",
                file=sys.stderr,
            )
            return 1
        print("Demo data added." if seed(settings) else "Database already has data; nothing added.")
        return 0
    if args.command == "verify-audit":
        return verify_audit(settings)
    if args.command == "directory":
        if args.action == "import":
            return import_directory(settings, args.file, dry_run=args.dry_run)
        return export_directory(settings, args.file)
    if args.command == "backup":
        return backup(settings, args.file)
    return serve(settings, args.host, args.port, demo=not args.no_demo)


if __name__ == "__main__":
    sys.exit(main())
