"""Save README screenshots of the demo, using a real browser against a real server.

Usage:  python scripts/screenshots.py [--channel msedge]   (writes docs/screenshots/*.png)
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

from accessdesk.clock import ManualClock
from accessdesk.config import Settings
from accessdesk.db import Database
from accessdesk.seed import seed_activity, seed_directory
from accessdesk.service import AccessService
from accessdesk.web import create_app
from accessdesk.web.server import background_server

OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
START = 1_800_000_000  # a fixed time so screenshots do not change between runs


def sign_in(page: Page, base: str, user: str) -> None:
    page.context.clear_cookies()
    page.goto(f"{base}/signin")
    page.check(f"#user-{user}")
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_url(f"{base}/")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", help="installed browser to use, e.g. msedge or chrome")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as folder:
        db = Database(str(Path(folder) / "shots.db"))
        seed_directory(db)
        service = AccessService(db, ManualClock(START))
        seed_activity(service)
        settings = Settings(
            db_path=db.path, secret_key="screenshot-secret-" * 2, api_key="k", sweep_seconds=0
        )
        with background_server(create_app(settings, service=service)) as base, sync_playwright() as pw:
            browser = pw.chromium.launch(channel=args.channel)
            page = browser.new_page(viewport={"width": 1280, "height": 860}, device_scale_factor=1)

            sign_in(page, base, "alice")
            page.screenshot(path=OUT / "my-access.png", full_page=True)
            page.goto(f"{base}/requests/new?resource=prod-db")
            page.fill("#hours", "48")
            page.get_by_role("button", name="Send request").click()
            page.wait_for_selector(".error-summary")
            page.screenshot(path=OUT / "form-errors.png", full_page=True)

            sign_in(page, base, "bob")
            page.goto(f"{base}/requests/6")
            page.screenshot(path=OUT / "approval.png", full_page=True)

            sign_in(page, base, "dan")
            page.goto(f"{base}/audit")
            page.screenshot(path=OUT / "audit-log.png")

            mobile = browser.new_page(viewport={"width": 360, "height": 780}, device_scale_factor=2)
            sign_in(mobile, base, "alice")
            mobile.goto(f"{base}/requests/3")
            mobile.screenshot(path=OUT / "mobile-request.png")
            browser.close()
        db.close()

    for shot in sorted(OUT.glob("*.png")):
        print(f"{shot.relative_to(OUT.parent.parent)}  {shot.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
