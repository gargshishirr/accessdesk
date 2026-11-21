"""Save README screenshots of the demo, using a real browser against a real server.

It walks the guided demo the way a visitor does, using only its own buttons: the sign-in page, Alice's
request form, approvals by Bob and Frank, the live access on its timeline and Dan's audit log, plus Alice's
home page (on a laptop and a phone) part-way through.

Usage:  python scripts/screenshots.py [--channel chrome] [--out docs/screenshots]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

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
WHY = "Running the approved index migration for incident INC-2041 (CHG-1207)."


def continue_as(page: Page, name: str, where: str = ".tour-strip") -> None:
    """Press the guided demo's "Continue as" button, which switches person and opens the next page."""
    page.locator(where).get_by_role("button", name=f"Continue as {name}").click()
    page.wait_for_load_state()


def approve(page: Page, comment: str) -> None:
    page.check("#decision-approve")
    page.fill("#comment", comment)
    page.get_by_role("button", name="Submit decision").click()
    page.wait_for_selector(".notice")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", help="installed browser to use, e.g. chrome or msedge")
    parser.add_argument("--out", type=Path, default=OUT, help="folder for the images")
    args = parser.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as folder:
        db = Database(str(Path(folder) / "shots.db"))
        seed_directory(db)
        service = AccessService(db, ManualClock(START))
        seed_activity(service)
        settings = Settings(
            db_path=db.path,
            secret_key="screenshot-secret-" * 2,
            api_keys=("k",),
            sweep_seconds=0,
            signin_rate_limit=0,
        )
        with background_server(create_app(settings, service=service)) as base, sync_playwright() as pw:
            browser = pw.chromium.launch(channel=args.channel)
            page = browser.new_page(viewport={"width": 1280, "height": 900}, device_scale_factor=1)

            page.goto(f"{base}/signin")
            page.screenshot(path=out / "signin.png", full_page=True)
            page.get_by_role("button", name="Start the guided demo").click()
            page.wait_for_url(f"{base}/")

            page.locator(".tour-next").get_by_role("link", name="Ask for Production Database").click()
            page.wait_for_url("**/requests/new?resource=prod-db")
            page.get_by_role("button", name="Send request").click()
            page.wait_for_selector(".error-summary")
            page.screenshot(path=out / "form-errors.png")

            page.goto(f"{base}/requests/new?resource=prod-db")
            page.check("#role-editor")
            page.check("#hours-8")
            page.fill("#justification", WHY)
            page.screenshot(path=out / "request-form.png", full_page=True)
            page.get_by_role("button", name="Send request").click()
            page.wait_for_selector(".notice")
            request_url = urlsplit(page.url).path

            continue_as(page, "Bob Singh")
            approve(page, "Agreed, this is for INC-2041.")

            page.locator(".switcher-toggle").click()
            page.locator(".switcher-panel").get_by_role("button", name="Alice Chen").click()
            page.wait_for_url(f"{base}/")
            page.screenshot(path=out / "home.png", full_page=True)
            mobile = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=2)
            mobile.context.add_cookies(page.context.cookies())
            mobile.goto(f"{base}/")
            mobile.screenshot(path=out / "mobile-home.png")
            mobile.close()

            continue_as(page, "Frank Moreau", ".tour-next")
            page.wait_for_url(f"{base}{request_url}")
            page.screenshot(path=out / "approval.png", full_page=True)
            approve(page, "OK for the migration window.")

            continue_as(page, "Alice Chen")
            page.wait_for_url(f"{base}{request_url}")
            page.screenshot(path=out / "request-timeline.png", full_page=True)

            continue_as(page, "Dan Okafor")
            page.wait_for_url(f"{base}/audit")
            page.screenshot(path=out / "audit-log.png")
            browser.close()
        db.close()

    for shot in sorted(out.glob("*.png")):
        print(f"{shot}  {shot.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
