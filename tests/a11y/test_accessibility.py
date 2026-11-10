"""Browser checks: axe-core on every page and state, reflow at 320px, keyboard-only use and forced colours.

Needs a Playwright browser: ``playwright install chromium``, or set A11Y_BROWSER_CHANNEL=msedge / chrome
to use an installed browser. The tests skip if no browser can start.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import axe_playwright_python
import pytest
from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Browser, Page, sync_playwright

from accessdesk.clock import ManualClock
from accessdesk.config import Settings
from accessdesk.db import Database
from accessdesk.seed import seed_activity, seed_directory
from accessdesk.service import AccessService
from accessdesk.web import create_app
from accessdesk.web.server import background_server
from tests.helpers import API_KEY, START

pytestmark = pytest.mark.a11y

AXE = Axe.from_file(Path(axe_playwright_python.__file__).parent / "axe.min.js")
AXE_OPTIONS = {
    "runOnly": {
        "type": "tag",
        "values": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"],
    },
    "resultTypes": ["violations"],
}
DESKTOP = {"width": 1280, "height": 900}
NARROW = {"width": 320, "height": 640}  # WCAG 1.4.10 Reflow: 1280px at 400% zoom


@contextmanager
def live_server(folder: Path) -> Iterator[str]:
    """The real app over real HTTP, seeded with the demo data and a frozen clock."""
    db = Database(str(folder / "a11y.db"))
    seed_directory(db)
    service = AccessService(db, ManualClock(START))
    seed_activity(service)
    settings = Settings(db_path=db.path, secret_key="a11y-secret-" * 4, api_key=API_KEY, sweep_seconds=0)
    with background_server(create_app(settings, service=service)) as url:
        yield url


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    with live_server(tmp_path_factory.mktemp("a11y")) as url:
        yield url


@pytest.fixture
def fresh_server(tmp_path: Path) -> Iterator[str]:
    with live_server(tmp_path) as url:
        yield url


@pytest.fixture(scope="session")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        try:
            launched = playwright.chromium.launch(channel=os.environ.get("A11Y_BROWSER_CHANNEL") or None)
        except Exception as exc:  # depends on the machine
            message = f"no Playwright browser available ({exc}); run `playwright install chromium`"
            if os.environ.get("A11Y_REQUIRE_BROWSER"):
                pytest.fail(message)  # CI must never pass by skipping
            pytest.skip(message)
        yield launched
        launched.close()


@pytest.fixture
def page(browser: Browser) -> Iterator[Page]:
    context = browser.new_context(viewport=DESKTOP)  # type: ignore[arg-type]
    yield context.new_page()
    context.close()


def sign_in(page: Page, base: str, user: str) -> None:
    page.context.clear_cookies()
    page.goto(f"{base}/signin")
    page.check(f"#user-{user}")
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_url(f"{base}/")


def visit(path: str) -> Callable[[Page, str], Any]:
    return lambda page, base: page.goto(base + path)


def submit_empty(path: str, button: str) -> Callable[[Page, str], Any]:
    def go(page: Page, base: str) -> None:
        page.goto(base + path)
        page.get_by_role("button", name=button).click()
        page.wait_for_selector(".error-summary")

    return go


def signed_out(page: Page, base: str) -> None:
    page.get_by_role("button", name="Sign out").click()
    page.wait_for_selector(".notice")


# Demo data ids: request 2 = Alice's pending prod-db request, 3 = approved, 4 = denied by separation
# of duties, 6 = Erin's payroll request waiting for Bob; grant 2 = Alice's payments-ledger access.
STATES: list[tuple[str, str | None, Callable[[Page, str], Any]]] = [
    ("sign-in", None, visit("/signin")),
    ("sign-in-error", None, submit_empty("/signin", "Sign in")),
    ("accessibility-statement", None, visit("/accessibility")),
    ("signed-out-notice", "alice", signed_out),
    ("my-access", "alice", visit("/")),
    ("catalogue", "alice", visit("/requests/new")),
    ("request-form", "alice", visit("/requests/new?resource=prod-db")),
    ("request-form-errors", "alice", submit_empty("/requests/new?resource=prod-db", "Send request")),
    ("request-pending", "alice", visit("/requests/2")),
    ("request-approved", "alice", visit("/requests/3")),
    ("request-denied", "alice", visit("/requests/4")),
    ("approvals-empty", "alice", visit("/approvals")),
    ("forbidden", "alice", visit("/audit")),
    ("not-found", "alice", visit("/no-such-page")),
    ("approvals", "bob", visit("/approvals")),
    ("decision-form", "bob", visit("/requests/6")),
    ("decision-errors", "bob", submit_empty("/requests/6", "Submit decision")),
    ("reviews-owner", "frank", visit("/reviews")),
    ("revoke-form", "frank", visit("/grants/2/revoke")),
    ("revoke-errors", "frank", submit_empty("/grants/2/revoke", "Remove access")),
    ("audit-log", "dan", visit("/audit")),
    ("reviews-security", "dan", visit("/reviews")),
]


def assert_no_violations(page: Page, label: str) -> None:
    results = AXE.run(page, options=AXE_OPTIONS)
    assert results.violations_count == 0, f"{label}\n{results.generate_report()}"


@pytest.mark.parametrize(("user", "go"), [(s[1], s[2]) for s in STATES], ids=[s[0] for s in STATES])
def test_every_page_and_state_passes_axe_and_reflows(
    page: Page, server: str, user: str | None, go: Any
) -> None:
    if user:
        sign_in(page, server, user)
    go(page, server)
    assert_no_violations(page, f"{page.url} at {DESKTOP['width']}px")

    page.set_viewport_size(NARROW)  # type: ignore[arg-type]
    overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    assert overflow <= 0, f"{page.url} scrolls sideways by {overflow}px at 320px wide"
    assert_no_violations(page, f"{page.url} at {NARROW['width']}px")


def focused(page: Page, selector: str) -> dict[str, Any]:
    info: dict[str, Any] = page.evaluate(
        """(selector) => {
            const el = document.activeElement;
            const style = getComputedStyle(el);
            return {
                matches: el.matches(selector),
                isBody: el === document.body,
                visible: (style.outlineStyle !== 'none' && style.outlineWidth !== '0px')
                    || style.boxShadow !== 'none',
                where: el.outerHTML.slice(0, 120),
            };
        }""",
        selector,
    )
    return info


def tab_to(page: Page, selector: str, *, backwards: bool = False, limit: int = 80) -> None:
    """Press Tab until ``selector`` has focus, checking every stop on the way shows a focus indicator."""
    for _ in range(limit):
        page.keyboard.press("Shift+Tab" if backwards else "Tab")
        info = focused(page, selector)
        if not info["isBody"]:
            assert info["visible"], f"no visible focus indicator on {info['where']}"
        if info["matches"]:
            return
    raise AssertionError(f"could not reach {selector} with the keyboard")


def choose_radio(page: Page, name: str, value: str) -> None:
    """Tab into a radio group, then use the arrow keys to select ``value``, as a keyboard user would."""
    tab_to(page, f'input[name="{name}"]')
    for _ in range(12):
        if page.evaluate("document.activeElement.value") == value:
            break
        page.keyboard.press("ArrowDown")
    page.keyboard.press("Space")
    assert page.is_checked(f'input[name="{name}"][value="{value}"]')


def keyboard_sign_in(page: Page, base: str, user: str) -> None:
    page.goto(f"{base}/signin")
    choose_radio(page, "user_id", user)
    tab_to(page, 'button[type="submit"]')
    page.keyboard.press("Enter")
    page.wait_for_url(f"{base}/")


def keyboard_sign_out(page: Page, base: str) -> None:
    tab_to(page, 'form[action="/signout"] button', backwards=True)
    page.keyboard.press("Enter")
    page.wait_for_url(f"{base}/signin")


def notice_has_focus(page: Page, text: str) -> None:
    """After a form post, focus must land on the result message so screen readers read it out."""
    page.wait_for_function("document.activeElement && document.activeElement.classList.contains('notice')")
    message = page.evaluate("document.activeElement.innerText")
    assert text in message, message


def test_request_and_approve_with_the_keyboard_only(browser: Browser, fresh_server: str) -> None:
    base = fresh_server
    context = browser.new_context(viewport=DESKTOP)  # type: ignore[arg-type]
    page = context.new_page()

    keyboard_sign_in(page, base, "alice")
    tab_to(page, 'nav a[href="/requests/new"]')
    page.keyboard.press("Enter")
    page.wait_for_url(f"{base}/requests/new")
    tab_to(page, 'a[href="/requests/new?resource=prod-db"]')
    page.keyboard.press("Enter")
    page.wait_for_url("**/requests/new?resource=prod-db")
    choose_radio(page, "role", "editor")  # the demo data already has her viewer request pending
    tab_to(page, "#hours")
    page.keyboard.type("8")
    tab_to(page, "#justification")
    page.keyboard.type("Reading the payments table for incident INC-2041.")
    tab_to(page, 'form[action="/requests"] button[type="submit"]')
    page.keyboard.press("Enter")
    page.wait_for_url(f"{base}/requests/7")
    notice_has_focus(page, "Request #7 sent")
    keyboard_sign_out(page, base)

    for approver, message in [
        ("bob", "Your approval is recorded"),
        ("frank", "Approved. Alice Chen now has editor"),
    ]:
        keyboard_sign_in(page, base, approver)
        tab_to(page, 'nav a[href="/approvals"]')
        page.keyboard.press("Enter")
        page.wait_for_url(f"{base}/approvals")
        tab_to(page, 'a[href="/requests/7"]')
        page.keyboard.press("Enter")
        page.wait_for_url(f"{base}/requests/7")
        choose_radio(page, "decision", "approve")
        tab_to(page, 'form[action="/requests/7/decision"] button[type="submit"]')
        page.keyboard.press("Enter")
        notice_has_focus(page, message)
        keyboard_sign_out(page, base)
    context.close()


def test_skip_link_is_first_visible_and_works(page: Page, server: str) -> None:
    sign_in(page, server, "alice")
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.textContent") == "Skip to main content"
    box = page.locator(".skip-link").bounding_box()
    assert box is not None
    assert box["y"] >= 0
    assert box["height"] >= 24
    page.keyboard.press("Enter")
    assert page.evaluate("document.activeElement.id") == "main"


OUTLINE_OF_FOCUSED = (
    "(() => { const s = getComputedStyle(document.activeElement); "
    "return [s.outlineStyle, s.outlineWidth]; })()"
)


def test_focus_stays_visible_in_forced_colours_mode(page: Page, server: str) -> None:
    page.emulate_media(forced_colors="active")
    page.goto(f"{server}/signin")
    for selector in ("a.skip-link", 'input[name="user_id"]', 'button[type="submit"]'):
        tab_to(page, selector)
        style = page.evaluate(OUTLINE_OF_FOCUSED)
        assert style == ["solid", "3px"], f"{selector} focus outline in forced colours: {style}"
