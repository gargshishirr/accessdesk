"""Browser checks: axe-core on every page and state, reflow at 320px, keyboard-only use and forced colours.

Needs a Playwright browser: ``playwright install chromium``, or set A11Y_BROWSER_CHANNEL=msedge / chrome
to use an installed browser. The tests skip if no browser can start.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import axe_playwright_python
import pytest
from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Browser, Page, sync_playwright

from accessdesk.clock import ManualClock
from accessdesk.config import OidcSettings, Settings
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
    settings = Settings(
        db_path=db.path,
        secret_key="a11y-secret-" * 4,
        api_keys=(API_KEY,),
        sweep_seconds=0,
        signin_rate_limit=0,  # these tests sign in dozens of times a minute from one address
    )
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


def choose_other_hours(page: Page, base: str) -> None:
    page.goto(base + "/requests/new?resource=prod-db")
    assert not page.is_visible("#hours")  # hidden until "Other" is chosen
    page.check("#hours-other")
    assert page.is_visible("#hours")


def open_switcher(page: Page, base: str) -> None:
    page.goto(base + "/")
    page.locator(".switcher-toggle").click()
    page.wait_for_selector(".switcher-panel", state="visible")


def signed_out(page: Page, base: str) -> None:
    page.get_by_role("button", name="Sign out").click()
    page.wait_for_selector(".notice")


# Demo data ids (seed.py): request 2 = Alice's approved payments-ledger access (grant 2, which Frank can
# remove), 3 = refused by separation of duties, 5 = Erin's revoked access, 6 = Alice's expired access,
# 7 = Erin's critical payroll request waiting for Bob, 8 = Leo's admin request waiting for two security
# approvals, 11 = Alice's request waiting for Bob.
STATES: list[tuple[str, str | None, Callable[[Page, str], Any]]] = [
    ("sign-in", None, visit("/signin")),
    ("sign-in-error", None, submit_empty("/signin", "Sign in")),
    ("accessibility-statement", None, visit("/accessibility")),
    ("signed-out-notice", "alice", signed_out),
    ("my-access", "alice", visit("/")),
    ("switch-person", "alice", visit("/switch")),
    ("switcher-open", "alice", open_switcher),
    ("catalogue", "alice", visit("/requests/new")),
    ("request-form", "alice", visit("/requests/new?resource=prod-db")),
    ("request-form-other-hours", "alice", choose_other_hours),
    ("request-form-errors", "alice", submit_empty("/requests/new?resource=prod-db", "Send request")),
    ("request-pending", "alice", visit("/requests/11")),
    ("request-approved", "alice", visit("/requests/2")),
    ("request-denied", "alice", visit("/requests/3")),
    ("request-expired", "alice", visit("/requests/6")),
    ("approvals-empty", "alice", visit("/approvals")),
    ("forbidden", "alice", visit("/audit")),
    ("not-found", "alice", visit("/no-such-page")),
    ("home-approver", "bob", visit("/")),
    ("approvals", "bob", visit("/approvals")),
    ("decision-form", "bob", visit("/requests/7")),
    ("decision-errors", "bob", submit_empty("/requests/7", "Submit decision")),
    ("reviews-owner", "frank", visit("/reviews")),
    ("revoke-form", "frank", visit("/grants/2/revoke")),
    ("revoke-errors", "frank", submit_empty("/grants/2/revoke", "Remove access")),
    ("audit-log", "dan", visit("/audit")),
    ("reviews-security", "dan", visit("/reviews")),
    ("request-revoked", "dan", visit("/requests/5")),
    ("request-two-security-steps", "dan", visit("/requests/8")),
    ("home-security", "dan", visit("/")),
]


def assert_no_violations(page: Page, label: str) -> None:
    results = AXE.run(page, options=AXE_OPTIONS)
    assert results.violations_count == 0, f"{label}\n{results.generate_report()}"


def assert_accessible_at_both_widths(page: Page) -> None:
    assert_no_violations(page, f"{page.url} at {DESKTOP['width']}px")
    page.set_viewport_size(NARROW)  # type: ignore[arg-type]
    overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    assert overflow <= 0, f"{page.url} scrolls sideways by {overflow}px at 320px wide"
    assert_no_violations(page, f"{page.url} at {NARROW['width']}px")


@pytest.mark.parametrize(("user", "go"), [(s[1], s[2]) for s in STATES], ids=[s[0] for s in STATES])
def test_every_page_and_state_passes_axe_and_reflows(
    page: Page, server: str, user: str | None, go: Any
) -> None:
    if user:
        sign_in(page, server, user)
    go(page, server)
    assert_accessible_at_both_widths(page)


@pytest.fixture(scope="module")
def sso_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """The app in single sign-on mode. These pages never contact the identity provider."""
    db = Database(str(tmp_path_factory.mktemp("a11y-sso") / "a11y.db"))
    seed_directory(db)
    oidc = OidcSettings("https://idp.invalid", "client-id", "client-secret", ("example.com",))
    settings = Settings(
        db_path=db.path,
        secret_key="a11y-secret-" * 4,
        api_keys=(),
        sweep_seconds=0,
        public_url="http://127.0.0.1:9",
        oidc=oidc,
    )
    with background_server(create_app(settings, service=AccessService(db, ManualClock(START)))) as url:
        yield url


SSO_STATES = [
    ("sso-sign-in", "/signin?next=/approvals"),
    ("sso-sign-in-problem", "/auth/callback?error=access_denied&state=unknown"),
]


@pytest.mark.parametrize("path", [s[1] for s in SSO_STATES], ids=[s[0] for s in SSO_STATES])
def test_single_sign_on_pages_pass_axe_and_reflow(page: Page, sso_server: str, path: str) -> None:
    page.goto(sso_server + path)
    assert_accessible_at_both_widths(page)


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
    assert page.is_checked(f'input[type="radio"][name="{name}"][value="{value}"]')


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
    # Poll with page.evaluate: wait_for_function evaluates strings in the page, which the strict CSP forbids.
    deadline = time.monotonic() + 10
    while not page.evaluate(
        "!!document.activeElement && document.activeElement.classList.contains('notice')"
    ):
        assert time.monotonic() < deadline, "focus never moved to the result message"
        page.wait_for_timeout(50)
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
    choose_radio(page, "role", "editor")
    choose_radio(page, "hours", "other")  # reveals the number box, with no script
    tab_to(page, "#hours")
    page.keyboard.type("5")
    tab_to(page, "#justification")
    page.keyboard.type("Reading the payments table for incident INC-2041.")
    tab_to(page, 'form[action="/requests"] button[type="submit"]')
    page.keyboard.press("Enter")
    page.wait_for_url(f"{base}/requests/12")
    notice_has_focus(page, "Request #12 sent")
    keyboard_sign_out(page, base)

    for approver, message in [
        ("bob", "Your approval is recorded"),
        ("frank", "Approved. Alice Chen now has editor"),
    ]:
        keyboard_sign_in(page, base, approver)
        tab_to(page, 'nav a[href="/approvals"]')
        page.keyboard.press("Enter")
        page.wait_for_url(f"{base}/approvals")
        tab_to(page, 'a[href="/requests/12"]')
        page.keyboard.press("Enter")
        page.wait_for_url(f"{base}/requests/12")
        choose_radio(page, "decision", "approve")
        tab_to(page, 'form[action="/requests/12/decision"] button[type="submit"]')
        page.keyboard.press("Enter")
        notice_has_focus(page, message)
        keyboard_sign_out(page, base)
    context.close()


def test_the_guided_demo_by_clicking_its_buttons(browser: Browser, fresh_server: str) -> None:
    """A visitor follows the 60-second checklist using only its buttons, and every stop stays accessible."""
    base = fresh_server
    context = browser.new_context(viewport=DESKTOP)  # type: ignore[arg-type]
    page = context.new_page()

    def stop(label: str) -> None:
        assert_accessible_at_both_widths(page)
        page.set_viewport_size(DESKTOP)  # type: ignore[arg-type]
        assert page.locator("h1").count() == 1, label

    page.goto(f"{base}/signin")
    page.get_by_role("button", name="Start the guided demo").click()
    page.wait_for_url(f"{base}/")
    assert "0 of 5" in page.locator(".tour-count").inner_text()
    stop("home at the start")

    page.locator(".tour-next").get_by_role("link", name="Ask for Production Database").click()
    page.wait_for_url("**/requests/new?resource=prod-db")
    page.check("#role-viewer")
    page.check("#hours-4")
    page.fill("#justification", "Checking the failed payouts for INC-2041.")
    page.get_by_role("button", name="Send request").click()
    page.wait_for_url(f"{base}/requests/12")
    stop("request sent")

    for approver in ("Bob Singh", "Frank Moreau"):
        page.locator(".tour-strip").get_by_role("button", name=f"Continue as {approver}").click()
        page.wait_for_url(f"{base}/requests/12")
        stop(f"{approver} reviewing")
        page.check("#decision-approve")
        page.get_by_role("button", name="Submit decision").click()
        page.wait_for_selector(".notice")

    page.locator(".tour-strip").get_by_role("button", name="Continue as Alice Chen").click()
    page.wait_for_url(f"{base}/requests/12")
    assert "4 hours left" in page.locator(".access-card").inner_text()
    stop("the access counting down")

    page.locator(".tour-strip").get_by_role("button", name="Continue as Dan Okafor").click()
    page.wait_for_url(f"{base}/audit")
    assert "Guided demo complete" in page.locator("main").inner_text()
    stop("audit log at the end")
    page.locator(".switcher-toggle").click()
    page.locator(".switcher-panel").get_by_role("button", name="Alice Chen").click()
    page.wait_for_url(f"{base}/")
    assert "5 of 5" in page.locator(".tour-count").inner_text()
    stop("home at the end")
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
