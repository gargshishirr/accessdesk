"""Signing in and out: single sign-on with OpenID Connect, or the demo person picker.

Only one of the two exists in a running app. With single sign-on set up, the person picker's form handler
is never registered, so nobody can sign in as somebody else.

Every sign-in gets a brand-new session: a random id in a signed cookie, stored (hashed) in the database.
Signing out deletes it, so a copied cookie stops working at once.
"""

from __future__ import annotations

import hmac
import logging
import math
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from accessdesk.models import User
from accessdesk.oidc import (
    EmailDomainNotAllowed,
    EmailNotVerified,
    OidcClient,
    ProviderUnavailable,
    SignInError,
    safe_code,
)
from accessdesk.web.ratelimit import client_address
from accessdesk.web.security import csrf_protect, safe_next
from accessdesk.web.ui import current_user, flash, get_metrics, get_service, render

log = logging.getLogger("accessdesk")

router = APIRouter(include_in_schema=False)  # both modes
demo_router = APIRouter(include_in_schema=False)  # demo mode only
sso_router = APIRouter(include_in_schema=False)  # single sign-on only

CSRF = [Depends(csrf_protect)]
PENDING_LOGINS = 3  # sign-ins started in other tabs that can still finish
LOGIN_SECONDS = 600  # time allowed on the identity provider's pages

# kind -> (status, heading, paragraphs). "{email}" is the address the provider vouched for.
PROBLEMS: dict[str, tuple[int, str, tuple[str, ...]]] = {
    "not_in_directory": (
        403,
        "You are not in AccessDesk's directory",
        (
            "You signed in as {email}, but nobody with that email address is in AccessDesk's directory.",
            "Ask your IT or security team to add you.",
        ),
    ),
    "unverified": (
        403,
        "Your email address could not be confirmed",
        (
            "Your sign-in service did not confirm your email address, so AccessDesk cannot tell who you are.",
            "Ask your IT team to check the single sign-on settings.",
        ),
    ),
    "wrong_domain": (
        403,
        "Use your work account",
        ("{email} is not a work account for this AccessDesk.", "Sign in again and choose your work account."),
    ),
    "refused": (
        400,
        "Sign-in did not finish",
        ("Your sign-in service stopped the sign-in.", "Try again. If it keeps happening, ask your IT team."),
    ),
    "expired": (
        400,
        "Sign-in did not finish",
        ("The sign-in took too long, or it was started in another browser.", "Try again."),
    ),
    "failed": (
        400,
        "Sign-in did not work",
        (
            "AccessDesk could not check the answer from your sign-in service.",
            "Try again. If it keeps happening, ask your IT team.",
        ),
    ),
    "unavailable": (
        503,
        "Single sign-on is not available right now",
        ("AccessDesk could not reach your company's sign-in service.", "Try again in a few minutes."),
    ),
    "too_many": (
        429,
        "Too many sign-in attempts",
        ("For your security, sign-in is paused for a moment.", "Wait a minute, then try again."),
    ),
}


def see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def begin_session(request: Request, user: User, method: str) -> None:
    """Sign ``user`` in with a brand-new session and CSRF token, so an old session id can never carry over."""
    settings = request.app.state.settings
    session_id = get_service(request).start_session(user.id, method, settings.session_hours * 3600)
    request.session.clear()
    request.session["sid"] = session_id
    request.state.user = user
    get_metrics(request).signins.labels(method, "success").inc()
    log.info("signed in: user=%s method=%s", user.id, method)


def problem_page(request: Request, kind: str, email: str = "", retry_after: float = 0) -> Response:
    status, heading, paragraphs = PROBLEMS[kind]
    response = render(
        request,
        "signin_problem.html",
        heading,
        status_code=status,
        heading=heading,
        paragraphs=[p.format(email=email) for p in paragraphs],
    )
    if retry_after:
        response.headers["Retry-After"] = str(max(1, math.ceil(retry_after)))
    return response


def signin_limited(request: Request) -> Response | None:
    """A 'too many attempts' page if this address has been signing in too often, else None."""
    wait = request.app.state.limits.signin.hit(client_address(request))
    if not wait:
        return None
    get_metrics(request).rate_limited.labels("signin").inc()
    return problem_page(request, "too_many", retry_after=wait)


# ----------------------------------------------------------------------------- both modes


@router.get("/signin")
def signin_form(request: Request, next_url: Annotated[str, Query(alias="next")] = "/") -> Response:
    target = safe_next(next_url)
    if current_user(request) is not None:
        return see_other(target)
    if request.app.state.settings.sso:
        query = "" if target == "/" else "?" + urlencode({"next": target})
        return render(request, "signin_sso.html", "Sign in", login_url=f"/auth/login{query}")
    people = get_service(request).users(active_only=True)
    return render(request, "signin.html", "Sign in", people=people, next_url=target)


@router.post("/signout", dependencies=CSRF)
def signout(request: Request) -> Response:
    session_id = request.session.get("sid")
    if isinstance(session_id, str):
        get_service(request).end_session(session_id)
    request.session.clear()
    request.state.user = None
    message = "You have signed out."
    if request.app.state.settings.sso:
        message += " Your company account is still signed in on this device."
    flash(request, "success", message)
    return see_other("/signin")


# ----------------------------------------------------------------------------- demo mode: the person picker


@demo_router.post("/signin", dependencies=CSRF)
def demo_signin(
    request: Request,
    user_id: Annotated[str, Form()] = "",
    next_url: Annotated[str, Form(alias="next")] = "/",
) -> Response:
    limited = signin_limited(request)
    if limited is not None:
        return limited
    service = get_service(request)
    user = service.user(user_id) if user_id else None
    if user is None or not user.active:
        people = service.users(active_only=True)
        return render(
            request,
            "signin.html",
            "Sign in",
            status_code=422,
            people=people,
            next_url=safe_next(next_url),
            errors={"user_id": "Choose who you want to sign in as"},
            error_anchors={"user_id": f"user-{people[0].id}" if people else "main"},
        )
    begin_session(request, user, "demo")
    return see_other(safe_next(next_url))


# ----------------------------------------------------------------------------- single sign-on


def _pending_logins(request: Request, now: int) -> dict[str, dict[str, Any]]:
    """Sign-ins this browser started and has not finished, oldest first. Stale ones are dropped."""
    raw = request.session.get("oidc")
    if not isinstance(raw, dict):
        return {}
    return {
        state: entry
        for state, entry in raw.items()
        if isinstance(entry, dict)
        and isinstance(entry.get("at"), int)
        and 0 <= now - entry["at"] < LOGIN_SECONDS
    }


def _take_pending(request: Request, state: str, now: int) -> dict[str, Any] | None:
    """Remove and return the pending sign-in for ``state``. Each state works once."""
    pending = _pending_logins(request, now)
    found = None
    for key in list(pending):
        if hmac.compare_digest(key.encode(), state.encode()):
            found = pending.pop(key)
    if pending:
        request.session["oidc"] = pending
    else:
        request.session.pop("oidc", None)
    return found


@sso_router.get("/auth/login")
async def sso_start(request: Request, next_url: Annotated[str, Query(alias="next")] = "/") -> Response:
    limited = await run_in_threadpool(signin_limited, request)
    if limited is not None:
        return limited
    oidc: OidcClient = request.app.state.oidc
    try:
        login = await oidc.start()
    except SignInError as exc:
        log.warning("single sign-on unavailable: %s", exc)
        get_metrics(request).signins.labels("sso", "unavailable").inc()
        return await run_in_threadpool(problem_page, request, "unavailable")
    now = get_service(request).clock.now()
    pending = _pending_logins(request, now)
    pending[login.state] = {
        "nonce": login.nonce,
        "verifier": login.verifier,
        "next": safe_next(next_url),
        "at": now,
    }
    request.session["oidc"] = dict(list(pending.items())[-PENDING_LOGINS:])
    return RedirectResponse(login.url, status_code=303)


@sso_router.get("/auth/callback")
async def sso_finish(request: Request) -> Response:
    # Not rate limited itself: each callback needs a pending sign-in from /auth/login, which is limited, and
    # uses it up, so the provider never sees more token requests than sign-ins started.
    params = request.query_params
    service = get_service(request)
    entry = _take_pending(request, params.get("state", ""), service.clock.now())

    if params.get("error"):
        return await _refuse(request, "refused", SignInError("provider_refused", safe_code(params["error"])))
    if entry is None:
        if await run_in_threadpool(current_user, request) is not None:
            return see_other("/")  # already signed in, for example by a second tab that finished first
        return await _refuse(request, "expired", SignInError("unknown_or_expired_state"))
    code, verifier = params.get("code"), entry.get("verifier")
    if not code or not isinstance(verifier, str):
        return await _refuse(request, "failed", SignInError("no_code"))

    oidc: OidcClient = request.app.state.oidc
    try:
        identity = await oidc.finish(code, verifier, str(entry.get("nonce", "")))
    except EmailNotVerified as exc:
        return await _refuse(request, "unverified", exc)
    except EmailDomainNotAllowed as exc:
        return await _refuse(request, "wrong_domain", exc, exc.email)
    except ProviderUnavailable as exc:
        return await _refuse(request, "unavailable", exc)
    except SignInError as exc:
        return await _refuse(request, "failed", exc)

    user = await run_in_threadpool(service.user_by_email, identity.email)
    if user is None:
        # Log the domain only: enough to spot a setup problem without keeping people's addresses in logs.
        domain = identity.email.rsplit("@", 1)[-1]
        return await _refuse(
            request, "not_in_directory", SignInError("not_in_directory", domain), identity.email
        )
    await run_in_threadpool(begin_session, request, user, "sso")
    return see_other(safe_next(entry.get("next")))


async def _refuse(request: Request, kind: str, error: SignInError, email: str = "") -> Response:
    log.warning("single sign-on refused (%s): %s", kind, error)
    get_metrics(request).signins.labels("sso", kind).inc()
    return await run_in_threadpool(problem_page, request, kind, email)
