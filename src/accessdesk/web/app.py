"""Application factory: wires the service, middleware, error pages, health and metrics together."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Mapping
from urllib.parse import quote

from fastapi import Depends, FastAPI, Request
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from accessdesk import __version__
from accessdesk.clock import Clock, SystemClock
from accessdesk.config import ConfigError, Settings
from accessdesk.db import Database
from accessdesk.oidc import OidcClient
from accessdesk.service import AccessError, AccessService
from accessdesk.web import api, auth, pages
from accessdesk.web.metrics import Metrics, MetricsMiddleware
from accessdesk.web.ratelimit import Limits
from accessdesk.web.security import ApiKeys, CsrfFailed, SecurityHeaders, redact_access_log, require_api_key
from accessdesk.web.ui import WEB_DIR, SignInRequired, render, templates

log = logging.getLogger("accessdesk")

ERROR_HEADINGS = {
    400: "There is a problem with that request",
    403: "You do not have permission to do that",
    404: "Page not found",
    405: "That action is not available here",
    409: "That changed while you were looking at it",
    422: "There is a problem with that request",
    429: "Too many requests",
}
# Set in the database the first time it runs with single sign-on. From then on it refuses demo mode, so
# losing the single sign-on settings can never open a real database to the demo person picker.
SSO_LATCH = "sign_in"


def _is_machine_path(request: Request) -> bool:
    path = request.url.path
    return path.startswith("/api/") or path in {"/healthz", "/metrics"}


def _error_page(
    request: Request, status: int, message: str, headers: Mapping[str, str] | None = None
) -> Response:
    heading = ERROR_HEADINGS.get(status, "Sorry, something went wrong")
    response = render(request, "error.html", heading, status_code=status, heading=heading, message=message)
    response.headers.update(headers or {})
    return response


async def sweep_expired(service: AccessService, metrics: Metrics, every: float) -> None:
    """End grants as they expire, and forget expired sessions. Checks never depend on this: expired grants
    already fail closed, and expired sessions are already refused."""
    while True:
        try:
            ended = await asyncio.to_thread(service.expire_due)
            if ended:
                metrics.expired.inc(ended)
                log.info("expired %d grant(s)", ended)
            await asyncio.to_thread(service.purge_sessions)
        except Exception:
            metrics.sweep_errors.inc()
            log.exception("expiry sweep failed")
        await asyncio.sleep(every)


def create_app(
    settings: Settings | None = None,
    *,
    clock: Clock | None = None,
    service: AccessService | None = None,
    oidc: OidcClient | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    service = service or AccessService(Database(settings.db_path), clock or SystemClock())
    if settings.oidc is not None:
        service.set_meta(SSO_LATCH, "sso")
        service.end_sessions_except("sso")  # nobody stays signed in from the demo person picker
        oidc = oidc or OidcClient(settings.oidc, settings.redirect_uri)
    elif service.meta(SSO_LATCH) == "sso":
        service.db.close()
        raise ConfigError(
            "This database has been used with single sign-on, so AccessDesk will not open it in demo mode "
            "(anyone could sign in as anyone). Set the ACCESSDESK_OIDC_* settings again."
        )
    metrics = Metrics()
    redact_access_log()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        sweeper = None
        if settings.sweep_seconds > 0:
            sweeper = asyncio.create_task(sweep_expired(service, metrics, settings.sweep_seconds))
        try:
            yield
        finally:
            if sweeper is not None:
                sweeper.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await sweeper
            service.db.close()

    app = FastAPI(
        title="AccessDesk",
        version=__version__,
        summary="Just-in-time access requests with policy-routed approvals and a tamper-evident audit log.",
        # The interactive docs load scripts from a CDN onto this site's origin. That is fine for the demo,
        # but a real deployment should not trust a third party with its signed-in pages.
        docs_url=None if settings.sso else "/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.service = service
    app.state.metrics = metrics
    app.state.oidc = oidc
    app.state.api_keys = ApiKeys(settings.api_keys)
    app.state.limits = Limits(
        signin_per_minute=settings.signin_rate_limit, api_per_minute=settings.api_rate_limit
    )

    app.include_router(auth.router)
    # Exactly one way to sign in. With single sign-on, the person picker's form handler does not exist.
    app.include_router(auth.sso_router if settings.sso else auth.demo_router)
    app.include_router(pages.router)
    app.include_router(api.router)
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    # add_middleware wraps the app, so the last one added runs first.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        # The __Host- prefix makes browsers refuse the cookie unless it is Secure, for this host only and
        # for the whole site, so a neighbouring subdomain cannot plant a session.
        session_cookie="__Host-accessdesk" if settings.secure_cookies else "accessdesk_session",
        max_age=settings.session_hours * 3600,
        same_site="lax",
        https_only=settings.secure_cookies,
    )
    app.add_middleware(SecurityHeaders, hsts=settings.secure_cookies)
    app.add_middleware(MetricsMiddleware, metrics=metrics)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> Response:
        try:
            with service.db.connection() as conn:
                conn.execute("SELECT 1").fetchone()
        except Exception:
            log.exception("health check failed")
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok", "version": __version__})

    @app.get("/metrics", include_in_schema=False, dependencies=[Depends(require_api_key)])
    def prometheus_metrics() -> Response:
        return PlainTextResponse(metrics.exposition(), media_type=CONTENT_TYPE_LATEST)

    @app.exception_handler(SignInRequired)
    def on_sign_in_required(request: Request, exc: SignInRequired) -> Response:
        return RedirectResponse(f"/signin?next={quote(exc.next_url, safe='/')}", status_code=303)

    @app.exception_handler(CsrfFailed)
    def on_csrf_failed(request: Request, exc: CsrfFailed) -> Response:
        return render(
            request,
            "error.html",
            "This page has expired",
            status_code=403,
            heading="This page has expired",
            message=(
                "For your security, forms only work for a limited time. "
                "Go back, refresh the page and try again."
            ),
        )

    @app.exception_handler(AccessError)
    def on_access_error(request: Request, exc: AccessError) -> Response:
        if _is_machine_path(request):
            return JSONResponse({"detail": exc.message}, status_code=exc.status)
        return _error_page(request, exc.status, exc.message)

    @app.exception_handler(StarletteHTTPException)
    async def on_http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if _is_machine_path(request):
            return await http_exception_handler(request, exc)
        message = (
            "Check the web address, or go back to My access." if exc.status_code == 404 else str(exc.detail)
        )
        return await asyncio.to_thread(_error_page, request, exc.status_code, message, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def on_validation_error(request: Request, exc: RequestValidationError) -> Response:
        if _is_machine_path(request):
            return await request_validation_exception_handler(request, exc)
        # Only malformed web addresses (like /requests/abc) reach here; forms validate their own fields.
        return await asyncio.to_thread(
            _error_page, request, 404, "Check the web address, or go back to My access."
        )

    @app.exception_handler(Exception)
    def on_unexpected_error(request: Request, exc: Exception) -> Response:
        log.exception("unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
        if _is_machine_path(request):
            return JSONResponse({"detail": "Internal server error."}, status_code=500)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "title": "Sorry, there is a problem with the service",
                "heading": "Sorry, there is a problem with the service",
                "message": (
                    "Try again later. Each change is saved completely or not at all, "
                    "so nothing was half-saved."
                ),
                "user": None,
                "demo_mode": False,
                "errors": {},
                "error_anchors": {},
                "form": {},
                "active_nav": "",
                "flash": None,
                "csrf_token": "",
                "now": 0,
                "waiting": 0,
                "can_review": False,
                "names": {},
            },
            status_code=500,
        )

    return app
