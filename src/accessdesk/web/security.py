"""Web security plumbing: response headers, CSRF tokens, safe redirects and API keys."""

from __future__ import annotations

import secrets
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Form, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# No scripts at all: the UI is plain HTML forms and links.
CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)
BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}
# FastAPI's interactive API docs load their own scripts, so they get the default headers only.
DOCS_PREFIX = "/api/docs"


class SecurityHeaders:
    def __init__(self, app: ASGIApp, hsts: bool = False) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in BASE_HEADERS.items():
                    headers.setdefault(name, value)
                if not path.startswith(DOCS_PREFIX):
                    headers.setdefault("Content-Security-Policy", CSP)
                if not path.startswith("/static/"):
                    headers.setdefault("Cache-Control", "no-store")
                if self.hsts:
                    headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            await send(message)

        await self.app(scope, receive, send_with_headers)


class CsrfFailed(Exception):
    """The form did not carry this session's CSRF token."""


def csrf_token(request: Request) -> str:
    token: str | None = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


async def csrf_protect(request: Request, token: Annotated[str, Form(alias="csrf_token")] = "") -> None:
    expected: str = request.session.get("csrf", "")
    if not expected or not secrets.compare_digest(expected.encode(), token.encode()):
        raise CsrfFailed


def safe_next(value: str | None) -> str:
    """Only allow redirects to a path on this site, never to another host."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/"
    return value


api_key_header = APIKeyHeader(
    name="X-API-Key", auto_error=False, description="Shared key for calling services."
)


async def require_api_key(
    request: Request, key: Annotated[str | None, Security(api_key_header)] = None
) -> None:
    # async: a pure in-memory check, so it runs on the event loop instead of costing a thread hop.
    expected: str = request.app.state.settings.api_key
    if key is None or not secrets.compare_digest(key.encode(), expected.encode()):
        raise HTTPException(
            status_code=401, detail="Missing or invalid API key.", headers={"WWW-Authenticate": "ApiKey"}
        )
