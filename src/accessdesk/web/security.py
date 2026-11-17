"""Web security plumbing: response headers, CSRF tokens, safe redirects, API keys and log redaction."""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import re
import secrets
from collections.abc import Sequence
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Form, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from accessdesk.web.ratelimit import Limits, client_address

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


class ApiKeys:
    """The keys other services use. Any key in the list works, which makes rotation painless:
    add the new key, move the callers over, then remove the old key.

    Keys are compared as SHA-256 digests with ``hmac.compare_digest``, and every key is always compared,
    so the time taken says nothing about a key's content, its length or which key matched.
    """

    MAX_LENGTH = 512

    def __init__(self, keys: Sequence[str]) -> None:
        self._digests = tuple(self._digest(key) for key in keys)

    @staticmethod
    def _digest(key: str) -> bytes:
        return hashlib.sha256(key.encode()).digest()

    def __len__(self) -> int:
        return len(self._digests)

    def match(self, presented: str | None) -> int | None:
        """The position of the matching key (for rate limits and logs, never the key itself), or None."""
        if not presented or len(presented) > self.MAX_LENGTH:
            return None
        digest = self._digest(presented)
        found: int | None = None
        for position, expected in enumerate(self._digests):
            if hmac.compare_digest(digest, expected) and found is None:
                found = position
        return found


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="A key for calling services.")


def presented_key(request: Request, header_value: str | None) -> str | None:
    """The key from ``X-API-Key``, or from ``Authorization: Bearer`` (which Prometheus sends)."""
    if header_value:
        return header_value
    scheme, _, credentials = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and credentials.strip():
        return credentials.strip()
    return None


def too_many_requests(
    wait_seconds: float, detail: str = "Too many requests. Wait a minute."
) -> HTTPException:
    return HTTPException(
        status_code=429, detail=detail, headers={"Retry-After": str(max(1, math.ceil(wait_seconds)))}
    )


async def require_api_key(
    request: Request, key: Annotated[str | None, Security(api_key_header)] = None
) -> None:
    # async: pure in-memory checks, so they run on the event loop instead of costing a thread hop.
    state = request.app.state
    limits: Limits = state.limits
    position = state.api_keys.match(presented_key(request, key))
    if position is None:
        # A valid key always works, so nobody can lock a real service out by sending wrong keys in its
        # name. Keys are long and random, so guessing is hopeless anyway; this just turns noisy scanners away.
        wait = limits.api_key_failures.hit(client_address(request))
        if wait:
            state.metrics.rate_limited.labels("api_key_failures").inc()
            raise too_many_requests(wait)
        raise HTTPException(
            status_code=401, detail="Missing or invalid API key.", headers={"WWW-Authenticate": "ApiKey"}
        )
    wait = limits.api_calls.hit(f"key-{position}")
    if wait:
        state.metrics.rate_limited.labels("api").inc()
        raise too_many_requests(wait)


# ----------------------------------------------------------------------------- logs

_QUERY_IN_PATH = re.compile(r"\?.*$", re.DOTALL)
# Paths whose query strings carry one-time sign-in secrets (the authorization code and state).
SECRET_QUERY_PATHS = ("/auth/callback",)


class RedactSignInSecrets(logging.Filter):
    """Keep sign-in codes out of uvicorn's access log: the callback is logged without its query."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            path = args[2]
            if path.startswith(SECRET_QUERY_PATHS) and "?" in path:
                record.args = (*args[:2], _QUERY_IN_PATH.sub("?[redacted]", path), *args[3:])
        return True


def redact_access_log() -> None:
    """Install the filter once on uvicorn's access logger."""
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, RedactSignInSecrets) for f in access.filters):
        access.addFilter(RedactSignInSecrets())
