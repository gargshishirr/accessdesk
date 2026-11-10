"""Rendering helpers shared by every page: the signed-in user, flash messages and text formatting."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jinja2
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from accessdesk import policy
from accessdesk.models import (
    APPROVER_LABELS,
    REASON_TEXT,
    ROLE_DESCRIPTIONS,
    ApproverKind,
    Resource,
    Role,
    Sensitivity,
    User,
)
from accessdesk.service import AccessService
from accessdesk.web.metrics import Metrics
from accessdesk.web.security import csrf_token

WEB_DIR = Path(__file__).parent

STATUS_LABELS = {
    "pending": "Waiting for approval",
    "approved": "Approved",
    "denied": "Denied",
    "cancelled": "Cancelled",
}

_APPROVER_PHRASES = {
    ApproverKind.MANAGER: "your manager",
    ApproverKind.OWNER: "the owner",
    ApproverKind.SECURITY: "security",
}


class SignInRequired(Exception):
    def __init__(self, next_url: str) -> None:
        super().__init__(next_url)
        self.next_url = next_url


def get_service(request: Request) -> AccessService:
    service: AccessService = request.app.state.service
    return service


def get_metrics(request: Request) -> Metrics:
    metrics: Metrics = request.app.state.metrics
    return metrics


def current_user(request: Request) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    user = get_service(request).user(user_id)
    if user is None:
        request.session.pop("user_id", None)
    return user


def require_user(request: Request) -> User:
    user = current_user(request)
    if user is None:
        # After signing in, come back to the page that was asked for. A form post cannot be replayed.
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        raise SignInRequired(target if request.method == "GET" else "/")
    return user


def flash(request: Request, kind: str, text: str) -> None:
    request.session["flash"] = {"kind": kind, "text": text}


# ----------------------------------------------------------------------------- formatting


def when(ts: int | None) -> str:
    if ts is None:
        return ""
    moment = datetime.fromtimestamp(ts, tz=UTC)
    return f"{moment.day} {moment:%b %Y, %H:%M} UTC"


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def plural(count: int, word: str, many: str | None = None) -> str:
    return f"{count} {word if count == 1 else (many or word + 's')}"


def duration(hours: int) -> str:
    text = plural(hours, "hour")
    if hours >= 48 and hours % 24 == 0:
        text += f" ({hours // 24} days)"
    return text


def remaining(expires_at: int, now: int) -> str:
    seconds = max(0, expires_at - now)
    days, rest = divmod(seconds, 86_400)
    hours, rest = divmod(rest, 3_600)
    minutes = rest // 60
    parts = [plural(days, "day")] if days else []
    if hours:
        parts.append(plural(hours, "hour"))
    if minutes and not days:
        parts.append(plural(minutes, "minute"))
    return " ".join(parts[:2]) + " left" if parts else "less than a minute left"


def join_words(words: list[str]) -> str:
    if len(words) <= 1:
        return "".join(words)
    return ", ".join(words[:-1]) + " and " + words[-1]


def route_text(resource: Resource, user: User) -> str:
    """Plain-language summary of who approves requests for this resource."""
    kinds = list(dict.fromkeys(policy.BASE_APPROVALS[resource.sensitivity]))
    people = join_words([_APPROVER_PHRASES[k] for k in kinds])
    text = people[0].upper() + people[1:]
    if (
        resource.sensitivity is Sensitivity.LOW
        and Role.VIEWER in resource.roles
        and user.team in resource.auto_approve_teams
    ):
        text = f"Viewer access is instant for your team. Other access: {people}"
    if Role.ADMIN in resource.roles and ApproverKind.SECURITY not in kinds:
        text += ". Admin access also needs security"
    return text


def _environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(WEB_DIR / "templates"),
        autoescape=True,
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(when=when, iso=iso, duration=duration)
    env.globals.update(
        APPROVER_LABELS=APPROVER_LABELS,
        REASON_TEXT=REASON_TEXT,
        ROLE_DESCRIPTIONS=ROLE_DESCRIPTIONS,
        STATUS_LABELS=STATUS_LABELS,
        remaining=remaining,
        route_text=route_text,
        plural=plural,
    )
    return env


templates = Jinja2Templates(env=_environment())


def render(
    request: Request,
    template: str,
    title: str,
    *,
    status_code: int = 200,
    user: User | None = None,
    **context: Any,
) -> HTMLResponse:
    service = get_service(request)
    user = user or current_user(request)
    values: dict[str, Any] = {
        "title": title,
        "user": user,
        "errors": {},
        "error_anchors": {},
        "form": {},
        "active_nav": "",
        "flash": request.session.pop("flash", None),
        "csrf_token": csrf_token(request),
        "now": service.clock.now(),
        "waiting": len(service.pending_for(user.id)) if user else 0,
        "names": {u.id: u.name for u in service.users()},
        "can_review": user is not None
        and (user.is_security or any(r.owner_id == user.id for r in service.resources())),
    }
    values.update(context)
    return templates.TemplateResponse(request, template, values, status_code=status_code)
