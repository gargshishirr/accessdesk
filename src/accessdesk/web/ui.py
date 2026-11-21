"""Rendering helpers shared by every page: the signed-in user, flash messages and text formatting."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jinja2
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from accessdesk import audit, policy
from accessdesk.models import (
    APPROVER_LABELS,
    REASON_TEXT,
    ROLE_DESCRIPTIONS,
    ApproverKind,
    Decision,
    GrantEnd,
    Outcome,
    Reason,
    RequestStatus,
    Resource,
    Role,
    Sensitivity,
    User,
)
from accessdesk.service import AccessService, GrantView, RequestPage, RequestView
from accessdesk.web import demo
from accessdesk.web.metrics import Metrics
from accessdesk.web.security import csrf_token

WEB_DIR = Path(__file__).parent

STATUS_LABELS = {
    "pending": "Waiting for approval",
    "approved": "Approved",
    "denied": "Denied",
    "cancelled": "Cancelled",
}

GRANT_LABELS = {
    "active": "Active",
    "expiring": "Expiring soon",
    "expired": "Expired",
    "released": "Given back",
    "revoked": "Revoked",
}

_APPROVER_PHRASES = {
    ApproverKind.MANAGER: "your manager",
    ApproverKind.OWNER: "the owner",
    ApproverKind.SECURITY: "security",
}

_KIND_PHRASES = {
    ApproverKind.MANAGER: "the requester's manager",
    ApproverKind.OWNER: "the resource owner",
    ApproverKind.SECURITY: "the security team",
}

# The policy's reasons, said to the person asking (the stored REASON_TEXT is written about "the requester").
_YOU_TEXT = {
    Reason.ALREADY_HAS_ACCESS: "You already have this access or higher.",
    Reason.DUPLICATE_PENDING_REQUEST: "You already have a request waiting for this access.",
    Reason.SOD_CONFLICT: "It would break a separation-of-duties rule with access you hold.",
    Reason.LOW_RISK_AUTO_APPROVED: "Low-risk, read-only access for your team, so it is approved instantly.",
    Reason.NO_MANAGER_ESCALATED: "You have no manager on file, so security approves instead.",
    Reason.REQUESTER_IS_OWNER_ESCALATED: "You own this resource, so security approves instead of the owner.",
    Reason.MANAGER_IS_OWNER_ESCALATED: (
        "Your manager also owns this resource, so security approves the owner step to keep two "
        "independent approvers."
    ),
}
_REQUIRED = {
    Reason.MANAGER_APPROVAL_REQUIRED,
    Reason.OWNER_APPROVAL_REQUIRED,
    Reason.SECURITY_APPROVAL_REQUIRED,
}
_FINAL_CHECK = {Reason.ALREADY_HAS_ACCESS, Reason.SOD_CONFLICT}
HOUR_PRESETS = (1, 4, 8, 24, 72, 168, 720)


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
    """The signed-in person: a live session in the database for someone still in the directory."""
    if hasattr(request.state, "user"):
        cached: User | None = request.state.user
        return cached
    session_id = request.session.get("sid")
    method = "sso" if request.app.state.settings.sso else "demo"
    user = get_service(request).session_user(session_id, method) if isinstance(session_id, str) else None
    if user is None:
        request.session.pop("sid", None)  # signed out elsewhere, expired, or removed from the directory
    request.state.user = user
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


def join_or(words: list[str]) -> str:
    if len(words) <= 1:
        return "".join(words)
    return ", ".join(words[:-1]) + " or " + words[-1]


def ago(ts: int, now: int) -> str:
    seconds = now - ts
    if seconds < 60:
        return "just now"
    if seconds < 3_600:
        return plural(seconds // 60, "minute") + " ago"
    if seconds < 86_400:
        return plural(seconds // 3_600, "hour") + " ago"
    return plural(seconds // 86_400, "day") + " ago"


def short_duration(hours: int) -> str:
    if hours >= 24 and hours % 24 == 0:
        return plural(hours // 24, "day")
    return plural(hours, "hour")


def hour_presets(max_hours: int) -> list[int]:
    """A few common lengths up to the resource's limit, always including the limit itself."""
    choices = [h for h in HOUR_PRESETS if h < max_hours] + [max_hours]
    return choices if len(choices) <= 5 else choices[:2] + choices[-3:]


def initials(name: str) -> str:
    parts = name.split()
    return "".join(p[0] for p in parts[:1] + parts[1:][-1:]).upper()


def first_name(name: str) -> str:
    return name.split()[0] if name.strip() else name


def grant_state(grant: GrantView, now: int) -> str:
    """active, expiring (in its last quarter, at most a day and at least half an hour), expired, released
    or revoked."""
    if grant.active_at(now):
        total = max(1, grant.expires_at - grant.granted_at)
        soon = min(86_400, max(1_800, total // 4))
        return "expiring" if grant.expires_at - now <= soon else "active"
    if grant.end_reason is GrantEnd.RELEASED:
        return "released"
    if grant.end_reason is GrantEnd.REVOKED:
        return "revoked"
    return "expired"


def time_left_percent(grant: GrantView, now: int) -> int:
    """Share of the grant still to run, rounded to 5% so CSS can draw it without inline styles."""
    total = max(1, grant.expires_at - grant.granted_at)
    left = min(max(0, grant.expires_at - now), total)
    return round(left * 20 / total) * 5


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


def _person(kind: ApproverKind, requester: User, resource: Resource, users: Mapping[str, User]) -> str:
    """Who fills an approval step, by name where there is exactly one person who can."""
    if kind is ApproverKind.MANAGER:
        manager = users.get(requester.manager_id or "")
        return manager.name if manager else "the requester's manager"
    if kind is ApproverKind.OWNER:
        owner = users.get(resource.owner_id)
        return owner.name if owner else "the resource owner"
    team = [u.name for u in users.values() if u.active and u.is_security and u.id != requester.id]
    return f"someone from security ({join_or(team)})" if team else "someone from security"


def approver_lines(
    kinds: Sequence[ApproverKind],
    requester: User,
    resource: Resource,
    users: Mapping[str, User],
    *,
    you: bool,
) -> list[str]:
    """One phrase per approval step, like "Bob Singh (your manager)". Phrases about security start in
    lower case so they read well inside a sentence."""
    lines: list[str] = []
    for n, kind in enumerate(kinds):
        who = _person(kind, requester, resource, users)
        if kind is ApproverKind.MANAGER:
            role = "your manager" if you else f"{first_name(requester.name)}'s manager"
            lines.append(f"{who} ({role})")
        elif kind is ApproverKind.OWNER:
            lines.append(f"{who} (owner of {resource.name})")
        elif ApproverKind.SECURITY in kinds[:n]:
            lines.append("a second, different person from security")
        else:
            lines.append(who)
    return lines


def sentence_start(text: str) -> str:
    return text[:1].upper() + text[1:]


def policy_basis(resource: Resource) -> str:
    """Why a resource needs the approvals it does, straight from the policy's routing table."""
    kinds = policy.BASE_APPROVALS[resource.sensitivity]
    count = {1: "one approval", 2: "two independent approvals", 3: "three independent approvals"}[len(kinds)]
    who = join_words([_KIND_PHRASES[k] for k in kinds])
    return f"{resource.name} is {resource.sensitivity.value} sensitivity, so the policy needs {count}: {who}."


@dataclass(frozen=True, slots=True)
class RouteOption:
    """What the policy would do for one or more roles, in words."""

    roles: tuple[Role, ...]
    outcome: Outcome
    approvers: tuple[str, ...]
    short: str
    notes: tuple[str, ...]


def route_options(
    preview: Mapping[Role, Decision], requester: User, resource: Resource, users: Mapping[str, User]
) -> list[RouteOption]:
    """Group the roles whose policy decision is the same, and say who would approve each group."""
    grouped: dict[Decision, list[Role]] = {}
    for role, decision in preview.items():
        grouped.setdefault(decision, []).append(role)
    options: list[RouteOption] = []
    for decision, roles in grouped.items():
        notes = tuple(
            _YOU_TEXT.get(reason, REASON_TEXT[reason])
            for reason in decision.reasons
            if reason not in _REQUIRED
        )
        if decision.outcome is Outcome.DENY and decision.detail:
            notes += (f"Rule: {decision.detail}",)
        approvers: tuple[str, ...] = ()
        if decision.outcome is Outcome.AUTO_APPROVE:
            short = "Approved instantly"
        elif decision.outcome is Outcome.DENY:
            short = "Not available to you right now"
        else:
            lines = approver_lines(decision.approvals, requester, resource, users, you=True)
            approvers = tuple(sentence_start(line) for line in lines)
            names = [
                line.split(" (")[0] if not line.startswith(("someone", "a second")) else "security"
                for line in lines
            ]
            short = "Needs " + join_words(list(dict.fromkeys(names)))
        options.append(RouteOption(tuple(roles), decision.outcome, approvers, short, notes))
    return options


def route_for(role: Role, options: Sequence[RouteOption]) -> RouteOption | None:
    return next((o for o in options if role in o.roles), None)


def slot_progress(r: RequestView) -> list[tuple[ApproverKind, str]]:
    """Each approval step of a request and who approved it ("" while it is open)."""
    unused = [a for a in r.approvals if a.verdict == "approve"]
    progress: list[tuple[ApproverKind, str]] = []
    for kind in r.required:
        match = next((a for a in unused if a.kind is kind), None)
        if match is not None:
            unused.remove(match)
        progress.append((kind, match.approver.name if match else ""))
    return progress


@dataclass(frozen=True, slots=True)
class Moment:
    """One step on a request's timeline."""

    state: str  # done, current, upcoming, stopped or skipped
    title: str
    text: str
    when: int | None = None
    quote: str = ""


_STATE_WORDS = {
    "done": "Done",
    "current": "In progress",
    "upcoming": "Not yet",
    "stopped": "Stopped",
    "skipped": "Skipped",
}


def timeline(page: RequestPage, users: Mapping[str, User], now: int) -> list[Moment]:
    r = page.request
    who = r.requester.name
    moments = [
        Moment(
            "done",
            "Requested",
            f"{who} asked for {r.role.value} access for {duration(r.hours)}.",
            r.created_at,
            r.justification,
        )
    ]
    if not r.required:
        if r.status is RequestStatus.APPROVED:
            moments.append(
                Moment("done", "Approved instantly", REASON_TEXT[Reason.LOW_RISK_AUTO_APPROVED], r.decided_at)
            )
        else:
            reason = next((x for x in r.reasons), Reason.DENIED_BY_APPROVER)
            moments.append(Moment("stopped", "Not allowed by the policy", REASON_TEXT[reason], r.decided_at))
            return moments
    pending = r.status is RequestStatus.PENDING
    for n, slot in enumerate(page.slots):
        label = APPROVER_LABELS[slot.kind]
        if slot.approval is not None:
            a = slot.approval
            verdict = "Approved" if a.verdict == "approve" else "Denied"
            moments.append(
                Moment(
                    "done" if a.verdict == "approve" else "stopped",
                    f"{label}: {verdict.lower()}",
                    f"{verdict} by {a.approver.name}.",
                    a.created_at,
                    a.comment,
                )
            )
        elif pending:
            earlier = [s.kind for s in page.slots[:n]]
            person = approver_lines([*earlier, slot.kind], r.requester, r.resource, users, you=False)[-1]
            moments.append(Moment("current", f"{label}: waiting", f"Waiting for {person}."))
        else:
            moments.append(Moment("skipped", f"{label}: not needed", "The request ended before this step."))
    final = r.reasons[-1] if r.reasons else None
    if r.status is RequestStatus.DENIED and final in _FINAL_CHECK and r.required:
        moments.append(
            Moment("stopped", "Stopped by the final safety check", REASON_TEXT[final], r.decided_at)
        )
    if r.status is RequestStatus.CANCELLED:
        moments.append(
            Moment("stopped", "Cancelled", "The request was cancelled before it was decided.", r.decided_at)
        )
    g = r.grant
    if g is not None:
        moments.append(
            Moment(
                "done",
                "Access granted",
                f"{r.role.value.capitalize()} access until {when(g.expires_at)}.",
                g.granted_at,
            )
        )
        state = grant_state(g, now)
        if state in ("active", "expiring"):
            moments.append(
                Moment(
                    "current",
                    "Ends on its own",
                    f"{remaining(g.expires_at, now).capitalize()}. Ends at {when(g.expires_at)}.",
                )
            )
        else:
            remover = users.get(g.ended_by or "")
            ending = {
                "expired": "Expired on schedule.",
                "released": f"{who} gave it back early.",
                "revoked": f"Removed by {remover.name if remover else g.ended_by}.",
            }[state]
            title = {"expired": "Expired", "released": "Given back early", "revoked": "Revoked"}[state]
            moments.append(Moment("done", title, ending, g.ended_at or g.expires_at, g.end_note))
    elif pending:
        moments.append(Moment("upcoming", "Access starts", "As soon as every approval is in."))
        moments.append(
            Moment("upcoming", "Ends on its own", f"{duration(r.hours).capitalize()} after it starts.")
        )
    return moments


def waiting_for(page: RequestPage, users: Mapping[str, User], viewer: User | None = None) -> list[str]:
    """Who the open approval steps are waiting for, like "Frank Moreau (owner of Payments Ledger)"."""
    r = page.request
    kinds = [s.kind for s in page.slots]
    names = approver_lines(kinds, r.requester, r.resource, users, you=False)
    if viewer is not None:
        names = [n.replace(f"{viewer.name} (", "you (", 1) if n.startswith(viewer.name) else n for n in names]
    return [name for name, s in zip(names, page.slots, strict=True) if s.approval is None]


def explain(
    page: RequestPage, users: Mapping[str, User], now: int, viewer: User | None = None
) -> tuple[str, list[str]]:
    """A plain-English headline for where a request stands, and the policy's reasons for its route."""
    r = page.request
    first = first_name(r.requester.name)
    reasons = [
        REASON_TEXT[x] + (f" Rule: {r.detail}" if x is Reason.SOD_CONFLICT and r.detail else "")
        for x in r.reasons
        if x not in _REQUIRED
    ]
    if r.required:
        reasons.insert(0, policy_basis(r.resource))
        reasons.append(
            "Every approval must come from a different person, and nobody approves their own request."
        )
    if r.status is RequestStatus.PENDING:
        waiting = waiting_for(page, users, viewer)
        done = len(page.slots) - len(waiting)
        headline = f"Waiting for {join_words(waiting)}. {done} of {plural(len(page.slots), 'approval')} done."
    elif r.status is RequestStatus.APPROVED and r.grant is not None:
        g = r.grant
        if g.active_at(now):
            until = when(g.expires_at)
            headline = f"Approved. {first} has {r.role.value} access until {until}, then it ends on its own."
        else:
            headline = f"Approved. That access has ended: {GRANT_LABELS[grant_state(g, now)].lower()}."
    elif r.status is RequestStatus.APPROVED:
        headline = "Approved."
    elif r.status is RequestStatus.CANCELLED:
        headline = f"Cancelled by {first} before it was decided."
    else:
        denial = next((s.approval for s in page.slots if s.approval and s.approval.verdict == "deny"), None)
        if denial is not None:
            headline = f"Denied by {denial.approver.name}."
        elif r.required:
            headline = "Stopped by the final safety check when the last approval came in."
        else:
            headline = "Not allowed by the policy, so nobody was asked to approve it."
    return headline, reasons


def describe_event(
    event: audit.AuditEvent,
    names: Mapping[str, str],
    resources: Mapping[str, Resource],
    request: RequestView | None = None,
    viewer: str = "",
) -> str:
    """An audit entry in plain words."""
    d = event.details

    def person(user_id: str) -> str:
        if user_id == viewer:
            return "You"
        if user_id == "system":
            return "AccessDesk"
        if user_id == "policy":
            return "The policy"
        return names.get(user_id, user_id)

    def thing(resource_id: object) -> str:
        found = resources.get(str(resource_id))
        return found.name if found else str(resource_id)

    actor = person(event.actor)
    subject = event.subject.replace("request:", "request #").replace("grant:", "access grant #")
    about = subject
    if request is not None:
        whose = "your" if request.requester.id == viewer else f"{request.requester.name}'s"
        about = f"{whose} {request.role.value} access to {request.resource.name}"
    holder = str(d.get("user", ""))
    whose = "your" if holder == viewer else f"{person(holder)}'s"
    access = f"{d.get('role', '')} access to {thing(d.get('resource'))}"
    text = {
        "request.submitted": f"{actor} asked for {access}",
        "request.approved": f"{actor} approved {about}",
        "request.denied": f"{actor} denied {about}",
        "request.cancelled": f"{actor} cancelled {about}",
        "request.rerouted": f"{actor} sent a step of {subject} to security",
        "grant.created": f"{whose} {access} started",
        "grant.expired": f"{whose} {access} expired",
        "grant.released": f"{actor} gave back {access}",
        "grant.revoked": f"{actor} removed {whose} {access}",
    }.get(event.action, f"{actor}: {event.action.replace('.', ' ').replace('_', ' ')} ({subject})")
    reason = str(d.get("reason", ""))
    slot = str(d.get("slot", ""))
    if event.action in ("request.approved", "request.denied") and slot in {k.value for k in ApproverKind}:
        if request is not None and slot == ApproverKind.MANAGER.value:
            boss = "your" if request.requester.id == viewer else f"{first_name(request.requester.name)}'s"
            text += f" as {boss} manager"
        else:
            text += f" as {APPROVER_LABELS[ApproverKind(slot)].lower()}"
    if event.action == "request.denied" and reason in {r.value for r in Reason}:
        text += f": {REASON_TEXT[Reason(reason)]}"
    elif event.action == "request.submitted" and d.get("outcome") == Outcome.DENY.value:
        text += " (not allowed by the policy)"
    elif event.action == "request.submitted" and d.get("outcome") == Outcome.AUTO_APPROVE.value:
        text += " (approved instantly)"
    text = text[0].upper() + text[1:]
    return text if text.endswith(".") else text + "."


def _environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(WEB_DIR / "templates"),
        autoescape=True,
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(
        when=when,
        iso=iso,
        duration=duration,
        short_duration=short_duration,
        initials=initials,
        first_name=first_name,
    )
    env.globals.update(
        APPROVER_LABELS=APPROVER_LABELS,
        REASON_TEXT=REASON_TEXT,
        ROLE_DESCRIPTIONS=ROLE_DESCRIPTIONS,
        STATUS_LABELS=STATUS_LABELS,
        GRANT_LABELS=GRANT_LABELS,
        STATE_WORDS=_STATE_WORDS,
        remaining=remaining,
        route_text=route_text,
        route_for=route_for,
        plural=plural,
        ago=ago,
        grant_state=grant_state,
        time_left_percent=time_left_percent,
        describe_event=describe_event,
        policy_basis=policy_basis,
        slot_progress=slot_progress,
    )
    return env


templates = Jinja2Templates(env=_environment())


# Every key base.html reads, so error pages that skip ``render`` still have them.
BASE_CONTEXT: dict[str, Any] = {
    "user": None,
    "demo_mode": False,
    "errors": {},
    "error_anchors": {},
    "form": {},
    "active_nav": "",
    "flash": None,
    "csrf_token": "",
    "here": "",
    "now": 0,
    "waiting": 0,
    "can_review": False,
    "names": {},
    "personas": [],
    "persona_label": "",
    "tour": None,
    "show_tour_strip": True,
}


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
    demo_mode = not request.app.state.settings.sso
    users = service.users()
    resources = service.resources(active_only=True)
    cast = demo.personas(users, resources) if demo_mode and user else []
    values: dict[str, Any] = {
        **BASE_CONTEXT,
        "title": title,
        "user": user,
        "demo_mode": demo_mode,
        "flash": request.session.pop("flash", None),
        "csrf_token": csrf_token(request),
        "here": request.url.path + (f"?{request.url.query}" if request.url.query else ""),
        "now": service.clock.now(),
        "waiting": len(service.pending_for(user.id)) if user else 0,
        "names": {u.id: u.name for u in users},
        "can_review": user is not None
        and (user.is_security or any(r.owner_id == user.id for r in resources)),
        "personas": cast,
        "persona_label": demo.persona_label(user, cast) if user else "",
        "tour": demo.tour(service, users, request.session) if demo_mode and user else None,
    }
    values.update(context)
    return templates.TemplateResponse(request, template, values, status_code=status_code)
