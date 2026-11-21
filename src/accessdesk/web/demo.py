"""Demo mode only: one-click personas and the guided "full flow in 60 seconds" checklist.

Nothing here is used when single sign-on is on. Personas are people from the demo directory, so they only
appear if those people exist and are active. The checklist follows real data: it looks at the newest
high-risk request the requester persona made after the demo data was seeded.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from typing import Any

from accessdesk import policy
from accessdesk.models import ApproverKind, RequestStatus, Resource, Sensitivity, User
from accessdesk.seed import SEEDED_THROUGH
from accessdesk.service import AccessService, RequestPage

REQUESTER, MANAGER, OWNER, SECURITY = "requester", "manager", "owner", "security"
# (user id, kind, label). The ids are people in the demo directory (seed.py).
PERSONA_SPECS = (
    ("alice", REQUESTER, "Requester"),
    ("bob", MANAGER, "Manager"),
    ("frank", OWNER, "Resource owner"),
    ("dan", SECURITY, "Security reviewer"),
)
HIGH_RISK = (Sensitivity.HIGH, Sensitivity.CRITICAL)
SUGGESTED_RESOURCE = "prod-db"
# The session remembers the guided request whose live access the requester has looked at, and the one
# security checked the audit log for. They are request numbers, never credentials, and survive switching.
TOUR_SEEN_KEY = "tour_seen"
TOUR_AUDIT_KEY = "tour_audit"
TOUR_KEYS = (TOUR_SEEN_KEY, TOUR_AUDIT_KEY)


@dataclass(frozen=True, slots=True)
class Persona:
    user: User
    label: str
    summary: str


@dataclass(frozen=True, slots=True)
class TourStep:
    title: str
    detail: str
    person: User
    url: str
    action: str  # link text for when you are already this person
    done: bool


@dataclass(frozen=True, slots=True)
class Tour:
    steps: tuple[TourStep, ...]
    request_id: int | None
    note: str
    requester_id: str = ""
    granted: bool = False

    @property
    def done_count(self) -> int:
        return sum(step.done for step in self.steps)

    @property
    def complete(self) -> bool:
        return all(step.done for step in self.steps)

    @property
    def current(self) -> TourStep | None:
        return next((step for step in self.steps if not step.done), None)

    @property
    def current_number(self) -> int:
        return next((n for n, step in enumerate(self.steps, 1) if not step.done), len(self.steps))


def _names(items: Sequence[str], limit: int = 2) -> str:
    shown = list(items[:limit])
    if len(items) > limit:
        shown.append(f"{len(items) - limit} more")
    if len(shown) <= 1:
        return "".join(shown)
    return ", ".join(shown[:-1]) + " and " + shown[-1]


def personas(users: Sequence[User], resources: Sequence[Resource]) -> list[Persona]:
    """The demo's main characters, with one line each on what they can do."""
    by_id = {u.id: u for u in users if u.active}
    result: list[Persona] = []
    for user_id, kind, label in PERSONA_SPECS:
        user = by_id.get(user_id)
        if user is None:
            continue
        if kind == REQUESTER:
            summary = "Asks for temporary access to systems. Start the guided demo here."
        elif kind == MANAGER:
            reports = [u.name.split()[0] for u in by_id.values() if u.manager_id == user.id]
            summary = f"Manages {_names(reports)}, and approves their requests." if reports else ""
        elif kind == OWNER:
            mine = [r for r in resources if r.active and r.owner_id == user.id]
            mine.sort(key=lambda r: (r.id != SUGGESTED_RESOURCE, r.sensitivity not in HIGH_RISK, r.name))
            owned = [r.name for r in mine]
            summary = (
                f"Owns {_names(owned)}. Approves access to them and reviews who has it." if owned else ""
            )
        else:
            summary = "Approves critical and admin access, reviews everyone's access and reads the audit log."
        if summary and (kind != SECURITY or user.is_security):
            result.append(Persona(user, label, summary))
    return result


def persona_label(user: User, cast: Sequence[Persona]) -> str:
    return next((p.label for p in cast if p.user.id == user.id), "")


def _security_people(users: Sequence[User], requester: User) -> list[User]:
    preferred = [spec[0] for spec in PERSONA_SPECS if spec[1] == SECURITY]
    team = [u for u in users if u.active and u.is_security and u.id != requester.id]
    return sorted(team, key=lambda u: (u.id not in preferred, u.name))


def _suggested(resources: Sequence[Resource]) -> Resource | None:
    risky = [r for r in resources if r.active and r.sensitivity in HIGH_RISK]
    return next((r for r in risky if r.id == SUGGESTED_RESOURCE), risky[0] if risky else None)


def tour(service: AccessService, users: Sequence[User], marks: Mapping[str, Any] | None) -> Tour | None:
    """The guided demo's progress, or None if this database has no demo data to follow. ``marks`` is the
    session, which remembers the pages the last two steps ask you to open."""
    marks = marks or {}
    seeded = service.meta(SEEDED_THROUGH)
    by_id = {u.id: u for u in users}
    requester = by_id.get(PERSONA_SPECS[0][0])
    if seeded is None or not seeded.isdigit() or requester is None or not requester.active:
        return None
    resources = service.resources(active_only=True)
    suggested = _suggested(resources)
    security = _security_people(users, requester)
    manager = by_id.get(requester.manager_id or "")
    if suggested is None or not security or manager is None or not manager.active:
        return None

    page: RequestPage | None = None
    note = ""
    for candidate in service.my_requests(requester.id):
        if candidate.id <= int(seeded):
            break
        if candidate.resource.sensitivity in HIGH_RISK and candidate.required:
            if candidate.status in (RequestStatus.DENIED, RequestStatus.CANCELLED):
                note = f"Request #{candidate.id} was {candidate.status.value}. Ask again to restart the demo."
            else:
                page = service.request_page(candidate.id, requester.id)
            break

    first = requester.name.split()[0]
    target = page.request.resource if page else suggested
    steps = [
        TourStep(
            "Ask for high-risk access",
            f"As {first}, ask for {target.name}. Any level and duration.",
            requester,
            f"/requests/new?resource={suggested.id}",
            f"Ask for {target.name}",
            page is not None,
        )
    ]
    if page is not None:
        slots = [(slot.kind, slot.approval) for slot in page.slots]
    else:
        slots = [(kind, None) for kind in policy.BASE_APPROVALS[suggested.sensitivity]]
    used = {a.approver.id for _, a in slots if a is not None}
    url = f"/requests/{page.request.id}" if page else "/approvals"
    for kind, approval in slots:
        if approval is not None:
            person = approval.approver
        elif kind is ApproverKind.MANAGER:
            person = manager
        elif kind is ApproverKind.OWNER:
            person = by_id.get(target.owner_id) or security[0]
        else:
            person = next((u for u in security if u.id not in used), security[0])
            used.add(person.id)
        who = {
            ApproverKind.MANAGER: f"{first}'s manager",
            ApproverKind.OWNER: f"the owner of {target.name}",
            ApproverKind.SECURITY: "a member of the security team",
        }[kind]
        steps.append(
            TourStep(
                f"Approve as {person.name}",
                f"As {who}.",
                person,
                url,
                f"Review request #{page.request.id}" if page else "Open your approvals",
                approval is not None and approval.verdict == "approve",
            )
        )
    granted = page is not None and page.request.grant is not None
    request_id = page.request.id if page else None
    steps.append(
        TourStep(
            "See the access start and count down",
            f"Back as {first}: the access is live and counting down.",
            requester,
            url if page else "/",
            "See the access",
            granted and request_id is not None and marks.get(TOUR_SEEN_KEY) == request_id,
        )
    )
    steps.append(
        TourStep(
            "Check the audit log",
            f"As {security[0].name.split()[0]} from security, see every step and the chain verify.",
            security[0],
            "/audit",
            "Open the audit log",
            granted and request_id is not None and marks.get(TOUR_AUDIT_KEY) == request_id,
        )
    )
    return Tour(tuple(steps), request_id, note, requester.id, granted)


def record_visit(
    session: MutableMapping[str, Any],
    service: AccessService,
    viewer: User,
    *,
    request_id: int | None = None,
    audit: bool = False,
) -> None:
    """Tick off the guided demo's last two steps once their page is actually opened: the requester looking
    at the live access (home, or the request itself), and security opening the audit log."""
    progress = tour(service, service.users(), session)
    if progress is None or progress.request_id is None or not progress.granted:
        return
    if audit:
        session[TOUR_AUDIT_KEY] = progress.request_id
    elif viewer.id == progress.requester_id and request_id in (None, progress.request_id):
        session[TOUR_SEEN_KEY] = progress.request_id


def kept_progress(session: Mapping[str, Any]) -> dict[str, int]:
    """The guided demo's marks, to carry over when switching person starts a fresh session."""
    return {key: value for key in TOUR_KEYS if isinstance(value := session.get(key), int)}
