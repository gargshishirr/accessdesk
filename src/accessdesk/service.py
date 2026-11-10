"""Business operations. Each public method is a single transaction or a single read."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from accessdesk import audit, policy
from accessdesk.clock import Clock
from accessdesk.db import Database
from accessdesk.models import (
    ApproverKind,
    Decision,
    Draft,
    Entitlement,
    GrantEnd,
    Outcome,
    PolicyContext,
    Reason,
    RequestStatus,
    Resource,
    Role,
    Sensitivity,
    SodRule,
    User,
)

JUSTIFICATION_MIN = 10
JUSTIFICATION_MAX = 500
NOTE_MIN = 5
NOTE_MAX = 500


class AccessError(Exception):
    status = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFound(AccessError):
    status = 404


class Forbidden(AccessError):
    status = 403


class Conflict(AccessError):
    """The request changed since the caller looked at it, or is no longer in the right state."""

    status = 409


class ValidationFailed(AccessError):
    status = 422

    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(errors.values()))
        self.errors = errors


@dataclass(frozen=True, slots=True)
class ApprovalView:
    approver: User
    kind: ApproverKind
    verdict: str
    comment: str
    created_at: int


@dataclass(frozen=True, slots=True)
class GrantView:
    id: int
    request_id: int
    user: User
    resource: Resource
    role: Role
    granted_at: int
    expires_at: int
    ended_at: int | None
    end_reason: GrantEnd | None
    ended_by: str | None
    end_note: str

    def active_at(self, now: int) -> bool:
        return self.ended_at is None and self.expires_at > now


@dataclass(frozen=True, slots=True)
class RequestView:
    id: int
    requester: User
    resource: Resource
    role: Role
    hours: int
    justification: str
    status: RequestStatus
    required: tuple[ApproverKind, ...]
    reasons: tuple[Reason, ...]
    detail: str
    created_at: int
    decided_at: int | None
    version: int
    approvals: tuple[ApprovalView, ...] = ()
    grant: GrantView | None = None


@dataclass(frozen=True, slots=True)
class Slot:
    kind: ApproverKind
    approval: ApprovalView | None


@dataclass(frozen=True, slots=True)
class RequestPage:
    request: RequestView
    slots: tuple[Slot, ...]
    my_slot: ApproverKind | None
    can_cancel: bool


@dataclass(frozen=True, slots=True)
class SubmitResult:
    request_id: int
    decision: Decision
    grant_id: int | None


@dataclass(frozen=True, slots=True)
class ActionResult:
    request_id: int
    status: RequestStatus
    grant_id: int | None = None
    remaining: tuple[ApproverKind, ...] = ()


@dataclass(frozen=True, slots=True)
class CheckResult:
    allowed: bool
    reason: str
    expires_at: int | None = None
    grant_id: int | None = None


def _user(row: sqlite3.Row) -> User:
    return User(
        id=row["id"],
        name=row["name"],
        email=row["email"],
        team=row["team"],
        title=row["title"],
        manager_id=row["manager_id"],
        is_security=bool(row["is_security"]),
    )


def _resource(row: sqlite3.Row) -> Resource:
    return Resource(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        owner_id=row["owner_id"],
        sensitivity=Sensitivity(row["sensitivity"]),
        max_hours=row["max_hours"],
        roles=tuple(Role(r) for r in row["roles"].split(",")),
        auto_approve_teams=frozenset(t for t in row["auto_approve_teams"].split(",") if t),
    )


class AccessService:
    def __init__(self, db: Database, clock: Clock) -> None:
        self.db = db
        self.clock = clock

    # ----------------------------------------------------------------- directory

    def users(self) -> list[User]:
        with self.db.connection() as conn:
            return [_user(r) for r in conn.execute("SELECT * FROM users ORDER BY name")]

    def user(self, user_id: str) -> User | None:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _user(row) if row else None

    def resources(self) -> list[Resource]:
        with self.db.connection() as conn:
            return [_resource(r) for r in conn.execute("SELECT * FROM resources ORDER BY name")]

    def resource(self, resource_id: str) -> Resource | None:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM resources WHERE id = ?", (resource_id,)).fetchone()
        return _resource(row) if row else None

    def sod_rules(self) -> list[SodRule]:
        with self.db.connection() as conn:
            return self._sod_rules(conn)

    # ----------------------------------------------------------------- requests

    def submit(
        self, requester_id: str, resource_id: str, role: str, hours: str | int, justification: str
    ) -> SubmitResult:
        with self.db.write() as conn:
            requester = self._get_user(conn, requester_id)
            resource, role_, hours_, text = self._validate(conn, resource_id, role, hours, justification)
            now = self.clock.now()
            context = self._context(conn, requester, now)
            decision = policy.evaluate(Draft(requester, resource, role_, hours_, text), context)
            status = {
                Outcome.AUTO_APPROVE: RequestStatus.APPROVED,
                Outcome.NEEDS_APPROVAL: RequestStatus.PENDING,
                Outcome.DENY: RequestStatus.DENIED,
            }[decision.outcome]
            cursor = conn.execute(
                "INSERT INTO requests (requester_id, resource_id, role, hours, justification, status, "
                "required, reasons, detail, created_at, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    requester.id,
                    resource.id,
                    role_.value,
                    hours_,
                    text,
                    status.value,
                    json.dumps([k.value for k in decision.approvals]),
                    json.dumps([r.value for r in decision.reasons]),
                    decision.detail,
                    now,
                    None if status is RequestStatus.PENDING else now,
                ),
            )
            request_id = int(cursor.lastrowid or 0)
            audit.append(
                conn,
                ts=now,
                actor=requester.id,
                action="request.submitted",
                subject=f"request:{request_id}",
                details={
                    "resource": resource.id,
                    "role": role_.value,
                    "hours": hours_,
                    "outcome": decision.outcome.value,
                    "approvals": [k.value for k in decision.approvals],
                    "reasons": [r.value for r in decision.reasons],
                },
            )
            grant_id = None
            if decision.outcome is Outcome.AUTO_APPROVE:
                grant_id = self._create_grant(conn, request_id, requester.id, resource.id, role_, hours_, now)
        return SubmitResult(request_id, decision, grant_id)

    def approve(
        self, request_id: int, approver_id: str, comment: str = "", expected_version: int | None = None
    ) -> ActionResult:
        with self.db.write() as conn:
            row, requester, resource, approver = self._load_for_decision(
                conn, request_id, approver_id, expected_version
            )
            required = self._required(row)
            filled = self._filled(conn, request_id)
            slot = self._slot_for(required, filled, approver, requester, resource)
            now = self.clock.now()
            note = comment.strip()[:NOTE_MAX]
            conn.execute(
                "INSERT INTO approvals (request_id, approver_id, kind, verdict, comment, created_at) "
                "VALUES (?, ?, ?, 'approve', ?, ?)",
                (request_id, approver.id, slot.value, note, now),
            )
            audit.append(
                conn,
                ts=now,
                actor=approver.id,
                action="request.approved",
                subject=f"request:{request_id}",
                details={"slot": slot.value, "comment": note},
            )
            remaining = tuple(policy.open_slots(required, [*filled, (slot, approver.id)]))
            if remaining:
                self._bump(conn, row)
                return ActionResult(request_id, RequestStatus.PENDING, remaining=remaining)

            # Last approval: re-check against access held *now*, not at submission (fail closed).
            role = Role(row["role"])
            context = self._context(conn, requester, now)
            wanted = Entitlement(resource.id, role)
            problem: tuple[Reason, str] | None = None
            if any(h.satisfies(wanted) for h in context.held):
                problem = (Reason.ALREADY_HAS_ACCESS, "")
            else:
                conflict = policy.find_sod_conflict(wanted, context.held, context)
                if conflict is not None:
                    problem = (Reason.SOD_CONFLICT, conflict)
            if problem is not None:
                reason, detail = problem
                self._finish(conn, row, RequestStatus.DENIED, now, extra_reason=reason, detail=detail)
                audit.append(
                    conn,
                    ts=now,
                    actor="policy",
                    action="request.denied",
                    subject=f"request:{request_id}",
                    details={"reason": reason.value, "detail": detail},
                )
                return ActionResult(request_id, RequestStatus.DENIED)
            self._finish(conn, row, RequestStatus.APPROVED, now)
            grant_id = self._create_grant(
                conn, request_id, requester.id, resource.id, role, row["hours"], now
            )
            return ActionResult(request_id, RequestStatus.APPROVED, grant_id=grant_id)

    def deny(
        self, request_id: int, approver_id: str, comment: str, expected_version: int | None = None
    ) -> ActionResult:
        note = comment.strip()
        if len(note) < NOTE_MIN:
            raise ValidationFailed({"comment": "Tell the requester why you are denying this request"})
        with self.db.write() as conn:
            row, requester, resource, approver = self._load_for_decision(
                conn, request_id, approver_id, expected_version
            )
            slot = self._slot_for(
                self._required(row), self._filled(conn, request_id), approver, requester, resource
            )
            now = self.clock.now()
            conn.execute(
                "INSERT INTO approvals (request_id, approver_id, kind, verdict, comment, created_at) "
                "VALUES (?, ?, ?, 'deny', ?, ?)",
                (request_id, approver.id, slot.value, note[:NOTE_MAX], now),
            )
            self._finish(conn, row, RequestStatus.DENIED, now, extra_reason=Reason.DENIED_BY_APPROVER)
            audit.append(
                conn,
                ts=now,
                actor=approver.id,
                action="request.denied",
                subject=f"request:{request_id}",
                details={"slot": slot.value, "comment": note[:NOTE_MAX]},
            )
        return ActionResult(request_id, RequestStatus.DENIED)

    def cancel(self, request_id: int, requester_id: str, expected_version: int | None = None) -> ActionResult:
        with self.db.write() as conn:
            row = self._request_row(conn, request_id)
            if row["requester_id"] != requester_id:
                raise Forbidden("Only the person who asked for access can cancel the request.")
            self._check_version(row, expected_version)
            if row["status"] != RequestStatus.PENDING:
                raise Conflict(f"Request #{request_id} is already {row['status']}.")
            now = self.clock.now()
            self._finish(conn, row, RequestStatus.CANCELLED, now)
            audit.append(
                conn,
                ts=now,
                actor=requester_id,
                action="request.cancelled",
                subject=f"request:{request_id}",
                details={},
            )
        return ActionResult(request_id, RequestStatus.CANCELLED)

    # ----------------------------------------------------------------- grants

    def release(self, grant_id: int, user_id: str) -> None:
        """The holder gives access back early."""
        with self.db.write() as conn:
            grant = self._active_grant(conn, grant_id)
            if grant["user_id"] != user_id:
                raise Forbidden("You can only release your own access.")
            self._end_grant(conn, grant, GrantEnd.RELEASED, user_id, "")

    def revoke(self, grant_id: int, actor_id: str, note: str) -> None:
        """A resource owner or the security team removes someone's access, with a reason."""
        text = note.strip()
        if len(text) < NOTE_MIN:
            raise ValidationFailed(
                {"note": "Enter a reason for removing this access (at least 5 characters)"}
            )
        with self.db.write() as conn:
            actor = self._get_user(conn, actor_id)
            grant = self._active_grant(conn, grant_id)
            owner = conn.execute(
                "SELECT owner_id FROM resources WHERE id = ?", (grant["resource_id"],)
            ).fetchone()["owner_id"]
            if not (actor.is_security or actor.id == owner):
                raise Forbidden("Only the resource owner or the security team can remove access.")
            self._end_grant(conn, grant, GrantEnd.REVOKED, actor.id, text[:NOTE_MAX])

    def expire_due(self) -> int:
        """End every grant whose time is up. Returns how many ended."""
        now = self.clock.now()
        with self.db.connection() as conn:
            due = conn.execute(
                "SELECT COUNT(*) FROM grants WHERE ended_at IS NULL AND expires_at <= ?", (now,)
            ).fetchone()[0]
        if not due:
            return 0
        with self.db.write() as conn:
            rows = conn.execute(
                "SELECT * FROM grants WHERE ended_at IS NULL AND expires_at <= ? ORDER BY expires_at, id",
                (now,),
            ).fetchall()
            for grant in rows:
                conn.execute(
                    "UPDATE grants SET ended_at = expires_at, end_reason = 'expired', ended_by = 'system' "
                    "WHERE id = ?",
                    (grant["id"],),
                )
                audit.append(
                    conn,
                    ts=now,
                    actor="system",
                    action="grant.expired",
                    subject=f"grant:{grant['id']}",
                    details={
                        "user": grant["user_id"],
                        "resource": grant["resource_id"],
                        "role": grant["role"],
                    },
                )
        return len(rows)

    def check(self, user_id: str, resource_id: str, role: Role) -> CheckResult:
        """The decision point other systems call. Expired grants never pass, even before the sweeper runs."""
        now = self.clock.now()
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT id, role, expires_at FROM grants "
                "WHERE user_id = ? AND resource_id = ? AND ended_at IS NULL AND expires_at > ?",
                (user_id, resource_id, now),
            ).fetchall()
        covering = [r for r in rows if Role(r["role"]).covers(role)]
        if covering:
            best = max(covering, key=lambda r: r["expires_at"])
            return CheckResult(True, "active_grant", best["expires_at"], best["id"])
        return CheckResult(False, "role_insufficient" if rows else "no_active_grant")

    # ----------------------------------------------------------------- read models for the UI

    def my_grants(self, user_id: str, recent_ended: int = 10) -> tuple[list[GrantView], list[GrantView]]:
        now = self.clock.now()
        with self.db.connection() as conn:
            users, resources = self._directory(conn)
            active = conn.execute(
                "SELECT * FROM grants WHERE user_id = ? AND ended_at IS NULL AND expires_at > ? "
                "ORDER BY expires_at",
                (user_id, now),
            ).fetchall()
            ended = conn.execute(
                "SELECT * FROM grants WHERE user_id = ? AND (ended_at IS NOT NULL OR expires_at <= ?) "
                "ORDER BY COALESCE(ended_at, expires_at) DESC LIMIT ?",
                (user_id, now, recent_ended),
            ).fetchall()
        return (
            [self._grant_view(g, users, resources) for g in active],
            [self._grant_view(g, users, resources) for g in ended],
        )

    def my_requests(self, user_id: str, limit: int = 20) -> list[RequestView]:
        with self.db.connection() as conn:
            users, resources = self._directory(conn)
            rows = conn.execute(
                "SELECT * FROM requests WHERE requester_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit)
            ).fetchall()
        return [self._request_view(r, users, resources) for r in rows]

    def pending_for(self, approver_id: str) -> list[RequestView]:
        """Pending requests this person can act on right now."""
        with self.db.connection() as conn:
            users, resources = self._directory(conn)
            approver = users.get(approver_id)
            if approver is None:
                return []
            result: list[RequestView] = []
            for row in conn.execute("SELECT * FROM requests WHERE status = 'pending' ORDER BY id"):
                requester, resource = users[row["requester_id"]], resources[row["resource_id"]]
                kinds = policy.eligible_kinds(approver, requester, resource)
                if kinds and policy.assign_slot(
                    self._required(row), self._filled(conn, row["id"]), approver_id, kinds
                ):
                    result.append(self._request_view(row, users, resources))
        return result

    def request_page(self, request_id: int, viewer_id: str) -> RequestPage:
        with self.db.connection() as conn:
            users, resources = self._directory(conn)
            row = self._request_row(conn, request_id)
            viewer = users.get(viewer_id)
            requester, resource = users[row["requester_id"]], resources[row["resource_id"]]
            approval_rows = conn.execute(
                "SELECT * FROM approvals WHERE request_id = ? ORDER BY id", (request_id,)
            ).fetchall()
            grant_row = conn.execute("SELECT * FROM grants WHERE request_id = ?", (request_id,)).fetchone()
            filled = self._filled(conn, request_id)
        kinds = policy.eligible_kinds(viewer, requester, resource) if viewer else frozenset()
        involved = viewer is not None and (
            viewer.id == requester.id
            or viewer.is_security
            or viewer.id == resource.owner_id
            or bool(kinds)
            or any(a["approver_id"] == viewer.id for a in approval_rows)
        )
        if not involved:
            raise NotFound(f"Request #{request_id} was not found.")
        approvals = tuple(
            ApprovalView(
                users[a["approver_id"]], ApproverKind(a["kind"]), a["verdict"], a["comment"], a["created_at"]
            )
            for a in approval_rows
        )
        view = self._request_view(row, users, resources, approvals, grant_row)
        pending = view.status is RequestStatus.PENDING
        my_slot = policy.assign_slot(view.required, filled, viewer_id, kinds) if pending and kinds else None
        return RequestPage(
            request=view,
            slots=self._slots(view.required, approvals),
            my_slot=my_slot,
            can_cancel=pending and viewer_id == requester.id,
        )

    def reviewable_grants(self, actor_id: str) -> list[GrantView]:
        """Active grants on resources this person owns (everything, for the security team)."""
        now = self.clock.now()
        with self.db.connection() as conn:
            users, resources = self._directory(conn)
            actor = users.get(actor_id)
            if actor is None:
                return []
            rows = conn.execute(
                "SELECT * FROM grants WHERE ended_at IS NULL AND expires_at > ? "
                "ORDER BY resource_id, expires_at",
                (now,),
            ).fetchall()
        return [
            self._grant_view(g, users, resources)
            for g in rows
            if actor.is_security or resources[g["resource_id"]].owner_id == actor.id
        ]

    def grant(self, grant_id: int, viewer_id: str) -> GrantView:
        """One grant, visible to its holder, the resource owner and the security team."""
        with self.db.connection() as conn:
            users, resources = self._directory(conn)
            row = conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone()
        viewer = users.get(viewer_id)
        if row is None or viewer is None:
            raise NotFound(f"Access grant #{grant_id} was not found.")
        view = self._grant_view(row, users, resources)
        if not (viewer.is_security or viewer.id in (view.user.id, view.resource.owner_id)):
            raise NotFound(f"Access grant #{grant_id} was not found.")
        return view

    def audit_log(self, actor_id: str, limit: int = 100) -> tuple[list[audit.AuditEvent], audit.Verification]:
        actor = self.user(actor_id)
        if actor is None or not actor.is_security:
            raise Forbidden("Only the security team can read the audit log.")
        with self.db.connection() as conn:
            return audit.recent(conn, limit), audit.verify(conn)

    def verify_audit(self) -> audit.Verification:
        with self.db.connection() as conn:
            return audit.verify(conn)

    # ----------------------------------------------------------------- internals

    def _validate(
        self, conn: sqlite3.Connection, resource_id: str, role: str, hours: str | int, justification: str
    ) -> tuple[Resource, Role, int, str]:
        errors: dict[str, str] = {}
        resource = None
        if not resource_id:
            errors["resource_id"] = "Choose the resource you need access to"
        else:
            row = conn.execute("SELECT * FROM resources WHERE id = ?", (resource_id,)).fetchone()
            if row is None:
                errors["resource_id"] = "Choose a resource from the list"
            else:
                resource = _resource(row)

        role_: Role | None = None
        if not role:
            errors["role"] = "Choose the level of access you need"
        elif role not in {r.value for r in Role}:
            errors["role"] = "Choose viewer, editor or admin"
        else:
            role_ = Role(role)
            if resource is not None and role_ not in resource.roles:
                offered = " or ".join(r.value for r in resource.roles)
                errors["role"] = f"{resource.name} does not offer {role_.value} access. Choose {offered}"

        hours_: int | None = None
        raw_hours = str(hours).strip()
        if not raw_hours:
            errors["hours"] = "Enter how many hours you need access for"
        elif not (raw_hours.isascii() and raw_hours.isdigit()):
            errors["hours"] = "Enter the number of hours as a whole number, like 8"
        else:
            hours_ = int(raw_hours)
            if hours_ < 1:
                errors["hours"] = "Enter at least 1 hour"
            elif resource is not None and hours_ > resource.max_hours:
                errors["hours"] = f"Enter {resource.max_hours} hours or fewer for {resource.name}"

        text = justification.strip()
        if not text:
            errors["justification"] = "Explain why you need access"
        elif len(text) < JUSTIFICATION_MIN:
            errors["justification"] = (
                f"Write at least {JUSTIFICATION_MIN} characters so approvers understand why"
            )
        elif len(text) > JUSTIFICATION_MAX:
            errors["justification"] = f"Write {JUSTIFICATION_MAX} characters or fewer"

        if errors:
            raise ValidationFailed(errors)
        assert resource is not None
        assert role_ is not None
        assert hours_ is not None
        return resource, role_, hours_, text

    def _context(self, conn: sqlite3.Connection, requester: User, now: int) -> PolicyContext:
        held = frozenset(
            Entitlement(r["resource_id"], Role(r["role"]))
            for r in conn.execute(
                "SELECT resource_id, role FROM grants "
                "WHERE user_id = ? AND ended_at IS NULL AND expires_at > ?",
                (requester.id, now),
            )
        )
        pending = frozenset(
            Entitlement(r["resource_id"], Role(r["role"]))
            for r in conn.execute(
                "SELECT resource_id, role FROM requests WHERE requester_id = ? AND status = 'pending'",
                (requester.id,),
            )
        )
        manager = None
        if requester.manager_id is not None:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (requester.manager_id,)).fetchone()
            manager = _user(row) if row else None
        return PolicyContext(held, pending, tuple(self._sod_rules(conn)), manager)

    @staticmethod
    def _sod_rules(conn: sqlite3.Connection) -> list[SodRule]:
        return [
            SodRule(
                r["id"],
                r["description"],
                Entitlement(r["first_resource"], Role(r["first_role"])),
                Entitlement(r["second_resource"], Role(r["second_role"])),
            )
            for r in conn.execute("SELECT * FROM sod_rules ORDER BY id")
        ]

    def _create_grant(
        self,
        conn: sqlite3.Connection,
        request_id: int,
        user_id: str,
        resource_id: str,
        role: Role,
        hours: int,
        now: int,
    ) -> int:
        expires_at = now + hours * 3600
        cursor = conn.execute(
            "INSERT INTO grants (request_id, user_id, resource_id, role, granted_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (request_id, user_id, resource_id, role.value, now, expires_at),
        )
        grant_id = int(cursor.lastrowid or 0)
        audit.append(
            conn,
            ts=now,
            actor="system",
            action="grant.created",
            subject=f"grant:{grant_id}",
            details={
                "request": request_id,
                "user": user_id,
                "resource": resource_id,
                "role": role.value,
                "expires_at": expires_at,
            },
        )
        return grant_id

    def _end_grant(
        self, conn: sqlite3.Connection, grant: sqlite3.Row, how: GrantEnd, actor: str, note: str
    ) -> None:
        now = self.clock.now()
        conn.execute(
            "UPDATE grants SET ended_at = ?, end_reason = ?, ended_by = ?, end_note = ? WHERE id = ?",
            (now, how.value, actor, note, grant["id"]),
        )
        audit.append(
            conn,
            ts=now,
            actor=actor,
            action=f"grant.{how.value}",
            subject=f"grant:{grant['id']}",
            details={
                "user": grant["user_id"],
                "resource": grant["resource_id"],
                "role": grant["role"],
                "note": note,
            },
        )

    def _active_grant(self, conn: sqlite3.Connection, grant_id: int) -> sqlite3.Row:
        grant: sqlite3.Row | None = conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone()
        if grant is None:
            raise NotFound(f"Access grant #{grant_id} was not found.")
        if grant["ended_at"] is not None or grant["expires_at"] <= self.clock.now():
            raise Conflict("This access has already ended.")
        return grant

    def _load_for_decision(
        self, conn: sqlite3.Connection, request_id: int, approver_id: str, expected_version: int | None
    ) -> tuple[sqlite3.Row, User, Resource, User]:
        row = self._request_row(conn, request_id)
        self._check_version(row, expected_version)
        if row["status"] != RequestStatus.PENDING:
            raise Conflict(f"Request #{request_id} is already {row['status']}.")
        approver = self._get_user(conn, approver_id)
        requester = self._get_user(conn, row["requester_id"])
        resource = _resource(
            conn.execute("SELECT * FROM resources WHERE id = ?", (row["resource_id"],)).fetchone()
        )
        return row, requester, resource, approver

    @staticmethod
    def _slot_for(
        required: tuple[ApproverKind, ...],
        filled: list[tuple[ApproverKind, str]],
        approver: User,
        requester: User,
        resource: Resource,
    ) -> ApproverKind:
        if approver.id == requester.id:
            raise Forbidden("You cannot approve or deny your own request.")
        if any(who == approver.id for _, who in filled):
            raise Conflict(
                "You have already approved this request. Another approver must take the next step."
            )
        slot = policy.assign_slot(
            required, filled, approver.id, policy.eligible_kinds(approver, requester, resource)
        )
        if slot is None:
            raise Forbidden("You are not an approver for this request.")
        return slot

    @staticmethod
    def _check_version(row: sqlite3.Row, expected: int | None) -> None:
        if expected is not None and row["version"] != expected:
            raise Conflict(
                "This request changed after you opened it. Review the latest version and try again."
            )

    @staticmethod
    def _bump(conn: sqlite3.Connection, row: sqlite3.Row) -> None:
        updated = conn.execute(
            "UPDATE requests SET version = version + 1 WHERE id = ? AND version = ?",
            (row["id"], row["version"]),
        ).rowcount
        if updated != 1:
            raise Conflict(
                "This request changed after you opened it. Review the latest version and try again."
            )

    @staticmethod
    def _finish(
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        status: RequestStatus,
        now: int,
        extra_reason: Reason | None = None,
        detail: str = "",
    ) -> None:
        reasons = json.loads(row["reasons"])
        if extra_reason is not None:
            reasons.append(extra_reason.value)
        updated = conn.execute(
            "UPDATE requests SET status = ?, decided_at = ?, reasons = ?, "
            "detail = CASE WHEN ? = '' THEN detail ELSE ? END, version = version + 1 "
            "WHERE id = ? AND version = ?",
            (status.value, now, json.dumps(reasons), detail, detail, row["id"], row["version"]),
        ).rowcount
        if updated != 1:
            raise Conflict(
                "This request changed after you opened it. Review the latest version and try again."
            )

    @staticmethod
    def _request_row(conn: sqlite3.Connection, request_id: int) -> sqlite3.Row:
        row: sqlite3.Row | None = conn.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"Request #{request_id} was not found.")
        return row

    @staticmethod
    def _get_user(conn: sqlite3.Connection, user_id: str) -> User:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise Forbidden("Unknown user.")
        return _user(row)

    @staticmethod
    def _required(row: sqlite3.Row) -> tuple[ApproverKind, ...]:
        return tuple(ApproverKind(k) for k in json.loads(row["required"]))

    @staticmethod
    def _filled(conn: sqlite3.Connection, request_id: int) -> list[tuple[ApproverKind, str]]:
        return [
            (ApproverKind(a["kind"]), a["approver_id"])
            for a in conn.execute(
                "SELECT kind, approver_id FROM approvals "
                "WHERE request_id = ? AND verdict = 'approve' ORDER BY id",
                (request_id,),
            )
        ]

    @staticmethod
    def _slots(required: tuple[ApproverKind, ...], approvals: tuple[ApprovalView, ...]) -> tuple[Slot, ...]:
        unused = list(approvals)
        slots: list[Slot] = []
        for kind in required:
            match = next((a for a in unused if a.kind is kind), None)
            if match is not None:
                unused.remove(match)
            slots.append(Slot(kind, match))
        return tuple(slots)

    @staticmethod
    def _directory(conn: sqlite3.Connection) -> tuple[dict[str, User], dict[str, Resource]]:
        users = {r["id"]: _user(r) for r in conn.execute("SELECT * FROM users")}
        resources = {r["id"]: _resource(r) for r in conn.execute("SELECT * FROM resources")}
        return users, resources

    @staticmethod
    def _request_view(
        row: sqlite3.Row,
        users: dict[str, User],
        resources: dict[str, Resource],
        approvals: tuple[ApprovalView, ...] = (),
        grant_row: sqlite3.Row | None = None,
    ) -> RequestView:
        return RequestView(
            id=row["id"],
            requester=users[row["requester_id"]],
            resource=resources[row["resource_id"]],
            role=Role(row["role"]),
            hours=row["hours"],
            justification=row["justification"],
            status=RequestStatus(row["status"]),
            required=tuple(ApproverKind(k) for k in json.loads(row["required"])),
            reasons=tuple(Reason(r) for r in json.loads(row["reasons"])),
            detail=row["detail"],
            created_at=row["created_at"],
            decided_at=row["decided_at"],
            version=row["version"],
            approvals=approvals,
            grant=AccessService._grant_view(grant_row, users, resources) if grant_row is not None else None,
        )

    @staticmethod
    def _grant_view(row: sqlite3.Row, users: dict[str, User], resources: dict[str, Resource]) -> GrantView:
        return GrantView(
            id=row["id"],
            request_id=row["request_id"],
            user=users[row["user_id"]],
            resource=resources[row["resource_id"]],
            role=Role(row["role"]),
            granted_at=row["granted_at"],
            expires_at=row["expires_at"],
            ended_at=row["ended_at"],
            end_reason=GrantEnd(row["end_reason"]) if row["end_reason"] else None,
            ended_by=row["ended_by"],
            end_note=row["end_note"],
        )


def as_dict(result: CheckResult) -> dict[str, Any]:
    return {
        "allowed": result.allowed,
        "reason": result.reason,
        "expires_at": result.expires_at,
        "grant_id": result.grant_id,
    }
