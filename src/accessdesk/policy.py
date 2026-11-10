"""The access policy: a pure function from (request, context) to a decision.

No I/O and no clock, so every decision can be unit-tested, property-tested and replayed.

Rules, in order:

1. Deny requests the resource cannot satisfy (role not offered, duration out of range).
2. Deny requests that add nothing (access already held, identical request already pending).
3. Deny separation-of-duties conflicts with access the requester already holds.
4. Auto-approve only low-sensitivity, read-only access for teams the owner pre-approved.
5. Otherwise route to approvers by sensitivity, adding security for admin roles, and
   escalate to security whenever a slot could not be filled by an independent person
   (no manager, requester owns the resource, manager owns the resource).

Every approval slot must be filled by a different person (four-eyes principle), and nobody
can approve their own request.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from accessdesk.models import (
    KIND_ORDER,
    ApproverKind,
    Decision,
    Draft,
    Entitlement,
    Outcome,
    PolicyContext,
    Reason,
    Resource,
    Role,
    Sensitivity,
    User,
)

BASE_APPROVALS: dict[Sensitivity, tuple[ApproverKind, ...]] = {
    Sensitivity.LOW: (ApproverKind.MANAGER,),
    Sensitivity.MEDIUM: (ApproverKind.MANAGER,),
    Sensitivity.HIGH: (ApproverKind.MANAGER, ApproverKind.OWNER),
    Sensitivity.CRITICAL: (ApproverKind.MANAGER, ApproverKind.OWNER, ApproverKind.SECURITY),
}

_REQUIRED_REASON = {
    ApproverKind.MANAGER: Reason.MANAGER_APPROVAL_REQUIRED,
    ApproverKind.OWNER: Reason.OWNER_APPROVAL_REQUIRED,
    ApproverKind.SECURITY: Reason.SECURITY_APPROVAL_REQUIRED,
}


def _deny(reason: Reason, detail: str = "") -> Decision:
    return Decision(Outcome.DENY, (), (reason,), detail)


def find_sod_conflict(
    wanted: Entitlement, held: frozenset[Entitlement], context: PolicyContext
) -> str | None:
    """Return the description of the first separation-of-duties rule ``wanted`` breaks, if any."""
    for rule in context.sod_rules:
        if rule.conflicts(wanted, held):
            return rule.description
    return None


def evaluate(draft: Draft, context: PolicyContext) -> Decision:
    resource = draft.resource
    wanted = Entitlement(resource.id, draft.role)

    if draft.role not in resource.roles:
        return _deny(Reason.ROLE_NOT_OFFERED)
    if not 1 <= draft.hours <= resource.max_hours:
        return _deny(Reason.DURATION_OUT_OF_RANGE)
    if any(h.satisfies(wanted) for h in context.held):
        return _deny(Reason.ALREADY_HAS_ACCESS)
    if wanted in context.pending:
        return _deny(Reason.DUPLICATE_PENDING_REQUEST)
    conflict = find_sod_conflict(wanted, context.held, context)
    if conflict is not None:
        return _deny(Reason.SOD_CONFLICT, conflict)

    if (
        resource.sensitivity is Sensitivity.LOW
        and draft.role is Role.VIEWER
        and draft.requester.team in resource.auto_approve_teams
    ):
        return Decision(Outcome.AUTO_APPROVE, (), (Reason.LOW_RISK_AUTO_APPROVED,))

    slots = list(BASE_APPROVALS[resource.sensitivity])
    notes: list[Reason] = []
    if draft.role is Role.ADMIN and ApproverKind.SECURITY not in slots:
        slots.append(ApproverKind.SECURITY)
        notes.append(Reason.ADMIN_ROLE_NEEDS_SECURITY)

    if context.manager is None:
        _replace(slots, ApproverKind.MANAGER, ApproverKind.SECURITY)
        notes.append(Reason.NO_MANAGER_ESCALATED)
    if ApproverKind.OWNER in slots:
        if resource.owner_id == draft.requester.id:
            _replace(slots, ApproverKind.OWNER, ApproverKind.SECURITY)
            notes.append(Reason.REQUESTER_IS_OWNER_ESCALATED)
        elif (
            context.manager is not None
            and ApproverKind.MANAGER in slots
            and context.manager.id == resource.owner_id
        ):
            _replace(slots, ApproverKind.OWNER, ApproverKind.SECURITY)
            notes.append(Reason.MANAGER_IS_OWNER_ESCALATED)

    ordered = tuple(sorted(slots, key=KIND_ORDER.__getitem__))
    required = tuple(_REQUIRED_REASON[k] for k in dict.fromkeys(ordered))
    return Decision(Outcome.NEEDS_APPROVAL, ordered, required + tuple(notes))


def _replace(slots: list[ApproverKind], old: ApproverKind, new: ApproverKind) -> None:
    slots[slots.index(old)] = new


def eligible_kinds(approver: User, requester: User, resource: Resource) -> frozenset[ApproverKind]:
    """Which approval slots ``approver`` may fill for this request. Never the requester themselves."""
    if approver.id == requester.id:
        return frozenset()
    kinds: set[ApproverKind] = set()
    if requester.manager_id is not None and requester.manager_id == approver.id:
        kinds.add(ApproverKind.MANAGER)
    if resource.owner_id == approver.id:
        kinds.add(ApproverKind.OWNER)
    if approver.is_security:
        kinds.add(ApproverKind.SECURITY)
    return frozenset(kinds)


def open_slots(
    required: Sequence[ApproverKind], filled: Iterable[tuple[ApproverKind, str]]
) -> list[ApproverKind]:
    remaining = list(required)
    for kind, _ in filled:
        remaining.remove(kind)
    return remaining


def assign_slot(
    required: Sequence[ApproverKind],
    filled: Sequence[tuple[ApproverKind, str]],
    approver_id: str,
    kinds: frozenset[ApproverKind],
) -> ApproverKind | None:
    """The slot this approver would fill, or None. One person fills at most one slot per request.

    Manager and owner slots each have exactly one eligible person while security is a pool, so
    filling slots in canonical order (manager, owner, security) can never strand an open slot.
    """
    if any(who == approver_id for _, who in filled):
        return None
    for kind in open_slots(required, filled):
        if kind in kinds:
            return kind
    return None
