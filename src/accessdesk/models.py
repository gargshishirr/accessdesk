"""Domain types shared by the policy engine, the service layer and the web layer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Sensitivity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Role(StrEnum):
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self]

    def covers(self, other: Role) -> bool:
        """True if holding this role also satisfies a check for ``other``."""
        return self.rank >= other.rank


_ROLE_RANK = {Role.VIEWER: 1, Role.EDITOR: 2, Role.ADMIN: 3}

ROLE_DESCRIPTIONS = {
    Role.VIEWER: "Read only.",
    Role.EDITOR: "Read and change data.",
    Role.ADMIN: "Full control. Always needs a security approval.",
}


class ApproverKind(StrEnum):
    MANAGER = "manager"
    OWNER = "owner"
    SECURITY = "security"


APPROVER_LABELS = {
    ApproverKind.MANAGER: "Requester's manager",
    ApproverKind.OWNER: "Resource owner",
    ApproverKind.SECURITY: "Security team",
}

# Canonical order for approval slots, so decisions are deterministic and easy to compare.
KIND_ORDER = {ApproverKind.MANAGER: 0, ApproverKind.OWNER: 1, ApproverKind.SECURITY: 2}


class Outcome(StrEnum):
    AUTO_APPROVE = "auto_approve"
    NEEDS_APPROVAL = "needs_approval"
    DENY = "deny"


class Reason(StrEnum):
    # Denials
    ROLE_NOT_OFFERED = "role_not_offered"
    DURATION_OUT_OF_RANGE = "duration_out_of_range"
    ALREADY_HAS_ACCESS = "already_has_access"
    DUPLICATE_PENDING_REQUEST = "duplicate_pending_request"
    SOD_CONFLICT = "sod_conflict"
    DENIED_BY_APPROVER = "denied_by_approver"
    # Routing
    LOW_RISK_AUTO_APPROVED = "low_risk_auto_approved"
    MANAGER_APPROVAL_REQUIRED = "manager_approval_required"
    OWNER_APPROVAL_REQUIRED = "owner_approval_required"
    SECURITY_APPROVAL_REQUIRED = "security_approval_required"
    ADMIN_ROLE_NEEDS_SECURITY = "admin_role_needs_security"
    NO_MANAGER_ESCALATED = "no_manager_escalated"
    REQUESTER_IS_OWNER_ESCALATED = "requester_is_owner_escalated"
    MANAGER_IS_OWNER_ESCALATED = "manager_is_owner_escalated"


REASON_TEXT = {
    Reason.ROLE_NOT_OFFERED: "This resource does not offer the requested role.",
    Reason.DURATION_OUT_OF_RANGE: "The requested duration is outside what this resource allows.",
    Reason.ALREADY_HAS_ACCESS: "The requester already has this access or higher.",
    Reason.DUPLICATE_PENDING_REQUEST: "The requester already has a pending request for this access.",
    Reason.SOD_CONFLICT: (
        "Separation of duties: this access conflicts with access the requester already holds."
    ),
    Reason.DENIED_BY_APPROVER: "An approver denied the request.",
    Reason.LOW_RISK_AUTO_APPROVED: (
        "Low-risk, read-only access for a pre-approved team, so it was approved instantly."
    ),
    Reason.MANAGER_APPROVAL_REQUIRED: "Needs approval from the requester's manager.",
    Reason.OWNER_APPROVAL_REQUIRED: "Needs approval from the resource owner.",
    Reason.SECURITY_APPROVAL_REQUIRED: "Needs approval from the security team.",
    Reason.ADMIN_ROLE_NEEDS_SECURITY: "Admin access always needs a security approval.",
    Reason.NO_MANAGER_ESCALATED: "The requester has no manager on file, so security approves instead.",
    Reason.REQUESTER_IS_OWNER_ESCALATED: "The requester owns this resource, so security approves instead.",
    Reason.MANAGER_IS_OWNER_ESCALATED: (
        "The requester's manager also owns this resource, so security approves the owner step "
        "to keep two independent approvers."
    ),
}


class RequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CANCELLED = "cancelled"


class GrantEnd(StrEnum):
    EXPIRED = "expired"
    REVOKED = "revoked"
    RELEASED = "released"


@dataclass(frozen=True, slots=True)
class User:
    id: str
    name: str
    email: str
    team: str
    title: str = ""
    manager_id: str | None = None
    is_security: bool = False


@dataclass(frozen=True, slots=True)
class Resource:
    id: str
    name: str
    description: str
    owner_id: str
    sensitivity: Sensitivity
    max_hours: int
    roles: tuple[Role, ...]
    auto_approve_teams: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class Entitlement:
    resource_id: str
    role: Role

    def satisfies(self, other: Entitlement) -> bool:
        """True if holding this entitlement means you also have ``other``."""
        return self.resource_id == other.resource_id and self.role.covers(other.role)


@dataclass(frozen=True, slots=True)
class SodRule:
    """Separation of duties: nobody may hold ``first`` and ``second`` at the same time.

    Each side matches the given role or any higher role on that resource.
    """

    id: str
    description: str
    first: Entitlement
    second: Entitlement

    def conflicts(self, requested: Entitlement, held: frozenset[Entitlement]) -> bool:
        for mine, other in ((self.first, self.second), (self.second, self.first)):
            if requested.satisfies(mine) and any(h.satisfies(other) for h in held):
                return True
        return False


@dataclass(frozen=True, slots=True)
class Draft:
    """A request as submitted, before any decision."""

    requester: User
    resource: Resource
    role: Role
    hours: int
    justification: str


@dataclass(frozen=True, slots=True)
class PolicyContext:
    held: frozenset[Entitlement]
    pending: frozenset[Entitlement]
    sod_rules: tuple[SodRule, ...]
    manager: User | None


@dataclass(frozen=True, slots=True)
class Decision:
    outcome: Outcome
    approvals: tuple[ApproverKind, ...]
    reasons: tuple[Reason, ...]
    detail: str = ""
