from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from accessdesk import policy
from accessdesk.models import (
    ApproverKind,
    Draft,
    Entitlement,
    Outcome,
    PolicyContext,
    Reason,
    Resource,
    Role,
    Sensitivity,
    SodRule,
    User,
)

MGR, OWN, SEC = ApproverKind.MANAGER, ApproverKind.OWNER, ApproverKind.SECURITY
V, E, A = Role.VIEWER, Role.EDITOR, Role.ADMIN
LOW, MED, HIGH, CRIT = Sensitivity.LOW, Sensitivity.MEDIUM, Sensitivity.HIGH, Sensitivity.CRITICAL

BOSS = User("boss", "Boss", "boss@example.com", "eng")
ALICE = User("alice", "Alice", "alice@example.com", "eng", manager_id="boss")


def res(sensitivity: Sensitivity, owner: str = "owner", roles: tuple[Role, ...] = (V, E, A)) -> Resource:
    return Resource("res", "Res", "", owner, sensitivity, 24, roles, frozenset({"eng"}))


def ctx(
    held: tuple[Entitlement, ...] = (),
    pending: tuple[Entitlement, ...] = (),
    rules: tuple[SodRule, ...] = (),
    manager: User | None = BOSS,
) -> PolicyContext:
    return PolicyContext(frozenset(held), frozenset(pending), rules, manager)


def decide(
    resource: Resource, role: Role = V, hours: int = 4, requester: User = ALICE, **kw: object
) -> tuple:
    d = policy.evaluate(Draft(requester, resource, role, hours, "a good reason"), ctx(**kw))  # type: ignore[arg-type]
    return d.outcome, d.approvals, d.reasons


@pytest.mark.parametrize(
    ("resource", "role", "expected_outcome", "expected_slots"),
    [
        (res(LOW), V, Outcome.AUTO_APPROVE, ()),
        (res(LOW), E, Outcome.NEEDS_APPROVAL, (MGR,)),
        (res(MED), V, Outcome.NEEDS_APPROVAL, (MGR,)),
        (res(HIGH), V, Outcome.NEEDS_APPROVAL, (MGR, OWN)),
        (res(CRIT), V, Outcome.NEEDS_APPROVAL, (MGR, OWN, SEC)),
        (res(HIGH), A, Outcome.NEEDS_APPROVAL, (MGR, OWN, SEC)),
        (res(MED), A, Outcome.NEEDS_APPROVAL, (MGR, SEC)),
        (res(CRIT), A, Outcome.NEEDS_APPROVAL, (MGR, OWN, SEC)),
    ],
)
def test_routing_by_sensitivity_and_role(
    resource: Resource, role: Role, expected_outcome: Outcome, expected_slots: tuple[ApproverKind, ...]
) -> None:
    outcome, slots, _ = decide(resource, role)
    assert outcome is expected_outcome
    assert slots == expected_slots


def test_low_risk_is_not_auto_approved_for_other_teams() -> None:
    outsider = User("zed", "Zed", "zed@example.com", "sales", manager_id="boss")
    assert decide(res(LOW), V, requester=outsider)[:2] == (Outcome.NEEDS_APPROVAL, (MGR,))


def test_admin_note_is_explained() -> None:
    _, _, reasons = decide(res(HIGH), A)
    assert Reason.ADMIN_ROLE_NEEDS_SECURITY in reasons


@pytest.mark.parametrize(
    ("resource", "kwargs", "expected_slots", "note"),
    [
        (res(HIGH), {"manager": None}, (OWN, SEC), Reason.NO_MANAGER_ESCALATED),
        (res(HIGH, owner="alice"), {}, (MGR, SEC), Reason.REQUESTER_IS_OWNER_ESCALATED),
        (res(HIGH, owner="boss"), {}, (MGR, SEC), Reason.MANAGER_IS_OWNER_ESCALATED),
        (res(CRIT), {"manager": None}, (OWN, SEC, SEC), Reason.NO_MANAGER_ESCALATED),
    ],
)
def test_escalations_keep_independent_approvers(
    resource: Resource, kwargs: dict[str, object], expected_slots: tuple[ApproverKind, ...], note: Reason
) -> None:
    outcome, slots, reasons = decide(resource, V, **kwargs)
    assert outcome is Outcome.NEEDS_APPROVAL
    assert slots == expected_slots
    assert note in reasons


@pytest.mark.parametrize(
    ("resource", "role", "hours", "kwargs", "reason"),
    [
        (res(MED, roles=(V,)), E, 4, {}, Reason.ROLE_NOT_OFFERED),
        (res(MED), V, 0, {}, Reason.DURATION_OUT_OF_RANGE),
        (res(MED), V, 25, {}, Reason.DURATION_OUT_OF_RANGE),
        (res(MED), V, 4, {"held": (Entitlement("res", E),)}, Reason.ALREADY_HAS_ACCESS),
        (res(MED), V, 4, {"pending": (Entitlement("res", V),)}, Reason.DUPLICATE_PENDING_REQUEST),
    ],
)
def test_denials(
    resource: Resource, role: Role, hours: int, kwargs: dict[str, object], reason: Reason
) -> None:
    outcome, slots, reasons = decide(resource, role, hours, **kwargs)
    assert (outcome, slots, reasons) == (Outcome.DENY, (), (reason,))


def test_separation_of_duties_matches_higher_roles_on_either_side() -> None:
    rule = SodRule("sod", "No edit + release.", Entitlement("res", E), Entitlement("other", E))
    # Holding admin on the other side still conflicts with asking for editor here.
    d = policy.evaluate(
        Draft(ALICE, res(MED), E, 4, "a good reason"), ctx(held=(Entitlement("other", A),), rules=(rule,))
    )
    assert d.outcome is Outcome.DENY
    assert d.reasons == (Reason.SOD_CONFLICT,)
    assert d.detail == "No edit + release."
    # A viewer role on this side does not match the editor side of the rule.
    assert decide(res(MED), V, held=(Entitlement("other", A),), rules=(rule,))[0] is Outcome.NEEDS_APPROVAL


def test_eligibility_and_four_eyes() -> None:
    resource = res(CRIT, owner="carol")
    carol = User("carol", "Carol", "c@example.com", "fin")
    sec = User("sec", "Sec", "s@example.com", "security", is_security=True)
    assert policy.eligible_kinds(ALICE, ALICE, resource) == frozenset()
    assert policy.eligible_kinds(BOSS, ALICE, resource) == {MGR}
    assert policy.eligible_kinds(carol, ALICE, resource) == {OWN}
    assert policy.eligible_kinds(sec, ALICE, resource) == {SEC}

    required = (MGR, OWN, SEC)
    assert policy.assign_slot(required, [], "boss", frozenset({MGR, SEC})) is MGR
    # The same person can never fill a second slot.
    assert policy.assign_slot(required, [(MGR, "boss")], "boss", frozenset({MGR, SEC})) is None
    assert policy.assign_slot(required, [(MGR, "boss")], "sec", frozenset({SEC})) is SEC
    assert policy.open_slots(required, [(MGR, "boss"), (SEC, "sec")]) == [OWN]


# --------------------------------------------------------------------------- properties

TEAMS = ("eng", "ops")
UNIVERSE = tuple(Entitlement(r, role) for r in ("res", "other") for role in Role)
RULES = (SodRule("sod", "No edit + release.", Entitlement("res", E), Entitlement("other", E)),)


@st.composite
def scenarios(draw: st.DrawFn) -> tuple[Draft, PolicyContext]:
    has_manager = draw(st.booleans())
    requester = User(
        "req", "Req", "r@example.com", draw(st.sampled_from(TEAMS)), manager_id="mgr" if has_manager else None
    )
    manager = User("mgr", "Mgr", "m@example.com", "eng") if has_manager else None
    owner = draw(st.sampled_from(["req", "mgr", "someone"]))
    roles = tuple(sorted(draw(st.sets(st.sampled_from(list(Role)), min_size=1)), key=lambda r: r.rank))
    resource = Resource(
        "res",
        "Res",
        "",
        owner,
        draw(st.sampled_from(list(Sensitivity))),
        draw(st.integers(1, 100)),
        roles,
        frozenset(draw(st.sets(st.sampled_from(TEAMS)))),
    )
    draft = Draft(requester, resource, draw(st.sampled_from(list(Role))), draw(st.integers(-5, 200)), "why")
    held = frozenset(draw(st.sets(st.sampled_from(UNIVERSE), max_size=3)))
    pending = frozenset(draw(st.sets(st.sampled_from(UNIVERSE), max_size=2)))
    return draft, PolicyContext(held, pending, RULES, manager)


@given(scenarios())
def test_policy_is_deterministic(case: tuple[Draft, PolicyContext]) -> None:
    draft, context = case
    assert policy.evaluate(draft, context) == policy.evaluate(draft, context)


@given(scenarios())
def test_auto_approval_only_for_low_risk_read_access(case: tuple[Draft, PolicyContext]) -> None:
    draft, context = case
    if policy.evaluate(draft, context).outcome is Outcome.AUTO_APPROVE:
        assert draft.resource.sensitivity is Sensitivity.LOW
        assert draft.role is Role.VIEWER
        assert draft.requester.team in draft.resource.auto_approve_teams


@given(scenarios())
def test_escalation_never_lowers_the_number_of_approvers(case: tuple[Draft, PolicyContext]) -> None:
    draft, context = case
    decision = policy.evaluate(draft, context)
    if decision.outcome is Outcome.NEEDS_APPROVAL:
        base = policy.BASE_APPROVALS[draft.resource.sensitivity]
        extra = 1 if draft.role is Role.ADMIN and SEC not in base else 0
        assert len(decision.approvals) == len(base) + extra
        if draft.role is Role.ADMIN:
            assert SEC in decision.approvals


@given(scenarios())
def test_named_approvers_are_never_the_requester_and_never_doubled(case: tuple[Draft, PolicyContext]) -> None:
    draft, context = case
    decision = policy.evaluate(draft, context)
    if decision.outcome is not Outcome.NEEDS_APPROVAL:
        return
    named = []
    if MGR in decision.approvals:
        assert context.manager is not None
        named.append(context.manager.id)
    if OWN in decision.approvals:
        named.append(draft.resource.owner_id)
    assert draft.requester.id not in named
    assert len(named) == len(set(named))


@given(scenarios())
def test_bad_requests_are_always_denied(case: tuple[Draft, PolicyContext]) -> None:
    draft, context = case
    decision = policy.evaluate(draft, context)
    wanted = Entitlement(draft.resource.id, draft.role)
    if (
        draft.role not in draft.resource.roles
        or not 1 <= draft.hours <= draft.resource.max_hours
        or any(h.satisfies(wanted) for h in context.held)
        or any(rule.conflicts(wanted, context.held) for rule in RULES)
    ):
        assert decision.outcome is Outcome.DENY
