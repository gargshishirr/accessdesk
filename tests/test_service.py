from __future__ import annotations

import threading
from collections.abc import Callable
from functools import partial
from typing import Any

import pytest

from accessdesk.clock import ManualClock
from accessdesk.db import Database
from accessdesk.models import ApproverKind, GrantEnd, Outcome, Reason, RequestStatus, Role
from accessdesk.seed import seed_activity, seed_directory
from accessdesk.service import AccessService, Conflict, Forbidden, NotFound, ValidationFailed

MGR, OWN, SEC = ApproverKind.MANAGER, ApproverKind.OWNER, ApproverKind.SECURITY
WHY = "Investigating payment incident INC-2041."
HOUR = 3600


def granted(
    service: AccessService, user: str, resource: str, role: str, approvers: list[str], hours: int = 8
) -> int:
    submitted = service.submit(user, resource, role, hours, WHY)
    grant_id = submitted.grant_id
    for approver in approvers:
        grant_id = service.approve(submitted.request_id, approver).grant_id
    assert grant_id is not None
    return grant_id


def grants_for(db: Database, request_id: int) -> int:
    with db.connection() as conn:
        return int(
            conn.execute("SELECT COUNT(*) FROM grants WHERE request_id = ?", (request_id,)).fetchone()[0]
        )


def run_together(*calls: Callable[[], Any]) -> list[Any]:
    """Start every call at the same instant on its own thread; return results or raised exceptions."""
    barrier = threading.Barrier(len(calls))
    results: list[Any] = [None] * len(calls)

    def worker(i: int, call: Callable[[], Any]) -> None:
        barrier.wait()
        try:
            results[i] = call()
        except Exception as exc:
            results[i] = exc

    threads = [threading.Thread(target=worker, args=(i, c)) for i, c in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results


# --------------------------------------------------------------------------- happy paths


def test_low_risk_read_access_is_granted_at_once_and_expires_on_time(
    service: AccessService, clock: ManualClock
) -> None:
    result = service.submit("alice", "design-wiki", "viewer", 8, WHY)
    assert result.decision.outcome is Outcome.AUTO_APPROVE
    assert result.grant_id is not None
    assert service.check("alice", "design-wiki", Role.VIEWER).allowed
    assert service.check("alice", "design-wiki", Role.EDITOR).reason == "role_insufficient"

    clock.advance(8 * HOUR - 1)
    assert service.check("alice", "design-wiki", Role.VIEWER).allowed
    clock.advance(1)
    # Fail closed: the grant stops working at its expiry even before the sweeper has run.
    assert service.check("alice", "design-wiki", Role.VIEWER).reason == "no_active_grant"

    assert service.expire_due() == 1
    assert service.expire_due() == 0
    active, ended = service.my_grants("alice")
    assert active == []
    assert [(g.end_reason, g.ended_at == g.expires_at) for g in ended] == [(GrantEnd.EXPIRED, True)]


def test_high_risk_access_needs_manager_and_owner_in_any_order(service: AccessService) -> None:
    submitted = service.submit("alice", "prod-db", "editor", 8, WHY)
    assert submitted.decision.approvals == (MGR, OWN)
    request_id = submitted.request_id
    assert [r.id for r in service.pending_for("bob")] == [request_id]
    assert [r.id for r in service.pending_for("frank")] == [request_id]
    assert service.pending_for("dan") == []  # security has no slot on a high-risk viewer/editor request
    assert service.pending_for("carol") == []

    first = service.approve(request_id, "frank", "Owner OK.")
    assert (first.status, first.remaining) == (RequestStatus.PENDING, (MGR,))
    assert not service.check("alice", "prod-db", Role.VIEWER).allowed

    second = service.approve(request_id, "bob")
    assert second.status is RequestStatus.APPROVED
    assert second.grant_id is not None
    assert service.check("alice", "prod-db", Role.VIEWER).allowed  # editor covers viewer
    assert service.pending_for("bob") == []


def test_critical_access_needs_three_different_people(service: AccessService) -> None:
    request_id = service.submit("erin", "payroll-console", "viewer", 4, WHY).request_id
    assert service.approve(request_id, "bob").remaining == (OWN, SEC)
    with pytest.raises(Conflict, match="already approved"):
        service.approve(request_id, "bob")
    assert service.approve(request_id, "dan").remaining == (OWN,)
    assert service.pending_for("grace") == []  # the only security slot is taken
    final = service.approve(request_id, "carol")
    assert final.status is RequestStatus.APPROVED

    page = service.request_page(request_id, "erin")
    assert [(s.kind, s.approval.approver.id if s.approval else None) for s in page.slots] == [
        (MGR, "bob"),
        (OWN, "carol"),
        (SEC, "dan"),
    ]
    assert page.request.grant is not None
    assert page.request.grant.expires_at - page.request.grant.granted_at == 4 * HOUR


def test_people_outside_the_route_cannot_decide(service: AccessService) -> None:
    request_id = service.submit("bob", "prod-db", "viewer", 8, WHY).request_id
    with pytest.raises(Forbidden, match="your own request"):
        service.approve(request_id, "bob")
    with pytest.raises(Forbidden, match="not an approver"):
        service.approve(request_id, "erin")
    with pytest.raises(Forbidden, match="Unknown user"):
        service.approve(request_id, "nobody")
    with pytest.raises(NotFound):
        service.approve(9999, "maya")


# --------------------------------------------------------------------------- denials


def test_denial_needs_a_reason_and_closes_the_request(service: AccessService) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    with pytest.raises(ValidationFailed) as error:
        service.deny(request_id, "bob", "  no ")
    assert set(error.value.errors) == {"comment"}

    assert service.deny(request_id, "bob", "Use the read replica instead.").status is RequestStatus.DENIED
    page = service.request_page(request_id, "alice")
    assert Reason.DENIED_BY_APPROVER in page.request.reasons
    assert page.slots[0].approval is not None
    assert page.slots[0].approval.verdict == "deny"
    with pytest.raises(Conflict, match="already denied"):
        service.approve(request_id, "frank")


def test_only_the_requester_can_cancel_and_only_while_pending(service: AccessService) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    with pytest.raises(Forbidden):
        service.cancel(request_id, "bob")
    assert service.cancel(request_id, "alice").status is RequestStatus.CANCELLED
    with pytest.raises(Conflict):
        service.cancel(request_id, "alice")
    assert service.pending_for("bob") == []


def test_duplicate_requests_are_refused(service: AccessService) -> None:
    service.submit("alice", "prod-db", "viewer", 8, WHY)
    again = service.submit("alice", "prod-db", "viewer", 4, WHY)
    assert again.decision.outcome is Outcome.DENY
    assert again.decision.reasons == (Reason.DUPLICATE_PENDING_REQUEST,)


def test_separation_of_duties_blocks_the_second_half_at_submit(service: AccessService) -> None:
    granted(service, "alice", "payments-ledger", "editor", ["bob", "frank"])
    result = service.submit("alice", "payment-approvals", "editor", 8, WHY)
    assert result.decision.outcome is Outcome.DENY
    assert result.decision.reasons == (Reason.SOD_CONFLICT,)
    assert "edit payments and release them" in result.decision.detail
    assert result.grant_id is None


def test_separation_of_duties_is_rechecked_at_the_final_approval(service: AccessService) -> None:
    """Both halves were requested before either was granted; the second must fail closed."""
    approvals_request = service.submit("alice", "payment-approvals", "editor", 8, WHY).request_id
    granted(service, "alice", "payments-ledger", "editor", ["bob", "frank"])

    assert service.approve(approvals_request, "bob").status is RequestStatus.PENDING
    final = service.approve(approvals_request, "carol")
    assert final.status is RequestStatus.DENIED
    assert final.grant_id is None
    page = service.request_page(approvals_request, "alice")
    assert page.request.reasons[-1] is Reason.SOD_CONFLICT
    assert not service.check("alice", "payment-approvals", Role.EDITOR).allowed


def test_access_gained_meanwhile_is_rechecked_at_the_final_approval(service: AccessService) -> None:
    viewer_request = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    granted(service, "alice", "prod-db", "editor", ["bob", "frank"])
    service.approve(viewer_request, "bob")
    final = service.approve(viewer_request, "frank")
    assert final.status is RequestStatus.DENIED
    assert service.request_page(viewer_request, "alice").request.reasons[-1] is Reason.ALREADY_HAS_ACCESS


# --------------------------------------------------------------------------- concurrency


def test_a_stale_page_cannot_approve(service: AccessService) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    seen_by_bob = service.request_page(request_id, "bob").request.version
    service.approve(request_id, "frank", expected_version=seen_by_bob)
    with pytest.raises(Conflict, match="changed after you opened it"):
        service.approve(request_id, "bob", expected_version=seen_by_bob)
    latest = service.request_page(request_id, "bob").request.version
    assert service.approve(request_id, "bob", expected_version=latest).status is RequestStatus.APPROVED


def test_racing_final_approvals_create_exactly_one_grant(service: AccessService, db: Database) -> None:
    for _ in range(10):
        request_id = service.submit("erin", "payroll-console", "viewer", 4, WHY).request_id
        service.approve(request_id, "bob")
        service.approve(request_id, "carol")
        results = run_together(
            partial(service.approve, request_id, "dan"), partial(service.approve, request_id, "grace")
        )
        approved = [r for r in results if not isinstance(r, Exception)]
        assert len(approved) == 1, results
        assert approved[0].status is RequestStatus.APPROVED
        assert all(isinstance(r, Conflict) for r in results if isinstance(r, Exception)), results
        assert grants_for(db, request_id) == 1
        assert approved[0].grant_id is not None
        service.release(approved[0].grant_id, "erin")
    assert service.verify_audit().ok


def test_concurrent_writers_keep_the_audit_chain_linear(service: AccessService) -> None:
    people = ["alice", "bob", "carol", "dan", "erin", "frank", "grace", "maya"]
    results = run_together(*(partial(service.submit, p, "design-wiki", "viewer", 8, WHY) for p in people))
    assert all(r.grant_id is not None for r in results), results
    verification = service.verify_audit()
    assert verification.ok
    assert verification.events == 2 * len(people)  # one submit + one grant each


# --------------------------------------------------------------------------- grants


def test_release_and_revoke_rules(service: AccessService) -> None:
    grant_id = granted(service, "alice", "prod-db", "viewer", ["bob", "frank"])
    with pytest.raises(Forbidden):
        service.release(grant_id, "erin")
    with pytest.raises(Forbidden, match="owner or the security team"):
        service.revoke(grant_id, "carol", "Not your resource.")
    with pytest.raises(ValidationFailed) as error:
        service.revoke(grant_id, "frank", "")
    assert set(error.value.errors) == {"note"}

    service.revoke(grant_id, "frank", "Incident closed.")
    assert not service.check("alice", "prod-db", Role.VIEWER).allowed
    with pytest.raises(Conflict):
        service.revoke(grant_id, "dan", "Again.")
    _, ended = service.my_grants("alice")
    assert [(g.end_reason, g.ended_by, g.end_note) for g in ended] == [
        (GrantEnd.REVOKED, "frank", "Incident closed.")
    ]

    wiki = granted(service, "alice", "design-wiki", "viewer", [])
    service.release(wiki, "alice")
    assert not service.check("alice", "design-wiki", Role.VIEWER).allowed
    with pytest.raises(NotFound):
        service.release(9999, "alice")


def test_reviews_show_owners_their_resources_and_security_everything(service: AccessService) -> None:
    granted(service, "alice", "prod-db", "viewer", ["bob", "frank"])
    granted(service, "erin", "finance-dashboards", "viewer", ["bob"])
    assert [g.resource.id for g in service.reviewable_grants("frank")] == ["prod-db"]
    assert [g.resource.id for g in service.reviewable_grants("carol")] == ["finance-dashboards"]
    assert sorted(g.resource.id for g in service.reviewable_grants("grace")) == [
        "finance-dashboards",
        "prod-db",
    ]
    assert service.reviewable_grants("alice") == []
    assert service.reviewable_grants("nobody") == []


# --------------------------------------------------------------------------- validation & visibility


def test_every_missing_field_gets_its_own_message(service: AccessService) -> None:
    with pytest.raises(ValidationFailed) as error:
        service.submit("alice", "", "", "", "   ")
    assert set(error.value.errors) == {"resource_id", "role", "hours", "justification"}


@pytest.mark.parametrize(
    ("resource", "role", "hours", "why", "field", "message"),
    [
        ("no-such-thing", "viewer", "8", WHY, "resource_id", "Choose a resource from the list"),
        ("prod-db", "owner", "8", WHY, "role", "Choose viewer, editor or admin"),
        ("finance-dashboards", "admin", "8", WHY, "role", "Choose viewer or editor"),
        ("prod-db", "viewer", "eight", WHY, "hours", "whole number"),
        ("prod-db", "viewer", "\u0663", WHY, "hours", "whole number"),  # an Arabic-Indic digit
        ("prod-db", "viewer", "0", WHY, "hours", "at least 1 hour"),
        ("prod-db", "viewer", "25", WHY, "hours", "Enter 24 hours or fewer for Production Database"),
        ("prod-db", "viewer", "8", "Because", "justification", "at least 10 characters"),
        ("prod-db", "viewer", "8", "x" * 501, "justification", "500 characters or fewer"),
    ],
)
def test_field_level_validation(
    service: AccessService, resource: str, role: str, hours: str, why: str, field: str, message: str
) -> None:
    with pytest.raises(ValidationFailed) as error:
        service.submit("alice", resource, role, hours, why)
    assert set(error.value.errors) == {field}
    assert message in error.value.errors[field]


def test_unknown_users_cannot_submit(service: AccessService) -> None:
    with pytest.raises(Forbidden):
        service.submit("mallory", "prod-db", "viewer", 8, WHY)


def test_request_pages_are_visible_only_to_people_involved(service: AccessService) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    mine = service.request_page(request_id, "alice")
    assert (mine.can_cancel, mine.my_slot) == (True, None)
    assert service.request_page(request_id, "bob").my_slot is MGR
    assert service.request_page(request_id, "frank").my_slot is OWN
    security = service.request_page(request_id, "dan")
    assert (security.can_cancel, security.my_slot) == (False, None)
    for outsider in ("erin", "carol", "nobody"):
        with pytest.raises(NotFound):
            service.request_page(request_id, outsider)
    with pytest.raises(NotFound):
        service.request_page(424242, "alice")


def test_audit_log_is_security_only_and_records_the_demo(service: AccessService, db: Database) -> None:
    seed_activity(service)
    with pytest.raises(Forbidden):
        service.audit_log("alice")
    events, verification = service.audit_log("dan")
    assert verification.ok
    assert {e.action for e in events} >= {"request.submitted", "request.approved", "grant.created"}
    assert events[0].seq == verification.events  # newest first
    assert not seed_directory(db)  # seeding twice is a no-op
