"""Loading and saving the directory: people, managers, resources, owners and separation-of-duties rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from accessdesk import directory
from accessdesk.directory import ACTOR, DirectoryError
from accessdesk.models import ApproverKind, Reason, Role
from accessdesk.service import AccessService, ValidationFailed
from tests.helpers import csrf_from, sign_in

WHY = "Investigating payment incident INC-2041."


def audit_entries(service: AccessService) -> list[tuple[str, str, str]]:
    with service.db.connection() as conn:
        return [
            (r["actor"], r["action"], r["subject"])
            for r in conn.execute("SELECT * FROM audit_log ORDER BY seq")
        ]


def with_person(data: dict[str, Any], person_id: str, **changes: Any) -> dict[str, Any]:
    for person in data["people"]:
        if person["id"] == person_id:
            person.update(changes)
    return data


def with_resource(data: dict[str, Any], resource_id: str, **changes: Any) -> dict[str, Any]:
    for resource in data["resources"]:
        if resource["id"] == resource_id:
            resource.update(changes)
    return data


def apply(service: AccessService, data: dict[str, Any], *, dry_run: bool = False) -> directory.Report:
    return directory.apply(service, directory.parse(json.loads(json.dumps(data))), dry_run=dry_run)


def test_exporting_and_importing_again_changes_nothing(service: AccessService) -> None:
    exported = directory.export(service)
    assert [p["id"] for p in exported["people"]][:3] == ["alice", "bob", "carol"]
    assert exported["resources"][0]["id"] == "design-wiki"
    assert {r["id"] for r in exported["separation_of_duties"]} == {"sod-payments", "sod-payroll"}
    report = apply(service, exported)
    assert not report.changed
    assert report.lines() == ["No changes."]
    assert audit_entries(service) == []


def test_adding_people_resources_and_rules(service: AccessService, client: TestClient) -> None:
    data = directory.export(service)
    data["people"].append(
        {"id": "hana", "name": "Hana Ito", "email": "Hana@Example.com", "team": "data", "manager": "zed"}
    )
    data["people"].append(
        {"id": "zed", "name": "Zed Park", "email": "zed@example.com", "title": "Head of Data"}
    )
    data["resources"].append(
        {
            "id": "warehouse",
            "name": "Data Warehouse",
            "owner": "zed",
            "sensitivity": "medium",
            "max_hours": 48,
            "roles": ["viewer", "editor"],
        }
    )
    data["separation_of_duties"].append(
        {
            "id": "sod-warehouse",
            "description": "Nobody may both edit the warehouse and approve payments.",
            "first": {"resource": "warehouse", "role": "editor"},
            "second": {"resource": "payment-approvals", "role": "editor"},
        }
    )
    report = apply(service, data)
    assert report.people_added == ["hana", "zed"]
    assert report.resources_added == ["warehouse"]
    assert report.rules_replaced == 3
    assert report.lines()[:3] == [
        "People: 2 added (hana, zed), 0 updated.",
        "Resources: 1 added (warehouse), 0 updated.",
        "Separation-of-duties rules: replaced (3 now).",
    ]
    assert audit_entries(service) == [
        (ACTOR, "directory.person_added", "user:hana"),
        (ACTOR, "directory.person_added", "user:zed"),
        (ACTOR, "directory.resource_added", "resource:warehouse"),
        (ACTOR, "directory.sod_rules_replaced", "sod_rules"),
    ]
    hana = service.user("hana")
    assert hana is not None
    assert (hana.email, hana.manager_id, hana.is_security, hana.active) == (
        "hana@example.com",
        "zed",
        False,
        True,
    )

    sign_in(client, "hana")
    assert "Data Warehouse" in client.get("/requests/new").text
    result = service.submit("hana", "warehouse", "viewer", 8, WHY)
    assert result.decision.approvals == (ApproverKind.MANAGER,)


def test_changes_are_audited_with_before_and_after(service: AccessService) -> None:
    data = with_person(directory.export(service), "erin", title="Security Analyst", security=True)
    data = with_person(data, "alice", manager="maya")
    report = apply(service, data)
    assert report.people_updated == ["alice", "erin"]
    assert report.security_added == ["erin"]
    assert "Security team: added erin." in report.lines()
    with service.db.connection() as conn:
        details = [
            json.loads(r["details"]) for r in conn.execute("SELECT details FROM audit_log ORDER BY seq")
        ]
    assert details == [
        {"changes": {"manager": ["bob", "maya"]}},
        {"changes": {"title": ["Support Engineer", "Security Analyst"], "security": [False, True]}},
    ]
    erin = service.user("erin")
    assert erin is not None
    assert erin.is_security


def test_someone_who_leaves_loses_access_at_once(service: AccessService, client: TestClient) -> None:
    wiki = service.submit("alice", "design-wiki", "viewer", 8, WHY).grant_id
    pending = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    sign_in(client, "alice")
    assert service.check("alice", "design-wiki", Role.VIEWER).allowed

    report = apply(service, with_person(directory.export(service), "alice", active=False))
    assert report.people_removed == ["alice"]
    assert (report.grants_ended, report.requests_cancelled, report.sessions_ended) == (1, 1, 1)
    assert not service.check("alice", "design-wiki", Role.VIEWER).allowed
    assert service.request_page(pending, "dan").request.status.value == "cancelled"
    [grant] = service.my_grants("alice")[1]
    assert (grant.id, grant.end_reason, grant.ended_by) == (wiki, "revoked", ACTOR)
    assert client.get("/").status_code == 303  # the session ended

    picker = client.get("/signin").text
    assert 'value="alice"' not in picker
    refused = client.post("/signin", data={"csrf_token": csrf_from(picker), "user_id": "alice"})
    assert refused.status_code == 422

    # Coming back works too, without the old access.
    apply(service, with_person(directory.export(service), "alice", active=True))
    assert "alice" in {u.id for u in service.users(active_only=True)}
    assert not service.check("alice", "design-wiki", Role.VIEWER).allowed


def test_retiring_a_resource(service: AccessService, client: TestClient) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    service.approve(request_id, "bob")
    service.approve(request_id, "frank")
    waiting = service.submit("erin", "prod-db", "viewer", 8, WHY).request_id

    report = apply(service, with_resource(directory.export(service), "prod-db", active=False))
    assert report.resources_retired == ["prod-db"]
    assert (report.grants_ended, report.requests_cancelled) == (1, 1)
    assert not service.check("alice", "prod-db", Role.VIEWER).allowed
    assert service.request_page(waiting, "dan").request.status.value == "cancelled"
    with pytest.raises(ValidationFailed) as refused:
        service.submit("alice", "prod-db", "viewer", 8, WHY)
    assert refused.value.errors == {"resource_id": "Choose a resource from the list"}

    sign_in(client, "alice")
    assert "Production Database" not in client.get("/requests/new").text
    assert client.get("/requests/new?resource=prod-db").status_code == 404
    assert "Production Database" in client.get(f"/requests/{request_id}").text  # history stays


def test_every_mistake_is_reported_and_nothing_changes(service: AccessService) -> None:
    data = {
        "people": [
            {"id": "ok", "name": "Ok", "email": "ok@example.com", "manager": "ok"},
            {"id": "bad id!", "name": "", "email": "not-an-email", "colour": "blue"},
            {"id": "twin", "name": "Twin", "email": "OK@example.com", "security": "yes"},
            {"id": "twin", "name": "Twin again", "email": "twin@example.com"},
        ],
        "resources": [
            {
                "id": "r1",
                "name": "R1",
                "owner": "ok",
                "sensitivity": "extreme",
                "max_hours": 0,
                "roles": ["root"],
            },
            {"id": "r2", "name": "R2", "owner": "ok", "sensitivity": "low", "max_hours": 1, "roles": []},
        ],
        "separation_of_duties": [
            {"id": "s1", "description": "x", "first": {"resource": "r1"}, "second": "r2"}
        ],
        "groups": [],
    }
    with pytest.raises(DirectoryError) as caught:
        directory.parse(data)
    problems = caught.value.problems
    expected = [
        'Unknown section "groups"',
        'people[0] ("ok") cannot be their own manager.',
        'people[1] ("bad id!") has an unknown field "colour"',
        'people[1] ("bad id!") "id" must be an id',
        'people[1] ("bad id!") "email" does not look like an email address',
        'people[1] ("bad id!") "name" cannot be empty.',
        'people[2] ("twin") has the same email as ok.',
        'people[2] ("twin") "security" must be true or false.',
        'people[3] ("twin") repeats the id "twin".',
        'resources[0] ("r1") "sensitivity" must be low, medium, high or critical.',
        'resources[0] ("r1") "max_hours" must be a whole number from 1 to 8760.',
        'resources[0] ("r1") "roles" can only contain viewer, editor and admin.',
        'resources[1] ("r2") "roles" must list at least one of viewer, editor, admin.',
        'separation_of_duties[0] ("s1") "first" must look like',
        'separation_of_duties[0] ("s1") "second" must look like',
    ]
    for text in expected:
        assert any(text in problem for problem in problems), (text, problems)
    assert len(problems) == len(expected)


def test_references_are_checked_against_the_whole_directory(service: AccessService) -> None:
    before = directory.export(service)
    cases: list[tuple[dict[str, Any], str]] = [
        ({"people": [{"id": "x", "name": "X", "email": "x@example.com", "manager": "nobody"}]}, "manager"),
        ({"people": [{"id": "x", "name": "X", "email": "alice@example.com"}]}, "own email address"),
        (with_person(directory.export(service), "frank", active=False), "needs an owner who is"),
        (
            {
                "resources": [
                    {
                        "id": "r",
                        "name": "R",
                        "owner": "ghost",
                        "sensitivity": "low",
                        "max_hours": 1,
                        "roles": ["viewer"],
                    }
                ]
            },
            'Resource "r" needs an owner',
        ),
        (
            {
                "separation_of_duties": [
                    {
                        "id": "s",
                        "description": "Rule",
                        "first": {"resource": "prod-db", "role": "admin"},
                        "second": {"resource": "missing", "role": "viewer"},
                    }
                ]
            },
            'rule "s" names a resource that does not exist',
        ),
    ]
    for data, message in cases:
        with pytest.raises(DirectoryError, match=message):
            apply(service, data)
    assert directory.export(service) == before
    assert audit_entries(service) == []


def test_two_people_can_swap_email_addresses(service: AccessService) -> None:
    data = with_person(directory.export(service), "dan", email="grace@example.com")
    data = with_person(data, "grace", email="dan@example.com")
    assert apply(service, data).people_updated == ["dan", "grace"]
    dan = service.user_by_email("grace@example.com")
    assert dan is not None
    assert dan.id == "dan"


def test_a_dry_run_reports_without_saving(service: AccessService) -> None:
    before = directory.export(service)
    report = apply(service, with_person(directory.export(service), "bob", title="Director"), dry_run=True)
    assert report.people_updated == ["bob"]
    assert directory.export(service) == before
    assert audit_entries(service) == []


def test_if_a_manager_leaves_security_approves_instead(service: AccessService) -> None:
    report = apply(service, with_person(directory.export(service), "bob", active=False))
    assert (
        "Warning: alice's manager bob is not active, so security approves their requests." in report.lines()
    )
    result = service.submit("alice", "finance-dashboards", "viewer", 8, WHY)
    assert result.decision.approvals == (ApproverKind.SECURITY,)
    assert Reason.NO_MANAGER_ESCALATED in result.decision.reasons


def test_people_not_in_the_file_are_left_alone(service: AccessService) -> None:
    report = apply(service, {"people": [{"id": "new", "name": "New Person", "email": "new@example.com"}]})
    assert report.people_added == ["new"]
    assert len(report.people_not_in_file) == 8
    assert service.user("alice") is not None
    assert "Not in the file, so left as they are: 8 people (alice, bob" in "\n".join(report.lines())


def test_loading_reports_unreadable_files(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text('{"people": [}', encoding="utf-8")
    with pytest.raises(DirectoryError, match="is not valid JSON"):
        directory.load(broken)
    with pytest.raises(DirectoryError, match="Cannot read"):
        directory.load(tmp_path / "missing.json")
    with pytest.raises(DirectoryError, match="one JSON object"):
        directory.parse([])


def test_waiting_requests_go_to_security_when_the_manager_leaves(service: AccessService) -> None:
    waiting = service.submit("alice", "finance-dashboards", "viewer", 8, WHY).request_id  # needs bob
    half_done = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    service.approve(half_done, "bob")  # bob's step is done; only the owner's is left

    report = apply(service, with_person(directory.export(service), "bob", active=False))
    assert report.requests_rerouted == 1
    assert "Sent 1 waiting request(s) to the security team" in "\n".join(report.lines())
    page = service.request_page(waiting, "dan")
    assert page.request.required == (ApproverKind.SECURITY,)
    assert Reason.NO_MANAGER_ESCALATED in page.request.reasons
    assert page.my_slot is ApproverKind.SECURITY
    assert [r.id for r in service.pending_for("dan")] == [waiting]
    assert service.approve(waiting, "dan").status.value == "approved"
    assert service.request_page(half_done, "frank").request.required == (
        ApproverKind.MANAGER,
        ApproverKind.OWNER,
    )
    assert (ACTOR, "request.rerouted", f"request:{waiting}") in audit_entries(service)


def test_a_new_manager_takes_over_waiting_requests(service: AccessService) -> None:
    waiting = service.submit("alice", "finance-dashboards", "viewer", 8, WHY).request_id
    data = with_person(directory.export(service), "bob", active=False)
    data = with_person(data, "alice", manager="maya")
    data = with_person(data, "erin", manager="maya")
    assert apply(service, data).requests_rerouted == 0
    assert service.request_page(waiting, "maya").my_slot is ApproverKind.MANAGER


def test_broken_files_never_crash_or_half_apply(service: AccessService, tmp_path: Path) -> None:
    retired = {
        "resources": [
            {
                "id": "old",
                "name": "Old",
                "owner": "ghost",
                "sensitivity": "low",
                "max_hours": 1,
                "roles": ["viewer"],
                "active": False,
            }
        ]
    }
    for dry_run in (True, False):
        with pytest.raises(DirectoryError, match='Resource "old" needs an owner'):
            apply(service, retired, dry_run=dry_run)
    assert apply(service, {"people": []}).lines()[0] == "No changes."  # the connection is still usable

    rule = {"id": "s", "description": "Rule", "first": {"resource": "a", "role": ["editor"]}, "second": "x"}
    with pytest.raises(DirectoryError, match='"first" must look like'):
        directory.parse({"separation_of_duties": [rule]})

    latin1 = tmp_path / "latin1.json"
    latin1.write_bytes('{"people": [{"name": "Jos\xe9"}]}'.encode("latin-1"))
    with pytest.raises(DirectoryError, match="is not UTF-8 text"):
        directory.load(latin1)


def test_changing_someones_email_signs_them_out(service: AccessService, client: TestClient) -> None:
    sign_in(client, "alice")
    report = apply(service, with_person(directory.export(service), "alice", email="alice.chen@example.com"))
    assert report.sessions_ended == 1
    assert client.get("/").status_code == 303


@pytest.mark.parametrize(
    ("change", "approve_first", "reason"),
    [
        ({"people": {"alice": {"manager": "frank"}}}, None, Reason.MANAGER_IS_OWNER_ESCALATED),
        ({"resources": {"prod-db": {"owner": "alice"}}}, None, Reason.REQUESTER_IS_OWNER_ESCALATED),
        ({"resources": {"prod-db": {"owner": "bob"}}}, "bob", Reason.DIRECTORY_CHANGED_ESCALATED),
    ],
    ids=["manager-now-owns-it", "requester-now-owns-it", "owner-already-approved"],
)
def test_steps_nobody_could_approve_after_a_change_go_to_security(
    service: AccessService,
    change: dict[str, dict[str, dict[str, str]]],
    approve_first: str | None,
    reason: Reason,
) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id  # manager bob, owner frank
    if approve_first:
        service.approve(request_id, approve_first)
    data = directory.export(service)
    for person, values in change.get("people", {}).items():
        data = with_person(data, person, **values)
    for resource, values in change.get("resources", {}).items():
        data = with_resource(data, resource, **values)
    assert apply(service, data).requests_rerouted == 1

    request = service.request_page(request_id, "dan").request
    assert ApproverKind.OWNER not in request.required
    assert request.required.count(ApproverKind.SECURITY) == 1
    assert reason in request.reasons
    manager = service.user("alice").manager_id  # type: ignore[union-attr]
    if not approve_first:
        service.approve(request_id, str(manager))
    assert service.approve(request_id, "dan").status.value == "approved"
