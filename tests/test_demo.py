"""Demo mode's guided experience: persona sign-in, the person switcher, the approval summary on the request
form, duration presets, the 60-second checklist and the dashboard."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from accessdesk.models import Outcome, Role
from accessdesk.seed import seed_activity
from accessdesk.service import AccessService
from tests.helpers import csrf_from, sign_in

WHY = "Investigating payment incident INC-2041."


def switch_to(client: TestClient, user_id: str, next_url: str = "/") -> str:
    """Click a persona button: a form post that keeps the browser's cookies, as a real switch does. The
    token comes from a page that does not tick off any guided demo step."""
    page = client.get("/requests/new")
    token = csrf_from((client.get("/signin") if page.status_code == 303 else page).text)
    response = client.post("/signin", data={"csrf_token": token, "user_id": user_id, "next": next_url})
    assert response.status_code == 303, response.text
    return str(response.headers["location"])


def route_summary(html: str) -> dict[str, list[str]]:
    """The request form's "Who will approve this" box: roles -> approver lines, in order."""
    box = re.search(r'<section class="route-summary".*?</section>', html, re.DOTALL)
    assert box, "the form has no approval summary"
    options: dict[str, list[str]] = {}
    for option in re.findall(r'<div class="route-option">(.*?)</div>', box.group(0), re.DOTALL):
        roles = re.search(r"<strong>(.*?) access:</strong>", option)
        assert roles
        options[roles.group(1)] = [line.strip() for line in re.findall(r"<li>(.*?)</li>", option, re.DOTALL)]
    return options


# --------------------------------------------------------------------------- personas and switching


def test_persona_cards_sign_in_with_one_click(client: TestClient) -> None:
    picker = client.get("/signin?next=/approvals").text
    for name, label in [
        ("Alice Chen", "Requester"),
        ("Bob Singh", "Manager"),
        ("Frank Moreau", "Resource owner"),
        ("Dan Okafor", "Security reviewer"),
    ]:
        assert f"Continue as {name}</button>" in picker
        assert f'<span class="chip">{label}</span>' in picker
    assert "Manages Alice and Erin, and approves their requests." in picker
    assert "Owns Production Database, Payments Ledger and 2 more." in picker
    assert 'id="user-maya"' in picker  # everyone else is still one radio button away

    token = csrf_from(picker)
    response = client.post("/signin", data={"csrf_token": token, "user_id": "bob", "next": "/approvals"})
    assert response.headers["location"] == "/approvals"
    page = client.get("/approvals").text
    assert '<span class="account-label">Viewing as</span> <span class="account-name">Bob Singh</span>' in page
    assert '<span class="account-role">Manager</span>' in page


def test_the_header_switches_person_in_one_click(client: TestClient) -> None:
    sign_in(client, "alice")
    home = client.get("/").text
    assert "Switch person</summary>" in home
    switcher = home[home.index('<details class="switcher">') : home.index("</details>")]
    assert re.findall(r'name="user_id" value="(\w+)"', switcher) == ["bob", "frank", "dan"]  # not herself
    assert 'href="/switch"' in switcher

    assert switch_to(client, "frank") == "/"
    assert '<span class="account-name">Frank Moreau</span>' in client.get("/").text
    everyone = client.get("/switch")
    assert everyone.status_code == 200
    assert "You are viewing as Frank Moreau." in everyone.text
    assert 'id="user-priya"' in everyone.text


def test_switch_page_needs_a_signed_in_person(client: TestClient) -> None:
    assert client.get("/switch").headers["location"] == "/signin?next=/switch"


def test_people_who_left_are_not_personas(client: TestClient, service: AccessService) -> None:
    with service.db.write() as conn:
        conn.execute("UPDATE users SET active = 0 WHERE id = 'frank'")
    picker = client.get("/signin").text
    assert "Continue as Frank Moreau" not in picker
    assert 'value="frank"' not in picker
    assert "Continue as Alice Chen" in picker


# --------------------------------------------------------------------------- the request form


@pytest.mark.parametrize(
    ("person", "resource", "expected"),
    [
        (
            "alice",
            "prod-db",
            {
                "Viewer or editor": [
                    "Bob Singh (your manager)",
                    "Frank Moreau (owner of Production Database)",
                ],
                "Admin": [
                    "Bob Singh (your manager)",
                    "Frank Moreau (owner of Production Database)",
                    "Someone from security (Dan Okafor or Grace Liu)",
                ],
            },
        ),
        # Frank owns the database, so security takes the owner's place.
        (
            "frank",
            "prod-db",
            {
                "Viewer or editor": [
                    "Maya Rao (your manager)",
                    "Someone from security (Dan Okafor or Grace Liu)",
                ],
                "Admin": [
                    "Maya Rao (your manager)",
                    "Someone from security (Dan Okafor or Grace Liu)",
                    "A second, different person from security",
                ],
            },
        ),
        # Leo's manager owns the cluster, so security approves the owner step instead.
        (
            "leo",
            "k8s-prod",
            {
                "Viewer or editor": [
                    "Frank Moreau (your manager)",
                    "Someone from security (Dan Okafor or Grace Liu)",
                ],
                "Admin": [
                    "Frank Moreau (your manager)",
                    "Someone from security (Dan Okafor or Grace Liu)",
                    "A second, different person from security",
                ],
            },
        ),
        # Security staff never approve their own requests, so only the other security engineer can.
        (
            "dan",
            "payroll-console",
            {
                "Viewer or editor or admin": [
                    "Maya Rao (your manager)",
                    "Carol Diaz (owner of Payroll Admin Console)",
                    "Someone from security (Grace Liu)",
                ]
            },
        ),
        ("alice", "design-wiki", {"Viewer": [], "Editor": ["Bob Singh (your manager)"]}),
    ],
)
def test_the_approval_summary_is_what_the_policy_will_do(
    client: TestClient, service: AccessService, person: str, resource: str, expected: dict[str, list[str]]
) -> None:
    sign_in(client, person)
    form = client.get(f"/requests/new?resource={resource}").text
    assert route_summary(form) == expected

    # What the form promised is exactly what submitting does, role by role.
    preview = service.preview(person, resource)
    for role, decision in preview.items():
        sent = service.submit(person, resource, role.value, 1, WHY)
        assert sent.decision == decision
        if decision.outcome is Outcome.NEEDS_APPROVAL:
            service.cancel(sent.request_id, person)
        elif sent.grant_id is not None:
            service.release(sent.grant_id, person)


def test_the_summary_explains_when_a_role_is_not_available(
    client: TestClient, service: AccessService
) -> None:
    ledger = service.submit("alice", "payments-ledger", "editor", 8, WHY).request_id
    service.approve(ledger, "bob")
    service.approve(ledger, "frank")
    sign_in(client, "alice")
    form = client.get("/requests/new?resource=payment-approvals").text
    assert route_summary(form) == {
        "Viewer": ["Bob Singh (your manager)", "Carol Diaz (owner of Payment Approvals)"],
        "Editor": [],
    }
    assert "not available to you right now." in form
    assert "Rule: Nobody may both edit payments and release them." in form
    assert "Payment Approvals is high sensitivity, so the policy needs two independent approvals" in form
    assert service.preview("alice", "payment-approvals")[Role.EDITOR].outcome is Outcome.DENY


@pytest.mark.parametrize(
    ("hours", "other", "saved"),
    [("8", "", 8), ("other", "5", 5), ("", "3", 3), ("4", "9", 4)],
    ids=["preset", "other", "typed-without-choosing", "preset-wins"],
)
def test_duration_presets_and_other_lengths(
    client: TestClient, service: AccessService, hours: str, other: str, saved: int
) -> None:
    token = sign_in(client, "alice")
    form = client.get("/requests/new?resource=prod-db").text
    assert [int(h) for h in re.findall(r'id="hours-(\d+)" name="hours"', form)] == [1, 4, 8, 24]
    sent = client.post(
        "/requests",
        data={
            "csrf_token": token,
            "resource_id": "prod-db",
            "role": "viewer",
            "hours": hours,
            "hours_other": other,
            "justification": WHY,
        },
    )
    assert sent.status_code == 303
    [request] = service.my_requests("alice")
    assert request.hours == saved


def test_choosing_other_without_a_number_keeps_the_choice(client: TestClient) -> None:
    token = sign_in(client, "alice")
    data = {"csrf_token": token, "resource_id": "prod-db", "role": "viewer", "justification": WHY}
    response = client.post("/requests", data={**data, "hours": "other", "hours_other": ""})
    assert response.status_code == 422
    assert '<a href="#hours">Enter how many hours you need access for</a>' in response.text
    assert 'id="hours-other" name="hours" value="other" checked' in response.text


# --------------------------------------------------------------------------- the guided demo


def tour_progress(client: TestClient) -> str:
    match = re.search(r'<p class="tour-count"><strong>(\d+ of \d+)</strong>', client.get("/").text)
    assert match, "no guided demo on the home page"
    return match.group(1)


def strip_step(html: str) -> str:
    """The guided demo strip at the top of a page: "step N of M: title"."""
    match = re.search(r"Guided demo, step (\d+ of \d+):</strong> ([^<.,]+)", html)
    assert match, "no guided demo strip on this page"
    return f"step {match.group(1)}: {match.group(2)}"


def test_no_guided_demo_without_demo_data(client: TestClient) -> None:
    assert "hero-cta" not in client.get("/signin").text
    sign_in(client, "alice")
    home = client.get("/").text
    assert "Try the full flow in 60 seconds" not in home
    assert "Guided demo" not in client.get("/requests/new").text


def test_the_guided_demo_ticks_off_real_steps(client: TestClient, service: AccessService) -> None:
    seed_activity(service)
    picker = client.get("/signin?next=/approvals").text
    start = picker[picker.index('<form class="hero-cta"') :]
    start = start[: start.index("</form>")]
    assert 'name="user_id" value="alice">' in start
    assert 'name="next" value="/">' in start  # the checklist lives on the home page
    assert "You begin as Alice Chen, the requester." in start
    sign_in(client, "alice")
    assert "hero-cta" not in client.get("/switch").text
    home = client.get("/").text
    assert "Try the full flow in 60 seconds" in home
    assert tour_progress(client) == "0 of 5"
    assert 'href="/requests/new?resource=prod-db">Ask for Production Database' in home

    request_id = service.submit("alice", "prod-db", "editor", 8, WHY).request_id
    assert tour_progress(client) == "1 of 5"
    page = client.get(f"/requests/{request_id}").text
    assert "Guided demo, step 2 of 5:</strong> Approve as Bob Singh" in page
    assert 'name="user_id" value="bob">' in page
    assert f'name="next" value="/requests/{request_id}">' in page

    service.approve(request_id, "bob")
    assert tour_progress(client) == "2 of 5"
    service.approve(request_id, "frank")

    # The access is live, but step 4 only ticks once Alice opens it; the owner seeing it does not count.
    switch_to(client, "frank", f"/requests/{request_id}")
    page = client.get(f"/requests/{request_id}").text
    assert strip_step(page) == "step 4 of 5: See the access start and count down"
    assert 'name="user_id" value="alice">' in page
    assert tour_progress(client) == "3 of 5"

    switch_to(client, "alice", f"/requests/{request_id}")
    page = client.get(f"/requests/{request_id}").text
    assert "8 hours left" in page
    assert strip_step(page) == "step 5 of 5: Check the audit log"
    assert 'name="user_id" value="dan">' in page
    assert tour_progress(client) == "4 of 5"

    assert switch_to(client, "dan", "/audit") == "/audit"  # switching person keeps the progress
    audit = client.get("/audit").text
    assert "Guided demo complete." in audit
    switch_to(client, "alice")
    assert tour_progress(client) == "5 of 5"
    assert "That is the whole flow" in client.get("/").text


def test_the_requester_home_page_also_counts_as_seeing_the_access(
    client: TestClient, service: AccessService
) -> None:
    seed_activity(service)
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    service.approve(request_id, "bob")
    service.approve(request_id, "frank")
    sign_in(client, "bob")
    assert tour_progress(client) == "3 of 5"
    switch_to(client, "alice")
    assert tour_progress(client) == "4 of 5"


def test_admin_access_adds_a_security_step_to_the_guided_demo(
    client: TestClient, service: AccessService
) -> None:
    seed_activity(service)
    request_id = service.submit("alice", "prod-db", "admin", 2, WHY).request_id
    sign_in(client, "alice")
    home = client.get("/").text
    assert tour_progress(client) == "1 of 6"
    assert "Approve as Dan Okafor" in home
    service.approve(request_id, "dan")  # any order works
    assert tour_progress(client) == "2 of 6"


def test_a_denied_guided_request_restarts_the_demo(client: TestClient, service: AccessService) -> None:
    seed_activity(service)
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    service.deny(request_id, "bob", "Use the read replica instead.")
    sign_in(client, "alice")
    assert f"Request #{request_id} was denied. Ask again to restart the demo." in client.get("/").text
    assert tour_progress(client) == "0 of 5"


# --------------------------------------------------------------------------- dashboard, timeline and audit


def test_dashboards_show_access_work_and_activity(client: TestClient, service: AccessService) -> None:
    seed_activity(service)
    sign_in(client, "alice")
    home = client.get("/").text
    assert "<h1>Hi, Alice</h1>" in home
    assert '<strong class="tag tag-expiring">Expiring soon</strong>' in home
    assert "30 minutes left" in home
    assert "You gave back viewer access to Incident Runbooks." in home
    assert "Bob Singh approved your viewer access to Production Kubernetes as your manager." in home
    assert "Your viewer access to Production Kubernetes expired." in home
    assert "Nothing needs your decision" in home

    sign_in(client, "bob")
    home = client.get("/").text
    assert 'href="/requests/7">Erin Walsh' in home
    assert 'href="/requests/11">Alice Chen' in home
    assert "You approved Erin Walsh&#39;s viewer access to Production Database as Erin&#39;s manager." in home
    assert "No temporary access right now" in home


def test_the_request_page_explains_and_shows_a_timeline(client: TestClient, service: AccessService) -> None:
    seed_activity(service)
    sign_in(client, "dan")
    page = client.get("/requests/8").text  # Leo's admin request: his manager owns the cluster
    assert (
        "Waiting for someone from security (Dan Okafor or Grace Liu) and a second, different person from "
        "security. 1 of 3 approvals done." in page
    )
    assert "The requester&#39;s manager also owns this resource" in page
    assert (
        '<p class="moment-title"><span class="visually-hidden">Done: </span>Requester&#39;s manager: approved'
        in page
    )
    assert page.count("Security team: waiting") == 2

    sign_in(client, "bob")  # Erin's critical request: the owner said yes, security is still to come
    assert "Then it waits for 1 more approval." in client.get("/requests/7").text
    sign_in(client, "frank")  # the manager said yes, so the owner's is the last approval
    assert (
        "The last approval. After a final safety check, Erin gets viewer access for 8 hours."
        in client.get("/requests/10").text
    )

    sign_in(client, "dan")
    page = client.get("/requests/5").text  # Erin's access, removed by the owner
    assert "Removed by Carol Diaz." in page
    assert "“Refund question answered, so this is no longer needed.”" in page


def test_the_audit_log_reads_in_plain_words(client: TestClient, service: AccessService) -> None:
    seed_activity(service)
    sign_in(client, "dan")
    audit = client.get("/audit").text
    assert "Chain verified just now" in audit
    assert "Alice Chen asked for viewer access to Design Wiki (approved instantly)." in audit
    assert "Bob Singh approved request #2 as requester&#39;s manager." in audit
    assert "Carol Diaz removed Erin Walsh&#39;s viewer access to Finance Dashboards." in audit
    assert 'href="/requests/8">request:8</a>' in audit
    assert 'href="/requests/2">grant:2</a>' in audit  # a grant links to the request that started it
