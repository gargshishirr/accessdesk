from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from accessdesk.service import AccessService
from accessdesk.web.security import safe_next
from tests.helpers import csrf_from, sign_in

WHY = "Investigating payment incident INC-2041."


def follow(client: TestClient, response: object) -> str:
    location = response.headers["location"]  # type: ignore[attr-defined]
    return client.get(location).text


def test_pages_need_sign_in_and_return_to_the_page_asked_for(client: TestClient) -> None:
    response = client.get("/requests/new?resource=prod-db")
    assert response.status_code == 303
    assert response.headers["location"] == "/signin?next=/requests/new%3Fresource%3Dprod-db"

    form = client.get(response.headers["location"]).text
    assert 'name="next" value="/requests/new?resource=prod-db"' in form
    signed_in = client.post(
        "/signin",
        data={"csrf_token": csrf_from(form), "user_id": "alice", "next": "/requests/new?resource=prod-db"},
    )
    assert signed_in.headers["location"] == "/requests/new?resource=prod-db"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("/approvals", "/approvals"),
        ("/requests/7?tab=log", "/requests/7?tab=log"),
        ("https://evil.example/", "/"),
        ("//evil.example/", "/"),
        ("/\\evil.example/", "/"),
        ("javascript:alert(1)", "/"),
        ("/ok\r\nSet-Cookie: x=1", "/"),
        ("", "/"),
    ],
)
def test_only_local_redirects_are_followed(target: str, expected: str) -> None:
    assert safe_next(target) == expected


def test_signing_in_without_choosing_shows_a_linked_error(client: TestClient) -> None:
    response = client.post("/signin", data={"csrf_token": csrf_from(client.get("/signin").text)})
    assert response.status_code == 422
    assert "<title>Error: Sign in | AccessDesk</title>" in response.text
    assert '<a href="#user-alice">Choose who you want to sign in as</a>' in response.text


def test_forms_without_the_session_token_are_refused(client: TestClient, service: AccessService) -> None:
    sign_in(client, "alice")
    data = {"resource_id": "prod-db", "role": "viewer", "hours": "8", "justification": WHY}
    for token in ("", "forged"):
        response = client.post("/requests", data={**data, "csrf_token": token})
        assert response.status_code == 403
        assert "This page has expired" in response.text
    assert service.my_requests("alice") == []


def test_security_headers_and_cookie_flags(client: TestClient) -> None:
    page = client.get("/signin")
    headers = page.headers
    assert "default-src 'none'" in headers["content-security-policy"]
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "same-origin"
    assert headers["cache-control"] == "no-store"
    cookie = headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert "<script" not in page.text

    css = client.get("/static/app.css")
    assert css.status_code == 200
    assert "no-store" not in css.headers.get("cache-control", "")
    assert "content-security-policy" not in client.get("/api/docs").headers


def test_request_and_two_approvals_through_the_ui(client: TestClient) -> None:
    sign_in(client, "alice")
    catalog = client.get("/requests/new").text
    assert 'href="/requests/new?resource=prod-db"' in catalog
    form = client.get("/requests/new?resource=prod-db").text
    assert "Your manager and the owner." in form
    sent = client.post(
        "/requests",
        data={
            "csrf_token": csrf_from(form),
            "resource_id": "prod-db",
            "role": "viewer",
            "hours": "8",
            "justification": WHY,
        },
    )
    assert sent.status_code == 303
    page = follow(client, sent)
    assert "Request #1 sent. It needs approval from: requester&#39;s manager, resource owner." in page
    assert "Waiting for approval" in page

    for approver, message in [
        ("bob", "Your approval is recorded. Still waiting for: resource owner."),
        ("frank", "Approved. Alice Chen now has viewer access to Production Database."),
    ]:
        token = sign_in(client, approver)
        assert 'href="/requests/1"' in client.get("/approvals").text
        detail = client.get("/requests/1").text
        version = re.search(r'name="version" value="(\d+)"', detail)
        assert version, "approver should see the decision form"
        decided = client.post(
            "/requests/1/decision",
            data={"csrf_token": token, "decision": "approve", "version": version.group(1)},
        )
        assert decided.status_code == 303
        assert message in follow(client, decided)

    sign_in(client, "alice")
    home = client.get("/").text
    assert "Production Database" in home
    assert "Give back now" in home


def test_form_errors_are_summarised_linked_and_kept(client: TestClient) -> None:
    token = sign_in(client, "alice")
    response = client.post(
        "/requests",
        data={
            "csrf_token": token,
            "resource_id": "prod-db",
            "role": "",
            "hours": "lots",
            "justification": "short",
        },
    )
    assert response.status_code == 422
    html = response.text
    assert "<title>Error: Request access to Production Database | AccessDesk</title>" in html
    assert 'class="error-summary" tabindex="-1" autofocus' in html
    for anchor in ('href="#role-viewer"', 'href="#hours"', 'href="#justification"'):
        assert anchor in html
    assert 'aria-describedby="hours-hint hours-error" aria-invalid="true"' in html
    assert 'id="hours-error" class="error-message"><span class="visually-hidden">Error:</span>' in html
    assert 'value="lots"' in html
    assert ">short</textarea>" in html


def test_unknown_resource_ids_go_back_to_the_catalogue(client: TestClient) -> None:
    token = sign_in(client, "alice")
    response = client.post(
        "/requests",
        data={
            "csrf_token": token,
            "resource_id": "nope",
            "role": "viewer",
            "hours": "1",
            "justification": WHY,
        },
    )
    assert response.status_code == 422
    assert '<a href="#catalog">Choose a resource from the list</a>' in response.text
    assert client.get("/requests/new?resource=nope").status_code == 404


def test_denying_needs_a_reason_and_a_choice(client: TestClient, service: AccessService) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    token = sign_in(client, "bob")
    no_choice = client.post(f"/requests/{request_id}/decision", data={"csrf_token": token, "comment": ""})
    assert no_choice.status_code == 422
    assert '<a href="#decision-approve">Choose whether to approve or deny this request</a>' in no_choice.text

    no_reason = client.post(
        f"/requests/{request_id}/decision", data={"csrf_token": token, "decision": "deny"}
    )
    assert no_reason.status_code == 422
    assert '<a href="#comment">Tell the requester why you are denying this request</a>' in no_reason.text
    assert 'id="decision-deny" name="decision" value="deny" checked' in no_reason.text

    denied = client.post(
        f"/requests/{request_id}/decision",
        data={"csrf_token": token, "decision": "deny", "comment": "Use the read replica."},
    )
    page = follow(client, denied)
    assert "denied. Alice Chen can see your reason." in page
    assert "“Use the read replica.”" in page


def test_a_stale_decision_form_explains_what_happened(client: TestClient, service: AccessService) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    token = sign_in(client, "bob")
    seen = re.search(r'name="version" value="(\d+)"', client.get(f"/requests/{request_id}").text)
    assert seen
    service.approve(request_id, "frank")  # someone else acts first
    response = client.post(
        f"/requests/{request_id}/decision",
        data={"csrf_token": token, "decision": "approve", "version": seen.group(1)},
    )
    assert "This request changed after you opened it." in follow(client, response)


def test_final_approval_that_breaks_separation_of_duties_is_refused(
    client: TestClient, service: AccessService
) -> None:
    request_id = service.submit("alice", "payment-approvals", "editor", 8, WHY).request_id
    ledger = service.submit("alice", "payments-ledger", "editor", 8, WHY).request_id
    service.approve(ledger, "bob")
    service.approve(ledger, "frank")
    service.approve(request_id, "bob")
    token = sign_in(client, "carol")
    response = client.post(
        f"/requests/{request_id}/decision", data={"csrf_token": token, "decision": "approve"}
    )
    page = follow(client, response)
    assert f"Request #{request_id} was not approved. Separation of duties" in page


def test_people_outside_a_request_cannot_see_or_decide_it(client: TestClient, service: AccessService) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    token = sign_in(client, "erin")
    assert client.get(f"/requests/{request_id}").status_code == 404
    response = client.post(
        f"/requests/{request_id}/decision", data={"csrf_token": token, "decision": "approve"}
    )
    assert response.status_code == 404
    token = sign_in(client, "dan")  # security can read it, but has no slot on a high-risk viewer request
    assert client.get(f"/requests/{request_id}").status_code == 200
    response = client.post(
        f"/requests/{request_id}/decision", data={"csrf_token": token, "decision": "approve"}
    )
    assert response.status_code == 403


def test_requester_can_cancel_and_give_access_back(client: TestClient, service: AccessService) -> None:
    pending = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    wiki = service.submit("alice", "design-wiki", "viewer", 8, WHY).grant_id
    token = sign_in(client, "alice")
    cancelled = client.post(f"/requests/{pending}/cancel", data={"csrf_token": token, "version": "1"})
    assert f"Request #{pending} cancelled." in follow(client, cancelled)
    released = client.post(f"/grants/{wiki}/release", data={"csrf_token": token})
    home = follow(client, released)
    assert "You gave back viewer access to Design Wiki." in home
    assert "Given back early" in home


def test_owner_removes_access_with_a_reason(client: TestClient, service: AccessService) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    service.approve(request_id, "bob")
    grant_id = service.approve(request_id, "frank").grant_id
    assert grant_id is not None

    token = sign_in(client, "carol")
    assert client.get(f"/grants/{grant_id}/revoke").status_code == 404  # not hers to see

    token = sign_in(client, "frank")
    assert f'href="/grants/{grant_id}/revoke"' in client.get("/reviews").text
    assert client.get(f"/grants/{grant_id}/revoke").status_code == 200
    missing = client.post(f"/grants/{grant_id}/revoke", data={"csrf_token": token, "note": ""})
    assert missing.status_code == 422
    assert (
        '<a href="#note">Enter a reason for removing this access (at least 5 characters)</a>' in missing.text
    )
    removed = client.post(
        f"/grants/{grant_id}/revoke", data={"csrf_token": token, "note": "Incident closed."}
    )
    assert "Access removed. Alice Chen no longer has viewer access to Production Database." in follow(
        client, removed
    )
    again = client.get(f"/grants/{grant_id}/revoke")
    assert again.headers["location"] == "/reviews"

    sign_in(client, "alice")
    assert "Removed by Frank Moreau: “Incident closed.”" in client.get("/").text


def test_audit_log_page_is_for_security_only(client: TestClient, service: AccessService) -> None:
    service.submit("alice", "design-wiki", "viewer", 8, WHY)
    sign_in(client, "alice")
    assert 'href="/audit"' not in client.get("/").text
    assert client.get("/audit").status_code == 403
    sign_in(client, "dan")
    page = client.get("/audit").text
    assert "Chain intact." in page
    assert "All 2 entries check out." in page


def test_errors_and_sign_out(client: TestClient) -> None:
    token = sign_in(client, "alice")
    missing = client.get("/no-such-page")
    assert missing.status_code == 404
    assert "<h1>Page not found</h1>" in missing.text
    assert client.get("/requests/not-a-number").status_code == 404
    assert client.get("/requests/999").status_code == 404

    out = client.post("/signout", data={"csrf_token": token})
    assert out.headers["location"] == "/signin"
    assert "You have signed out." in client.get("/signin").text
    assert client.get("/").status_code == 303
