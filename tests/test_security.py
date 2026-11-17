"""Security review checks: who may do what, API keys, rate limits, CSRF and what reaches the logs."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from accessdesk import directory
from accessdesk.config import Settings
from accessdesk.service import AccessService, Forbidden
from accessdesk.web import create_app
from accessdesk.web.ratelimit import RateLimiter
from accessdesk.web.security import ApiKeys, RedactSignInSecrets, redact_access_log
from tests.helpers import API_KEY, csrf_from, sign_in

WHY = "Investigating payment incident INC-2041."
OLD_KEY = "old-key-0123456789abcdefghijklmnopqrstuv"
NEW_KEY = "new-key-0123456789abcdefghijklmnopqrstuv"
CHECK = {"user": "alice", "resource": "prod-db"}


def api_client(service: AccessService, **settings: object) -> TestClient:
    values: dict[str, object] = {
        "db_path": service.db.path,
        "secret_key": "s" * 40,
        "api_keys": (API_KEY,),
        "sweep_seconds": 0,
    }
    values.update(settings)
    return TestClient(create_app(Settings(**values), service=service))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- authorization


def test_requesters_cannot_approve_their_own_requests_even_as_owner(
    client: TestClient, service: AccessService
) -> None:
    # Frank owns the production database, so security takes the owner's place on his own request.
    request_id = service.submit("frank", "prod-db", "viewer", 8, WHY).request_id
    token = sign_in(client, "frank")
    page = client.get(f"/requests/{request_id}").text
    assert 'name="decision"' not in page
    response = client.post(
        f"/requests/{request_id}/decision", data={"csrf_token": token, "decision": "approve"}
    )
    assert response.status_code == 403
    with pytest.raises(Forbidden):
        service.approve(request_id, "frank")


def test_security_cannot_approve_their_own_admin_request(client: TestClient, service: AccessService) -> None:
    request_id = service.submit("dan", "prod-db", "admin", 2, WHY).request_id
    token = sign_in(client, "dan")
    response = client.post(
        f"/requests/{request_id}/decision", data={"csrf_token": token, "decision": "approve"}
    )
    assert response.status_code == 403
    assert service.approve(request_id, "grace").status.value == "pending"  # another security person can


def test_owners_cannot_approve_for_resources_they_do_not_own(
    client: TestClient, service: AccessService
) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    service.approve(request_id, "bob")
    token = sign_in(client, "carol")  # owns other resources, not the production database
    response = client.post(
        f"/requests/{request_id}/decision", data={"csrf_token": token, "decision": "approve"}
    )
    assert response.status_code == 404
    with pytest.raises(Forbidden):
        service.approve(request_id, "carol")
    assert service.request_page(request_id, "alice").request.status.value == "pending"


@pytest.mark.parametrize("person", ["alice", "bob", "frank", "carol"])
def test_only_the_security_team_reads_the_full_audit_log(client: TestClient, person: str) -> None:
    sign_in(client, person)
    assert client.get("/audit").status_code == 403
    assert 'href="/audit"' not in client.get("/").text
    assert client.get("/api/v1/audit/verify").status_code == 401  # the API needs a key, not a session


def test_people_who_left_can_do_nothing(client: TestClient, service: AccessService) -> None:
    request_id = service.submit("alice", "prod-db", "viewer", 8, WHY).request_id
    sign_in(client, "bob")
    assert 'href="/requests/1"' in client.get("/approvals").text
    people = directory.export(service)["people"]
    for person in people:
        if person["id"] == "bob":
            person["active"] = False
    for person in people:
        if person["manager"] == "bob":
            person["manager"] = "maya"
    directory.apply(service, directory.parse({"people": people}))

    assert client.get("/approvals").status_code == 303  # his session ended
    with pytest.raises(Forbidden):
        service.approve(request_id, "bob")
    with pytest.raises(Forbidden):
        service.submit("bob", "design-wiki", "viewer", 8, WHY)
    assert "bob" not in {u.id for u in service.users(active_only=True)}


def test_sign_out_needs_the_form_token(client: TestClient) -> None:
    sign_in(client, "alice")
    assert client.post("/signout", data={"csrf_token": "forged"}).status_code == 403
    assert client.get("/").status_code == 200  # still signed in


# --------------------------------------------------------------------------- API keys


def test_every_listed_api_key_works_so_keys_can_be_rotated(service: AccessService) -> None:
    with api_client(service, api_keys=(NEW_KEY, OLD_KEY)) as both:
        for key in (NEW_KEY, OLD_KEY):
            assert both.get("/api/v1/check", params=CHECK, headers={"X-API-Key": key}).status_code == 200
    with api_client(service, api_keys=(NEW_KEY,)) as rotated:
        assert rotated.get("/api/v1/check", params=CHECK, headers={"X-API-Key": OLD_KEY}).status_code == 401
        bearer = rotated.get("/api/v1/check", params=CHECK, headers={"Authorization": f"Bearer {NEW_KEY}"})
        assert bearer.status_code == 200


def test_with_no_api_keys_the_api_is_off(service: AccessService) -> None:
    with api_client(service, api_keys=()) as client:
        assert client.get("/api/v1/check", params=CHECK, headers={"X-API-Key": ""}).status_code == 401
        assert client.get("/metrics").status_code == 401


def test_api_key_matching() -> None:
    keys = ApiKeys([OLD_KEY, NEW_KEY])
    assert keys.match(NEW_KEY) == 1
    assert keys.match(OLD_KEY) == 0
    for wrong in (None, "", OLD_KEY[:-1], OLD_KEY + "x", OLD_KEY.upper(), "x" * 10_000):
        assert keys.match(wrong) is None
    assert ApiKeys([]).match(OLD_KEY) is None


def test_guessing_api_keys_is_rate_limited_but_never_locks_out_real_keys(service: AccessService) -> None:
    with api_client(service) as client:
        for _ in range(10):
            assert (
                client.get("/api/v1/check", params=CHECK, headers={"X-API-Key": "guess"}).status_code == 401
            )
        blocked = client.get("/api/v1/check", params=CHECK, headers={"X-API-Key": "guess"})
        assert blocked.status_code == 429
        assert int(blocked.headers["retry-after"]) >= 1
        assert blocked.json() == {"detail": "Too many requests. Wait a minute."}
        # Wrong keys sent "from" a real service's address cannot lock that service out.
        assert client.get("/api/v1/check", params=CHECK, headers={"X-API-Key": API_KEY}).status_code == 200
        metrics = client.app.state.metrics.exposition().decode()  # type: ignore[attr-defined]
    assert 'accessdesk_rate_limited_total{limit="api_key_failures"} 1.0' in metrics


def test_rate_limits_can_use_the_address_a_trusted_proxy_reports(service: AccessService) -> None:
    def guess(client: TestClient, headers: dict[str, str]) -> int:
        response = client.get("/api/v1/check", params=CHECK, headers={"X-API-Key": "guess", **headers})
        return response.status_code

    with api_client(service, client_ip_header="CF-Connecting-IP") as client:
        for _ in range(10):
            assert guess(client, {"CF-Connecting-IP": "203.0.113.1"}) == 401
        assert guess(client, {"CF-Connecting-IP": "203.0.113.1"}) == 429
        assert guess(client, {"CF-Connecting-IP": "198.51.100.2"}) == 401  # another visitor
        # Only the last value counts: a client can add to the header, but the proxy adds after it.
        assert guess(client, {"CF-Connecting-IP": "198.51.100.9, 203.0.113.1"}) == 429
        # A proxy may add its own header line instead of extending the client's: the last line counts.
        for spoofed in range(3):
            lines = [
                ("X-API-Key", "guess"),
                ("CF-Connecting-IP", f"10.0.0.{spoofed}"),
                ("CF-Connecting-IP", "203.0.113.1"),
            ]
            assert client.get("/api/v1/check", params=CHECK, headers=lines).status_code == 429
    with api_client(service) as client:  # without the setting, the header is ignored
        for spoofed in range(11):
            guess(client, {"CF-Connecting-IP": f"192.0.2.{spoofed}"})
        assert guess(client, {"CF-Connecting-IP": "192.0.2.200"}) == 429


def test_each_api_key_has_a_request_limit(service: AccessService) -> None:
    with api_client(service, api_keys=(OLD_KEY, NEW_KEY), api_rate_limit=2) as client:
        for _ in range(2):
            assert (
                client.get("/api/v1/check", params=CHECK, headers={"X-API-Key": OLD_KEY}).status_code == 200
            )
        assert client.get("/api/v1/check", params=CHECK, headers={"X-API-Key": OLD_KEY}).status_code == 429
        assert client.get("/api/v1/check", params=CHECK, headers={"X-API-Key": NEW_KEY}).status_code == 200


def test_the_rate_limiter_refills_over_time_and_can_be_turned_off() -> None:
    now = [0.0]
    limiter = RateLimiter(2, clock=lambda: now[0])
    assert (limiter.hit("a"), limiter.hit("a")) == (0, 0)
    assert limiter.hit("a") == pytest.approx(30)  # one token comes back every 30 seconds
    assert limiter.hit("b") == 0  # other keys are separate
    now[0] += 30
    assert limiter.wait("a") == 0
    assert limiter.hit("a") == 0
    off = RateLimiter(0)
    assert all(off.hit("a") == 0 for _ in range(100))


def test_demo_sign_in_is_rate_limited(service: AccessService) -> None:
    with api_client(service, signin_rate_limit=2) as client:
        token = csrf_from(client.get("/signin").text)
        statuses = [client.post("/signin", data={"csrf_token": token}).status_code for _ in range(3)]
    assert statuses == [422, 422, 429]


# --------------------------------------------------------------------------- headers and logs


def test_demo_mode_is_labelled_on_every_page(client: TestClient) -> None:
    assert "anyone can sign in as anyone" in client.get("/signin").text
    sign_in(client, "alice")
    assert "anyone can sign in as anyone" in client.get("/").text


def test_sign_in_codes_are_kept_out_of_the_access_log() -> None:
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("203.0.113.9:5000", "GET", "/auth/callback?code=SECRET-CODE&state=SECRET-STATE", "1.1", 303),
        None,
    )
    assert RedactSignInSecrets().filter(record)
    message = record.getMessage()
    assert "SECRET" not in message
    assert '"GET /auth/callback?[redacted] HTTP/1.1" 303' in message

    other = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        "%s %s %s",
        ("a", "GET", "/requests/new?resource=x"),
        None,
    )
    RedactSignInSecrets().filter(other)
    assert other.getMessage() == "a GET /requests/new?resource=x"


@pytest.fixture
def access_logger() -> Iterator[logging.Logger]:
    logger = logging.getLogger("uvicorn.access")
    before = list(logger.filters)
    yield logger
    logger.filters[:] = before


def test_the_log_filter_is_installed_once(access_logger: logging.Logger) -> None:
    redact_access_log()
    redact_access_log()
    assert sum(isinstance(f, RedactSignInSecrets) for f in access_logger.filters) == 1
