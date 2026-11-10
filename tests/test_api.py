from __future__ import annotations

import time

from fastapi.testclient import TestClient

from accessdesk.clock import ManualClock
from accessdesk.config import Settings
from accessdesk.service import AccessService
from accessdesk.web import create_app
from tests.helpers import API_KEY

KEY = {"X-API-Key": API_KEY}
WHY = "Investigating payment incident INC-2041."


def test_check_needs_the_api_key(client: TestClient) -> None:
    params = {"user": "alice", "resource": "prod-db"}
    for headers in ({}, {"X-API-Key": "wrong"}):
        response = client.get("/api/v1/check", params=params, headers=headers)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "ApiKey"
        assert response.json() == {"detail": "Missing or invalid API key."}


def test_check_follows_grants_and_fails_closed_at_expiry(
    client: TestClient, service: AccessService, clock: ManualClock
) -> None:
    params = {"user": "alice", "resource": "prod-db", "role": "editor"}
    assert client.get("/api/v1/check", params=params, headers=KEY).json()["reason"] == "no_active_grant"

    request_id = service.submit("alice", "prod-db", "viewer", 2, WHY).request_id
    service.approve(request_id, "bob")
    grant_id = service.approve(request_id, "frank").grant_id
    assert client.get("/api/v1/check", params=params, headers=KEY).json()["reason"] == "role_insufficient"

    viewer = client.get("/api/v1/check", params={**params, "role": "viewer"}, headers=KEY).json()
    assert viewer == {
        "allowed": True,
        "reason": "active_grant",
        "expires_at": clock.now() + 7200,
        "grant_id": grant_id,
    }

    clock.advance(7200)
    expired = client.get("/api/v1/check", params={**params, "role": "viewer"}, headers=KEY).json()
    assert (expired["allowed"], expired["reason"]) == (False, "no_active_grant")


def test_check_validates_its_input(client: TestClient) -> None:
    bad_role = client.get(
        "/api/v1/check", params={"user": "alice", "resource": "x", "role": "owner"}, headers=KEY
    )
    assert bad_role.status_code == 422
    assert bad_role.json()["detail"][0]["loc"] == ["query", "role"]
    assert client.get("/api/v1/check", params={"user": "", "resource": "x"}, headers=KEY).status_code == 422


def test_audit_verify_reports_tampering(client: TestClient, service: AccessService) -> None:
    service.submit("alice", "design-wiki", "viewer", 8, WHY)
    healthy = client.get("/api/v1/audit/verify", headers=KEY).json()
    assert healthy["ok"] is True
    assert healthy["events"] == 2
    assert len(healthy["head_hash"]) == 64

    with service.db.connection() as conn:
        conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 1")
    broken = client.get("/api/v1/audit/verify", headers=KEY).json()
    assert (broken["ok"], broken["first_invalid_seq"]) == (False, 1)


def test_health_metrics_and_openapi(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok", "version": "1.0.0"}
    client.get("/api/v1/check", params={"user": "alice", "resource": "prod-db"}, headers=KEY)
    client.get("/requests/42")

    metrics = client.get("/metrics")
    assert metrics.headers["content-type"].startswith("text/plain")
    body = metrics.text
    assert 'accessdesk_access_checks_total{allowed="false",reason="no_active_grant"} 1.0' in body
    assert 'accessdesk_http_requests_total{method="GET",route="/api/v1/check",status="200"} 1.0' in body
    # Raw ids never become label values.
    assert 'route="/requests/{request_id}"' in body
    assert "/requests/42" not in body

    paths = set(client.get("/api/openapi.json").json()["paths"])
    assert paths == {"/api/v1/check", "/api/v1/audit/verify"}


def test_background_sweeper_ends_expired_grants(service: AccessService, clock: ManualClock) -> None:
    grant_id = service.submit("alice", "design-wiki", "viewer", 1, WHY).grant_id
    clock.advance(3600)
    settings = Settings(db_path=service.db.path, secret_key="s" * 32, api_key=API_KEY, sweep_seconds=0.05)
    with TestClient(create_app(settings, service=service)) as client:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _, ended = service.my_grants("alice")
            if ended and ended[0].end_reason is not None:
                break
            time.sleep(0.05)
        assert [(g.id, g.end_reason) for g in ended] == [(grant_id, "expired")]
        assert "accessdesk_grants_expired_total 1.0" in client.get("/metrics").text
