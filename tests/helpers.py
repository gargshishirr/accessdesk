"""Helpers shared by the web, API and accessibility tests."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

START = 1_800_000_000  # 2027-01-15 08:00 UTC
API_KEY = "test-api-key"


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "page has no CSRF token"
    return match.group(1)


def sign_in(client: TestClient, user_id: str) -> str:
    """Sign in through the real form. Returns the new session's CSRF token."""
    client.cookies.clear()
    response = client.post(
        "/signin", data={"csrf_token": csrf_from(client.get("/signin").text), "user_id": user_id}
    )
    assert response.status_code == 303, response.text
    return csrf_from(client.get("/").text)
