"""Single sign-on, end to end, against the fake identity provider in tests/fake_idp.py (no network)."""

from __future__ import annotations

import base64
import json
import logging
import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from accessdesk.clock import ManualClock
from accessdesk.config import GOOGLE_ISSUER, OidcSettings, Settings
from accessdesk.oidc import OidcClient, pkce_challenge
from accessdesk.seed import SEEDED_THROUGH
from accessdesk.service import AccessService
from accessdesk.web import create_app
from tests.fake_idp import (
    CLIENT_ID,
    CLIENT_SECRET,
    DROP,
    NEXT_KEY,
    STRANGER_KEY,
    FakeProvider,
    hmac_token,
    unsigned_token,
)
from tests.helpers import csrf_from

PUBLIC_URL = "https://access.example.test"
SECRET_KEY = "sso-test-session-secret-" * 2
API_KEY = "sso-test-api-key-0123456789abcdefghij"


def sso_app(
    service: AccessService, provider: FakeProvider, allowed: tuple[str, ...] = ("example.com",), **extra: Any
) -> FastAPI:
    oidc = OidcSettings(provider.issuer, CLIENT_ID, CLIENT_SECRET, allowed)
    settings = Settings(
        db_path=service.db.path,
        secret_key=SECRET_KEY,
        api_keys=(API_KEY,),
        sweep_seconds=0,
        public_url=PUBLIC_URL,
        secure_cookies=True,
        oidc=oidc,
        **extra,
    )
    client = OidcClient(oidc, settings.redirect_uri, transport=provider.transport, now=service.clock.now)
    return create_app(settings, service=service, oidc=client)


@pytest.fixture
def provider(clock: ManualClock) -> FakeProvider:
    return FakeProvider(clock.now)


@pytest.fixture
def sso(service: AccessService, provider: FakeProvider) -> Iterator[TestClient]:
    with TestClient(sso_app(service, provider), base_url=PUBLIC_URL, follow_redirects=False) as client:
        yield client


def start(client: TestClient, next_path: str | None = None) -> str:
    response = client.get("/auth/login", params={"next": next_path} if next_path else None)
    assert response.status_code == 303, response.text
    location: str = response.headers["location"]
    return location


def sign_in(
    client: TestClient, provider: FakeProvider, email: str = "alice@example.com", **claims: Any
) -> Any:
    return client.get(provider.sign_in(start(client), email, **claims))


def session_data(client: TestClient) -> dict[str, Any]:
    """What the signed session cookie holds (it is signed, not encrypted)."""
    value = client.cookies.get("__Host-accessdesk") or ""
    payload = value.split(".")[0]
    data: dict[str, Any] = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)))
    return data


def signed_in_as(client: TestClient) -> str | None:
    page = client.get("/")
    if page.status_code != 200:
        return None
    match = re.search(r'<span class="account-name">([^<]+)</span>', page.text)
    return match.group(1) if match else None


# --------------------------------------------------------------------------- the happy path


def test_sign_in_with_the_company_account_end_to_end(sso: TestClient, provider: FakeProvider) -> None:
    protected = sso.get("/requests/new?resource=prod-db")
    assert protected.headers["location"] == "/signin?next=/requests/new%3Fresource%3Dprod-db"
    page = sso.get(protected.headers["location"]).text
    assert 'href="/auth/login?next=%2Frequests%2Fnew%3Fresource%3Dprod-db"' in page
    assert "Sign in with your company account" in page
    assert 'name="user_id"' not in page  # no person picker
    assert "anyone can sign in as anyone" not in page  # no demo banner

    authorize = start(sso, "/requests/new?resource=prod-db")
    params = {key: values[0] for key, values in parse_qs(urlsplit(authorize).query).items()}
    assert authorize.startswith("https://idp.example.test/authorize?")
    assert params["redirect_uri"] == "https://access.example.test/auth/callback"
    assert params["scope"] == "openid email profile"
    assert len(params["state"]) >= 43
    assert len(params["nonce"]) >= 43
    assert params["state"] != params["nonce"]

    callback = sso.get(provider.sign_in(authorize))
    assert callback.status_code == 303
    assert callback.headers["location"] == "/requests/new?resource=prod-db"
    cookie = callback.headers["set-cookie"]
    assert cookie.startswith("__Host-accessdesk=")
    for flag in ("path=/;", "secure", "httponly", "samesite=lax"):
        assert flag in cookie.lower()
    assert "domain=" not in cookie.lower()
    assert signed_in_as(sso) == "Alice Chen"

    # The code went to the token endpoint with the PKCE verifier, and the client secret in Basic auth.
    [token_call] = provider.token_requests
    form = {key: values[0] for key, values in parse_qs(token_call.content.decode()).items()}
    assert pkce_challenge(form["code_verifier"]) == params["code_challenge"]
    assert form["redirect_uri"] == params["redirect_uri"]
    assert "client_secret" not in form
    basic = base64.b64decode(token_call.headers["authorization"].removeprefix("Basic ")).decode()
    assert basic == f"{CLIENT_ID}:{CLIENT_SECRET}"


def test_the_demo_person_picker_does_not_exist_with_single_sign_on(sso: TestClient) -> None:
    sso.get("/signin")
    response = sso.post("/signin", data={"csrf_token": session_data(sso)["csrf"], "user_id": "dan"})
    assert response.status_code == 405
    assert signed_in_as(sso) is None


def test_client_secret_post_when_the_provider_only_offers_that(
    sso: TestClient, provider: FakeProvider
) -> None:
    provider.auth_methods = ["client_secret_post"]
    assert sign_in(sso, provider).status_code == 303
    [token_call] = provider.token_requests
    assert "authorization" not in token_call.headers
    assert parse_qs(token_call.content.decode())["client_secret"] == [CLIENT_SECRET]


def test_the_other_client_auth_method_is_tried_when_the_first_is_refused(
    sso: TestClient, provider: FakeProvider
) -> None:
    provider.accepted_methods = {
        "client_secret_post"
    }  # registered for the body method only, like some providers
    assert sign_in(sso, provider).status_code == 303
    basic, post = provider.token_requests
    assert "authorization" in basic.headers
    assert "client_secret" in post.content.decode()
    provider.accepted_methods = set()
    sso.cookies.clear()
    assert sign_in(sso, provider).status_code == 400  # a wrong secret still fails cleanly
    assert len(provider.token_requests) == 4


def test_microsoft_style_tokens_use_xms_edov_instead_of_email_verified(
    sso: TestClient, provider: FakeProvider
) -> None:
    assert sign_in(sso, provider, email_verified=DROP, xms_edov=True).status_code == 303
    assert signed_in_as(sso) == "Alice Chen"


def test_email_case_and_string_booleans_are_accepted(sso: TestClient, provider: FakeProvider) -> None:
    assert sign_in(sso, provider, email="Bob@Example.COM", email_verified="true").status_code == 303
    assert signed_in_as(sso) == "Bob Singh"


# --------------------------------------------------------------------------- who may sign in


def test_unknown_people_get_a_clear_not_in_the_directory_page(
    sso: TestClient, provider: FakeProvider
) -> None:
    response = sign_in(sso, provider, email="zoe@example.com")
    assert response.status_code == 403
    assert "<h1>You are not in AccessDesk&#39;s directory</h1>" in response.text
    assert "You signed in as zoe@example.com" in response.text
    assert signed_in_as(sso) is None


def test_people_who_left_cannot_sign_in(
    sso: TestClient, provider: FakeProvider, service: AccessService
) -> None:
    with service.db.write() as conn:
        conn.execute("UPDATE users SET active = 0 WHERE id = 'alice'")
    assert sign_in(sso, provider).status_code == 403
    assert signed_in_as(sso) is None


@pytest.mark.parametrize(
    "claims",
    [
        {"email_verified": False},
        {"email_verified": DROP},
        {"email_verified": "false"},
        {"email_verified": 0},
        {"email_verified": DROP, "xms_edov": False},
        {"email": DROP},
    ],
    ids=["false", "missing", "false-string", "zero", "xms_edov-false", "no-email"],
)
def test_the_email_address_must_be_verified(
    sso: TestClient, provider: FakeProvider, claims: dict[str, Any]
) -> None:
    response = sign_in(sso, provider, **claims)
    assert response.status_code == 403
    assert "Your email address could not be confirmed" in response.text
    assert signed_in_as(sso) is None


def test_only_allowed_email_domains(sso: TestClient, provider: FakeProvider) -> None:
    response = sign_in(sso, provider, email="alice@example.org")
    assert response.status_code == 403
    assert "<h1>Use your work account</h1>" in response.text
    assert signed_in_as(sso) is None


def test_google_needs_a_workspace_account_from_the_allowed_domain(
    service: AccessService, clock: ManualClock
) -> None:
    google = FakeProvider(clock.now, issuer=GOOGLE_ISSUER)
    with TestClient(sso_app(service, google), base_url=PUBLIC_URL, follow_redirects=False) as client:
        authorize = start(client)
        assert "hd=example.com" in authorize  # the account chooser only offers the company's accounts
        # A personal Google account that carries a work address has no "hd" claim.
        assert client.get(google.sign_in(authorize)).status_code == 403
        assert client.get(google.sign_in(start(client), hd="other.example")).status_code == 403
        # Google documents two spellings of its issuer.
        assert (
            client.get(google.sign_in(start(client), hd="example.com", iss="accounts.google.com")).status_code
            == 303
        )
        assert signed_in_as(client) == "Alice Chen"


# --------------------------------------------------------------------------- the ID token is checked


def forged_audience(claims: dict[str, Any]) -> dict[str, Any]:
    return {**claims, "aud": [CLIENT_ID, "another-app"]}


@pytest.mark.parametrize(
    ("claims", "forge"),
    [
        ({"iss": "https://evil.example"}, None),
        ({"aud": "another-app"}, None),
        ({"aud": [CLIENT_ID, "another-app"], "azp": CLIENT_ID}, None),
        ({"azp": "another-app"}, None),
        ({"exp": 1_799_999_000}, None),  # expired 1,000 seconds before the test clock
        ({"iat": 1_800_003_600}, None),  # issued an hour in the future
        ({"nonce": "not-the-nonce-we-sent"}, None),
        ({"nonce": DROP}, None),
        ({"sub": DROP}, None),
        ({"sub": ""}, None),
        ({}, "unsigned"),
        ({}, "hmac"),
        ({}, "stranger"),
        ({}, "tampered"),
    ],
    ids=[
        "wrong-issuer",
        "wrong-audience",
        "extra-audience",
        "wrong-authorized-party",
        "expired",
        "issued-in-the-future",
        "wrong-nonce",
        "no-nonce",
        "no-subject",
        "empty-subject",
        "alg-none",
        "hmac-with-client-secret",
        "signed-by-someone-else",
        "tampered-payload",
    ],
)
def test_bad_id_tokens_are_refused(
    sso: TestClient, provider: FakeProvider, claims: dict[str, Any], forge: str | None
) -> None:
    def tampered(c: dict[str, Any]) -> str:
        header, _, signature = provider.sign(c).split(".")
        return f"{header}.{base64.urlsafe_b64encode(b'{}').rstrip(b'=').decode()}.{signature}"

    forgers = {
        "unsigned": unsigned_token,
        "hmac": hmac_token,
        "stranger": lambda c: provider.sign(c, STRANGER_KEY),
        "tampered": tampered,
    }
    provider.forge = forgers[forge] if forge else None
    response = sign_in(sso, provider, **claims)
    assert response.status_code == 400
    assert "<h1>Sign-in did not work</h1>" in response.text
    assert signed_in_as(sso) is None


def test_new_signing_keys_are_fetched_when_the_provider_rotates(
    sso: TestClient, provider: FakeProvider, clock: ManualClock
) -> None:
    assert sign_in(sso, provider).status_code == 303
    assert provider.jwks_fetches == 1
    provider.published = [provider.signing_key, NEXT_KEY]
    provider.signing_key = NEXT_KEY
    clock.advance(120)
    sso.cookies.clear()
    assert sign_in(sso, provider).status_code == 303
    assert provider.jwks_fetches == 2


def test_unknown_key_ids_do_not_make_us_hammer_the_provider(sso: TestClient, provider: FakeProvider) -> None:
    provider.forge = lambda claims: provider.sign(claims, NEXT_KEY)  # a key the provider never published
    for _ in range(3):
        assert sign_in(sso, provider).status_code == 400
    assert provider.jwks_fetches == 1


# --------------------------------------------------------------------------- the round trip is checked


def test_the_state_must_come_from_this_browser_and_works_once(
    sso: TestClient, provider: FakeProvider, service: AccessService
) -> None:
    callback = provider.sign_in(start(sso))
    with TestClient(sso_app(service, provider), base_url=PUBLIC_URL, follow_redirects=False) as other:
        stolen = other.get(callback)  # another browser cannot finish this sign-in (login CSRF)
        assert stolen.status_code == 400
        assert "<h1>Sign-in did not finish</h1>" in stolen.text
    assert sso.get(callback).status_code == 303
    sso.cookies.clear()
    assert sso.get(callback).status_code == 400  # replayed
    assert sso.get("/auth/callback?code=abc&state=made-up").status_code == 400
    assert sso.get("/auth/callback").status_code == 400


def test_a_sign_in_left_open_too_long_expires(
    sso: TestClient, provider: FakeProvider, clock: ManualClock
) -> None:
    callback = provider.sign_in(start(sso))
    clock.advance(601)
    assert sso.get(callback).status_code == 400
    assert signed_in_as(sso) is None


def test_sign_ins_started_in_several_tabs_can_each_finish(sso: TestClient, provider: FakeProvider) -> None:
    first = provider.sign_in(start(sso, "/approvals"))
    second = provider.sign_in(start(sso, "/reviews"))
    assert sso.get(second).headers["location"] == "/reviews"
    assert sso.get(first).headers["location"] == "/"  # already signed in by the other tab
    assert signed_in_as(sso) == "Alice Chen"


def test_the_return_address_cannot_leave_the_site(sso: TestClient, provider: FakeProvider) -> None:
    for target in ("https://evil.example/", "//evil.example/", "/\\evil.example"):
        sso.cookies.clear()
        assert sso.get(provider.sign_in(start(sso, target))).headers["location"] == "/"


def test_provider_errors_and_outages_get_friendly_pages(sso: TestClient, provider: FakeProvider) -> None:
    state = parse_qs(urlsplit(start(sso)).query)["state"][0]
    refused = sso.get(f"/auth/callback?error=access_denied&state={state}")
    assert refused.status_code == 400
    assert "Your sign-in service stopped the sign-in." in refused.text

    provider.token_error = (400, {"error": "invalid_grant"})
    assert sign_in(sso, provider).status_code == 400
    provider.token_error = (503, {"error": "temporarily_unavailable"})
    assert sign_in(sso, provider).status_code == 503

    provider.token_error = None
    provider.down = True  # the provider's settings are cached, so sign-in starts, but the token call fails
    down = sso.get(provider.sign_in(start(sso)))
    assert down.status_code == 503
    assert "Single sign-on is not available right now" in down.text
    assert signed_in_as(sso) is None


def test_sign_in_cannot_start_while_the_provider_is_unreachable(
    service: AccessService, clock: ManualClock
) -> None:
    provider = FakeProvider(clock.now)
    provider.down = True
    with TestClient(sso_app(service, provider), base_url=PUBLIC_URL, follow_redirects=False) as client:
        response = client.get("/auth/login")
    assert response.status_code == 503
    assert "Try again in a few minutes." in response.text


def test_a_provider_that_names_a_different_issuer_is_refused(
    service: AccessService, clock: ManualClock
) -> None:
    provider = FakeProvider(clock.now)
    provider.discovery_changes = {"issuer": "https://login.example/{tenantid}/v2.0"}
    with TestClient(sso_app(service, provider), base_url=PUBLIC_URL, follow_redirects=False) as client:
        response = client.get("/auth/login")
    assert response.status_code == 503


# --------------------------------------------------------------------------- sessions


def test_signing_in_starts_a_fresh_session_and_signing_out_ends_it_everywhere(
    sso: TestClient, provider: FakeProvider
) -> None:
    sso.get("/signin")
    before_token = session_data(sso)["csrf"]
    before_cookie = sso.cookies.get("__Host-accessdesk")
    assert sign_in(sso, provider).status_code == 303
    after_token = csrf_from(sso.get("/").text)
    stolen = sso.cookies.get("__Host-accessdesk")
    assert after_token != before_token
    assert stolen != before_cookie

    out = sso.post("/signout", data={"csrf_token": after_token})
    assert out.headers["location"] == "/signin"
    assert "Your company account is still signed in" in sso.get("/signin").text
    # Someone who copied the cookie before sign-out cannot use it.
    sso.cookies.clear()
    sso.cookies.set("__Host-accessdesk", stolen or "", domain="access.example.test")
    assert sso.get("/").status_code == 303


def test_demo_sessions_stop_working_once_single_sign_on_is_on(
    service: AccessService, provider: FakeProvider
) -> None:
    demo = Settings(
        db_path=service.db.path,
        secret_key=SECRET_KEY,
        api_keys=(API_KEY,),
        sweep_seconds=0,
        public_url=PUBLIC_URL,
        secure_cookies=True,
    )
    with TestClient(create_app(demo, service=service), base_url=PUBLIC_URL, follow_redirects=False) as client:
        token = csrf_from(client.get("/signin").text)
        assert client.post("/signin", data={"csrf_token": token, "user_id": "dan"}).status_code == 303
        cookie = client.cookies.get("__Host-accessdesk") or ""
        assert client.get("/audit").status_code == 200
    with TestClient(sso_app(service, provider), base_url=PUBLIC_URL, follow_redirects=False) as sso:
        sso.cookies.set("__Host-accessdesk", cookie, domain="access.example.test")
        assert sso.get("/audit").status_code == 303


def test_sessions_end_after_their_lifetime(
    sso: TestClient, provider: FakeProvider, clock: ManualClock
) -> None:
    sign_in(sso, provider)
    clock.advance(24 * 3600 - 1)
    assert signed_in_as(sso) == "Alice Chen"
    clock.advance(1)
    assert sso.get("/").status_code == 303


def test_removing_someone_from_the_directory_ends_their_session(
    sso: TestClient, provider: FakeProvider, service: AccessService
) -> None:
    sign_in(sso, provider)
    with service.db.write() as conn:
        conn.execute("UPDATE users SET active = 0 WHERE id = 'alice'")
    assert sso.get("/").status_code == 303


# --------------------------------------------------------------------------- abuse and secrets


def test_sign_in_attempts_are_rate_limited(service: AccessService, provider: FakeProvider) -> None:
    app = sso_app(service, provider, signin_rate_limit=3)
    with TestClient(app, base_url=PUBLIC_URL, follow_redirects=False) as client:
        for _ in range(3):
            assert client.get("/auth/login").status_code == 303
        limited = client.get("/auth/login")
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) >= 1
    assert "Too many sign-in attempts" in limited.text


def test_sign_in_pages_keep_the_strict_security_headers(sso: TestClient, provider: FakeProvider) -> None:
    pages = [sso.get("/signin"), sign_in(sso, provider, email="zoe@example.com"), sso.get("/auth/callback")]
    for page in pages:
        assert "default-src 'none'" in page.headers["content-security-policy"]
        assert page.headers["cache-control"] == "no-store"
        assert page.headers["strict-transport-security"].startswith("max-age=")
        assert "<script" not in page.text


def test_demo_personas_switcher_and_guided_demo_never_appear_with_single_sign_on(
    sso: TestClient, provider: FakeProvider, service: AccessService
) -> None:
    service.set_meta(SEEDED_THROUGH, "0")  # even on a database that once had demo data
    picker = sso.get("/signin").text
    assert "Continue as" not in picker
    assert 'name="user_id"' not in picker
    assert sso.get("/switch").status_code == 404

    sign_in(sso, provider)
    assert sso.get("/switch").status_code == 404
    token = csrf_from(sso.get("/").text)
    persona = sso.post("/signin", data={"csrf_token": token, "user_id": "bob", "next": "/"})
    assert persona.status_code == 405
    for path in ("/", "/requests/new?resource=prod-db", "/approvals"):
        page = sso.get(path).text
        assert "Signed in as" in page
        assert "Viewing as" not in page
        assert "Switch person" not in page
        assert 'action="/signin"' not in page
        assert "Guided demo" not in page
    assert signed_in_as(sso) == "Alice Chen"


def test_real_deployments_load_no_third_party_scripts(sso: TestClient) -> None:
    assert sso.get("/api/docs").status_code == 404
    assert 'href="/api/docs"' not in sso.get("/signin").text
    assert set(sso.get("/api/openapi.json").json()["paths"]) == {"/api/v1/check", "/api/v1/audit/verify"}


def test_no_secrets_reach_the_logs(
    sso: TestClient, provider: FakeProvider, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    authorize = start(sso)
    callback = provider.sign_in(authorize)
    assert sign_in(sso, provider, email="zoe@example.com").status_code == 403  # logged without the address
    assert sso.get(callback).status_code == 303

    query = parse_qs(urlsplit(authorize).query)
    form = parse_qs(provider.token_requests[-1].content.decode())
    secrets_seen = [
        CLIENT_SECRET,
        SECRET_KEY,
        API_KEY,
        query["state"][0],
        query["nonce"][0],
        form["code"][0],
        form["code_verifier"][0],
        "zoe@example.com",
    ]
    # The test client's own request logs are not the app's, so only the app's loggers count.
    logged = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith(("accessdesk", "uvicorn", "joserfc"))
    )
    assert "signed in: user=alice method=sso" in logged
    assert "not_in_directory: example.com" in logged
    for secret in secrets_seen:
        assert secret not in logged
