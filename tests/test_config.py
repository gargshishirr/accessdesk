"""Settings from environment variables, and the rules that keep single sign-on from being half set up."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from accessdesk.clock import ManualClock
from accessdesk.config import ConfigError, OidcSettings, Settings
from accessdesk.db import Database
from accessdesk.service import AccessService
from accessdesk.web import create_app
from tests.helpers import START

SSO_ENV = {
    "ACCESSDESK_OIDC_ISSUER": "https://login.example.com/tenant/v2.0",
    "ACCESSDESK_OIDC_CLIENT_ID": "client-id",
    "ACCESSDESK_OIDC_CLIENT_SECRET": "client-secret",
    "ACCESSDESK_PUBLIC_URL": "https://access.example.com/",
    "ACCESSDESK_SECRET_KEY": "k" * 40,
}


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in list(os.environ):
        if name.startswith("ACCESSDESK_") or name in {"RENDER_EXTERNAL_URL"}:
            monkeypatch.delenv(name)
    return monkeypatch


def set_env(env: pytest.MonkeyPatch, values: dict[str, str]) -> None:
    for name, value in values.items():
        env.setenv(name, value)


def test_demo_mode_is_the_default(env: pytest.MonkeyPatch) -> None:
    settings = Settings.from_env()
    assert not settings.sso
    assert settings.secure_cookies is False
    assert len(settings.api_keys) == 1
    assert len(settings.api_keys[0]) >= 32
    assert settings.signin_rate_limit == 30
    assert settings.client_ip_header == ""


def test_single_sign_on_settings(env: pytest.MonkeyPatch) -> None:
    set_env(
        env,
        {
            **SSO_ENV,
            "ACCESSDESK_OIDC_ALLOWED_DOMAINS": "Example.com, example.org",
            "ACCESSDESK_API_KEYS": "a" * 32 + "," + "b" * 32,
            "ACCESSDESK_API_KEY": "a" * 32,
            "ACCESSDESK_SESSION_HOURS": "12",
        },
    )
    settings = Settings.from_env()
    assert settings.sso
    assert settings.oidc is not None
    assert settings.oidc.allowed_domains == ("example.com", "example.org")
    assert settings.redirect_uri == "https://access.example.com/auth/callback"
    assert settings.secure_cookies is True  # because the public address is https
    assert settings.api_keys == ("a" * 32, "b" * 32)
    assert settings.session_hours == 12
    assert "client-secret" not in repr(settings)
    assert "k" * 40 not in repr(settings)


def test_with_single_sign_on_and_no_api_key_the_api_is_off(env: pytest.MonkeyPatch) -> None:
    set_env(env, SSO_ENV)
    assert Settings.from_env().api_keys == ()


def test_render_supplies_the_public_address(env: pytest.MonkeyPatch) -> None:
    set_env(
        env,
        {**SSO_ENV, "ACCESSDESK_PUBLIC_URL": "", "RENDER_EXTERNAL_URL": "https://accessdesk.onrender.com"},
    )
    assert Settings.from_env().redirect_uri == "https://accessdesk.onrender.com/auth/callback"


def test_localhost_may_use_plain_http_for_trying_things_out(env: pytest.MonkeyPatch) -> None:
    set_env(
        env,
        {
            **SSO_ENV,
            "ACCESSDESK_OIDC_ISSUER": "http://localhost:8080/realms/test",
            "ACCESSDESK_PUBLIC_URL": "http://127.0.0.1:8000",
        },
    )
    settings = Settings.from_env()
    assert settings.secure_cookies is False
    assert settings.redirect_uri == "http://127.0.0.1:8000/auth/callback"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"ACCESSDESK_OIDC_CLIENT_SECRET": ""}, "Also set ACCESSDESK_OIDC_CLIENT_SECRET"),
        ({"ACCESSDESK_OIDC_ISSUER": "", "ACCESSDESK_OIDC_CLIENT_ID": ""}, "only half set up"),
        ({"ACCESSDESK_SECRET_KEY": ""}, "needs a fixed ACCESSDESK_SECRET_KEY"),
        ({"ACCESSDESK_SECRET_KEY": "too-short"}, "at least 32 characters"),
        ({"ACCESSDESK_API_KEYS": "short-key"}, "every API key must be at least 32"),
        ({"ACCESSDESK_OIDC_ISSUER": "http://login.example.com"}, "ACCESSDESK_OIDC_ISSUER must be an https"),
        ({"ACCESSDESK_PUBLIC_URL": ""}, "needs ACCESSDESK_PUBLIC_URL"),
        (
            {"ACCESSDESK_PUBLIC_URL": "http://access.example.com"},
            "ACCESSDESK_PUBLIC_URL must start with https",
        ),
        ({"ACCESSDESK_SECURE_COOKIES": "false"}, "ACCESSDESK_SECURE_COOKIES must be true"),
        (
            {"ACCESSDESK_OIDC_ISSUER": "https://accounts.google.com"},
            "With Google, set ACCESSDESK_OIDC_ALLOWED",
        ),
        ({"ACCESSDESK_OIDC_ALLOWED_DOMAINS": "@example.com"}, "lower-case domains like example.com"),
        ({"ACCESSDESK_SESSION_HOURS": "a day"}, "must be a whole number"),
        ({"ACCESSDESK_SESSION_HOURS": "0"}, "at least 1"),
        ({"ACCESSDESK_API_RATE_LIMIT": "-1"}, "cannot be negative"),
        ({"ACCESSDESK_CLIENT_IP_HEADER": "X Forwarded"}, "must be a header name"),
    ],
)
def test_settings_that_cannot_work_stop_the_app(
    env: pytest.MonkeyPatch, changes: dict[str, str], message: str
) -> None:
    set_env(env, {**SSO_ENV, **changes})
    with pytest.raises(ConfigError, match=message):
        Settings.from_env()


def test_half_set_up_single_sign_on_never_falls_back_to_demo_mode(env: pytest.MonkeyPatch) -> None:
    env.setenv("ACCESSDESK_OIDC_ALLOWED_DOMAINS", "example.com")
    with pytest.raises(ConfigError, match="only half set up"):
        Settings.from_env()


def test_a_database_used_with_single_sign_on_never_opens_in_demo_mode(tmp_path: Path) -> None:
    path = str(tmp_path / "real.db")
    sso = Settings(
        db_path=path,
        secret_key="k" * 40,
        api_keys=(),
        public_url="https://access.example.com",
        secure_cookies=True,
        oidc=OidcSettings("https://login.example.com", "id", "secret"),
    )
    create_app(sso).state.service.db.close()
    with pytest.raises(ConfigError, match="will not open it in demo mode"):
        create_app(Settings(db_path=path), service=AccessService(Database(path), ManualClock(START)))
