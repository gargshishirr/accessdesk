"""Settings, read from environment variables.

AccessDesk runs in one of two modes:

* **Demo mode** (no ``ACCESSDESK_OIDC_*`` settings): a person picker, so anyone can sign in as anyone.
  Good for trying it out, never for real access.
* **Single sign-on** (``ACCESSDESK_OIDC_ISSUER``, ``_CLIENT_ID`` and ``_CLIENT_SECRET`` set): people sign in
  with the company's identity provider, and the person picker does not exist.

Half-finished single sign-on settings stop the app from starting, so it can never fall back to demo mode
by accident.
"""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit

GOOGLE_ISSUER = "https://accounts.google.com"
MIN_SECRET_LENGTH = 32
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
HOW_TO_MAKE_A_KEY = 'Make one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'


class ConfigError(ValueError):
    """The settings cannot work. The message says what to change."""


def _flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _number(name: str, default: float, *, whole: bool = True) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw) if whole else float(raw)
    except ValueError:
        kind = "a whole number" if whole else "a number"
        raise ConfigError(f"{name} must be {kind}, not {raw!r}.") from None


def _list(raw: str | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(item.strip() for item in (raw or "").split(",") if item.strip()))


def is_secure_url(url: str) -> bool:
    """https, or plain http to this computer (for trying things out locally)."""
    parts = urlsplit(url)
    if not parts.hostname or parts.query or parts.fragment:
        return False
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS)


@dataclass(frozen=True)
class OidcSettings:
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    # Email domains allowed to sign in, for example ("example.com",). Empty means any domain.
    allowed_domains: tuple[str, ...] = ()

    @property
    def is_google(self) -> bool:
        return self.issuer.rstrip("/") == GOOGLE_ISSUER


@dataclass(frozen=True)
class Settings:
    db_path: str = "accessdesk.db"
    secret_key: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    # Every key in the list works, so a new key can be added before the old one is removed.
    api_keys: tuple[str, ...] = field(default_factory=lambda: (secrets.token_urlsafe(32),), repr=False)
    sweep_seconds: float = 30.0
    secure_cookies: bool = False
    # Over 20 hours, so the time limit meets WCAG 2.2.1 (Timing Adjustable) without a warning dialog.
    session_hours: int = 24
    # The address people use, like https://access.example.com. Single sign-on sends them back to it.
    public_url: str = ""
    oidc: OidcSettings | None = None
    # Sign-ins started per client address and minute. 0 turns the limit off.
    signin_rate_limit: int = 30
    # A header that trusted infrastructure fills with the visitor's address, like CF-Connecting-IP on
    # Render. Empty means the address of whatever connected to the server.
    client_ip_header: str = ""
    # Per API key and minute. 0 turns the limit off.
    api_rate_limit: int = 6000
    # A JSON directory file that ``accessdesk serve`` loads at start-up.
    directory_file: str = ""

    def __post_init__(self) -> None:
        if self.session_hours < 1:
            raise ConfigError("ACCESSDESK_SESSION_HOURS must be at least 1.")
        if self.sweep_seconds < 0 or self.signin_rate_limit < 0 or self.api_rate_limit < 0:
            raise ConfigError("ACCESSDESK_SWEEP_SECONDS and the rate limits cannot be negative.")
        if self.client_ip_header and not re.fullmatch(r"[A-Za-z0-9-]+", self.client_ip_header):
            raise ConfigError(
                f"ACCESSDESK_CLIENT_IP_HEADER must be a header name, not {self.client_ip_header!r}."
            )
        if self.public_url and not is_secure_url(self.public_url):
            raise ConfigError(
                "ACCESSDESK_PUBLIC_URL must start with https:// (http:// is only allowed for localhost), "
                f"not {self.public_url!r}."
            )
        if self.oidc is not None:
            self._check_single_sign_on(self.oidc)

    def _check_single_sign_on(self, oidc: OidcSettings) -> None:
        if not is_secure_url(oidc.issuer):
            raise ConfigError(
                "ACCESSDESK_OIDC_ISSUER must be an https:// address (http:// only for localhost), "
                f"not {oidc.issuer!r}."
            )
        if not oidc.client_id or not oidc.client_secret:
            raise ConfigError("Set both ACCESSDESK_OIDC_CLIENT_ID and ACCESSDESK_OIDC_CLIENT_SECRET.")
        if not self.public_url:
            raise ConfigError(
                "Single sign-on needs ACCESSDESK_PUBLIC_URL, the address people use "
                "(for example https://access.example.com)."
            )
        if self.public_url.startswith("https://") and not self.secure_cookies:
            raise ConfigError("ACCESSDESK_SECURE_COOKIES must be true when ACCESSDESK_PUBLIC_URL uses https.")
        if len(self.secret_key) < MIN_SECRET_LENGTH:
            raise ConfigError(
                f"With single sign-on, ACCESSDESK_SECRET_KEY must be at least {MIN_SECRET_LENGTH} "
                f"characters. {HOW_TO_MAKE_A_KEY}"
            )
        if any(len(key) < MIN_SECRET_LENGTH for key in self.api_keys):
            raise ConfigError(
                f"With single sign-on, every API key must be at least {MIN_SECRET_LENGTH} characters. "
                f"{HOW_TO_MAKE_A_KEY}"
            )
        for domain in oidc.allowed_domains:
            if "@" in domain or "." not in domain or domain != domain.lower():
                raise ConfigError(
                    "ACCESSDESK_OIDC_ALLOWED_DOMAINS takes lower-case domains like example.com, "
                    f"not {domain!r}."
                )
        if oidc.is_google and not oidc.allowed_domains:
            raise ConfigError(
                "With Google, set ACCESSDESK_OIDC_ALLOWED_DOMAINS to your Google Workspace domain, "
                "so personal Google accounts cannot sign in."
            )

    @property
    def sso(self) -> bool:
        return self.oidc is not None

    @property
    def redirect_uri(self) -> str:
        """Where the identity provider sends people back to. Register this exact address with it."""
        return self.public_url.rstrip("/") + "/auth/callback"

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ
        defaults = cls()
        oidc = _oidc_from_env()
        public_url = (env.get("ACCESSDESK_PUBLIC_URL") or env.get("RENDER_EXTERNAL_URL") or "").strip()
        public_url = public_url.rstrip("/")

        secret_key = env.get("ACCESSDESK_SECRET_KEY", "").strip()
        if oidc is not None and not secret_key:
            raise ConfigError(
                "Single sign-on needs a fixed ACCESSDESK_SECRET_KEY so sessions survive restarts. "
                + HOW_TO_MAKE_A_KEY
            )
        api_keys = _list(env.get("ACCESSDESK_API_KEYS")) + _list(env.get("ACCESSDESK_API_KEY"))
        if not api_keys and oidc is None:
            api_keys = defaults.api_keys  # demo mode: a key for this run, printed at start-up
        return cls(
            db_path=env.get("ACCESSDESK_DB", defaults.db_path),
            secret_key=secret_key or defaults.secret_key,
            api_keys=tuple(dict.fromkeys(api_keys)),
            sweep_seconds=_number("ACCESSDESK_SWEEP_SECONDS", defaults.sweep_seconds, whole=False),
            secure_cookies=_flag("ACCESSDESK_SECURE_COOKIES", public_url.startswith("https://")),
            session_hours=int(_number("ACCESSDESK_SESSION_HOURS", defaults.session_hours)),
            public_url=public_url,
            oidc=oidc,
            signin_rate_limit=int(_number("ACCESSDESK_SIGNIN_RATE_LIMIT", defaults.signin_rate_limit)),
            client_ip_header=env.get("ACCESSDESK_CLIENT_IP_HEADER", "").strip(),
            api_rate_limit=int(_number("ACCESSDESK_API_RATE_LIMIT", defaults.api_rate_limit)),
            directory_file=env.get("ACCESSDESK_DIRECTORY_FILE", "").strip(),
        )


def _oidc_from_env() -> OidcSettings | None:
    names = ("ACCESSDESK_OIDC_ISSUER", "ACCESSDESK_OIDC_CLIENT_ID", "ACCESSDESK_OIDC_CLIENT_SECRET")
    values = [os.environ.get(name, "").strip() for name in names]
    domains = _list(os.environ.get("ACCESSDESK_OIDC_ALLOWED_DOMAINS"))
    if not any(values) and not domains:
        return None
    missing = [name for name, value in zip(names, values, strict=True) if not value]
    if missing:
        raise ConfigError("Single sign-on is only half set up. Also set " + ", ".join(missing) + ".")
    issuer, client_id, client_secret = values
    return OidcSettings(issuer, client_id, client_secret, tuple(d.lower() for d in domains))
