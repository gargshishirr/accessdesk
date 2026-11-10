"""Settings, read from environment variables."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    db_path: str = "accessdesk.db"
    secret_key: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    api_key: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    sweep_seconds: float = 30.0
    secure_cookies: bool = False
    # Over 20 hours, so the time limit meets WCAG 2.2.1 (Timing Adjustable) without a warning dialog.
    session_hours: int = 24

    @classmethod
    def from_env(cls) -> Settings:
        defaults = cls()
        return cls(
            db_path=os.environ.get("ACCESSDESK_DB", defaults.db_path),
            secret_key=os.environ.get("ACCESSDESK_SECRET_KEY") or defaults.secret_key,
            api_key=os.environ.get("ACCESSDESK_API_KEY") or defaults.api_key,
            sweep_seconds=float(os.environ.get("ACCESSDESK_SWEEP_SECONDS", defaults.sweep_seconds)),
            secure_cookies=_flag("ACCESSDESK_SECURE_COOKIES", defaults.secure_cookies),
        )
