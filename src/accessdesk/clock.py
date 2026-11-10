"""Time source. All times are integer Unix seconds (UTC) so expiry checks are exact and testable."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> int: ...


class SystemClock:
    def now(self) -> int:
        return int(time.time())


class ManualClock:
    """A clock that only moves when told to. Used by tests and the demo seeder."""

    def __init__(self, start: int) -> None:
        self._now = start

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> None:
        if seconds < 0:
            raise ValueError("time only moves forward")
        self._now += seconds
