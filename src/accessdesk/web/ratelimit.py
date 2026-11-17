"""Small in-memory rate limits (token buckets).

Each key (a client address, or an API key's number) gets a bucket that holds up to ``per_minute`` tokens and
refills evenly over a minute, so short bursts are fine but a steady flood is not. Every worker process keeps
its own buckets, which is enough to slow down guessing and runaway scripts.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from fastapi import Request

MAX_KEYS = 50_000  # memory bound: beyond this, buckets that have refilled completely are forgotten


class RateLimiter:
    def __init__(self, per_minute: int, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.capacity = float(per_minute)
        self.refill_per_second = per_minute / 60.0
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, when counted)
        self._lock = threading.Lock()

    def _tokens(self, key: str, now: float) -> float:
        tokens, then = self._buckets.get(key, (self.capacity, now))
        return min(self.capacity, tokens + (now - then) * self.refill_per_second)

    def _wait_for(self, tokens: float) -> float:
        return 0.0 if tokens >= 1 else (1 - tokens) / self.refill_per_second

    def hit(self, key: str) -> float:
        """Use one token. Returns 0 if that was allowed, otherwise the seconds to wait."""
        if self.capacity <= 0:
            return 0.0
        with self._lock:
            now = self._clock()
            tokens = self._tokens(key, now)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return self._wait_for(tokens)
            self._buckets[key] = (tokens - 1, now)
            if len(self._buckets) > MAX_KEYS:
                self._forget_full(now)
            return 0.0

    def wait(self, key: str) -> float:
        """Seconds until ``key`` may act again (0 if now), without using a token."""
        if self.capacity <= 0:
            return 0.0
        with self._lock:
            return self._wait_for(self._tokens(key, self._clock()))

    def _forget_full(self, now: float) -> None:
        full = [key for key in self._buckets if self._tokens(key, now) >= self.capacity]
        for key in full:
            del self._buckets[key]
        if len(self._buckets) > MAX_KEYS:
            self._buckets.clear()  # a flood of distinct keys: start again rather than grow without limit


class Limits:
    """The app's rate limits."""

    # Wrong or missing API keys allowed per client address and minute before it is refused for a while.
    API_KEY_FAILURES_PER_MINUTE = 10

    def __init__(self, *, signin_per_minute: int, api_per_minute: int) -> None:
        self.signin = RateLimiter(signin_per_minute)
        self.api_calls = RateLimiter(api_per_minute)
        self.api_key_failures = RateLimiter(self.API_KEY_FAILURES_PER_MINUTE)


def client_address(request: Request) -> str:
    """The caller's address, for rate limits.

    Behind a proxy, set ``ACCESSDESK_CLIENT_IP_HEADER`` to a header the proxy fills in. Its last value is
    used, because proxies add to such headers: anything a client sent itself comes earlier in the list.
    """
    header = request.app.state.settings.client_ip_header
    if header:
        # Some proxies add a second header line rather than extending the first, so read every line.
        value = ",".join(request.headers.getlist(header)).rsplit(",", 1)[-1].strip()
        if value:
            return value
    return request.client.host if request.client else "unknown"
