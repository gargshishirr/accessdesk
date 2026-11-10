"""Prometheus metrics, kept in a per-app registry so several apps (and tests) never collide."""

from __future__ import annotations

import time

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest
from starlette.types import ASGIApp, Message, Receive, Scope, Send

LATENCY_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.http_requests = Counter(
            "accessdesk_http_requests",
            "HTTP requests handled.",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.http_latency = Histogram(
            "accessdesk_http_request_duration_seconds",
            "Time to handle an HTTP request.",
            ["route"],
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.checks = Counter(
            "accessdesk_access_checks",
            "Access checks answered, by result.",
            ["allowed", "reason"],
            registry=self.registry,
        )
        self.requests = Counter(
            "accessdesk_access_requests",
            "Access requests submitted, by policy outcome.",
            ["outcome"],
            registry=self.registry,
        )
        self.expired = Counter(
            "accessdesk_grants_expired", "Grants ended by the expiry sweeper.", registry=self.registry
        )
        self.sweep_errors = Counter(
            "accessdesk_sweep_errors", "Expiry sweeps that failed.", registry=self.registry
        )

    def exposition(self) -> bytes:
        output: bytes = generate_latest(self.registry)
        return output


def route_label(scope: Scope) -> str:
    """The route template (``/requests/{request_id}``), never the raw path, to keep label cardinality low."""
    route = scope.get("route")
    template = getattr(route, "path_format", None)
    if isinstance(template, str):
        return template
    if scope["path"].startswith("/static/"):
        return "/static"
    return "unmatched"


class MetricsMiddleware:
    def __init__(self, app: ASGIApp, metrics: Metrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status = 500

        async def send_and_record(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_and_record)
        finally:
            route = route_label(scope)
            self.metrics.http_requests.labels(scope["method"], route, str(status)).inc()
            self.metrics.http_latency.labels(route).observe(time.perf_counter() - start)
