"""Measure how fast AccessDesk answers "does this person have this access right now?".

Builds a database with thousands of people, resources and grants (10% of the grants already expired but
not yet swept, so the check must fail closed on its own), then times the check:

* in-process: ``AccessService.check`` called directly;
* over HTTP: ``GET /api/v1/check`` against uvicorn running as a separate process, as it is deployed,
  with one client, with several concurrent clients, and with several worker processes.

Every answer over HTTP is cross-checked against the in-process answer for the same query.

Usage:  python scripts/bench_check.py [--grants 20000] [--requests 20000] [--clients 8] [--workers 4]
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import platform
import random
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from accessdesk.clock import SystemClock
from accessdesk.db import Database
from accessdesk.models import Role
from accessdesk.seed import seed_directory
from accessdesk.service import AccessService
from accessdesk.web.ui import plural

API_KEY = "bench-key"
ROLES = list(Role)


def populate(db: Database, users: int, resources: int, grants: int, rng: random.Random, now: int) -> None:
    """Add synthetic people, resources and grants; 10% of the grants are already past their expiry."""
    pairs: set[tuple[str, str]] = set()
    while len(pairs) < grants:
        pairs.add((f"u{rng.randrange(users):05d}", f"r{rng.randrange(resources):04d}"))
    with db.write() as conn:
        conn.executemany(
            "INSERT INTO users (id, name, email, team, title, manager_id) VALUES (?, ?, ?, ?, ?, 'maya')",
            [
                (f"u{i:05d}", f"User {i}", f"u{i}@example.com", f"team-{i % 40}", "Engineer")
                for i in range(users)
            ],
        )
        conn.executemany(
            "INSERT INTO resources (id, name, description, owner_id, sensitivity, max_hours, roles) "
            "VALUES (?, ?, 'Synthetic.', 'frank', 'medium', 72, 'viewer,editor,admin')",
            [(f"r{j:04d}", f"Resource {j}") for j in range(resources)],
        )
        for k, (user, resource) in enumerate(sorted(pairs)):
            role = rng.choice(ROLES).value
            expires = now - 60 if k % 10 == 0 else now + 86_400
            cursor = conn.execute(
                "INSERT INTO requests (requester_id, resource_id, role, hours, justification, status, "
                "required, reasons, created_at, decided_at) "
                "VALUES (?, ?, ?, 24, 'benchmark', 'approved', '[]', '[]', ?, ?)",
                (user, resource, role, now - 3600, now - 3600),
            )
            conn.execute(
                "INSERT INTO grants (request_id, user_id, resource_id, role, granted_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (cursor.lastrowid, user, resource, role, now - 3600, expires),
            )


def workload(
    users: int, resources: int, held: list[tuple[str, str]], count: int, rng: random.Random
) -> list[dict[str, str]]:
    """Half the checks hit a granted resource (some asking for too high a role); half are random misses."""
    queries = []
    for _ in range(count):
        if rng.random() < 0.5:
            user, resource = rng.choice(held)
        else:
            user, resource = f"u{rng.randrange(users):05d}", f"r{rng.randrange(resources):04d}"
        queries.append({"user": user, "resource": resource, "role": rng.choice(ROLES).value})
    return queries


def percentile(sorted_values: list[float], p: float) -> float:
    rank = max(1, -(-len(sorted_values) * p // 100))  # nearest-rank method
    return sorted_values[int(rank) - 1]


def summarise(name: str, latencies_ns: list[int], wall_seconds: float) -> dict[str, Any]:
    ms = sorted(n / 1e6 for n in latencies_ns)
    return {
        "path": name,
        "checks": len(ms),
        "p50_ms": percentile(ms, 50),
        "p95_ms": percentile(ms, 95),
        "p99_ms": percentile(ms, 99),
        "max_ms": ms[-1],
        "per_second": len(ms) / wall_seconds,
    }


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def healthy(port: int) -> bool:
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        conn.request("GET", "/healthz")
        ok = conn.getresponse().status == 200
        conn.close()
        return ok
    except OSError:
        return False


@contextmanager
def server_process(db_path: str, workers: int) -> Iterator[int]:
    """uvicorn in its own process (or processes), configured through environment variables."""
    env = {
        **os.environ,
        "ACCESSDESK_DB": db_path,
        "ACCESSDESK_API_KEY": API_KEY,
        "ACCESSDESK_SECRET_KEY": "bench-secret",
        "ACCESSDESK_SWEEP_SECONDS": "0",
    }
    windows = sys.platform == "win32"
    group = subprocess.CREATE_NEW_PROCESS_GROUP if windows else 0
    for _attempt in range(3):  # another program can grab the free port before uvicorn binds it
        port = free_port()
        command = [
            sys.executable, "-m", "uvicorn", "accessdesk.web.app:create_app", "--factory",
            "--host", "127.0.0.1", "--port", str(port), "--workers", str(workers),
            "--log-level", "warning", "--no-access-log",
        ]  # fmt: skip
        process = subprocess.Popen(command, env=env, creationflags=group)
        deadline = time.monotonic() + 60
        while process.poll() is None and not healthy(port) and time.monotonic() < deadline:
            time.sleep(0.1)
        if process.poll() is None and healthy(port):
            break
        process.kill()
        process.wait()
    else:
        raise RuntimeError("the server did not start after 3 attempts")
    try:
        if workers > 1:
            time.sleep(2)  # let every worker finish starting
        yield port
    finally:
        process.send_signal(signal.CTRL_BREAK_EVENT if windows else signal.SIGTERM)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def http_client(port: int, queries: list[dict[str, str]]) -> tuple[list[int], list[bool]]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    latencies, answers = [], []
    for query in queries:
        start = time.perf_counter_ns()
        conn.request("GET", f"/api/v1/check?{urlencode(query)}", headers={"X-API-Key": API_KEY})
        response = conn.getresponse()
        body = response.read()
        latencies.append(time.perf_counter_ns() - start)
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {body[:200]!r}")
        answers.append(json.loads(body)["allowed"])
    conn.close()
    return latencies, answers


def run_clients(
    port: int, queries: list[dict[str, str]], clients: int
) -> tuple[list[int], list[bool], float]:
    chunks = [queries[i::clients] for i in range(clients)]
    start = time.perf_counter()
    with ThreadPoolExecutor(clients) as pool:
        results = list(pool.map(lambda chunk: http_client(port, chunk), chunks))
    wall = time.perf_counter() - start
    latencies = [n for lat, _ in results for n in lat]
    answers: list[bool] = [False] * len(queries)
    for i, (_, chunk_answers) in enumerate(results):
        answers[i::clients] = chunk_answers
    return latencies, answers, wall


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--users", type=int, default=5_000)
    parser.add_argument("--resources", type=int, default=500)
    parser.add_argument("--grants", type=int, default=20_000)
    parser.add_argument("--requests", type=int, default=20_000)
    parser.add_argument("--clients", type=int, default=8)
    parser.add_argument("--workers", type=int, default=4, help="worker processes for the scaled-out run")
    parser.add_argument("--json", type=Path, help="also write the results here")
    args = parser.parse_args()

    rng = random.Random(42)
    results = []
    with tempfile.TemporaryDirectory() as folder:
        db_path = os.path.join(folder, "bench.db")
        db = Database(db_path)
        seed_directory(db)
        service = AccessService(db, SystemClock())
        start = time.perf_counter()
        populate(db, args.users, args.resources, args.grants, rng, SystemClock().now())
        setup_seconds = time.perf_counter() - start
        with db.connection() as conn:
            held = [(r[0], r[1]) for r in conn.execute("SELECT user_id, resource_id FROM grants")]
        queries = workload(args.users, args.resources, held, args.requests, rng)

        for q in queries[:2_000]:  # warm up
            service.check(q["user"], q["resource"], Role(q["role"]))
        latencies, expected = [], []
        start = time.perf_counter()
        for q in queries:
            t0 = time.perf_counter_ns()
            expected.append(service.check(q["user"], q["resource"], Role(q["role"])).allowed)
            latencies.append(time.perf_counter_ns() - t0)
        results.append(summarise("In-process `AccessService.check`", latencies, time.perf_counter() - start))
        db.close()

        runs = [(1, 1, args.requests // 4), (1, args.clients, args.requests)]
        if args.workers > 1:
            runs.append((args.workers, args.clients, args.requests))
        for workers, clients, count in runs:
            with server_process(db_path, workers) as port:
                run_clients(port, queries[:1_000], clients)  # warm up
                latencies, answers, wall = run_clients(port, queries[:count], clients)
            if answers != expected[:count]:
                raise RuntimeError("HTTP answers differ from in-process answers")
            label = f"HTTP, {plural(workers, 'worker')}, {plural(clients, 'client')}"
            results.append(summarise(label, latencies, wall))

    cpu = platform.processor() or platform.machine()
    machine = f"{cpu}, {os.cpu_count()} logical CPUs, {platform.system()} {platform.release()}"
    print(f"\nPython {sys.version.split()[0]} on {machine}")
    print(
        f"Data: {args.users:,} people, {args.resources:,} resources, {args.grants:,} grants "
        f"(10% expired but not yet swept), built in {setup_seconds:.1f}s. "
        f"{sum(expected):,} of {len(expected):,} checks allowed; every HTTP answer matched.\n"
    )
    print("| Path | Checks | p50 | p95 | p99 | Max | Throughput |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for r in results:
        print(
            f"| {r['path']} | {r['checks']:,} | {r['p50_ms']:.3f} ms | {r['p95_ms']:.3f} ms | "
            f"{r['p99_ms']:.3f} ms | {r['max_ms']:.2f} ms | {r['per_second']:,.0f}/s |"
        )
    if args.json:
        args.json.write_text(
            json.dumps({"machine": machine, "python": sys.version, "results": results}, indent=2)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
