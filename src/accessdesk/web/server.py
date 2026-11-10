"""Serve the app on a free local port in a background thread (for browser tests, screenshots, benchmarks)."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import uvicorn
from starlette.types import ASGIApp


@contextmanager
def background_server(app: ASGIApp, startup_timeout: float = 15.0) -> Iterator[str]:
    """Yield the base URL of a real HTTP server for ``app``; stop it (running shutdown hooks) on exit."""
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + startup_timeout
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            sock.close()
            raise RuntimeError("server did not start")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=startup_timeout)
        sock.close()
