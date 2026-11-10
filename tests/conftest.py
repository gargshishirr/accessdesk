from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from accessdesk.clock import ManualClock
from accessdesk.config import Settings
from accessdesk.db import Database
from accessdesk.seed import seed_directory
from accessdesk.service import AccessService
from accessdesk.web import create_app
from tests.helpers import API_KEY, START


@pytest.fixture
def clock() -> ManualClock:
    return ManualClock(START)


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(str(tmp_path / "accessdesk.db"))
    seed_directory(database)
    yield database
    database.close()


@pytest.fixture
def service(db: Database, clock: ManualClock) -> AccessService:
    return AccessService(db, clock)


@pytest.fixture
def app(service: AccessService) -> FastAPI:
    settings = Settings(
        db_path=service.db.path, secret_key="test-secret-" * 4, api_key=API_KEY, sweep_seconds=0
    )
    return create_app(settings, service=service)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client
