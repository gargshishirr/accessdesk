from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from accessdesk.__main__ import main


def test_seed_and_verify_audit_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "cli.db"
    monkeypatch.setenv("ACCESSDESK_DB", str(path))

    assert main(["seed"]) == 0
    assert capsys.readouterr().out.strip() == "Demo data added."
    assert main(["seed"]) == 0
    assert "nothing added" in capsys.readouterr().out

    assert main(["verify-audit"]) == 0
    # 6 submissions + 3 approvals + 3 grants in the demo activity.
    assert capsys.readouterr().out.startswith("OK: 12 entries verified.")

    with closing(sqlite3.connect(path)) as conn:
        conn.execute("UPDATE audit_log SET details = '{}' WHERE seq = 4")
        conn.commit()
    assert main(["verify-audit"]) == 1
    assert "BROKEN at entry 4" in capsys.readouterr().err


def test_serve_seeds_once_and_prints_a_generated_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ACCESSDESK_DB", str(tmp_path / "serve.db"))
    monkeypatch.delenv("ACCESSDESK_API_KEY", raising=False)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append({"app": app, **kwargs}))

    assert main(["serve", "--port", "8123"]) == 0
    app = calls[0]["app"]
    app.state.service.db.close()  # uvicorn.run is mocked, so the app's shutdown hook never runs
    output = capsys.readouterr()
    assert "Added demo data" in output.out
    assert "API key for this run" in output.err
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 8123
    assert app.title == "AccessDesk"
