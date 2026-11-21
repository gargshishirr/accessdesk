from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from accessdesk.__main__ import main
from accessdesk.seed import USERS


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
    # The demo activity: 11 submissions, 8 approvals, 5 grants, 1 given back, 1 removed and 1 expired.
    assert capsys.readouterr().out.startswith("OK: 27 entries verified.")

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


SSO_ENV = {
    "ACCESSDESK_OIDC_ISSUER": "https://login.example.com/tenant/v2.0",
    "ACCESSDESK_OIDC_CLIENT_ID": "client-id",
    "ACCESSDESK_OIDC_CLIENT_SECRET": "client-secret",
    "ACCESSDESK_PUBLIC_URL": "https://access.example.com",
    "ACCESSDESK_SECRET_KEY": "k" * 40,
}


def fake_uvicorn(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def run(app: Any, **kwargs: Any) -> None:
        calls.append({"app": app, **kwargs})
        app.state.service.db.close()  # uvicorn.run is mocked, so the app's shutdown hook never runs

    monkeypatch.setattr(uvicorn, "run", run)
    return calls


def people_in(path: Path) -> int:
    with closing(sqlite3.connect(path)) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def test_directory_import_export_and_backup_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "cli.db"
    monkeypatch.setenv("ACCESSDESK_DB", str(path))
    assert main(["seed"]) == 0
    exported = tmp_path / "directory.json"
    assert main(["directory", "export", str(exported)]) == 0
    data = json.loads(exported.read_text(encoding="utf-8"))
    data["people"].append({"id": "hana", "name": "Hana Ito", "email": "hana@example.com", "manager": "maya"})
    exported.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()

    assert main(["directory", "import", str(exported), "--dry-run"]) == 0
    assert capsys.readouterr().out.startswith(f"Dry run, nothing saved. Directory from {exported}:")
    assert people_in(path) == len(USERS)
    assert main(["directory", "import", str(exported)]) == 0
    assert "People: 1 added (hana), 0 updated." in capsys.readouterr().out
    assert people_in(path) == len(USERS) + 1

    assert main(["directory", "export"]) == 0
    assert '"id": "hana"' in capsys.readouterr().out

    copy = tmp_path / "backup.db"
    assert main(["backup", str(copy)]) == 0
    assert people_in(copy) == len(USERS) + 1
    assert copy.stat().st_mode & 0o777 == 0o600  # personal data: readable by its owner only
    assert main(["backup", str(copy)]) == 1
    assert "already exists" in capsys.readouterr().err
    assert main(["backup", str(tmp_path / "no-such-folder" / "copy.db")]) == 1
    assert "does not exist" in capsys.readouterr().err
    monkeypatch.setenv("ACCESSDESK_DB", str(tmp_path / "missing.db"))
    assert main(["backup", str(tmp_path / "other.db")]) == 1


def test_a_directory_file_with_mistakes_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ACCESSDESK_DB", str(tmp_path / "cli.db"))
    bad = tmp_path / "bad.json"
    bad.write_text('{"people": [{"id": "x", "name": "X", "email": "nope"}]}', encoding="utf-8")
    assert main(["directory", "import", str(bad)]) == 1
    err = capsys.readouterr().err
    assert f"Nothing was changed. Fix these problems in {bad} first:" in err
    assert '"email" does not look like an email address' in err
    assert people_in(tmp_path / "cli.db") == 0


def test_serve_with_single_sign_on_adds_no_demo_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "real.db"
    monkeypatch.setenv("ACCESSDESK_DB", str(path))
    for name, value in SSO_ENV.items():
        monkeypatch.setenv(name, value)
    calls = fake_uvicorn(monkeypatch)
    assert main(["serve"]) == 0
    out = capsys.readouterr().out
    assert (
        "Redirect URI to register with your identity provider: https://access.example.com/auth/callback"
        in out
    )
    assert "The API is off." in out
    assert "The directory is empty, so nobody can sign in yet." in out
    assert people_in(path) == 0
    assert calls[0]["app"].state.settings.sso

    assert main(["seed"]) == 1
    assert "Use --force if you really want them." in capsys.readouterr().err
    assert people_in(path) == 0
    for name in SSO_ENV:
        monkeypatch.delenv(name)
    assert main(["seed"]) == 1  # the database remembers it was used with single sign-on
    assert main(["serve"]) == 2
    assert "will not open it in demo mode" in capsys.readouterr().err
    assert main(["seed", "--force"]) == 0
    assert people_in(path) == len(USERS)


def test_serve_loads_the_directory_file_at_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "real.db"
    people = tmp_path / "people.json"
    people.write_text(
        json.dumps(
            {"people": [{"id": "ana", "name": "Ana Silva", "email": "ana@example.com", "security": True}]}
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ACCESSDESK_DB", str(path))
    monkeypatch.setenv("ACCESSDESK_DIRECTORY_FILE", str(people))
    calls = fake_uvicorn(monkeypatch)
    assert main(["serve"]) == 0
    assert "Security team: added ana." in capsys.readouterr().out
    assert people_in(path) == 1  # its own directory, so no demo people

    people.write_text("not json", encoding="utf-8")
    assert main(["serve"]) == 1
    assert "is not valid JSON" in capsys.readouterr().err
    assert len(calls) == 1


def test_settings_that_cannot_work_stop_every_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ACCESSDESK_OIDC_ISSUER", "https://login.example.com")
    for command in (["serve"], ["seed"], ["verify-audit"]):
        assert main(command) == 2
        assert "AccessDesk cannot start: Single sign-on is only half set up." in capsys.readouterr().err
