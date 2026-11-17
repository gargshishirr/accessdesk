"""The directory: who works here, who manages whom, what can be requested and who owns it.

A company keeps it in one JSON file and loads it with ``accessdesk directory import FILE`` (or with
``ACCESSDESK_DIRECTORY_FILE`` at start-up). ``accessdesk directory export`` writes the current directory in
the same format, which is the easiest way to start a file.

* People and resources are added or updated by id. Anyone or anything not in the file is left alone.
* ``"active": false`` removes a person who left: their sessions end, their access ends and their pending
  requests are cancelled. They stay in the history. The same retires a resource.
* If the file has ``separation_of_duties``, those rules replace all the current ones.

An import is one transaction and every change lands in the audit log, so a file with a mistake changes
nothing at all.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from accessdesk import audit
from accessdesk.models import Entitlement, Role, Sensitivity
from accessdesk.service import AccessService

# Who the audit log says made directory changes. The colon keeps it apart from every person's id.
ACTOR = "admin:directory"
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_HOURS = 24 * 365
SECTIONS = ("people", "resources", "separation_of_duties")
PERSON_FIELDS = ("id", "name", "email", "team", "title", "manager", "security", "active")
RESOURCE_FIELDS = (
    "id",
    "name",
    "description",
    "owner",
    "sensitivity",
    "max_hours",
    "roles",
    "auto_approve_teams",
    "active",
)
RULE_FIELDS = ("id", "description", "first", "second")


class DirectoryError(ValueError):
    """The file cannot be loaded. ``problems`` lists every mistake found, in plain words."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = problems


@dataclass(frozen=True, slots=True)
class PersonEntry:
    id: str
    name: str
    email: str
    team: str = ""
    title: str = ""
    manager: str | None = None
    security: bool = False
    active: bool = True


@dataclass(frozen=True, slots=True)
class ResourceEntry:
    id: str
    name: str
    description: str
    owner: str
    sensitivity: Sensitivity
    max_hours: int
    roles: tuple[Role, ...]
    auto_approve_teams: tuple[str, ...] = ()
    active: bool = True


@dataclass(frozen=True, slots=True)
class RuleEntry:
    id: str
    description: str
    first: Entitlement
    second: Entitlement


@dataclass(frozen=True, slots=True)
class Directory:
    """A parsed file. A section that is None was not in the file and is left as it is."""

    people: tuple[PersonEntry, ...] | None = None
    resources: tuple[ResourceEntry, ...] | None = None
    rules: tuple[RuleEntry, ...] | None = None


@dataclass
class Report:
    people_added: list[str] = field(default_factory=list)
    people_updated: list[str] = field(default_factory=list)
    people_removed: list[str] = field(default_factory=list)
    security_added: list[str] = field(default_factory=list)
    security_removed: list[str] = field(default_factory=list)
    resources_added: list[str] = field(default_factory=list)
    resources_updated: list[str] = field(default_factory=list)
    resources_retired: list[str] = field(default_factory=list)
    rules_replaced: int | None = None
    requests_rerouted: int = 0
    grants_ended: int = 0
    requests_cancelled: int = 0
    sessions_ended: int = 0
    people_not_in_file: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(
            self.people_added
            or self.people_updated
            or self.resources_added
            or self.resources_updated
            or self.rules_replaced is not None
        )

    def lines(self) -> list[str]:
        out: list[str] = []
        if self.people_added or self.people_updated:
            out.append(
                f"People: {_counted(self.people_added, 'added')}, {_counted(self.people_updated, 'updated')}"
                + (f", {_counted(self.people_removed, 'removed')}" if self.people_removed else "")
                + "."
            )
        if self.security_added or self.security_removed:
            out.append(
                "Security team: "
                + "; ".join(
                    part
                    for part in (
                        "added " + ", ".join(self.security_added) if self.security_added else "",
                        "removed " + ", ".join(self.security_removed) if self.security_removed else "",
                    )
                    if part
                )
                + "."
            )
        if self.resources_added or self.resources_updated:
            out.append(
                f"Resources: {_counted(self.resources_added, 'added')}, "
                f"{_counted(self.resources_updated, 'updated')}"
                + (f", {_counted(self.resources_retired, 'retired')}" if self.resources_retired else "")
                + "."
            )
        if self.rules_replaced is not None:
            out.append(f"Separation-of-duties rules: replaced ({self.rules_replaced} now).")
        if self.requests_rerouted:
            out.append(
                f"Sent {self.requests_rerouted} waiting request(s) to the security team, because the "
                "requester's manager left."
            )
        if self.grants_ended or self.requests_cancelled or self.sessions_ended:
            out.append(
                f"Ended {self.grants_ended} access grant(s), cancelled {self.requests_cancelled} pending "
                f"request(s) and signed out {self.sessions_ended} session(s)."
            )
        if not self.changed:
            out.append("No changes.")
        if self.people_not_in_file:
            out.append(
                f"Not in the file, so left as they are: {len(self.people_not_in_file)} people "
                f"({_some(self.people_not_in_file)})."
            )
        out.extend(f"Warning: {w}" for w in self.warnings)
        return out


def _some(ids: list[str]) -> str:
    return ", ".join(ids[:10]) + (", ..." if len(ids) > 10 else "")


def _counted(ids: list[str], verb: str) -> str:
    return f"{len(ids)} {verb}" + (f" ({_some(ids)})" if ids else "")


# ----------------------------------------------------------------------------- reading the file


def load(path: str | Path) -> Directory:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise DirectoryError([f"Cannot read {path}: {exc.strerror or exc}."]) from None
    except UnicodeDecodeError:
        raise DirectoryError([f"{path} is not UTF-8 text. Save it as UTF-8 and try again."]) from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DirectoryError(
            [f"{path} is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})."]
        ) from None
    return parse(data)


class _Reader:
    """Reads one entry's fields and collects every problem instead of stopping at the first."""

    def __init__(
        self, raw: dict[str, Any], where: str, allowed: tuple[str, ...], problems: list[str]
    ) -> None:
        self.raw = raw
        self.where = where
        self.problems = problems
        for name in sorted(set(raw) - set(allowed)):
            self.problem(f'has an unknown field "{name}" (allowed: {", ".join(allowed)})')

    def problem(self, text: str) -> None:
        self.problems.append(f"{self.where} {text}.")

    def text(self, name: str, *, required: bool = True, max_length: int = 200) -> str:
        value = self.raw.get(name)
        if value is None:
            if required:
                self.problem(f'needs "{name}"')
            return ""
        if not isinstance(value, str):
            self.problem(f'"{name}" must be text')
            return ""
        value = value.strip()
        if required and not value:
            self.problem(f'"{name}" cannot be empty')
        if len(value) > max_length:
            self.problem(f'"{name}" is longer than {max_length} characters')
        return value

    def ident(self, name: str, *, required: bool = True) -> str | None:
        value = self.raw.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, str) or not ID_PATTERN.match(value):
            self.problem(
                f'"{name}" must be an id of 1 to 64 letters, digits, dots, dashes, underscores or @ '
                f"(got {json.dumps(value)})"
            )
            return None
        return value

    def boolean(self, name: str, default: bool) -> bool:
        value = self.raw.get(name, default)
        if not isinstance(value, bool):
            self.problem(f'"{name}" must be true or false')
            return default
        return value

    def strings(self, name: str) -> tuple[str, ...]:
        value = self.raw.get(name, [])
        if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            self.problem(f'"{name}" must be a list of names')
            return ()
        return tuple(dict.fromkeys(v.strip() for v in value))


def _entries(
    data: dict[str, Any], section: str, problems: list[str]
) -> list[tuple[str, dict[str, Any]]] | None:
    if section not in data:
        return None
    items = data[section]
    if not isinstance(items, list):
        problems.append(f'"{section}" must be a list.')
        return []
    found: list[tuple[str, dict[str, Any]]] = []
    for index, item in enumerate(items):
        where = f"{section}[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{where} must be an object.")
            continue
        if isinstance(item.get("id"), str):
            where += f' ("{item["id"]}")'
        found.append((where, item))
    return found


def parse(data: object) -> Directory:
    """Check the file's shape and values. References to people and resources are checked on import,
    because they may point at people already in the database."""
    if not isinstance(data, dict):
        raise DirectoryError(['The file must hold one JSON object with "people", "resources" or both.'])
    problems: list[str] = []
    for name in sorted(set(data) - set(SECTIONS)):
        problems.append(f'Unknown section "{name}" (allowed: {", ".join(SECTIONS)}).')

    people = _parse_people(_entries(data, "people", problems), problems)
    resources = _parse_resources(_entries(data, "resources", problems), problems)
    rules = _parse_rules(_entries(data, "separation_of_duties", problems), problems)
    if problems:
        raise DirectoryError(problems)
    return Directory(people, resources, rules)


def _parse_people(
    entries: list[tuple[str, dict[str, Any]]] | None, problems: list[str]
) -> tuple[PersonEntry, ...] | None:
    if entries is None:
        return None
    people: list[PersonEntry] = []
    seen_ids: set[str] = set()
    seen_emails: dict[str, str] = {}
    for where, raw in entries:
        read = _Reader(raw, where, PERSON_FIELDS, problems)
        person_id = read.ident("id")
        email = read.text("email", max_length=254).lower()
        if email and not EMAIL_PATTERN.match(email):
            read.problem(f'"email" does not look like an email address ({email})')
        person = PersonEntry(
            id=person_id or "",
            name=read.text("name"),
            email=email,
            team=read.text("team", required=False, max_length=100),
            title=read.text("title", required=False),
            manager=read.ident("manager", required=False),
            security=read.boolean("security", False),
            active=read.boolean("active", True),
        )
        if person_id:
            if person_id in seen_ids:
                read.problem(f'repeats the id "{person_id}"')
            seen_ids.add(person_id)
            if person.manager == person_id:
                read.problem("cannot be their own manager")
        if email:
            if email in seen_emails:
                read.problem(f"has the same email as {seen_emails[email]}")
            seen_emails.setdefault(email, person_id or where)
        people.append(person)
    return tuple(people)


def _parse_resources(
    entries: list[tuple[str, dict[str, Any]]] | None, problems: list[str]
) -> tuple[ResourceEntry, ...] | None:
    if entries is None:
        return None
    resources: list[ResourceEntry] = []
    seen_ids: set[str] = set()
    for where, raw in entries:
        read = _Reader(raw, where, RESOURCE_FIELDS, problems)
        resource_id = read.ident("id")
        sensitivity_text = read.text("sensitivity", max_length=20).lower()
        sensitivity = Sensitivity.LOW
        if sensitivity_text in {s.value for s in Sensitivity}:
            sensitivity = Sensitivity(sensitivity_text)
        elif sensitivity_text:
            read.problem('"sensitivity" must be low, medium, high or critical')
        max_hours = raw.get("max_hours")
        if isinstance(max_hours, bool) or not isinstance(max_hours, int) or not 1 <= max_hours <= MAX_HOURS:
            read.problem(f'"max_hours" must be a whole number from 1 to {MAX_HOURS}')
            max_hours = 1
        role_names = read.strings("roles")
        roles = tuple(r for r in Role if r.value in role_names)
        if not role_names:
            read.problem('"roles" must list at least one of viewer, editor, admin')
        elif len(roles) != len(role_names):
            read.problem('"roles" can only contain viewer, editor and admin')
        resources.append(
            ResourceEntry(
                id=resource_id or "",
                name=read.text("name"),
                description=read.text("description", required=False, max_length=500),
                owner=read.ident("owner") or "",
                sensitivity=sensitivity,
                max_hours=max_hours,
                roles=roles,
                auto_approve_teams=read.strings("auto_approve_teams"),
                active=read.boolean("active", True),
            )
        )
        if resource_id:
            if resource_id in seen_ids:
                read.problem(f'repeats the id "{resource_id}"')
            seen_ids.add(resource_id)
    return tuple(resources)


def _parse_rules(
    entries: list[tuple[str, dict[str, Any]]] | None, problems: list[str]
) -> tuple[RuleEntry, ...] | None:
    if entries is None:
        return None
    rules: list[RuleEntry] = []
    seen_ids: set[str] = set()
    for where, raw in entries:
        read = _Reader(raw, where, RULE_FIELDS, problems)
        rule_id = read.ident("id")
        sides: list[Entitlement] = []
        for side in ("first", "second"):
            value = raw.get(side)
            role_names = {r.value for r in Role}
            if (
                not isinstance(value, dict)
                or set(value) != {"resource", "role"}
                or not isinstance(value["resource"], str)
                or not ID_PATTERN.match(value["resource"])
                or not isinstance(value["role"], str)
                or value["role"] not in role_names
            ):
                read.problem(f'"{side}" must look like {{"resource": "payments-ledger", "role": "editor"}}')
                sides.append(Entitlement("", Role.VIEWER))
            else:
                sides.append(Entitlement(value["resource"], Role(value["role"])))
        rules.append(RuleEntry(rule_id or "", read.text("description", max_length=300), sides[0], sides[1]))
        if rule_id:
            if rule_id in seen_ids:
                read.problem(f'repeats the id "{rule_id}"')
            seen_ids.add(rule_id)
    return tuple(rules)


# ----------------------------------------------------------------------------- applying it


class _DryRun(Exception):
    """Raised at the end of a dry run so the transaction rolls back."""


def apply(service: AccessService, directory: Directory, *, dry_run: bool = False) -> Report:
    """Bring the database in line with ``directory`` in one transaction. Raises DirectoryError and changes
    nothing if the result would not make sense (for example an owner who is not in the directory)."""
    report = Report()
    try:
        with service.db.write() as conn:
            # Managers may appear after the people they manage; check references at the end instead.
            conn.execute("PRAGMA defer_foreign_keys = ON")
            if directory.people is not None:
                _apply_people(service, conn, directory.people, report)
                report.requests_rerouted = service.reroute_orphaned_manager_steps(conn, actor=ACTOR)
            if directory.resources is not None:
                _apply_resources(service, conn, directory.resources, report)
            if directory.rules is not None:
                _apply_rules(service, conn, directory.rules, report)
            _check_references(conn, report)
            broken = conn.execute("PRAGMA foreign_key_check").fetchall()
            if broken:  # a safety net: _check_references should already have explained the problem
                raise DirectoryError([f"The import would break {len(broken)} link(s) between records."])
            if dry_run:
                raise _DryRun
    except _DryRun:
        pass
    return report


_PERSON_COLUMNS = {
    "name": "name",
    "email": "email",
    "team": "team",
    "title": "title",
    "manager": "manager_id",
    "security": "is_security",
    "active": "active",
}


def _person_values(entry: PersonEntry) -> dict[str, Any]:
    return {
        "name": entry.name,
        "email": entry.email,
        "team": entry.team,
        "title": entry.title,
        "manager": entry.manager,
        "security": entry.security,
        "active": entry.active,
    }


def _apply_people(
    service: AccessService, conn: sqlite3.Connection, people: tuple[PersonEntry, ...], report: Report
) -> None:
    now = service.clock.now()
    current = {
        row["id"]: {
            "name": row["name"],
            "email": row["email"],
            "team": row["team"],
            "title": row["title"],
            "manager": row["manager_id"],
            "security": bool(row["is_security"]),
            "active": bool(row["active"]),
        }
        for row in conn.execute("SELECT * FROM users")
    }
    in_file = {p.id for p in people}
    report.people_not_in_file = sorted(set(current) - in_file)

    # Emails must stay unique. Park the emails that move first, so two people can swap addresses.
    final_emails: dict[str, str] = {pid: values["email"].lower() for pid, values in current.items()}
    final_emails.update({p.id: p.email for p in people})
    owners: dict[str, list[str]] = {}
    for pid, email in final_emails.items():
        owners.setdefault(email, []).append(pid)
    clashes = [
        f"{', '.join(sorted(ids))} would share {email}" for email, ids in owners.items() if len(ids) > 1
    ]
    if clashes:
        raise DirectoryError([f"Each person needs their own email address: {c}." for c in clashes])
    moving = [p.id for p in people if p.id in current and current[p.id]["email"].lower() != p.email]
    for pid in moving:
        conn.execute("UPDATE users SET email = ? WHERE id = ?", (f"moving:{pid}", pid))

    for entry in people:
        values = _person_values(entry)
        old = current.get(entry.id)
        if old is None:
            conn.execute(
                "INSERT INTO users (id, name, email, team, title, manager_id, is_security, active) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.id,
                    entry.name,
                    entry.email,
                    entry.team,
                    entry.title,
                    entry.manager,
                    entry.security,
                    entry.active,
                ),
            )
            audit.append(
                conn,
                ts=now,
                actor=ACTOR,
                action="directory.person_added",
                subject=f"user:{entry.id}",
                details=values,
            )
            report.people_added.append(entry.id)
            if entry.security:
                report.security_added.append(entry.id)
            continue
        changes = {name: [old[name], new] for name, new in values.items() if old[name] != new}
        if not changes:
            continue
        assignments = ", ".join(f"{_PERSON_COLUMNS[name]} = ?" for name in changes)
        conn.execute(
            f"UPDATE users SET {assignments} WHERE id = ?",  # noqa: S608 - column names come from a fixed map
            (*(changes[name][1] for name in changes), entry.id),
        )
        audit.append(
            conn,
            ts=now,
            actor=ACTOR,
            action="directory.person_updated",
            subject=f"user:{entry.id}",
            details={"changes": changes},
        )
        report.people_updated.append(entry.id)
        if "security" in changes:
            (report.security_added if entry.security else report.security_removed).append(entry.id)
        if old["active"] and not entry.active:
            grants, requests = service.end_access_in(
                conn, user_id=entry.id, actor=ACTOR, note="This person left the directory."
            )
            report.grants_ended += grants
            report.requests_cancelled += requests
            report.sessions_ended += conn.execute(
                "DELETE FROM sessions WHERE user_id = ?", (entry.id,)
            ).rowcount
            report.people_removed.append(entry.id)


def _apply_resources(
    service: AccessService, conn: sqlite3.Connection, resources: tuple[ResourceEntry, ...], report: Report
) -> None:
    now = service.clock.now()
    current = {
        row["id"]: {
            "name": row["name"],
            "description": row["description"],
            "owner": row["owner_id"],
            "sensitivity": row["sensitivity"],
            "max_hours": row["max_hours"],
            "roles": row["roles"].split(","),
            "auto_approve_teams": sorted(t for t in row["auto_approve_teams"].split(",") if t),
            "active": bool(row["active"]),
        }
        for row in conn.execute("SELECT * FROM resources")
    }
    for entry in resources:
        values: dict[str, Any] = {
            "name": entry.name,
            "description": entry.description,
            "owner": entry.owner,
            "sensitivity": entry.sensitivity.value,
            "max_hours": entry.max_hours,
            "roles": [r.value for r in entry.roles],
            "auto_approve_teams": sorted(entry.auto_approve_teams),
            "active": entry.active,
        }
        row = (
            entry.name,
            entry.description,
            entry.owner,
            entry.sensitivity.value,
            entry.max_hours,
            ",".join(values["roles"]),
            ",".join(values["auto_approve_teams"]),
            entry.active,
        )
        old = current.get(entry.id)
        if old is None:
            conn.execute(
                "INSERT INTO resources (name, description, owner_id, sensitivity, max_hours, roles, "
                "auto_approve_teams, active, id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*row, entry.id),
            )
            audit.append(
                conn,
                ts=now,
                actor=ACTOR,
                action="directory.resource_added",
                subject=f"resource:{entry.id}",
                details=values,
            )
            report.resources_added.append(entry.id)
            continue
        changes = {name: [old[name], new] for name, new in values.items() if old[name] != new}
        if not changes:
            continue
        conn.execute(
            "UPDATE resources SET name = ?, description = ?, owner_id = ?, sensitivity = ?, max_hours = ?, "
            "roles = ?, auto_approve_teams = ?, active = ? WHERE id = ?",
            (*row, entry.id),
        )
        audit.append(
            conn,
            ts=now,
            actor=ACTOR,
            action="directory.resource_updated",
            subject=f"resource:{entry.id}",
            details={"changes": changes},
        )
        report.resources_updated.append(entry.id)
        if old["active"] and not entry.active:
            grants, requests = service.end_access_in(
                conn, resource_id=entry.id, actor=ACTOR, note="This resource was retired."
            )
            report.grants_ended += grants
            report.requests_cancelled += requests
            report.resources_retired.append(entry.id)


def _apply_rules(
    service: AccessService, conn: sqlite3.Connection, rules: tuple[RuleEntry, ...], report: Report
) -> None:
    def key(rule_id: str, description: str, first: Entitlement, second: Entitlement) -> tuple[str, ...]:
        return (
            rule_id,
            description,
            first.resource_id,
            first.role.value,
            second.resource_id,
            second.role.value,
        )

    current = sorted(key(r.id, r.description, r.first, r.second) for r in service._sod_rules(conn))
    wanted = sorted(key(r.id, r.description, r.first, r.second) for r in rules)
    if current == wanted:
        return
    conn.execute("DELETE FROM sod_rules")
    conn.executemany(
        "INSERT INTO sod_rules (id, description, first_resource, first_role, second_resource, second_role) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        wanted,
    )
    audit.append(
        conn,
        ts=service.clock.now(),
        actor=ACTOR,
        action="directory.sod_rules_replaced",
        subject="sod_rules",
        details={"rules": [list(r) for r in wanted]},
    )
    report.rules_replaced = len(wanted)


def _check_references(conn: sqlite3.Connection, report: Report) -> None:
    problems = [
        f'{row["id"]}\'s manager "{row["manager_id"]}" is not in the directory.'
        for row in conn.execute(
            "SELECT u.id, u.manager_id FROM users u LEFT JOIN users m ON m.id = u.manager_id "
            "WHERE u.manager_id IS NOT NULL AND m.id IS NULL ORDER BY u.id"
        )
    ]
    problems += [
        f'Resource "{row["id"]}" needs an owner who is in the directory and active, not "{row["owner_id"]}".'
        for row in conn.execute(
            "SELECT r.id, r.owner_id FROM resources r LEFT JOIN users u ON u.id = r.owner_id "
            "WHERE u.id IS NULL OR (r.active = 1 AND u.active = 0) ORDER BY r.id"
        )
    ]
    problems += [
        f'Separation-of-duties rule "{row["id"]}" names a resource that does not exist.'
        for row in conn.execute(
            "SELECT s.id FROM sod_rules s "
            "LEFT JOIN resources a ON a.id = s.first_resource "
            "LEFT JOIN resources b ON b.id = s.second_resource "
            "WHERE a.id IS NULL OR b.id IS NULL ORDER BY s.id"
        )
    ]
    if problems:
        raise DirectoryError(problems)
    report.warnings += [
        f"{row['id']}'s manager {row['manager_id']} is not active, so security approves their requests."
        for row in conn.execute(
            "SELECT u.id, u.manager_id FROM users u JOIN users m ON m.id = u.manager_id "
            "WHERE u.active = 1 AND m.active = 0 ORDER BY u.id"
        )
    ]


# ----------------------------------------------------------------------------- writing it out


def export(service: AccessService) -> dict[str, Any]:
    """The whole directory in the import format, sorted by id so files diff nicely."""
    return {
        "people": [
            {
                "id": u.id,
                "name": u.name,
                "email": u.email,
                "team": u.team,
                "title": u.title,
                "manager": u.manager_id,
                "security": u.is_security,
                "active": u.active,
            }
            for u in sorted(service.users(), key=lambda u: u.id)
        ],
        "resources": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "owner": r.owner_id,
                "sensitivity": r.sensitivity.value,
                "max_hours": r.max_hours,
                "roles": [role.value for role in r.roles],
                "auto_approve_teams": sorted(r.auto_approve_teams),
                "active": r.active,
            }
            for r in sorted(service.resources(), key=lambda r: r.id)
        ],
        "separation_of_duties": [
            {
                "id": rule.id,
                "description": rule.description,
                "first": {"resource": rule.first.resource_id, "role": rule.first.role.value},
                "second": {"resource": rule.second.resource_id, "role": rule.second.role.value},
            }
            for rule in sorted(service.sod_rules(), key=lambda rule: rule.id)
        ],
    }
