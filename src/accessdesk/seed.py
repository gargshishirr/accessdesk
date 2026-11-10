"""Demo directory, resources and separation-of-duties rules, plus a little realistic activity."""

from __future__ import annotations

from accessdesk.db import Database
from accessdesk.models import Resource, Role, Sensitivity, User
from accessdesk.service import AccessService

USERS = (
    User("maya", "Maya Rao", "maya@example.com", "leadership", "Director of Engineering"),
    User("bob", "Bob Singh", "bob@example.com", "payments-eng", "Engineering Manager", manager_id="maya"),
    User("alice", "Alice Chen", "alice@example.com", "payments-eng", "Software Engineer", manager_id="bob"),
    User("erin", "Erin Walsh", "erin@example.com", "support", "Support Engineer", manager_id="bob"),
    User(
        "carol",
        "Carol Diaz",
        "carol@example.com",
        "finance-ops",
        "Finance Operations Lead",
        manager_id="maya",
    ),
    User("frank", "Frank Moreau", "frank@example.com", "platform-sre", "SRE Lead", manager_id="maya"),
    User(
        "dan",
        "Dan Okafor",
        "dan@example.com",
        "security",
        "Security Engineer",
        manager_id="maya",
        is_security=True,
    ),
    User(
        "grace",
        "Grace Liu",
        "grace@example.com",
        "security",
        "Security Engineer",
        manager_id="maya",
        is_security=True,
    ),
)

V, E, A = Role.VIEWER, Role.EDITOR, Role.ADMIN

RESOURCES = (
    Resource(
        "design-wiki",
        "Design Wiki",
        "Product specs and design reviews.",
        "maya",
        Sensitivity.LOW,
        720,
        (V, E),
        frozenset({"payments-eng", "support", "finance-ops", "platform-sre", "security", "leadership"}),
    ),
    Resource(
        "finance-dashboards",
        "Finance Dashboards",
        "Revenue and spend reports.",
        "carol",
        Sensitivity.MEDIUM,
        168,
        (V, E),
    ),
    Resource(
        "prod-db",
        "Production Database",
        "Customer data in production.",
        "frank",
        Sensitivity.HIGH,
        24,
        (V, E, A),
    ),
    Resource(
        "payments-ledger",
        "Payments Ledger",
        "Create and edit outgoing payments.",
        "frank",
        Sensitivity.HIGH,
        72,
        (V, E),
    ),
    Resource(
        "payment-approvals",
        "Payment Approvals",
        "Release payments to banks.",
        "carol",
        Sensitivity.HIGH,
        72,
        (V, E),
    ),
    Resource(
        "payroll-console",
        "Payroll Admin Console",
        "Salaries and bank details for every employee.",
        "carol",
        Sensitivity.CRITICAL,
        8,
        (V, E, A),
    ),
)

SOD_RULES = (
    (
        "sod-payments",
        "Nobody may both edit payments and release them.",
        "payments-ledger",
        E,
        "payment-approvals",
        E,
    ),
    (
        "sod-payroll",
        "Nobody may both administer payroll and edit finance reports.",
        "payroll-console",
        A,
        "finance-dashboards",
        E,
    ),
)


def seed_directory(db: Database) -> bool:
    """Insert the demo directory if the database is empty. Returns True if it seeded."""
    with db.write() as conn:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return False
        for u in sorted(USERS, key=lambda u: u.manager_id is not None):
            conn.execute(
                "INSERT INTO users (id, name, email, team, title, manager_id, is_security) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (u.id, u.name, u.email, u.team, u.title, u.manager_id, int(u.is_security)),
            )
        for r in RESOURCES:
            conn.execute(
                "INSERT INTO resources (id, name, description, owner_id, sensitivity, max_hours, roles, "
                "auto_approve_teams) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    r.id,
                    r.name,
                    r.description,
                    r.owner_id,
                    r.sensitivity.value,
                    r.max_hours,
                    ",".join(x.value for x in r.roles),
                    ",".join(sorted(r.auto_approve_teams)),
                ),
            )
        for rule_id, text, r1, role1, r2, role2 in SOD_RULES:
            conn.execute(
                "INSERT INTO sod_rules (id, description, first_resource, first_role, second_resource, "
                "second_role) VALUES (?, ?, ?, ?, ?, ?)",
                (rule_id, text, r1, role1.value, r2, role2.value),
            )
    return True


def seed_activity(service: AccessService) -> None:
    """A few requests in different states, created through the real workflow so the audit log is genuine."""
    service.submit("alice", "design-wiki", "viewer", 720, "Reading the payments redesign specs.")
    service.submit(
        "alice",
        "prod-db",
        "viewer",
        8,
        "Investigating failed payment INC-2041; need to read the payments table.",
    )
    ledger = service.submit(
        "alice", "payments-ledger", "editor", 48, "Fixing a duplicated payout batch from the March run."
    )
    service.approve(ledger.request_id, "bob", "Agreed, this is the March incident.")
    service.approve(ledger.request_id, "frank", "OK for 48 hours.")
    service.submit("alice", "payment-approvals", "editor", 24, "Want to release the corrected batch myself.")
    dashboards = service.submit(
        "erin", "finance-dashboards", "viewer", 24, "Answering a customer's refund question."
    )
    service.approve(dashboards.request_id, "bob", "")
    service.submit(
        "erin", "payroll-console", "viewer", 4, "Checking a payslip error reported by an employee."
    )
