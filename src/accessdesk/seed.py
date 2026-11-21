"""Demo directory, resources and separation-of-duties rules, plus a few days of realistic activity."""

from __future__ import annotations

from accessdesk.clock import Clock
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
    User("priya", "Priya Nair", "priya@example.com", "finance-ops", "Financial Analyst", manager_id="carol"),
    User("frank", "Frank Moreau", "frank@example.com", "platform-sre", "SRE Lead", manager_id="maya"),
    User(
        "leo",
        "Leo Martins",
        "leo@example.com",
        "platform-sre",
        "Site Reliability Engineer",
        manager_id="frank",
    ),
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
ENGINEERING = frozenset({"payments-eng", "support", "platform-sre", "security"})

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
        "incident-runbooks",
        "Incident Runbooks",
        "Step-by-step guides for whoever is on call.",
        "frank",
        Sensitivity.LOW,
        720,
        (V, E),
        ENGINEERING,
    ),
    Resource(
        "k8s-prod",
        "Production Kubernetes",
        "Deploy, scale and debug the services customers use.",
        "frank",
        Sensitivity.HIGH,
        12,
        (V, E, A),
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
    Resource(
        "support-console",
        "Support Console",
        "Look up customer accounts and issue refunds.",
        "erin",
        Sensitivity.MEDIUM,
        72,
        (V, E),
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

# Requests up to this id came from the seed. The guided demo only follows requests made after it.
SEEDED_THROUGH = "demo_seeded_through"


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


class _StoryClock:
    """Replays the demo story over the last few days, ending at the real clock's 'now'."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._hours_ago = 0.0

    def at(self, hours_ago: float) -> None:
        self._hours_ago = hours_ago

    def now(self) -> int:
        return self._clock.now() - int(self._hours_ago * 3600)


def seed_activity(service: AccessService) -> None:
    """A few days of requests in every state, made through the real workflow so the audit log is genuine.

    Every approver has something waiting, nobody has asked for the production database yet (that is the
    guided demo's first step), and Alice's payments access is about to run out.
    """
    clock = _StoryClock(service.clock)
    story = AccessService(service.db, clock)

    clock.at(75)
    story.submit("alice", "design-wiki", "viewer", 720, "Reading the payments redesign specs.")  # 1: instant

    clock.at(49)
    ledger = story.submit(  # 2: approved, ends within the hour
        "alice", "payments-ledger", "editor", 48, "Fixing a duplicated payout batch from the March run."
    ).request_id
    clock.at(48.5)
    story.approve(ledger, "bob", "Agreed, this is the March incident.")
    clock.at(47.5)
    story.approve(ledger, "frank", "OK for 48 hours.")

    clock.at(46)
    story.submit(  # 3: refused by separation of duties
        "alice", "payment-approvals", "editor", 24, "Want to release the corrected batch myself."
    )

    clock.at(41)
    runbooks = story.submit(  # 4: instant, given back early
        "alice", "incident-runbooks", "viewer", 72, "On call this week for the payments service."
    ).grant_id
    clock.at(30)
    dashboards = story.submit(  # 5: approved by the manager, then removed by the owner
        "erin", "finance-dashboards", "viewer", 24, "Answering a customer's refund question."
    ).request_id
    clock.at(29)
    finance_grant = story.approve(dashboards, "bob", "").grant_id

    clock.at(28)
    pods = story.submit(  # 6: approved, then expired
        "alice", "k8s-prod", "viewer", 4, "Checking pod restarts during the payments outage."
    ).request_id
    clock.at(27.5)
    story.approve(pods, "bob", "Go ahead.")
    clock.at(27)
    story.approve(pods, "frank", "Read-only is fine.")
    clock.at(23)
    story.expire_due()  # the 4 hours are up, so the sweeper ends it

    clock.at(22)
    payroll = story.submit(  # 7: critical, waiting for the manager and security
        "erin", "payroll-console", "viewer", 4, "Checking a payslip error reported by an employee."
    ).request_id
    clock.at(20)
    story.approve(payroll, "carol", "Fine for a payslip check.")

    clock.at(19)
    if runbooks is not None:
        story.release(runbooks, "alice")
    clock.at(14)
    if finance_grant is not None:
        story.revoke(finance_grant, "carol", "Refund question answered, so this is no longer needed.")

    clock.at(9)
    certs = story.submit(  # 8: Leo's manager owns the cluster, so two people from security approve too
        "leo", "k8s-prod", "admin", 2, "Rotating the cluster certificates before they expire (CHG-1190)."
    ).request_id
    clock.at(8)
    story.approve(certs, "frank", "Planned change, approved in CAB.")

    clock.at(6)
    story.submit(  # 9: waiting for the manager, who also owns it
        "priya", "finance-dashboards", "editor", 72, "Updating the Q3 revenue forecast model."
    )

    clock.at(3)
    lookup = story.submit(  # 10: manager approved, waiting for the owner
        "erin", "prod-db", "viewer", 8, "Looking up a customer's failed payment for ticket SUP-3318."
    ).request_id
    clock.at(2)
    story.approve(lookup, "bob", "Yes, read-only for the ticket.")

    clock.at(1)
    last = story.submit(  # 11: waiting for the manager
        "alice", "finance-dashboards", "viewer", 24, "Reconciling payout refunds against the revenue report."
    ).request_id

    clock.at(0)
    story.expire_due()
    service.set_meta(SEEDED_THROUGH, str(last))
