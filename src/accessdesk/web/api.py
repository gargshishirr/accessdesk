"""JSON API for other services: the access check and the audit-chain status."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from accessdesk.models import Role
from accessdesk.web.security import require_api_key
from accessdesk.web.ui import get_metrics, get_service

router = APIRouter(prefix="/api/v1", tags=["access"], dependencies=[Depends(require_api_key)])


class CheckResponse(BaseModel):
    allowed: bool = Field(description="True only if an unexpired grant covers the requested role.")
    reason: str = Field(description="active_grant, no_active_grant or role_insufficient.")
    expires_at: int | None = Field(description="Unix time when the covering grant ends.")
    grant_id: int | None = None


class AuditStatus(BaseModel):
    ok: bool
    events: int
    head_hash: str = Field(description="Hash of the newest entry. Store it elsewhere to detect truncation.")
    first_invalid_seq: int | None = None
    problem: str = ""


@router.get("/check", summary="Does this person have this access right now?")
async def check(
    request: Request,
    user: Annotated[str, Query(min_length=1, max_length=64, description="User id, for example alice.")],
    resource: Annotated[
        str, Query(min_length=1, max_length=64, description="Resource id, for example prod-db.")
    ],
    role: Annotated[Role, Query(description="The minimum role needed.")] = Role.VIEWER,
) -> CheckResponse:
    # Deliberately async: the lookup is one indexed SQLite read (about 10 microseconds, and WAL readers never
    # wait for writers), while handing it to a worker thread would cost two thread hops per request.
    result = get_service(request).check(user, resource, role)
    get_metrics(request).checks.labels(str(result.allowed).lower(), result.reason).inc()
    return CheckResponse(
        allowed=result.allowed, reason=result.reason, expires_at=result.expires_at, grant_id=result.grant_id
    )


@router.get("/audit/verify", summary="Verify the audit log hash chain")
def verify_audit(request: Request) -> AuditStatus:
    # Sync on purpose: re-hashing the whole chain is O(entries), so it runs in the thread pool.
    v = get_service(request).verify_audit()
    return AuditStatus(
        ok=v.ok,
        events=v.events,
        head_hash=v.head_hash,
        first_invalid_seq=v.first_invalid_seq,
        problem=v.problem,
    )
