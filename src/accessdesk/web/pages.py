"""HTML pages. Every action is a plain form post followed by a redirect, so the UI needs no JavaScript."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import RedirectResponse, Response

from accessdesk.models import APPROVER_LABELS, REASON_TEXT, Outcome, RequestStatus, Resource, User
from accessdesk.service import (
    ActionResult,
    Conflict,
    Forbidden,
    GrantView,
    NotFound,
    RequestPage,
    ValidationFailed,
)
from accessdesk.web.security import csrf_protect, safe_next
from accessdesk.web.ui import current_user, flash, get_metrics, get_service, render, require_user

router = APIRouter(include_in_schema=False)
CSRF = [Depends(csrf_protect)]
FormText = Annotated[str, Form()]


def see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _version(raw: str) -> int | None:
    return int(raw) if raw.isascii() and raw.isdigit() else None


# ----------------------------------------------------------------------------- sign in


@router.get("/signin")
def signin_form(request: Request, next_url: Annotated[str, Query(alias="next")] = "/") -> Response:
    if current_user(request) is not None:
        return see_other(safe_next(next_url))
    people = get_service(request).users()
    return render(request, "signin.html", "Sign in", people=people, next_url=safe_next(next_url))


@router.post("/signin", dependencies=CSRF)
def signin(
    request: Request, user_id: FormText = "", next_url: Annotated[str, Form(alias="next")] = "/"
) -> Response:
    service = get_service(request)
    user = service.user(user_id) if user_id else None
    if user is None:
        people = service.users()
        return render(
            request,
            "signin.html",
            "Sign in",
            status_code=422,
            people=people,
            next_url=safe_next(next_url),
            errors={"user_id": "Choose who you want to sign in as"},
            error_anchors={"user_id": f"user-{people[0].id}"},
        )
    # A fresh session (and CSRF token) on every sign-in prevents session fixation.
    request.session.clear()
    request.session["user_id"] = user.id
    return see_other(safe_next(next_url))


@router.post("/signout", dependencies=CSRF)
def signout(request: Request) -> Response:
    request.session.clear()
    flash(request, "success", "You have signed out.")
    return see_other("/signin")


# ----------------------------------------------------------------------------- my access


@router.get("/")
def home(request: Request) -> Response:
    user = require_user(request)
    service = get_service(request)
    active, ended = service.my_grants(user.id)
    return render(
        request,
        "home.html",
        "My access",
        user=user,
        active_nav="home",
        grants=active,
        ended=ended,
        requests=service.my_requests(user.id),
    )


@router.post("/grants/{grant_id}/release", dependencies=CSRF)
def release(request: Request, grant_id: int) -> Response:
    user = require_user(request)
    service = get_service(request)
    grant = service.grant(grant_id, user.id)
    try:
        service.release(grant_id, user.id)
    except Conflict as exc:
        flash(request, "error", exc.message)
        return see_other("/")
    flash(request, "success", f"You gave back {grant.role.value} access to {grant.resource.name}.")
    return see_other("/")


# ----------------------------------------------------------------------------- requesting access


@router.get("/requests/new")
def new_request(request: Request, resource: str = "") -> Response:
    user = require_user(request)
    service = get_service(request)
    if not resource:
        return _catalog(request, user)
    chosen = service.resource(resource)
    if chosen is None:
        raise NotFound("That resource was not found.")
    return _request_form(request, user, chosen)


@router.post("/requests", dependencies=CSRF)
def submit_request(
    request: Request,
    resource_id: FormText = "",
    role: FormText = "",
    hours: FormText = "",
    justification: FormText = "",
) -> Response:
    user = require_user(request)
    service = get_service(request)
    try:
        result = service.submit(user.id, resource_id, role, hours, justification)
    except ValidationFailed as exc:
        chosen = service.resource(resource_id)
        if chosen is None:
            return _catalog(request, user, errors={"resource_id": exc.errors["resource_id"]}, status_code=422)
        form = {"role": role, "hours": hours, "justification": justification}
        return _request_form(request, user, chosen, form=form, errors=exc.errors, status_code=422)

    get_metrics(request).requests.labels(result.decision.outcome.value).inc()
    decision = result.decision
    if decision.outcome is Outcome.AUTO_APPROVE:
        flash(request, "success", f"Access granted. {REASON_TEXT[decision.reasons[0]]}")
    elif decision.outcome is Outcome.NEEDS_APPROVAL:
        steps = ", ".join(APPROVER_LABELS[k].lower() for k in decision.approvals)
        flash(request, "success", f"Request #{result.request_id} sent. It needs approval from: {steps}.")
    else:
        flash(
            request,
            "error",
            f"Request #{result.request_id} was not allowed. {REASON_TEXT[decision.reasons[0]]}",
        )
    return see_other(f"/requests/{result.request_id}")


def _catalog(
    request: Request, user: User, *, errors: dict[str, str] | None = None, status_code: int = 200
) -> Response:
    return render(
        request,
        "catalog.html",
        "Request access",
        status_code=status_code,
        user=user,
        active_nav="new",
        resources=get_service(request).resources(),
        errors=errors or {},
        error_anchors={"resource_id": "catalog"},
    )


def _request_form(
    request: Request,
    user: User,
    resource: Resource,
    *,
    form: dict[str, str] | None = None,
    errors: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    service = get_service(request)
    return render(
        request,
        "request_form.html",
        f"Request access to {resource.name}",
        status_code=status_code,
        user=user,
        active_nav="new",
        resource=resource,
        owner=service.user(resource.owner_id),
        manager=service.user(user.manager_id) if user.manager_id else None,
        form=form or {},
        errors=errors or {},
        error_anchors={"role": f"role-{resource.roles[0].value}"},
    )


# ----------------------------------------------------------------------------- one request


@router.get("/requests/{request_id}")
def request_detail(request: Request, request_id: int) -> Response:
    user = require_user(request)
    return _detail(request, user, get_service(request).request_page(request_id, user.id))


@router.post("/requests/{request_id}/decision", dependencies=CSRF)
def decide(
    request: Request, request_id: int, decision: FormText = "", comment: FormText = "", version: FormText = ""
) -> Response:
    user = require_user(request)
    service = get_service(request)
    page = service.request_page(request_id, user.id)
    form = {"decision": decision, "comment": comment}
    if page.request.status is not RequestStatus.PENDING:
        flash(request, "error", f"Request #{request_id} is already {page.request.status.value}.")
        return see_other(f"/requests/{request_id}")
    if page.my_slot is None:
        raise Forbidden("You are not an approver for this request.")
    try:
        if decision == "approve":
            result = service.approve(request_id, user.id, comment, _version(version))
        elif decision == "deny":
            result = service.deny(request_id, user.id, comment, _version(version))
        else:
            raise ValidationFailed({"decision": "Choose whether to approve or deny this request"})
    except ValidationFailed as exc:
        return _detail(request, user, page, form=form, errors=exc.errors, status_code=422)
    except Conflict as exc:
        flash(request, "error", exc.message)
        return see_other(f"/requests/{request_id}")
    if result.status is RequestStatus.DENIED and decision == "approve":
        # The final safety re-check refused it (separation of duties, or access gained meanwhile).
        latest = service.request_page(request_id, user.id).request
        flash(request, "error", f"Request #{request_id} was not approved. {REASON_TEXT[latest.reasons[-1]]}")
    else:
        flash(request, "success", _decision_message(result, page))
    return see_other(f"/requests/{request_id}")


@router.post("/requests/{request_id}/cancel", dependencies=CSRF)
def cancel(request: Request, request_id: int, version: FormText = "") -> Response:
    user = require_user(request)
    try:
        get_service(request).cancel(request_id, user.id, _version(version))
    except Conflict as exc:
        flash(request, "error", exc.message)
        return see_other(f"/requests/{request_id}")
    flash(request, "success", f"Request #{request_id} cancelled.")
    return see_other(f"/requests/{request_id}")


def _decision_message(result: ActionResult, page: RequestPage) -> str:
    request = page.request
    if result.status is RequestStatus.APPROVED:
        who, what = request.requester.name, request.resource.name
        return f"Approved. {who} now has {request.role.value} access to {what}."
    if result.status is RequestStatus.PENDING:
        steps = ", ".join(APPROVER_LABELS[k].lower() for k in result.remaining)
        return f"Your approval is recorded. Still waiting for: {steps}."
    return f"Request #{request.id} denied. {request.requester.name} can see your reason."


def _detail(
    request: Request,
    user: User,
    page: RequestPage,
    *,
    form: dict[str, str] | None = None,
    errors: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    view = page.request
    return render(
        request,
        "request.html",
        f"Request #{view.id}: {view.resource.name}",
        status_code=status_code,
        user=user,
        page=page,
        r=view,
        form=form or {},
        errors=errors or {},
        error_anchors={"decision": "decision-approve", "comment": "comment"},
    )


# ----------------------------------------------------------------------------- approvers and owners


@router.get("/approvals")
def approvals(request: Request) -> Response:
    user = require_user(request)
    pending = get_service(request).pending_for(user.id)
    return render(request, "approvals.html", "Approvals", user=user, active_nav="approvals", pending=pending)


@router.get("/reviews")
def reviews(request: Request) -> Response:
    user = require_user(request)
    grants = get_service(request).reviewable_grants(user.id)
    return render(request, "reviews.html", "Access reviews", user=user, active_nav="reviews", grants=grants)


def _revocable(request: Request, user: User, grant_id: int) -> GrantView:
    grant = get_service(request).grant(grant_id, user.id)
    if not (user.is_security or grant.resource.owner_id == user.id):
        raise Forbidden("Only the resource owner or the security team can remove access.")
    return grant


@router.get("/grants/{grant_id}/revoke")
def revoke_form(request: Request, grant_id: int) -> Response:
    user = require_user(request)
    grant = _revocable(request, user, grant_id)
    if not grant.active_at(get_service(request).clock.now()):
        flash(request, "error", "This access has already ended.")
        return see_other("/reviews")
    return render(request, "revoke.html", f"Remove access for {grant.user.name}", user=user, grant=grant)


@router.post("/grants/{grant_id}/revoke", dependencies=CSRF)
def revoke(request: Request, grant_id: int, note: FormText = "") -> Response:
    user = require_user(request)
    grant = _revocable(request, user, grant_id)
    try:
        get_service(request).revoke(grant_id, user.id, note)
    except ValidationFailed as exc:
        return render(
            request,
            "revoke.html",
            f"Remove access for {grant.user.name}",
            status_code=422,
            user=user,
            grant=grant,
            form={"note": note},
            errors=exc.errors,
        )
    except Conflict as exc:
        flash(request, "error", exc.message)
        return see_other("/reviews")
    flash(
        request,
        "success",
        f"Access removed. {grant.user.name} no longer has {grant.role.value} access "
        f"to {grant.resource.name}.",
    )
    return see_other("/reviews")


@router.get("/audit")
def audit_page(request: Request) -> Response:
    user = require_user(request)
    events, verification = get_service(request).audit_log(user.id)
    return render(
        request,
        "audit.html",
        "Audit log",
        user=user,
        active_nav="audit",
        events=events,
        verification=verification,
    )


@router.get("/accessibility")
def accessibility(request: Request) -> Response:
    return render(request, "accessibility.html", "Accessibility statement")
