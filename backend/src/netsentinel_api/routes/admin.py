"""Accounts, sensors and the audit trail: the administrator's three jobs.

Each has its own permission (``users:manage``, ``sensors:manage``, ``audit:read``),
held by the administrator role alone. Every change made here writes an audit row, in
the same transaction as the change, so the trail cannot say less than happened.

Two refusals protect the system from its own administrator: an account cannot be
disabled or moved to another role by the person signed in to it. Without them the
last administrator is one click from a deployment nobody can administer.

Disabling an account ends its sessions at once rather than at token expiry, because
``deps.current_user`` reloads the user and checks ``is_active`` on every request.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from netsentinel_api.db.models import AuditLog, Sensor, User
from netsentinel_api.deps import AdminRepoDep, SessionDep, require
from netsentinel_api.rbac import AUDIT_READ, SENSORS_MANAGE, USERS_MANAGE, permissions_for
from netsentinel_api.routes.alerts import TIME_HELP, _window
from netsentinel_api.schemas import (
    AccountIn,
    AccountOut,
    AccountUpdate,
    AuditEntryOut,
    RoleOut,
    SensorOut,
    SensorUpdate,
)
from netsentinel_api.security import hash_password

router = APIRouter(prefix="/admin", tags=["admin"])


def _account(user: User) -> AccountOut:
    return AccountOut(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        role=user.role.name if user.role else None,
        created_at=user.created_at,
    )


def _sensor(sensor: Sensor, hostname: str) -> SensorOut:
    return SensorOut(
        sensor_id=sensor.sensor_id,
        type=sensor.type,
        hostname=hostname,
        status=sensor.status,
        last_seen=sensor.last_seen,
        revoked=sensor.revoked,
    )


def _role_named(admin: AdminRepoDep, name: str):
    role = admin.role(name)
    if role is None:
        known = ", ".join(r.name for r in admin.roles())
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"no role named {name!r}; the roles are {known}",
        )
    return role


# --- accounts --------------------------------------------------------------

@router.get("/roles", response_model=list[RoleOut])
def list_roles(
    admin: AdminRepoDep,
    _: Annotated[object, Depends(require(USERS_MANAGE))],
) -> list[RoleOut]:
    """Served rather than hardcoded in the dashboard, for the reason ``/auth/me``
    serves permissions: two copies of the role table would drift."""
    return [
        RoleOut(name=role.name, permissions=sorted(permissions_for(role.permissions)))
        for role in admin.roles()
    ]


@router.get("/users", response_model=list[AccountOut])
def list_users(
    admin: AdminRepoDep,
    _: Annotated[object, Depends(require(USERS_MANAGE))],
) -> list[AccountOut]:
    return [_account(user) for user in admin.users()]


@router.post("/users", response_model=AccountOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: AccountIn,
    admin: AdminRepoDep,
    session: SessionDep,
    actor: Annotated[User, Depends(require(USERS_MANAGE))],
) -> AccountOut:
    role = _role_named(admin, payload.role)
    if admin.taken(payload.username, payload.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="that username or email already belongs to an account",
        )
    try:
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=password_hash,
        role_id=role.role_id,
        is_active=True,
    )
    user.role = role
    session.add(user)
    session.add(
        AuditLog(
            user_id=actor.user_id,
            action="user.created",
            entity=f"username:{payload.username}",
            details={"role": role.name},
        )
    )
    # The id is assigned by the database, and the reply is useless without it.
    session.flush()
    return _account(user)


@router.patch("/users/{user_id}", response_model=AccountOut)
def update_user(
    user_id: int,
    payload: AccountUpdate,
    admin: AdminRepoDep,
    session: SessionDep,
    actor: Annotated[User, Depends(require(USERS_MANAGE))],
) -> AccountOut:
    user = admin.user(user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")

    current_role = user.role.name if user.role else None
    if user.user_id == actor.user_id:
        # 409: the request is well formed; it is this account's state that forbids it.
        if payload.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="you cannot disable your own account; ask another administrator, "
                "so the system is never left without one",
            )
        if payload.role is not None and payload.role != current_role:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="you cannot change your own role; ask another administrator, "
                "so the system is never left without one",
            )

    if payload.role is not None and payload.role != current_role:
        role = _role_named(admin, payload.role)
        user.role_id = role.role_id
        user.role = role
        session.add(
            AuditLog(
                user_id=actor.user_id,
                action="user.role_changed",
                entity=f"user:{user.user_id}",
                details={"from": current_role, "to": role.name},
            )
        )

    if payload.is_active is not None and payload.is_active != user.is_active:
        user.is_active = payload.is_active
        session.add(
            AuditLog(
                user_id=actor.user_id,
                action="user.enabled" if payload.is_active else "user.disabled",
                entity=f"user:{user.user_id}",
                details={"username": user.username},
            )
        )

    return _account(user)


# --- sensors ---------------------------------------------------------------

@router.get("/sensors", response_model=list[SensorOut])
def list_sensors(
    admin: AdminRepoDep,
    _: Annotated[object, Depends(require(SENSORS_MANAGE))],
) -> list[SensorOut]:
    return [_sensor(sensor, hostname) for sensor, hostname in admin.sensors()]


@router.patch("/sensors/{sensor_id}", response_model=SensorOut)
def update_sensor(
    sensor_id: int,
    payload: SensorUpdate,
    admin: AdminRepoDep,
    session: SessionDep,
    actor: Annotated[User, Depends(require(SENSORS_MANAGE))],
) -> SensorOut:
    """Revoke a sensor, or trust it again. The writer refuses a revoked sensor."""
    found = admin.sensor(sensor_id)
    if found is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="sensor not found")
    sensor, hostname = found

    if payload.revoked != sensor.revoked:
        sensor.revoked = payload.revoked
        session.add(
            AuditLog(
                user_id=actor.user_id,
                action="sensor.revoked" if payload.revoked else "sensor.restored",
                entity=f"sensor:{sensor.sensor_id}",
                details={"hostname": hostname, "type": sensor.type.value},
            )
        )
    return _sensor(sensor, hostname)


# --- the audit trail -------------------------------------------------------

@router.get("/audit", response_model=list[AuditEntryOut])
def read_audit(
    admin: AdminRepoDep,
    _: Annotated[object, Depends(require(AUDIT_READ))],
    actor: Annotated[
        str | None, Query(max_length=50, description="the acting user's username")
    ] = None,
    action: Annotated[
        str | None,
        Query(max_length=100, description="an action, or its start: user. finds all of them"),
    ] = None,
    start: Annotated[
        str | None, Query(alias="from", max_length=40, description=TIME_HELP)
    ] = None,
    end: Annotated[
        str | None, Query(alias="to", max_length=40, description=TIME_HELP)
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditEntryOut]:
    """Newest first. Reading the trail is not itself recorded: it changes nothing,
    and an audit log that grows every time it is read buries what it is for."""
    rows = admin.audit(
        actor=actor.strip() if actor else None,
        action=action.strip() if action else None,
        window=_window(start, end),
        limit=limit,
        offset=offset,
    )
    return [
        AuditEntryOut(
            log_id=entry.log_id,
            ts=entry.ts,
            user_id=entry.user_id,
            username=username,
            action=entry.action,
            entity=entry.entity,
            details=entry.details or {},
        )
        for entry, username in rows
    ]
