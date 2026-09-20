"""Login.

Every outcome, success or failure, writes an audit row. A failed login is the
single most useful signal in an authentication log, and it is the one most often
not recorded.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from netsentinel_api.db.models import AuditLog
from netsentinel_api.deps import CurrentUser, SessionDep, SettingsDep, UserRepoDep
from netsentinel_api.schemas import TokenResponse, UserOut
from netsentinel_api.security import create_access_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

# One message for every failure. Saying "no such user" tells an attacker which
# usernames are worth attacking.
BAD_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="incorrect username or password",
    headers={"WWW-Authenticate": "Bearer"},
)


@router.post("/token", response_model=TokenResponse)
def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    users: UserRepoDep,
    session: SessionDep,
    settings: SettingsDep,
) -> TokenResponse:
    user = users.by_username(form.username)

    if user is None or not verify_password(form.password, user.password_hash):
        session.add(
            AuditLog(
                user_id=user.user_id if user else None,
                action="auth.login_failed",
                entity=f"username:{form.username}",
                # The attempted password is never recorded, not even hashed.
                details={"reason": "bad_credentials"},
            )
        )
        raise BAD_CREDENTIALS

    if not user.is_active:
        session.add(
            AuditLog(
                user_id=user.user_id,
                action="auth.login_failed",
                entity=f"username:{form.username}",
                details={"reason": "inactive_account"},
            )
        )
        # Same response as a wrong password: whether an account exists but is
        # disabled is not something an unauthenticated caller should learn.
        raise BAD_CREDENTIALS

    token = create_access_token(
        settings, user_id=user.user_id, role=user.role.name if user.role else ""
    )
    session.add(
        AuditLog(
            user_id=user.user_id,
            action="auth.login",
            entity=f"user:{user.user_id}",
            details={"role": user.role.name if user.role else None},
        )
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_ttl_minutes * 60,
    )


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)
