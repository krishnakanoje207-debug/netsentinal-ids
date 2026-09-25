"""FastAPI dependencies: who is calling, and may they.

The current user is loaded from the database on every request rather than trusted
from the token payload. That costs a query and buys immediate revocation:
deactivating an account or changing its role takes effect at once, instead of
whenever the holder's token happens to expire.
"""

from __future__ import annotations

import hmac
from typing import Annotated, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from netsentinel_api.config import Settings, get_settings
from netsentinel_api.db.models import User
from netsentinel_api.db.repositories import (
    ActionRepository,
    AlertRepository,
    AssetRepository,
    ModelRepository,
    UserRepository,
)
from netsentinel_api.db.session import get_session
from netsentinel_api.rbac import permissions_for
from netsentinel_api.security import TokenError, decode_access_token, subject_id

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

# WWW-Authenticate is required on a 401 by the HTTP spec, and clients use it to
# know a bearer token is what is missing.
UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    try:
        payload = decode_access_token(settings, token)
        user_id = subject_id(payload)
    except TokenError:
        # Deliberately uniform: an expired token, a forged one and a malformed one
        # all look identical from outside.
        raise UNAUTHENTICATED from None

    user = session.scalar(
        select(User).options(joinedload(User.role)).where(User.user_id == user_id)
    )
    if user is None or not user.is_active:
        raise UNAUTHENTICATED
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def require(*required: str) -> Callable[[User], User]:
    """Dependency factory: the caller must hold every named permission.

    Returns 403 rather than 404 once authenticated - the caller exists, they are
    simply not allowed - and names the missing permission, which is useful to an
    operator and tells an attacker nothing they could not learn by trying.
    """

    def guard(user: CurrentUser) -> User:
        granted = permissions_for(user.role.permissions if user.role else None)
        missing = [p for p in required if p not in granted]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing permission: {', '.join(missing)}",
            )
        return user

    return guard


sensor_bearer = HTTPBearer(auto_error=False)


def sensor_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(sensor_bearer)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """The sensor's credential: the static token in ``Settings.sensor_token``.

    A token rather than a user account, because the sensor is not a person: an
    account would need a password, a role invented for it and a login on every
    start, to end up holding the same kind of long-lived secret this is. The token
    opens only the endpoints that take this dependency, and a JWT is never accepted
    in its place, nor it in a JWT's.

    Compared in constant time, so the response time says nothing about how much of
    a guess was right.
    """
    expected = settings.sensor_token
    if expected is None:
        # Said plainly: the sensor stops on this, and an operator reading its log
        # needs to know which side is misconfigured.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no sensor token is configured on the API",
        )
    presented = credentials.credentials if credentials is not None else ""
    if not hmac.compare_digest(
        presented.encode("utf-8"), expected.get_secret_value().encode("utf-8")
    ):
        raise UNAUTHENTICATED


def get_user_repo(
    session: Annotated[Session, Depends(get_session)],
) -> UserRepository:
    return UserRepository(session)


def get_alert_repo(
    session: Annotated[Session, Depends(get_session)],
) -> AlertRepository:
    return AlertRepository(session)


def get_asset_repo(
    session: Annotated[Session, Depends(get_session)],
) -> AssetRepository:
    return AssetRepository(session)


def get_action_repo(
    session: Annotated[Session, Depends(get_session)],
) -> ActionRepository:
    return ActionRepository(session)


def get_model_repo(
    session: Annotated[Session, Depends(get_session)],
) -> ModelRepository:
    return ModelRepository(session)


SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
UserRepoDep = Annotated[UserRepository, Depends(get_user_repo)]
AlertRepoDep = Annotated[AlertRepository, Depends(get_alert_repo)]
AssetRepoDep = Annotated[AssetRepository, Depends(get_asset_repo)]
ActionRepoDep = Annotated[ActionRepository, Depends(get_action_repo)]
ModelRepoDep = Annotated[ModelRepository, Depends(get_model_repo)]
