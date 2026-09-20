"""Password hashing and JWT issuing.

Both libraries here have a sharp edge that is silent if ignored:

* **bcrypt truncates at 72 bytes.** A longer password is accepted and only its
  first 72 bytes matter, so two different long passwords can unlock the same
  account. This module refuses anything longer instead of truncating quietly.
* **PyJWT will honour the token's own algorithm header** if you let it. ``decode``
  is always given an explicit algorithm list, so a token claiming ``none`` or a
  weaker algorithm is rejected rather than trusted.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from netsentinel_api.config import Settings

#: bcrypt's own limit, not a policy choice.
MAX_PASSWORD_BYTES = 72

#: Rejected outright at issuing time; see the module docstring.
FORBIDDEN_ALGORITHMS = {"none", "None", "NONE"}


class TokenError(Exception):
    """A token was absent, malformed, expired or not trustworthy."""


def hash_password(password: str) -> str:
    """Hash a password with a per-password salt."""
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"password is {len(encoded)} bytes; bcrypt ignores everything past "
            f"{MAX_PASSWORD_BYTES}, so a longer one would be silently truncated"
        )
    if not password:
        raise ValueError("password must not be empty")
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time comparison via bcrypt. False on any malformed input."""
    try:
        encoded = password.encode("utf-8")
        if len(encoded) > MAX_PASSWORD_BYTES:
            return False
        return bcrypt.checkpw(encoded, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # A corrupted or non-bcrypt hash is a failed login, not a crash.
        return False


def create_access_token(
    settings: Settings,
    user_id: int,
    role: str,
    expires_in: timedelta | None = None,
) -> str:
    """Issue a short-lived access token.

    Permissions are deliberately not in the payload. They are read from the
    database per request, so deactivating a user or changing a role takes effect
    immediately rather than when their token happens to expire.
    """
    if settings.jwt_algorithm in FORBIDDEN_ALGORITHMS:
        raise ValueError("refusing to issue an unsigned token")

    now = datetime.now(timezone.utc)
    ttl = expires_in or timedelta(minutes=settings.access_token_ttl_minutes)
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        # A unique id per token, so an individual one can be denied later.
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(
        payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm
    )


def decode_access_token(settings: Settings, token: str) -> dict:
    """Verify and decode a token, or raise TokenError.

    The algorithm list is explicit and the expiry is required, so neither can be
    chosen by whoever sent the token.
    """
    try:
        return jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub"], "verify_exp": True},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token has expired") from exc
    except jwt.InvalidTokenError as exc:
        # Covers a wrong signature, a wrong algorithm and a missing claim. The
        # message stays generic: which of those failed is not the caller's business.
        raise TokenError("token is not valid") from exc


def subject_id(payload: dict) -> int:
    """Read the user id out of a verified payload."""
    try:
        return int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenError("token subject is not a user id") from exc
