"""First-run setup: the roles from M2, and one administrator to log in as.

    python -m netsentinel_api.bootstrap

Without this the database has no roles and no users, so the API is correct and
completely unusable.

Two rules here:

* Idempotent. Running it twice must not duplicate a role or reset a password, so it
  is safe to call from a deployment script.
* If no password is supplied, one is generated and printed **once**. A default
  administrator password is how a lab deployment becomes an open door, and this
  system is deliberately full of attack traffic.
"""

from __future__ import annotations

import os
import secrets
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from netsentinel_api.db.models import AuditLog, Role, User
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.rbac import (
    ADMINISTRATOR,
    DEFAULT_ROLE_PERMISSIONS,
    as_column,
)
from netsentinel_api.security import hash_password

ADMIN_USERNAME_ENV = "NETSENTINEL_ADMIN_USERNAME"
ADMIN_EMAIL_ENV = "NETSENTINEL_ADMIN_EMAIL"
ADMIN_PASSWORD_ENV = "NETSENTINEL_ADMIN_PASSWORD"

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_EMAIL = "admin@netsentinel.local"

#: Long enough that guessing is hopeless, short enough to retype once.
GENERATED_PASSWORD_BYTES = 24


def sync_roles(session: Session) -> dict[str, Role]:
    """Create or update the three roles. Existing rows keep their identity."""
    roles: dict[str, Role] = {}
    for name, permissions in DEFAULT_ROLE_PERMISSIONS.items():
        role = session.scalar(select(Role).where(Role.name == name))
        if role is None:
            role = Role(name=name, permissions=as_column(permissions))
            session.add(role)
        else:
            # Permissions are re-synced so a code change reaches the database, but
            # the role row itself is reused so user_id references survive.
            role.permissions = as_column(permissions)
        roles[name] = role
    return roles


def ensure_admin(
    session: Session,
    role: Role,
    username: str,
    email: str,
    password: str | None,
) -> tuple[User, bool, str | None]:
    """Create the administrator if absent.

    Returns ``(user, created, generated password)``. ``created`` is reported
    separately from the generated password because the two are not the same fact:
    supplying a password creates an account and generates nothing, and reading
    "nothing was generated" as "nothing was created" tells an operator their
    password was not applied when it was.

    An existing account is left completely alone - no password reset, no
    reactivation - because a bootstrap re-run must not be a way to take over an
    account.
    """
    existing = session.scalar(select(User).where(User.username == username))
    if existing is not None:
        return existing, False, None

    generated = None
    if not password:
        generated = secrets.token_urlsafe(GENERATED_PASSWORD_BYTES)
        password = generated

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role_id=role.role_id,
        is_active=True,
    )
    user.role = role
    session.add(user)
    session.add(
        AuditLog(
            user_id=None,  # nobody was logged in; this is a deployment action
            action="bootstrap.admin_created",
            entity=f"username:{username}",
            details={"role": role.name, "password_generated": generated is not None},
        )
    )
    return user, True, generated


def bootstrap(session: Session) -> tuple[User, bool, str | None]:
    roles = sync_roles(session)
    # Roles need identities before a user can reference one.
    session.flush()
    return ensure_admin(
        session,
        roles[ADMINISTRATOR],
        os.environ.get(ADMIN_USERNAME_ENV, DEFAULT_ADMIN_USERNAME),
        os.environ.get(ADMIN_EMAIL_ENV, DEFAULT_ADMIN_EMAIL),
        os.environ.get(ADMIN_PASSWORD_ENV),
    )


def main() -> int:
    with get_sessionmaker()() as session:
        user, created, generated = bootstrap(session)
        session.commit()

        print(f"roles synced: {', '.join(sorted(DEFAULT_ROLE_PERMISSIONS))}")
        if not created:
            print(f"administrator {user.username!r} already exists; left untouched")
        else:
            print(f"administrator {user.username!r} created")
            if generated is None:
                print("password: the one supplied in the environment")
            else:
                print(f"password: {generated}")
                print("This is shown once. Store it now.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
