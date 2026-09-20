"""First-run setup.

Driven with a fake session rather than a database: what matters here is the
decisions, and the riskiest one is what happens on a second run.
"""

from __future__ import annotations

import pytest

from netsentinel_api.bootstrap import bootstrap, ensure_admin, sync_roles
from netsentinel_api.db.models import AuditLog, Role, User
from netsentinel_api.rbac import (
    ADMINISTRATOR,
    APPROVALS_DECIDE,
    DEFAULT_ROLE_PERMISSIONS,
    as_column,
    permissions_for,
)
from netsentinel_api.security import verify_password


class RecordingSession:
    """A fake session that also answers lookups from what has been added."""

    def __init__(self, existing: list[object] | None = None) -> None:
        self.added: list[object] = []
        self.existing: list[object] = list(existing or [])
        self.flushed = 0

    def add(self, instance: object, /) -> None:
        self.added.append(instance)

    def flush(self) -> None:
        self.flushed += 1

    def scalar(self, statement):
        """Resolve the two lookups bootstrap performs: Role by name, User by username."""
        target = statement.column_descriptions[0]["entity"]
        wanted = _bound(statement)
        for row in self.existing + self.added:
            if not isinstance(row, target):
                continue
            if isinstance(row, Role) and row.name == wanted:
                return row
            if isinstance(row, User) and row.username == wanted:
                return row
        return None


def _bound(statement) -> object:
    """The literal on the right-hand side of the WHERE clause."""
    return statement.whereclause.right.value  # type: ignore[attr-defined]


@pytest.fixture
def session() -> RecordingSession:
    return RecordingSession()


def test_roles_are_created_with_their_seed_permissions(session):
    roles = sync_roles(session)
    assert set(roles) == set(DEFAULT_ROLE_PERMISSIONS)
    for name, role in roles.items():
        assert permissions_for(role.permissions) == DEFAULT_ROLE_PERMISSIONS[name]


def test_existing_role_is_reused_not_duplicated(session):
    """A new row would orphan every users.role_id pointing at the old one."""
    original = Role(role_id=9, name=ADMINISTRATOR, permissions={"granted": []})
    session.existing.append(original)

    roles = sync_roles(session)
    assert roles[ADMINISTRATOR] is original
    assert original.role_id == 9
    # Permissions are re-synced so a code change reaches the database.
    assert APPROVALS_DECIDE not in permissions_for(original.permissions)
    assert permissions_for(original.permissions) == DEFAULT_ROLE_PERMISSIONS[ADMINISTRATOR]


def test_admin_is_created_with_a_generated_password(session):
    role = Role(role_id=1, name=ADMINISTRATOR, permissions=as_column(set()))
    user, generated = ensure_admin(session, role, "admin", "admin@test", None)

    assert generated is not None and len(generated) >= 24
    assert verify_password(generated, user.password_hash)
    assert user.is_active


def test_a_supplied_password_is_used_and_not_echoed(session):
    role = Role(role_id=1, name=ADMINISTRATOR, permissions=as_column(set()))
    user, generated = ensure_admin(session, role, "admin", "admin@test", "a-chosen-password")

    assert generated is None
    assert verify_password("a-chosen-password", user.password_hash)


def test_creating_the_admin_is_audited(session):
    role = Role(role_id=1, name=ADMINISTRATOR, permissions=as_column(set()))
    ensure_admin(session, role, "admin", "admin@test", None)

    entries = [o for o in session.added if isinstance(o, AuditLog)]
    assert len(entries) == 1
    assert entries[0].action == "bootstrap.admin_created"
    # No password, generated or supplied, may reach the audit trail.
    assert entries[0].details == {"role": ADMINISTRATOR, "password_generated": True}


def test_rerunning_does_not_reset_an_existing_password(session):
    """A second bootstrap must not be a way to take over the account."""
    role = Role(role_id=1, name=ADMINISTRATOR, permissions=as_column(set()))
    first, generated = ensure_admin(session, role, "admin", "admin@test", None)

    again, second_password = ensure_admin(session, role, "admin", "admin@test", "attacker")
    assert again is first
    assert second_password is None
    assert verify_password(generated, first.password_hash)
    assert not verify_password("attacker", first.password_hash)


def test_rerunning_does_not_reactivate_a_disabled_admin(session):
    role = Role(role_id=1, name=ADMINISTRATOR, permissions=as_column(set()))
    user, _ = ensure_admin(session, role, "admin", "admin@test", "p")
    user.is_active = False

    again, _ = ensure_admin(session, role, "admin", "admin@test", "p")
    assert again.is_active is False


def test_bootstrap_flushes_roles_before_creating_the_user(session):
    """A user cannot reference a role that has no identity yet."""
    bootstrap(session)
    assert session.flushed >= 1
    assert any(isinstance(o, User) for o in session.added)
