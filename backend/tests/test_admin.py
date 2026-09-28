"""The administrator's page: accounts, sensors and the audit trail."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from netsentinel_api.db.models import (
    AuditLog,
    Role,
    Sensor,
    SensorStatus,
    SensorType,
    User,
)
from netsentinel_api.deps import get_admin_repo
from netsentinel_api.rbac import DEFAULT_ROLE_PERMISSIONS, as_column

V1 = "/api/v1"
NOW = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)


class FakeAdminRepo:
    """The admin queries over lists, with the audit filters reproduced as the SQL
    applies them: actor by username, action by prefix, both ends inclusive."""

    def __init__(self, users, roles, sensors, entries) -> None:
        self.users_ = users
        self.roles_ = roles
        self.sensors_ = sensors
        self.entries = entries

    def users(self):
        return sorted(self.users_, key=lambda u: u.username)

    def user(self, user_id):
        return next((u for u in self.users_ if u.user_id == user_id), None)

    def taken(self, username, email):
        return any(u.username == username or u.email == email for u in self.users_)

    def roles(self):
        return sorted(self.roles_, key=lambda r: r.name)

    def role(self, name):
        return next((r for r in self.roles_ if r.name == name), None)

    def sensors(self):
        return [(s, "dataset-replay") for s in self.sensors_]

    def sensor(self, sensor_id):
        return next(((s, "dataset-replay") for s in self.sensors_
                     if s.sensor_id == sensor_id), None)

    def audit(self, *, actor=None, action=None, window=None, limit=50, offset=0):
        names = {u.user_id: u.username for u in self.users_}
        rows = [(e, names.get(e.user_id)) for e in self.entries]
        if actor:
            rows = [r for r in rows if r[1] == actor]
        if action:
            rows = [r for r in rows if r[0].action.startswith(action)]
        if window is not None:
            rows = [r for r in rows
                    if (window.start is None or r[0].ts >= window.start)
                    and (window.end is None or r[0].ts <= window.end)]
        rows.sort(key=lambda r: (r[0].ts, r[0].log_id), reverse=True)
        return rows[offset : offset + limit]


@pytest.fixture
def sensor() -> Sensor:
    return Sensor(sensor_id=1, type=SensorType.early_flow, host_asset_id=1,
                  status=SensorStatus.online, last_seen=NOW, revoked=False)


@pytest.fixture
def entries() -> list[AuditLog]:
    return [
        AuditLog(log_id=1, user_id=1, action="auth.login", entity="user:1",
                 details={}, ts=NOW - timedelta(hours=2)),
        AuditLog(log_id=2, user_id=3, action="user.created", entity="username:x",
                 details={"role": "viewer"}, ts=NOW - timedelta(hours=1)),
        AuditLog(log_id=3, user_id=None, action="model.registered", entity="m:1",
                 details={}, ts=NOW),
    ]


@pytest.fixture
def admin_client(client, analyst, ml_engineer, administrator, viewer, sensor, entries):
    roles = [Role(role_id=i, name=name, permissions=as_column(perms))
             for i, (name, perms) in enumerate(DEFAULT_ROLE_PERMISSIONS.items(), start=1)]
    repo = FakeAdminRepo([analyst, ml_engineer, administrator, viewer], roles,
                         [sensor], entries)
    client.app.dependency_overrides[get_admin_repo] = lambda: repo
    return client


# --- who may -----------------------------------------------------------------

ROUTES = [
    ("get", "/admin/roles", None),
    ("get", "/admin/users", None),
    ("post", "/admin/users",
     {"username": "new", "email": "new@example.test", "password": "pw", "role": "viewer"}),
    ("patch", "/admin/users/1", {"is_active": False}),
    ("get", "/admin/sensors", None),
    ("patch", "/admin/sensors/1", {"revoked": True}),
    ("get", "/admin/audit", None),
]


@pytest.mark.parametrize("method, path, body", ROUTES)
def test_every_admin_route_needs_a_token(admin_client, method, path, body):
    response = admin_client.request(method, f"{V1}{path}", json=body)
    assert response.status_code == 401


@pytest.mark.parametrize("method, path, body", ROUTES)
@pytest.mark.parametrize("header", ["auth_header", "viewer_header", "engineer_header"])
def test_no_other_role_may_use_an_admin_route(
    admin_client, request, header, method, path, body, session
):
    response = admin_client.request(
        method, f"{V1}{path}", json=body, headers=request.getfixturevalue(header)
    )
    assert response.status_code == 403
    assert "missing permission" in response.json()["detail"]
    assert session.audit_entries() == []


# --- accounts ----------------------------------------------------------------

def test_roles_are_served_with_their_permissions(admin_client, admin_header):
    body = admin_client.get(f"{V1}/admin/roles", headers=admin_header).json()
    by_name = {role["name"]: role["permissions"] for role in body}
    assert set(by_name) == set(DEFAULT_ROLE_PERMISSIONS)
    assert "users:manage" in by_name["administrator"]


def test_users_are_listed_without_password_hashes(admin_client, admin_header):
    response = admin_client.get(f"{V1}/admin/users", headers=admin_header)
    assert response.status_code == 200
    body = response.json()
    assert [u["username"] for u in body] == ["admin", "analyst", "modeller", "viewer"]
    assert body[0]["role"] == "administrator"
    assert all("password_hash" not in u and "password" not in u for u in body)
    assert "$2b$" not in response.text


def test_an_account_is_created_hashed_and_recorded(admin_client, admin_header, session):
    response = admin_client.post(
        f"{V1}/admin/users",
        json={"username": "noc", "email": "noc@example.test",
              "password": "a-good-password", "role": "viewer"},
        headers=admin_header,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "noc" and body["role"] == "viewer" and body["is_active"]
    assert body["user_id"] is not None

    created = next(o for o in session.added if isinstance(o, User))
    assert created.password_hash.startswith("$2b$")
    assert created.password_hash != "a-good-password"
    [entry] = session.audit_entries()
    assert (entry.action, entry.user_id, entry.details) == ("user.created", 3,
                                                            {"role": "viewer"})


@pytest.mark.parametrize("change, status, phrase", [
    ({"username": "analyst"}, 409, "already belongs"),
    ({"email": "analyst@example.test"}, 409, "already belongs"),
    ({"role": "root"}, 422, "no role named 'root'"),
    ({"password": "x" * 73}, 422, "bcrypt"),
])
def test_an_account_that_cannot_be_created_is_refused_with_a_reason(
    admin_client, admin_header, session, change, status, phrase
):
    body = {"username": "noc", "email": "noc@example.test", "password": "pw",
            "role": "viewer", **change}
    response = admin_client.post(f"{V1}/admin/users", json=body, headers=admin_header)
    assert response.status_code == status
    assert phrase in response.json()["detail"]
    assert session.audit_entries() == []


def test_a_role_change_is_applied_and_recorded(admin_client, admin_header, session,
                                               analyst):
    response = admin_client.patch(f"{V1}/admin/users/1", json={"role": "viewer"},
                                  headers=admin_header)
    assert response.status_code == 200
    assert response.json()["role"] == "viewer"
    assert analyst.role.name == "viewer"
    [entry] = session.audit_entries()
    assert entry.action == "user.role_changed"
    assert entry.details == {"from": "soc_analyst", "to": "viewer"}


def test_a_disabled_user_cannot_log_in_and_their_token_stops_working(
    admin_client, admin_header, auth_header, session, analyst, analyst_password
):
    response = admin_client.patch(f"{V1}/admin/users/1", json={"is_active": False},
                                  headers=admin_header)
    assert response.status_code == 200
    assert response.json()["is_active"] is False
    assert [e.action for e in session.audit_entries()] == ["user.disabled"]

    login = admin_client.post(f"{V1}/auth/token", data={
        "username": analyst.username, "password": analyst_password})
    assert login.status_code == 401

    session.user = analyst  # the fake session now answers as the analyst
    assert admin_client.get(f"{V1}/alerts", headers=auth_header).status_code == 401


def test_a_disabled_user_can_be_enabled_again(admin_client, admin_header, session, analyst):
    analyst.is_active = False
    response = admin_client.patch(f"{V1}/admin/users/1", json={"is_active": True},
                                  headers=admin_header)
    assert response.json()["is_active"] is True
    assert [e.action for e in session.audit_entries()] == ["user.enabled"]


@pytest.mark.parametrize("change, phrase", [
    ({"is_active": False}, "cannot disable your own account"),
    ({"role": "viewer"}, "cannot change your own role"),
])
def test_an_administrator_cannot_disable_or_demote_themselves(
    admin_client, admin_header, session, administrator, change, phrase
):
    response = admin_client.patch(f"{V1}/admin/users/3", json=change, headers=admin_header)
    assert response.status_code == 409
    assert phrase in response.json()["detail"]
    assert administrator.is_active and administrator.role.name == "administrator"
    assert session.audit_entries() == []


def test_an_unchanged_update_records_nothing(admin_client, admin_header, session):
    response = admin_client.patch(f"{V1}/admin/users/3",
                                  json={"role": "administrator", "is_active": True},
                                  headers=admin_header)
    assert response.status_code == 200
    assert session.audit_entries() == []


def test_an_unknown_user_is_404(admin_client, admin_header):
    response = admin_client.patch(f"{V1}/admin/users/99", json={"is_active": False},
                                  headers=admin_header)
    assert response.status_code == 404


# --- sensors -----------------------------------------------------------------

def test_sensors_are_listed_with_last_seen(admin_client, admin_header):
    response = admin_client.get(f"{V1}/admin/sensors", headers=admin_header)
    assert response.status_code == 200
    [row] = response.json()
    assert row["sensor_id"] == 1 and row["hostname"] == "dataset-replay"
    assert row["status"] == "online" and row["revoked"] is False
    assert row["last_seen"].startswith("2026-09-20T10:00")


def test_a_sensor_is_revoked_and_restored_on_the_record(
    admin_client, admin_header, session, sensor
):
    revoked = admin_client.patch(f"{V1}/admin/sensors/1", json={"revoked": True},
                                 headers=admin_header)
    assert revoked.status_code == 200 and revoked.json()["revoked"] is True
    assert sensor.revoked is True

    restored = admin_client.patch(f"{V1}/admin/sensors/1", json={"revoked": False},
                                  headers=admin_header)
    assert restored.json()["revoked"] is False
    assert [(e.action, e.entity) for e in session.audit_entries()] == [
        ("sensor.revoked", "sensor:1"), ("sensor.restored", "sensor:1")]


def test_an_unknown_sensor_is_404(admin_client, admin_header):
    response = admin_client.patch(f"{V1}/admin/sensors/9", json={"revoked": True},
                                  headers=admin_header)
    assert response.status_code == 404


# --- the audit trail ---------------------------------------------------------

def _audit(client, header, **params):
    return client.get(f"{V1}/admin/audit", params=params, headers=header)


def test_the_audit_trail_is_newest_first_with_usernames(admin_client, admin_header):
    body = _audit(admin_client, admin_header).json()
    assert [e["log_id"] for e in body] == [3, 2, 1]
    assert [e["username"] for e in body] == [None, "admin", "analyst"]


@pytest.mark.parametrize("params, expected", [
    ({"actor": "analyst"}, [1]),
    ({"action": "user."}, [2]),
    ({"action": "model.registered"}, [3]),
    ({"from": "2026-09-20T09:00:00Z"}, [3, 2]),
    ({"to": "2026-09-20T09:00:00"}, [2, 1]),
    ({"from": "2026-09-20T08:30:00Z", "to": "2026-09-20T09:30:00Z"}, [2]),
    ({"limit": 1, "offset": 1}, [2]),
])
def test_the_audit_trail_filters(admin_client, admin_header, params, expected):
    response = _audit(admin_client, admin_header, **params)
    assert response.status_code == 200
    assert [e["log_id"] for e in response.json()] == expected


@pytest.mark.parametrize("params, phrase", [
    ({"from": "yesterday"}, "cannot read 'yesterday' as the 'from' time"),
    ({"to": "20-09-2026"}, "cannot read '20-09-2026' as the 'to' time"),
    ({"from": "2026-09-20T10:00:00Z", "to": "2026-09-20T09:00:00Z"}, "starts"),
])
def test_bad_audit_time_input_is_refused_with_a_sentence(
    admin_client, admin_header, params, phrase
):
    response = _audit(admin_client, admin_header, **params)
    assert response.status_code == 422
    assert phrase in response.json()["detail"]
