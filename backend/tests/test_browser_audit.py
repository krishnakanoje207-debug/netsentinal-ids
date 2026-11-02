"""Verify privacy boundaries and WAL-consistent browser metadata."""
import sqlite3
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netsentinel_api.deps import current_user
from netsentinel_api.routes.browser_audit import router
from netsentinel_api.services.browser_audit import read_profile
from netsentinel_api.services.site_risk import assess, digest, load_feed


def test_read_committed_wal_and_redact(tmp_path):
    path = tmp_path / "History"
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE urls(url TEXT,last_visit_time INTEGER)")
    db.execute("CREATE TABLE downloads(target_path TEXT,start_time INTEGER,danger_type INTEGER,state INTEGER)")
    db.execute("INSERT INTO urls VALUES (?,?)", ("https://user:secret@example.com/private?token=secret", 13300000000000000))
    db.execute("INSERT INTO downloads VALUES (?,?,?,?)", (r"C:\Users\person\Downloads\review.exe", 13300000000000000, 1, 0))
    db.commit()
    result = read_profile(path, "Test", "Default")
    assert result["status"] == "available"
    assert result["visits"][0]["domain"] == "example.com"
    assert "secret" not in str(result)
    assert result["downloads"][0]["filename"] == "review.exe"
    assert result["downloads"][0]["browser_danger_code"] == 1
    assert "safe" not in result["visits"][0]["evidence"].lower()
    db.close()


@pytest.mark.parametrize("journal_header", [None, bytes(8), b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"])
def test_locked_connection_uses_validated_snapshot_and_cleans_up(tmp_path, monkeypatch, journal_header):
    path = tmp_path / "History"
    source = sqlite3.connect(path)
    source.execute("PRAGMA journal_mode=WAL")
    source.execute("CREATE TABLE urls(url TEXT,last_visit_time INTEGER)")
    source.execute("INSERT INTO urls VALUES ('https://example.test/',13300000000000000)")
    source.commit()
    if journal_header is not None:
        from pathlib import Path
        Path(str(path) + "-journal").write_bytes(journal_header + bytes(512))
    original = sqlite3.connect
    calls = []

    def locked_once(*args, **kwargs):
        calls.append(args[0])
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        return original(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", locked_once)
    result = read_profile(path, "Test", "Default")
    if journal_header is not None and any(journal_header):
        assert result["status"] == "unavailable"
        assert len(calls) == 1
        source.close()
        return
    assert result["status"] == "available"
    assert result["visits"][0]["domain"] == "example.test"
    assert "snapshot" in result["provenance"]
    from urllib.parse import unquote, urlsplit
    from pathlib import Path
    copied = Path(unquote(urlsplit(calls[1]).path).lstrip("/"))
    assert not copied.exists()
    source.close()


@pytest.mark.parametrize("role,host,expected", [("viewer", "127.0.0.1", 403), ("administrator", "192.0.2.2", 403), ("administrator", "127.0.0.1", 200)])
def test_local_admin_opt_in(monkeypatch, role, host, expected):
    monkeypatch.delenv("NETSENTINEL_LOCAL_BROWSER_AUDIT", raising=False)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(role=SimpleNamespace(name=role))
    with TestClient(app, client=(host, 1234)) as client:
        response = client.get("/browser-audit")
    assert response.status_code == expected
    if expected == 200:
        assert response.json()["status"] == "disabled"
        assert response.headers["cache-control"] == "no-store"


def test_requires_authentication():
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        assert client.get("/browser-audit").status_code == 401


def test_phishing_match_and_unknown(tmp_path):
    url = "https://example.test/phishing"
    feed = {"freshness": "fresh", "url_hashes": [digest(url)]}
    assert assess(url, feed).startswith("WARNING")
    assert "safety remains unassessed" in assess(url + "?different", feed)
    assert "unknown" in assess(url, {**feed, "freshness": "stale"})
    assert "unknown" in assess(url, load_feed(tmp_path / "absent"))
