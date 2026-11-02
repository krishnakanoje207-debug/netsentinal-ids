"""Bounded, read-only browser metadata for the current Windows account.

Read SQLite normally in read-only mode so committed WAL records are included.
Never use immutable mode or copy a live database without its WAL.
"""
from __future__ import annotations

import os
import json
import sqlite3
import time
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit
from netsentinel_api.services.site_risk import assess, load_feed


@contextmanager
def browser_database(path: Path):
    """Use the live read-only connection, or a validated stable transient snapshot.

    Chromium on Windows may hold an exclusive SQLite lock while allowing shared
    file reads. Snapshot all committed WAL data together, reject active rollback
    journals and changing sources, and never weaken the browser's locks.
    """
    db = None
    try:
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.2)
        db.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlite3.OperationalError as exc:
        if db is not None:
            db.close()
        if "locked" not in str(exc).lower():
            raise
    else:
        try:
            yield db, "Live read-only SQLite connection; committed records only"
        finally:
            db.close()
        return

    sources = [path, Path(str(path) + "-wal"), Path(str(path) + "-journal")]

    def fingerprint():
        values = []
        for source in sources:
            try:
                stat = source.stat()
                values.append((stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns))
            except FileNotFoundError:
                values.append(None)
        return values

    before = fingerprint()
    if before[0] is None:
        raise sqlite3.OperationalError("Missing browser source")
    if before[2] is not None and before[2][2] > 0:
        # SQLite PERSIST mode retains an allocated journal after commit but
        # invalidates its header. Nonzero headers can hold an active/hot
        # transaction and must never be discarded from the snapshot.
        with sources[2].open("rb") as journal:
            if any(journal.read(8)):
                raise sqlite3.OperationalError("Active rollback journal; snapshot rejected")
    if sum(item[2] for item in before if item) > 256 * 1024 * 1024:
        raise sqlite3.OperationalError("Browser snapshot exceeds bounded size")
    deadline = time.monotonic() + 3
    with tempfile.TemporaryDirectory(prefix="netsentinel-browser-") as temporary:
        target = Path(temporary) / "History"
        for source, metadata, destination in zip(sources[:2], before[:2], [target, Path(str(target) + "-wal")]):
            if metadata is None:
                continue
            copied = 0
            with source.open("rb") as reader, destination.open("wb") as writer:
                while chunk := reader.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > metadata[2] or time.monotonic() > deadline:
                        raise sqlite3.OperationalError("Browser snapshot changed or exceeded time bound")
                    writer.write(chunk)
        if fingerprint() != before:
            raise sqlite3.OperationalError("Browser source changed during snapshot")
        snapshot = sqlite3.connect(target.as_uri() + "?mode=ro", uri=True, timeout=0.2)
        try:
            snapshot.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            if snapshot.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise sqlite3.OperationalError("Browser snapshot integrity check failed")
            if fingerprint() != before:
                raise sqlite3.OperationalError("Browser source changed during validation")
            yield snapshot, "Transient validated SQLite + WAL snapshot; last committed records only; raw copy deleted after reading"
        finally:
            snapshot.close()


def domain(url: str) -> str:
    try:
        return urlsplit(url).hostname or "(local or non-web address)"
    except ValueError:
        return "(invalid address)"


def transport_evidence(url: str) -> str:
    try:
        if urlsplit(url).scheme == "http":
            return "HTTP transport recorded; content unassessed"
    except ValueError:
        pass
    return "Content and reputation unassessed"


def stamp(value: int, chromium: bool = True) -> str | None:
    try:
        epoch = datetime(1601 if chromium else 1970, 1, 1, tzinfo=timezone.utc)
        return (epoch + timedelta(microseconds=value)).isoformat() if value else None
    except (ValueError, OverflowError, TypeError):
        return None


def read_profile(path: Path, browser: str, profile: str, firefox: bool = False, feed: dict | None = None) -> dict:
    result = {"browser": browser, "profile": profile, "status": "available", "visits": [], "downloads": []}
    if not firefox:
        try:
            preferences = json.loads((path.parent / "Preferences").read_text(encoding="utf-8"))
            settings = preferences.get("safebrowsing", {})
            result["safe_browsing"] = {"enabled_preference": settings.get("enabled"),
                                       "enhanced_preference": settings.get("enhanced"),
                                       "meaning": "Explicit profile preferences only. Missing values mean unknown; defaults and enterprise policies are not verified."}
        except (OSError, ValueError, TypeError):
            result["safe_browsing"] = {"meaning": "Profile protection settings unreadable; current protection is unknown"}
    try:
        with browser_database(path) as (db, provenance):
            result["provenance"] = provenance
            result["observed_at"] = datetime.now(timezone.utc).isoformat()
            deadline = time.monotonic() + 1
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            sql = (
                "SELECT url, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 50"
                if firefox else
                "SELECT url, last_visit_time FROM urls WHERE last_visit_time > 0 ORDER BY last_visit_time DESC LIMIT 50"
            )
            result["visits"] = [
                {"domain": domain(url), "visited_at": stamp(at, not firefox),
                 "evidence": transport_evidence(url), "risk": assess(url, feed or {"freshness": "unavailable"})}
                for url, at in db.execute(sql)
            ]
            if firefox:
                result["download_status"] = "Firefox download metadata is not supported"
            else:
                columns = {row[1] for row in db.execute("PRAGMA table_info(downloads)")}
                if {"target_path", "start_time", "danger_type", "state"} <= columns:
                    for target, at, danger, state in db.execute(
                        "SELECT target_path,start_time,danger_type,state FROM downloads ORDER BY start_time DESC LIMIT 50"
                    ):
                        result["downloads"].append({
                            "filename": PureWindowsPath(target).name, "started_at": stamp(at),
                            "browser_danger_code": danger, "browser_state_code": state,
                            "evidence": f"Browser recorded danger code {danger}; review in browser Downloads" if danger else "Browser recorded no danger flag; file contents unassessed",
                        })
                    result["download_status"] = "available"
                else:
                    result["download_status"] = "Unsupported or absent download schema"
    except (sqlite3.Error, OSError):
        result.update(status="unavailable", error="Browser database is locked, unreadable, or has an unsupported schema")
    return result


def collect_browser_audit() -> dict:
    feed = load_feed()
    result = {"observed_at": datetime.now(timezone.utc).isoformat(), "profiles": [],
              "scope": "Current API process Windows account only; at most 8 profiles and 50 recent sites/downloads per profile. Domains only; no URL paths, queries, page titles, cookies, or credentials.",
              "limitations": "History review after browser records activity; not a pre-download blocker or website reputation verdict. Private browsing, deleted history, other accounts and unsaved activity are unavailable. HTTPS does not establish content safety."}
    result["site_risk_feed"] = {key: value for key, value in feed.items() if key != "url_hashes"}
    if os.name != "nt":
        return {**result, "status": "unsupported", "reason": "Windows browser audit is unavailable on this host"}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice") as key:
            result["default_https_browser"] = winreg.QueryValueEx(key, "ProgId")[0]
    except OSError:
        result["default_https_browser"] = "Unknown; registration unavailable"
    # Resolve this account's actual profile, including when a launcher redirects
    # LOCALAPPDATA into its own application sandbox.
    local = Path.home() / "AppData/Local"
    roaming = Path.home() / "AppData/Roaming"
    roots = [("Chrome", local / "Google/Chrome/User Data"),
             ("Edge", local / "Microsoft/Edge/User Data"),
             ("Brave", local / "BraveSoftware/Brave-Browser/User Data")]
    candidates = []
    for browser, root in roots:
        for path in sorted(root.glob("*/History")):
            candidates.append((browser, path, False))
    for path in sorted((roaming / "Mozilla/Firefox/Profiles").glob("*/places.sqlite")):
        candidates.append(("Firefox", path, True))
    default_browser = result["default_https_browser"].lower()
    candidates.sort(key=lambda item: 0 if item[0].lower() in default_browser else 1)
    for browser, path, firefox in candidates[:8]:
        result["profiles"].append(read_profile(path, browser, path.parent.name, firefox, feed))
    result["status"] = "available" if result["profiles"] else "unavailable"
    return result
