"""Authenticated local snapshots; no shell, scan or caller-selected filesystem paths."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Response

from netsentinel_api.deps import require
from netsentinel_api.rbac import ALERTS_READ

router = APIRouter(tags=["endpoint"])
LOCAL_OUT = Path(__file__).resolve().parents[4] / "lab" / "local" / "out"


def _read(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _age(value: object) -> float | None:
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if moment.tzinfo is None:
            return None
        return max(0, (datetime.now(timezone.utc) - moment).total_seconds())
    except (TypeError, ValueError):
        return None


@router.get("/endpoint/status")
def endpoint_status(response: Response, _: Annotated[object, Depends(require(ALERTS_READ))]) -> dict:
    response.headers["Cache-Control"] = "no-store"
    snapshot = _read(LOCAL_OUT / "endpoint.json")
    age = _age(snapshot.get("collected_at"))
    monitoring = _read(LOCAL_OUT / "live" / "status.json")
    monitor_age = _age(monitoring.get("updated_at"))
    monitoring["age_seconds"] = monitor_age
    monitoring["freshness"] = (
        "unavailable" if monitor_age is None else "fresh" if monitor_age < 60 else "stale"
    )
    monitoring.setdefault("state", "unknown")
    monitoring["latest_capture_at"] = None
    monitoring["latest_scored_flow_at"] = None
    # Only the launcher's timestamp run names are accepted, never a snapshot path.
    run = monitoring.get("run")
    if isinstance(run, str) and re.fullmatch(r"\d{8}-\d{6}-\d{3}", run):
        run_dir = LOCAL_OUT / "live" / run
        try:
            captures = list((run_dir / "windows").glob("*.pcapng"))
            if captures:
                modified = max(path.stat().st_mtime for path in captures)
                monitoring["latest_capture_at"] = datetime.fromtimestamp(modified, timezone.utc).isoformat()
            flows = run_dir / "flows.jsonl"
            if flows.is_file() and flows.stat().st_size:
                monitoring["latest_scored_flow_at"] = datetime.fromtimestamp(flows.stat().st_mtime, timezone.utc).isoformat()
        except OSError:
            pass
    return {
        "collected_at": snapshot.get("collected_at"),
        "age_seconds": age,
        "freshness": "unavailable" if age is None else "fresh" if age < 180 else "stale",
        "defender": snapshot.get("defender", {"available": False, "status": None,
                                                "error": "No local endpoint snapshot collected."}),
        "smart_screen": snapshot.get("smart_screen", {}),
        "download_locations": snapshot.get("download_locations", []),
        "threats": snapshot.get("threats", {"available": False, "active_count": None,
                                            "historical_detection_count": None}),
        "scans": snapshot.get("scans", {"downloads": {"state": "not_run"},
                                         "quick": {"state": "not_run"}}),
        "monitoring": monitoring,
        "limitation": snapshot.get("limitation", "Endpoint collection has not run on this installation."),
    }
