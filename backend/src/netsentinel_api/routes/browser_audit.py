"""Personal browsing data is opt-in and restricted to a local administrator."""
import os
from fastapi import APIRouter, HTTPException, Request, Response
from netsentinel_api.deps import CurrentUser
from netsentinel_api.services.browser_audit import collect_browser_audit

router = APIRouter(tags=["local browser audit"])


@router.get("/browser-audit")
def browser_audit(request: Request, response: Response, user: CurrentUser) -> dict:
    response.headers["Cache-Control"] = "no-store"
    if not user.role or user.role.name != "administrator":
        raise HTTPException(403, "Personal browser audit requires a local administrator")
    if not request.client or request.client.host not in {"127.0.0.1", "::1"}:
        raise HTTPException(403, "Personal browser audit is available only on the local host")
    if os.environ.get("NETSENTINEL_LOCAL_BROWSER_AUDIT") != "1":
        return {"status": "disabled", "profiles": [], "reason": "Local browser audit is disabled. Enable only in a trusted loopback-only deployment with NETSENTINEL_LOCAL_BROWSER_AUDIT=1."}
    return collect_browser_audit()
