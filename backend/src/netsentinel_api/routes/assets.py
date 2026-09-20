"""The estate, and what a scan found on it.

Read-only. Assets arrive from the inventory and vulnerabilities from Greenbone
through ``sync_vulns``; an API that let either be edited by hand would produce a
patch list that disagrees with the last scan and no way to tell which is right.

Vulnerabilities hang off an asset rather than forming a feed of their own. "What is
wrong with this host" is the question asked during triage - an analyst looking at an
alert on 172.30.0.10 wants to know what else is open on it - and a flat list of every
CVE in the lab answers nobody.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from netsentinel_api.db.models import Asset, Vulnerability
from netsentinel_api.deps import AssetRepoDep, require
from netsentinel_api.rbac import ASSETS_READ
from netsentinel_api.schemas import AssetOut, VulnerabilityOut

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(
    assets: AssetRepoDep,
    _: Annotated[object, Depends(require(ASSETS_READ))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Asset]:
    return assets.list(limit=limit, offset=offset)


@router.get("/{asset_id}/vulnerabilities", response_model=list[VulnerabilityOut])
def asset_vulnerabilities(
    asset_id: int,
    assets: AssetRepoDep,
    _: Annotated[object, Depends(require(ASSETS_READ))],
) -> list[Vulnerability]:
    asset = assets.get(asset_id)
    if asset is None:
        # 404 on the asset, not an empty list: a host that does not exist and a
        # host with nothing wrong with it are different answers, and reading the
        # second for the first is how an unscanned machine passes for a clean one.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")
    return assets.vulnerabilities(asset)
