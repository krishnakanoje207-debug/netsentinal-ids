"""The asset inventory: which hosts are the estate's own.

Three things read it. Greenbone findings attach only to known hosts, the response
gate refuses a block aimed at one of them, and the dashboard's estate page lists them.
Without an inventory the only asset is the sensor's own row, so every scan finding
is an unknown host and nothing stops a block on the web server.

The inventory is a CSV the operator keeps (hostname, ip_address, os, criticality).
The address is the key, as it is for the scan import: a host renamed in the CSV is
the same host, and a second row for one address would split its vulnerabilities.
Hosts missing from a later CSV are left alone rather than deleted, because sensors
and alerts point at asset rows and a trimmed spreadsheet must not orphan them.
"""

from __future__ import annotations

import csv
import io
import ipaddress
from dataclasses import asdict, dataclass
from typing import Iterable

from netsentinel_api.db.models import Asset, Criticality

COLUMNS = ("hostname", "ip_address", "os", "criticality")


class InventoryError(ValueError):
    """The CSV cannot be imported. The message names the line and the rule."""


@dataclass(frozen=True, slots=True)
class InventoryRow:
    hostname: str
    ip_address: str
    os: str | None
    criticality: Criticality


@dataclass(slots=True)
class InventoryStats:
    read: int = 0
    added: int = 0
    updated: int = 0
    unchanged: int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


def parse_inventory(text: str) -> list[InventoryRow]:
    """Every row, or an error naming the first bad line: half an inventory is worse
    than none, because the missing half would look like hosts nobody owns."""
    reader = csv.DictReader(io.StringIO(text))
    missing = [name for name in ("hostname", "ip_address") if name not in (reader.fieldnames or [])]
    if missing:
        raise InventoryError(f"the header must name {', '.join(missing)}; it has {reader.fieldnames}")

    rows: list[InventoryRow] = []
    seen: dict[str, int] = {}
    for line, record in enumerate(reader, start=2):
        hostname = (record.get("hostname") or "").strip()
        raw_ip = (record.get("ip_address") or "").strip()
        if not hostname:
            raise InventoryError(f"line {line}: hostname is empty")
        try:
            address = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            raise InventoryError(f"line {line}: {raw_ip!r} is not an IP address") from None
        if address in seen:
            raise InventoryError(f"line {line}: {address} is already on line {seen[address]}")
        seen[address] = line

        raw_criticality = (record.get("criticality") or "").strip().lower() or Criticality.medium.value
        try:
            criticality = Criticality(raw_criticality)
        except ValueError:
            allowed = ", ".join(level.value for level in Criticality)
            raise InventoryError(
                f"line {line}: criticality {raw_criticality!r} is not one of {allowed}"
            ) from None

        rows.append(
            InventoryRow(
                hostname=hostname,
                ip_address=address,
                os=(record.get("os") or "").strip() or None,
                criticality=criticality,
            )
        )
    return rows


def sync_inventory(session, rows: Iterable[InventoryRow], existing: Iterable[Asset]) -> InventoryStats:
    """Add new hosts and bring known ones up to date, matched by address."""
    stats = InventoryStats()
    by_ip = {str(ipaddress.ip_address(str(asset.ip_address))): asset for asset in existing}
    for row in rows:
        stats.read += 1
        asset = by_ip.get(row.ip_address)
        if asset is None:
            asset = Asset(
                hostname=row.hostname,
                ip_address=row.ip_address,
                os=row.os,
                criticality=row.criticality,
            )
            session.add(asset)
            by_ip[row.ip_address] = asset
            stats.added += 1
            continue
        wanted = (row.hostname, row.os, row.criticality)
        if (asset.hostname, asset.os, asset.criticality) == wanted:
            stats.unchanged += 1
            continue
        asset.hostname, asset.os, asset.criticality = wanted
        stats.updated += 1
    return stats
