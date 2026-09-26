"""The inventory import: every host or none, keyed by address, never deleting."""

from __future__ import annotations

import pytest

from netsentinel_api.db.models import Asset, Criticality
from netsentinel_api.services.inventory import InventoryError, parse_inventory, sync_inventory

CSV = """hostname,ip_address,os,criticality
web-01,172.30.0.10,Ubuntu 24.04,high
ssh-01,172.30.0.11,Debian 12,
"""


class RecordingSession:
    def __init__(self) -> None:
        self.added: list = []

    def add(self, row) -> None:
        self.added.append(row)


def test_rows_are_read_with_medium_as_the_default_criticality():
    rows = parse_inventory(CSV)
    assert [(r.hostname, r.ip_address, r.os, r.criticality) for r in rows] == [
        ("web-01", "172.30.0.10", "Ubuntu 24.04", Criticality.high),
        ("ssh-01", "172.30.0.11", "Debian 12", Criticality.medium),
    ]


def test_an_address_is_stored_in_one_spelling():
    rows = parse_inventory("hostname,ip_address\nv6,2001:DB8::0001\n")
    assert rows[0].ip_address == "2001:db8::1"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("name,ip\nx,1.2.3.4\n", "the header must name hostname, ip_address"),
        ("hostname,ip_address\n,1.2.3.4\n", "line 2: hostname is empty"),
        ("hostname,ip_address\nx,1.2.3\n", "line 2: '1.2.3' is not an IP address"),
        ("hostname,ip_address\na,1.2.3.4\nb,1.2.3.4\n", "line 3: 1.2.3.4 is already on line 2"),
        ("hostname,ip_address,criticality\nx,1.2.3.4,urgent\n", "line 2: criticality 'urgent'"),
    ],
)
def test_a_bad_line_refuses_the_whole_file(text, message):
    with pytest.raises(InventoryError, match=message):
        parse_inventory(text)


def test_new_hosts_are_added_and_known_ones_updated_by_address():
    known = Asset(asset_id=1, hostname="old-name", ip_address="172.30.0.10", os=None,
                  criticality=Criticality.low)
    session = RecordingSession()

    stats = sync_inventory(session, parse_inventory(CSV), [known])

    assert stats.as_dict() == {"read": 2, "added": 1, "updated": 1, "unchanged": 0}
    assert (known.hostname, known.os, known.criticality) == ("web-01", "Ubuntu 24.04", Criticality.high)
    assert [asset.hostname for asset in session.added] == ["ssh-01"]


def test_a_second_import_of_the_same_file_changes_nothing():
    session = RecordingSession()
    first = sync_inventory(session, parse_inventory(CSV), [])
    second = sync_inventory(RecordingSession(), parse_inventory(CSV), session.added)

    assert first.added == 2
    assert second.as_dict() == {"read": 2, "added": 0, "updated": 0, "unchanged": 2}


def test_a_host_left_out_of_the_csv_is_not_deleted():
    """Sensors and alerts point at asset rows; a trimmed spreadsheet must not orphan them."""
    sensor_host = Asset(asset_id=9, hostname="dataset-replay", ip_address="192.0.2.1",
                        os="replay", criticality=Criticality.low)
    stats = sync_inventory(RecordingSession(), parse_inventory(CSV), [sensor_host])

    assert stats.added == 2
    assert sensor_host.hostname == "dataset-replay"
