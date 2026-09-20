"""PCAP preparation.

The rule worth pinning is that splitting happens per capture file, never per flow. Flows
from one capture share a session, a host pair and a clock, so splitting them across train
and test leaks - and produces exactly the inflated accuracy this project set out to
question.
"""

from __future__ import annotations

import dpkt
import polars as pl
import pytest

from netsentinel_core.features.contract import FEATURE_ORDER
from netsentinel_training.data.pcap_prep import (
    ATTACK_COLUMN,
    LABEL_COLUMN,
    SOURCE_COLUMN,
    NoCapturesFound,
    assign_splits,
    find_captures,
    label_for,
    prepare,
)

CLIENT_MAC, SERVER_MAC = b"\xaa\xbb\xcc\x00\x00\x01", b"\xaa\xbb\xcc\x00\x00\x02"


def _frame(src: str, dst: str, sport: int, dport: int, flags: int) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=1, ack=1)
    ip = dpkt.ip.IP(
        src=bytes(int(o) for o in src.split(".")),
        dst=bytes(int(o) for o in dst.split(".")),
        ttl=64,
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=CLIENT_MAC, dst=SERVER_MAC, type=dpkt.ethernet.ETH_TYPE_IP, data=ip
    )
    return bytes(eth)


def write_capture(path, flows: int = 2) -> None:
    """A capture holding `flows` short TCP conversations that close cleanly."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        timestamp = 1000.0
        for index in range(flows):
            sport = 40000 + index
            for flags in (dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK):
                writer.writepkt(_frame("10.0.0.5", "10.0.0.9", sport, 80, flags), ts=timestamp)
                timestamp += 0.01


@pytest.fixture
def capture_root(tmp_path):
    """Enough captures that a 70/15/15 split has something to divide."""
    root = tmp_path / "captures"
    for index in range(8):
        write_capture(root / "benign" / f"normal_{index}.pcap", flows=3)
    for index in range(4):
        write_capture(root / "portscan" / f"scan_{index}.pcap", flows=2)
    return root


# --- discovery and labelling ----------------------------------------------

def test_finds_every_capture(capture_root):
    assert len(find_captures(capture_root)) == 12


def test_an_empty_root_says_what_was_expected(tmp_path):
    with pytest.raises(NoCapturesFound, match="Expected"):
        find_captures(tmp_path)


def test_benign_directory_is_the_negative_class(capture_root):
    label, attack = label_for(capture_root / "benign" / "normal_0.pcap", capture_root)
    assert (label, attack) == (0, "Benign")


def test_any_other_directory_names_the_attack(capture_root):
    label, attack = label_for(capture_root / "portscan" / "scan_0.pcap", capture_root)
    assert (label, attack) == (1, "portscan")


def test_a_capture_outside_a_label_directory_is_refused(capture_root):
    """Guessing a label would be worse than refusing one."""
    stray = capture_root / "loose.pcap"
    write_capture(stray)
    with pytest.raises(ValueError, match="not inside a label directory"):
        label_for(stray, capture_root)


# --- splitting -------------------------------------------------------------

def test_splits_are_stable_between_runs():
    captures = [f"benign/c{i}.pcap" for i in range(40)]
    assert assign_splits(captures) == assign_splits(captures)


def test_adding_a_capture_does_not_reshuffle_the_others():
    """A shuffle would silently invalidate every model trained before the addition."""
    original = [f"benign/c{i}.pcap" for i in range(40)]
    first = assign_splits(original)
    second = assign_splits(original + ["benign/new.pcap"])
    for capture in original:
        assert first[capture] == second[capture]


def test_every_capture_lands_in_exactly_one_split():
    captures = [f"benign/c{i}.pcap" for i in range(60)]
    assignment = assign_splits(captures)
    assert set(assignment) == set(captures)
    assert set(assignment.values()) <= {"train", "val", "test"}


# --- end to end ------------------------------------------------------------

def test_prepare_writes_the_full_contract(capture_root, tmp_path):
    counts = prepare(capture_root, tmp_path / "out")
    assert sum(counts.values()) > 0

    frame = pl.read_parquet(tmp_path / "out" / "train.parquet")
    for feature in FEATURE_ORDER:
        assert feature in frame.columns, f"{feature} missing from the extracted rows"
    assert LABEL_COLUMN in frame.columns
    assert ATTACK_COLUMN in frame.columns


def test_a_capture_never_spans_two_splits(capture_root, tmp_path):
    """The leak this module exists to prevent."""
    out = tmp_path / "out"
    prepare(capture_root, out)

    seen: dict[str, str] = {}
    for name in ("train", "val", "test"):
        frame = pl.read_parquet(out / f"{name}.parquet")
        for capture in frame.get_column(SOURCE_COLUMN).unique().to_list():
            assert seen.setdefault(capture, name) == name, (
                f"{capture} appears in both {seen[capture]} and {name}"
            )


def test_both_classes_are_extracted(capture_root, tmp_path):
    out = tmp_path / "out"
    prepare(capture_root, out)
    labels = set()
    for name in ("train", "val", "test"):
        labels |= set(pl.read_parquet(out / f"{name}.parquet").get_column(LABEL_COLUMN).to_list())
    assert labels == {0, 1}


def test_flows_are_counted_not_packets(capture_root, tmp_path):
    """Three packets per conversation; the unit of training data is the flow."""
    out = tmp_path / "out"
    counts = prepare(capture_root, out)
    # 8 benign captures x 3 flows + 4 scan captures x 2 flows.
    assert sum(counts.values()) == 8 * 3 + 4 * 2
