"""PCAP preparation.

The rule worth pinning is that splitting happens per capture file, never per flow. Flows
from one capture share a session, a host pair and a clock, so splitting them across train
and test leaks - and produces exactly the inflated accuracy this project set out to
question.
"""

from __future__ import annotations

from datetime import datetime, timezone

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
    chronological_split,
    extract_in_chunks,
    find_captures,
    label_flows,
    label_for,
    prepare,
    prepare_labelled,
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


# --- one capture labelled from a labelled-flow file ------------------------

DAY = datetime(2017, 7, 7, 12, 0, tzinfo=timezone.utc)


def write_timed_capture(path, starts: list[float]) -> None:
    """One short TCP conversation per start time, each from its own client port."""
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for index, start in enumerate(starts):
            for step, flags in enumerate(
                (dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)
            ):
                frame = _frame("10.0.0.5", "10.0.0.9", 40000 + index, 80, flags)
                writer.writepkt(frame, ts=start + step * 0.01)


def labels_for(rows: list[tuple[int, float, str]], reverse: bool = False) -> pl.DataFrame:
    """Labelled-flow rows (client port, start, label), timestamps floored to the minute."""
    columns = {"Source IP": [], " Source Port": [], "Destination IP": [],
               "Destination Port": [], "Protocol": [], "Timestamp": [], " Label": []}
    for port, start, label in rows:
        client, server = ("10.0.0.5", port), ("10.0.0.9", 80)
        if reverse:
            client, server = server, client
        columns["Source IP"].append(client[0])
        columns[" Source Port"].append(client[1])
        columns["Destination IP"].append(server[0])
        columns["Destination Port"].append(server[1])
        columns["Protocol"].append(6)
        when = datetime.fromtimestamp(start, timezone.utc).replace(second=0, microsecond=0)
        columns["Timestamp"].append(when.replace(tzinfo=None))
        columns[" Label"].append(label)
    return pl.DataFrame(columns)


def _flows(tmp_path, starts):
    capture = tmp_path / "day.pcap"
    write_timed_capture(capture, starts)
    extract_in_chunks(capture, tmp_path / "parts")
    return pl.read_parquet(tmp_path / "parts" / "*.parquet")


def test_extraction_is_written_in_chunks(tmp_path):
    capture = tmp_path / "day.pcap"
    write_timed_capture(capture, [DAY.timestamp() + i for i in range(5)])
    assert extract_in_chunks(capture, tmp_path / "parts", chunk_rows=2) == 5
    assert len(list((tmp_path / "parts").glob("*.parquet"))) == 3
    assert pl.read_parquet(tmp_path / "parts" / "*.parquet").height == 5


def test_labels_join_on_the_five_tuple_in_either_direction(tmp_path):
    start = DAY.timestamp() + 10
    flows = _flows(tmp_path, [start, start + 1])
    for reverse in (False, True):
        labels = labels_for([(40000, start, "BENIGN"), (40001, start + 1, "PortScan")], reverse)
        labelled = label_flows(flows, labels).sort("src_port")
        assert labelled.get_column(LABEL_COLUMN).to_list() == [0, 1]
        assert labelled.get_column(ATTACK_COLUMN).to_list() == ["Benign", "PortScan"]


def test_an_unmatched_flow_is_dropped_not_called_benign(tmp_path):
    start = DAY.timestamp() + 10
    flows = _flows(tmp_path, [start, start + 1])
    labelled = label_flows(flows, labels_for([(40000, start, "BENIGN")]))
    assert labelled.height == 1


def test_a_label_too_far_away_in_time_does_not_match(tmp_path):
    """A reused port an hour later is a different conversation."""
    start = DAY.timestamp() + 10
    flows = _flows(tmp_path, [start])
    assert label_flows(flows, labels_for([(40000, start + 3600, "DDoS")])).height == 0


def test_the_nearest_label_wins(tmp_path):
    start = DAY.timestamp() + 600
    flows = _flows(tmp_path, [start])
    labels = labels_for([(40000, start - 90, "BENIGN"), (40000, start, "DDoS")])
    assert label_flows(flows, labels).get_column(ATTACK_COLUMN).to_list() == ["DDoS"]


def test_an_attack_label_beats_a_benign_one_in_the_same_minute(tmp_path):
    """CICFlowMeter also writes the server's side of an attacked conversation as a
    reversed flow labelled BENIGN, in the same minute; that must not unlabel the attack."""
    start = DAY.timestamp() + 10
    flows = _flows(tmp_path, [start])
    labels = pl.concat([labels_for([(40000, start, "BENIGN")], reverse=True),
                        labels_for([(40000, start, "DDoS")])])
    for order in (labels, labels.reverse()):
        assert label_flows(flows, order).get_column(ATTACK_COLUMN).to_list() == ["DDoS"]


def test_each_capture_is_split_by_its_own_timeline():
    """Test is always later than train, within every capture, however far apart they are."""
    frame = pl.DataFrame({
        "source": ["a"] * 20 + ["b"] * 20,
        "ts": [float(i) for i in range(20)] + [5000.0 + 10 * i for i in range(20)],
    }).with_columns(chronological_split(pl.col("ts"), "source").alias("split"))
    for source in ("a", "b"):
        part = frame.filter(pl.col("source") == source)
        per_split = dict(part.group_by("split").len().iter_rows())
        assert per_split == {"train": 14, "val": 3, "test": 3}
        last_train = part.filter(pl.col("split") == "train").get_column("ts").max()
        assert part.filter(pl.col("split") == "test").get_column("ts").min() > last_train


def test_prepare_labelled_end_to_end(tmp_path):
    start = DAY.timestamp()
    captures, rows = [], []
    for window in range(2):
        starts = [start + window * 3600 + i * 30 for i in range(20)]
        captures.append(tmp_path / f"window{window}.pcap")
        write_timed_capture(captures[-1], starts)
        rows += [(40000 + i, s, "PortScan" if i % 2 else "BENIGN") for i, s in enumerate(starts)]
    labels_for(rows).write_parquet(tmp_path / "labels.parquet")

    counts = prepare_labelled(captures, [tmp_path / "labels.parquet"], tmp_path / "out")
    # Each window's first flow falls in its opening idle timeout and is skipped.
    assert counts == {"train": 26, "val": 6, "test": 6}
    test = pl.read_parquet(tmp_path / "out" / "test.parquet")
    assert set(test.get_column(LABEL_COLUMN).to_list()) == {0, 1}
    assert set(test.get_column(SOURCE_COLUMN).to_list()) == {"window0.pcap", "window1.pcap"}
    for feature in FEATURE_ORDER:
        assert feature in test.columns

    # A second run reuses the extracted flows rather than reading the captures again.
    for capture in captures:
        capture.unlink()
    assert prepare_labelled(captures, [tmp_path / "labels.parquet"], tmp_path / "out") == counts


def test_flows_in_a_capture_s_opening_idle_timeout_are_skipped(tmp_path):
    """They may be the tail of a conversation that began before the capture was cut."""
    start = DAY.timestamp()
    starts = [start, start + 5, start + 20, start + 40]
    capture = tmp_path / "window.pcap"
    write_timed_capture(capture, starts)
    labels_for([(40000 + i, s, "BENIGN") for i, s in enumerate(starts)]).write_parquet(
        tmp_path / "labels.parquet"
    )
    counts = prepare_labelled([capture], [tmp_path / "labels.parquet"], tmp_path / "out")
    assert sum(counts.values()) == 2
