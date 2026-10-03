"""Packet sources.

Live capture is driven through tcpdump, so the failure worth testing is the one an
operator will actually hit: tcpdump absent, or refusing to open the interface. Both must
say so plainly rather than yielding zero packets and looking healthy.
"""

from __future__ import annotations

import pytest

from netsentinel_sensor.capture import CaptureError, from_interface, from_pcap_file


def test_reads_a_pcap_file(pcap_path, frames):
    read = list(from_pcap_file(pcap_path))
    assert len(read) == len(frames)
    assert read[0][0] == pytest.approx(1000.0)


def test_a_non_pcap_file_is_refused(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("this is not a capture", encoding="utf-8")
    with pytest.raises(CaptureError, match="not a pcap"):
        list(from_pcap_file(path))


def test_a_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(from_pcap_file(tmp_path / "absent.pcap"))


def test_missing_tcpdump_is_explained(monkeypatch):
    """An operator needs the fix, not a traceback."""
    monkeypatch.setattr("netsentinel_sensor.capture.shutil.which", lambda _name: None)
    with pytest.raises(CaptureError, match="apt install tcpdump"):
        list(from_interface("eth0"))


def test_a_failing_tcpdump_surfaces_its_own_error(monkeypatch):
    """tcpdump's stderr is the whole diagnosis: no such device, permission denied."""
    import io
    import subprocess

    class FailedProcess:
        def __init__(self) -> None:
            # No pcap header: what tcpdump leaves behind when it cannot open the device.
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"tcpdump: eth99: No such device exists\n")

        def terminate(self) -> None:
            pass

        def wait(self, timeout=None) -> int:
            return 1

    monkeypatch.setattr("netsentinel_sensor.capture.shutil.which", lambda _name: "/usr/bin/tcpdump")
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: FailedProcess())

    with pytest.raises(CaptureError, match="No such device"):
        list(from_interface("eth99"))


def test_the_default_filter_keeps_only_ip(monkeypatch):
    """The extractor parses IPv4 only; anything else is parsed and discarded downstream."""
    import io
    import subprocess

    captured_command: list[list[str]] = []

    class EmptyProcess:
        def __init__(self) -> None:
            # A valid but empty pcap stream: little-endian magic, version 2.4, LINKTYPE_EN10MB.
            self.stdout = io.BytesIO(
                b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 8 + b"\xff\xff\x00\x00\x01\x00\x00\x00"
            )
            self.stderr = io.BytesIO(b"")

        def terminate(self) -> None:
            pass

        def wait(self, timeout=None) -> int:
            return 0

    def fake_popen(command, **_kwargs):
        captured_command.append(command)
        return EmptyProcess()

    monkeypatch.setattr("netsentinel_sensor.capture.shutil.which", lambda _name: "/usr/bin/tcpdump")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    assert list(from_interface("netsentinel-lab")) == []
    command = captured_command[0]
    assert command[:3] == ["tcpdump", "-i", "netsentinel-lab"]
    # -U flushes per packet, so a quiet link still yields flows promptly.
    assert "-U" in command
    assert command[-1] == "ip"


def test_flows_extracted_from_a_file_match_the_expected_count(pcap_path, expected_flows):
    """Belt and braces: the capture path feeds the same extractor the tests elsewhere use."""
    from netsentinel_core.features.extractor import FlowTracker

    tracker = FlowTracker()
    flows = []
    for timestamp, frame in from_pcap_file(pcap_path):
        flows.extend(tracker.update(timestamp, frame))
    flows.extend(tracker.flush())
    assert len(flows) == expected_flows


def test_a_packet_logged_twice_is_read_once():
    """pktmon logs one packet at each stack component it passes."""
    from netsentinel_sensor.capture import drop_repeats

    packets = [(1.0, b"a"), (1.001, b"a"), (1.002, b"b"), (1.0021, b"b"), (1.003, b"a")]
    assert list(drop_repeats(iter(packets))) == [(1.0, b"a"), (1.002, b"b")]


def test_the_same_bytes_later_are_a_new_packet():
    from netsentinel_sensor.capture import drop_repeats

    packets = [(1.0, b"a"), (1.5, b"a"), (3.0, b"a")]
    assert list(drop_repeats(iter(packets))) == packets


# A folder of capture windows, as Windows' pktmon loop writes them.


def test_windows_are_read_in_name_order_until_the_stop_file(tmp_path, frames, write_window):
    """Every window is drained before the stop file is honoured, and each is deleted."""
    from netsentinel_sensor.capture import from_pcap_dir

    write_window(tmp_path / "window-000002.pcapng", frames[3:])
    write_window(tmp_path / "window-000001.pcapng", frames[:3])
    (tmp_path / "stop").touch()
    stopped = []

    read = list(from_pcap_dir(
        tmp_path, should_stop=lambda: False, sleep=pytest.fail,
        on_stop_file=lambda: stopped.append(True),
    ))

    assert [ts for ts, _frame in read] == pytest.approx([ts for ts, _frame in frames])
    assert stopped == [True]
    # The windows held real traffic and are gone; the stop file is the capture loop's.
    assert sorted(path.name for path in tmp_path.iterdir()) == ["stop"]


def test_a_window_still_being_written_waits_for_its_rename(tmp_path, frames, write_window):
    from netsentinel_sensor.capture import from_pcap_dir

    part = write_window(tmp_path / "window-000001.pcapng.part", frames)
    naps = []

    def sleep(seconds):
        # First nap: the capture loop finishes the window. Second: it ends.
        naps.append(seconds)
        if len(naps) == 1:
            part.rename(tmp_path / "window-000001.pcapng")
        else:
            (tmp_path / "stop").touch()

    read = list(from_pcap_dir(tmp_path, should_stop=lambda: False, poll_seconds=0.5, sleep=sleep))

    assert len(read) == len(frames)
    assert naps == [0.5, 0.5]


def test_keep_leaves_each_window_and_reads_it_once(tmp_path, frames, write_window):
    from netsentinel_sensor.capture import from_pcap_dir

    write_window(tmp_path / "window-000001.pcapng", frames)
    (tmp_path / "stop").touch()

    read = list(from_pcap_dir(tmp_path, should_stop=lambda: False, sleep=pytest.fail, keep=True))

    assert len(read) == len(frames)
    assert (tmp_path / "window-000001.pcapng").exists()


def test_a_file_that_is_not_a_capture_is_set_aside(tmp_path, frames, write_window):
    """One bad window must not end a stream meant to run for days, nor be retried."""
    from netsentinel_sensor.capture import from_pcap_dir

    (tmp_path / "window-000001.pcapng").write_text("not a capture", encoding="utf-8")
    write_window(tmp_path / "window-000002.pcapng", frames)
    (tmp_path / "stop").touch()

    read = list(from_pcap_dir(tmp_path, should_stop=lambda: False, sleep=pytest.fail))

    assert len(read) == len(frames)
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "stop", "window-000001.pcapng.bad",
    ]


def test_a_stop_while_waiting_ends_the_stream(tmp_path):
    """Ctrl+C with no window waiting must not leave the sensor polling forever."""
    from netsentinel_sensor.capture import from_pcap_dir

    stop = []
    stopped_by_file = []
    read = list(from_pcap_dir(
        tmp_path, should_stop=lambda: bool(stop), sleep=lambda _s: stop.append(True),
        on_stop_file=lambda: stopped_by_file.append(True),
    ))

    assert read == []
    assert stop == [True], "noticed at the first look after the nap"
    assert stopped_by_file == []


def test_a_window_read_part_way_is_not_deleted(tmp_path, frames, write_window):
    """A stop mid-window closes the stream there; the rest of that window is not lost."""
    from netsentinel_sensor.capture import from_pcap_dir

    window = write_window(tmp_path / "window-000001.pcapng", frames)
    stream = from_pcap_dir(tmp_path, should_stop=lambda: False, sleep=pytest.fail)
    next(stream)
    stream.close()

    assert window.exists()
