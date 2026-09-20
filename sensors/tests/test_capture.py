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
