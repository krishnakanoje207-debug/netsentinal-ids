"""Fixtures wrapping the synthetic capture builders in ``synthetic.py``.

Test modules import shared values from ``synthetic``, never from ``conftest`` by
name - see the note in that module for why.
"""

from __future__ import annotations

import pytest

from synthetic import build_frames, write_pcap


@pytest.fixture(scope="session")
def frames() -> list[tuple[float, bytes]]:
    return build_frames()


@pytest.fixture(scope="session")
def pcap_path(frames, tmp_path_factory) -> str:
    """The same frames written out as a PCAP file, for the offline path."""
    return write_pcap(tmp_path_factory.mktemp("captures") / "synthetic.pcap", frames)
