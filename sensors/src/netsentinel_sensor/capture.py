"""Where packets come from.

Live capture shells out to ``tcpdump -w -`` and reads its pcap stream, rather than
binding libpcap through a Python extension. Three reasons, in order:

* the sensor stays installable with no compiler and no libpcap headers, which matters
  because it is the one component that may end up on a constrained host;
* ``tcpdump`` already drops privileges after opening the interface, so the Python process
  never needs CAP_NET_RAW;
* the same dpkt reader then serves both live traffic and a PCAP file, which is what keeps
  the offline and online feature paths identical.

The cost is a subprocess and a pipe. At lab traffic rates that is not the bottleneck; if
it ever became one, the fix is a ring buffer, not a rewrite.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Iterator

import dpkt

logger = logging.getLogger(__name__)

#: Packets per tcpdump write. -U flushes per packet so a quiet link still yields flows
#: promptly instead of waiting for a 4 KB buffer to fill.
TCPDUMP = "tcpdump"


class CaptureError(RuntimeError):
    """Capture could not start, or died."""


def from_pcap_file(path: str | Path) -> Iterator[tuple[float, bytes]]:
    """Yield (timestamp, frame) from a PCAP or PCAPNG file."""
    path = Path(path)
    with open(path, "rb") as handle:
        # dpkt raises ValueError for a wrong magic number but NeedData - an UnpackError -
        # for a file too short to hold a header. Both mean "not a capture".
        try:
            reader = dpkt.pcap.Reader(handle)
        except (ValueError, dpkt.dpkt.UnpackError):
            handle.seek(0)
            try:
                reader = dpkt.pcapng.Reader(handle)
            except (ValueError, dpkt.dpkt.UnpackError) as exc:
                raise CaptureError(f"{path} is not a pcap or pcapng file") from exc
        yield from reader


def from_interface(
    interface: str,
    snaplen: int = 262144,
    bpf_filter: str = "ip",
) -> Iterator[tuple[float, bytes]]:
    """Yield (timestamp, frame) from a live interface via tcpdump.

    The default filter is ``ip`` because the extractor only parses IPv4; letting ARP and
    IPv6 through would just be parsed and discarded one process later.
    """
    if shutil.which(TCPDUMP) is None:
        raise CaptureError(
            "tcpdump is not on PATH. Install it (apt install tcpdump) - the sensor reads "
            "its pcap stream rather than binding libpcap directly."
        )

    command = [TCPDUMP, "-i", interface, "-U", "-w", "-", "-s", str(snaplen)]
    if bpf_filter:
        command.append(bpf_filter)

    logger.info("starting capture: %s", " ".join(command))
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None:  # pragma: no cover - Popen with PIPE always sets it
        raise CaptureError("tcpdump produced no stdout")

    try:
        try:
            reader = dpkt.pcap.Reader(process.stdout)
        except (ValueError, dpkt.dpkt.UnpackError) as exc:
            # tcpdump failed before writing a pcap header; its stderr says why, and that
            # message ("no such device", "permission denied") is the whole diagnosis.
            stderr = (process.stderr.read().decode("utf-8", "replace") if process.stderr else "")
            raise CaptureError(f"tcpdump did not start: {stderr.strip() or exc}") from exc

        yield from reader
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            process.kill()
