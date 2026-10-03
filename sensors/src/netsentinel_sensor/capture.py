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
import time
from pathlib import Path
from typing import Callable, Iterator

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


#: What a capture window may be called. A window still being written ends in ``.part``,
#: so it is not one of these until the capture loop renames it.
CAPTURE_SUFFIXES = (".pcap", ".pcapng")

#: Created in the folder by the capture loop after its last window: the capture is over.
STOP_FILE = "stop"


def from_pcap_dir(
    directory: str | Path,
    should_stop: Callable[[], bool],
    poll_seconds: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    keep: bool = False,
    on_stop_file: Callable[[], None] = lambda: None,
) -> Iterator[tuple[float, bytes]]:
    """Yield (timestamp, frame) from each capture window dropped into ``directory``.

    Windows' pktmon can only capture to a file, so continuous capture there is a loop
    writing consecutive windows into a folder. Read as one stream, in name order, the
    flow tracker downstream keeps its state across them: a connection that spans two
    windows stays one flow.

    A window is deleted once read, unless ``keep``: it holds the host's real traffic,
    and a sensor that runs for days must not fill the disk. When no window is waiting
    this sleeps and looks again, until ``should_stop()``; or until the capture loop has
    left a ``stop`` file and every window is read, when ``on_stop_file`` is called -
    the capture ended mid-connection, so that is a stop, not the end of a file. The
    ``stop`` file is left for the capture loop, which removes it when it starts again.
    """
    directory = Path(directory)
    read: set[Path] = set()
    while not should_stop():
        # Looked for before the listing, not after: the capture loop renames its last
        # window and only then creates the stop file, so seen in this order no window
        # can appear between the two looks and be left unread.
        stop_file = (directory / STOP_FILE).exists()
        ready = sorted(
            path for path in directory.iterdir()
            if path.suffix in CAPTURE_SUFFIXES and path not in read
        )
        if not ready:
            if stop_file:
                on_stop_file()
                return
            sleep(poll_seconds)
            continue
        path = ready[0]
        try:
            # If the agent stops part way through, the generator is closed here and the
            # window is not deleted: it was not fully read.
            yield from from_pcap_file(path)
        except CaptureError as exc:
            # One bad file must not end a stream meant to run for days. Renamed rather
            # than skipped in place, so it is not retried on every poll.
            set_aside = path.with_name(path.name + ".bad")
            logger.error("%s; set aside as %s", exc, set_aside.name)
            path.replace(set_aside)
            continue
        if keep:
            read.add(path)
        else:
            path.unlink()


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


#: How close together two identical frames must be to count as one packet logged twice.
REPEAT_WINDOW_SECONDS = 0.005


def drop_repeats(
    packets: Iterator[tuple[float, bytes]],
    window: float = REPEAT_WINDOW_SECONDS,
) -> Iterator[tuple[float, bytes]]:
    """Drop a frame identical to one seen within ``window`` seconds before it.

    Windows' pktmon logs a packet at every network-stack component it passes, so one
    packet can appear two or three times in its capture. Counted as it stands, that
    doubles packet and byte counts and every rate the models read. A real retransmission
    is not dropped: Windows gives each IP packet a new identification field, so a resent
    segment is not byte-identical to the original.
    """
    recent: dict[int, float] = {}
    oldest = 0.0
    for timestamp, frame in packets:
        digest = hash(frame)
        seen = recent.get(digest)
        if seen is not None and timestamp - seen <= window:
            continue
        recent[digest] = timestamp
        # Forget old frames now and then, so a long capture does not grow the table.
        if timestamp - oldest > 1.0:
            recent = {key: ts for key, ts in recent.items() if timestamp - ts <= window}
            oldest = timestamp
        yield timestamp, frame
