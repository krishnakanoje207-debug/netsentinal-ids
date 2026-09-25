"""Tier C's window scores off the bus, into ClickHouse ``tier_c_scores``.

``netsentinel_scoring.window`` publishes one message per flow of each scored window to
``TIER_C_TOPIC``: the flow's identity, a shadow verdict carrying
``model_scores["tier_c"]``, the model, and the window's size. This stores each as one
row, so the graph tier's scores can be read next to the flows they belong to.

It is the flow sink with a different row, topic and table: the same batching, the
same offset commit after each insert, and the same dead-letter handling, on its own
dead-letter topic. See ``flow_sink``.
"""

from __future__ import annotations

import sys
from typing import Any, Mapping

from netsentinel_core.bus import TIER_C_TOPIC
from netsentinel_core.features.clickhouse import tier_c_scores_columns

from netsentinel_writer import flow_sink

#: The columns a row fills. ``ingested_at`` is left to ClickHouse's default.
COLUMNS: tuple[str, ...] = tuple(
    name for name, _ in tier_c_scores_columns() if name != "ingested_at"
)

DEAD_LETTER_TOPIC = f"{TIER_C_TOPIC}.deadletter"


def tier_c_row(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The tier_c_scores row for one Tier C message."""
    flow = payload["flow"]
    verdict = payload["verdict"]
    # One model per message: the window scorer serves exactly one Tier C card.
    model = payload["models"][0]
    window = payload["window"]
    return {
        # A decimal, as in the flow sink: a whole number reads as milliseconds.
        "ts": float(flow["ts"]),
        "flow_id": flow["flow_id"],
        "sensor": flow["sensor"],
        "src_ip": flow["src_ip"],
        "dst_ip": flow["dst_ip"],
        "model_name": model["name"],
        "model_version": model["version"],
        "probability": float(verdict["model_scores"]["tier_c"]),
        "threshold": float(verdict["threshold"]),
        "window_flows": int(window["flows"]),
        "window_hosts": int(window["hosts"]),
    }


def main(argv: list[str] | None = None) -> int:
    return flow_sink.main(
        argv,
        description="Write Tier C's window scores to ClickHouse",
        group_id="netsentinel-tier-c-sink",
        topic=TIER_C_TOPIC,
        table="netsentinel.tier_c_scores",
        row=tier_c_row,
        dead_letter_topic=DEAD_LETTER_TOPIC,
    )


if __name__ == "__main__":
    sys.exit(main())
