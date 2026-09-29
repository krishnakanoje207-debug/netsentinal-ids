"""The sensor agent.

The assertion that matters most is that an undecided flow is still published. The sensor
is the only place the feature vector exists; dropping a flow because no active model
scored it would mean the flow never reaches storage, and a shadow-mode deployment would
quietly record nothing at all.
"""

from __future__ import annotations

import dpkt
import pytest

from netsentinel_core.features.contract import FEATURE_ORDER, SCALAR_FIELDS, TIER_B_FEATURES
from netsentinel_sensor.agent import SensorAgent, flow_payload
from netsentinel_sensor.capture import from_pcap_file
from netsentinel_sensor.publisher import CollectingPublisher


@pytest.fixture
def publisher() -> CollectingPublisher:
    return CollectingPublisher()


def run(agent: SensorAgent, pcap_path: str):
    return agent.run(from_pcap_file(pcap_path))


def test_every_flow_is_published(scorer, publisher, pcap_path, expected_flows):
    agent = SensorAgent(scorer, publisher)
    stats = run(agent, pcap_path)

    assert stats.flows == expected_flows
    assert len(publisher.published) == expected_flows
    assert stats.packets == 5


def test_undecided_flows_are_still_published(shadow_scorer, publisher, pcap_path, expected_flows):
    """Shadow mode must record everything, or it records nothing."""
    agent = SensorAgent(shadow_scorer, publisher)
    stats = run(agent, pcap_path)

    assert stats.undecided == expected_flows
    assert stats.decided == 0
    assert len(publisher.published) == expected_flows
    for _key, payload in publisher.published:
        assert payload["verdict"]["undecided"] is True
        assert payload["verdict"]["risk_score"] is None
        # Absence of a score must not be published as zero.
        assert payload["flow"]["risk_score"] is None


def test_alerts_are_counted_but_not_acted_on(scorer, publisher, pcap_path, expected_flows):
    agent = SensorAgent(scorer, publisher)
    stats = run(agent, pcap_path)
    # Risk 0.8 over a 0.5 threshold on every flow.
    assert stats.alerts == expected_flows
    assert all(payload["verdict"]["is_alert"] for _k, payload in publisher.published)


def test_payload_carries_the_whole_feature_vector(scorer, publisher, pcap_path):
    """The SHAP writer needs the exact values that produced the verdict."""
    agent = SensorAgent(scorer, publisher)
    run(agent, pcap_path)

    _key, payload = publisher.published[0]
    for feature in FEATURE_ORDER:
        assert feature in payload["flow"], f"{feature} missing from the published flow"
    assert payload["contract"]["features"] == len(FEATURE_ORDER)


def test_payload_carries_the_packet_sequence_under_tier_b_names(scorer, publisher, pcap_path):
    """Tier B reads the first packets, so the message must carry them as extracted, under
    the names its card declares - not just columns that happen to exist."""
    agent = SensorAgent(scorer, publisher)
    run(agent, pcap_path)

    by_id = {str(features.key): features for features in scorer.scored}
    for _key, payload in publisher.published:
        features = by_id[payload["flow"]["flow_id"]]
        assert [payload["flow"][name] for name in TIER_B_FEATURES] == (
            features.splt_len + features.splt_iat
        )


def test_payload_names_every_model_that_scored(shadow_scorer, publisher, pcap_path):
    """Including the shadow ones, which decided_by deliberately omits."""
    agent = SensorAgent(shadow_scorer, publisher)
    run(agent, pcap_path)

    _, payload = publisher.published[0]
    assert payload["verdict"]["decided_by"] == []
    assert payload["models"] == [
        {"tier": "A", "name": "stub", "version": "0", "mode": "shadow"}
    ]


def test_payload_is_keyed_by_flow(scorer, publisher, pcap_path, tcp_dport):
    agent = SensorAgent(scorer, publisher)
    run(agent, pcap_path)

    keys = [key for key, _payload in publisher.published]
    # The key is src:sport-dst:dport-proto.
    assert any(f":{tcp_dport}-6" in key for key in keys)
    # One record per flow, so keys are unique in this capture.
    assert len(set(keys)) == len(keys)


def test_sensor_name_is_stamped_on_every_flow(scorer, publisher, pcap_path):
    agent = SensorAgent(scorer, publisher, sensor_name="lab-bridge")
    run(agent, pcap_path)
    assert all(payload["flow"]["sensor"] == "lab-bridge" for _k, payload in publisher.published)


def test_open_flows_are_emitted_at_shutdown(scorer, publisher, open_flow_frames):
    """A long-lived connection must not be lost because the process stopped."""
    agent = SensorAgent(scorer, publisher)
    stats = agent.run(iter(open_flow_frames))

    assert stats.flows == 1, "the open flow should be flushed on exit"
    assert publisher.flushed >= 1


def _stopped_after(agent, packets):
    """Feed ``packets``, calling stop() as the last one is read, as SIGTERM does."""
    def stream():
        for index, packet in enumerate(packets):
            if index == len(packets) - 1:
                agent.stop()
            yield packet
    return agent.run(stream())


def test_a_young_flow_cut_by_a_stop_is_published_but_not_an_alert(scorer, publisher, tcp_frame):
    """Live, the one false alert on benign traffic was a connection flushed as one packet."""
    agent = SensorAgent(scorer, publisher)
    stats = _stopped_after(agent, [(1000.0, tcp_frame(dpkt.tcp.TH_SYN))])

    (_key, payload), = publisher.published
    assert payload["verdict"]["cut_short"] is True
    assert payload["verdict"]["is_alert"] is False
    assert payload["verdict"]["risk_score"] == 0.8, "still scored"
    assert (stats.cut_short, stats.alerts) == (1, 0)


def test_a_long_lived_flow_open_at_a_stop_still_alerts(scorer, publisher, tcp_frame):
    agent = SensorAgent(scorer, publisher)
    _stopped_after(agent, [
        (1000.0, tcp_frame(dpkt.tcp.TH_SYN)),
        (1010.0, tcp_frame(dpkt.tcp.TH_ACK)),
        (1020.0, tcp_frame(dpkt.tcp.TH_ACK)),
    ])
    (_key, payload), = publisher.published
    assert payload["verdict"]["cut_short"] is False
    assert payload["verdict"]["is_alert"] is True


def test_a_capture_that_simply_ends_cuts_nothing_short(scorer, publisher, open_flow_frames):
    agent = SensorAgent(scorer, publisher)
    agent.run(iter(open_flow_frames))
    (_key, payload), = publisher.published
    assert payload["verdict"]["is_alert"] is True


def test_a_connection_already_under_way_at_start_is_not_an_alert(scorer, publisher, tcp_frame):
    """No SYN, first seen in the first seconds: it began before the sensor did."""
    agent = SensorAgent(scorer, publisher)
    agent.run(iter([
        (1000.0, tcp_frame(dpkt.tcp.TH_ACK)),
        (1000.1, tcp_frame(dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK, to_server=False)),
    ]))
    (_key, payload), = publisher.published
    assert payload["verdict"]["cut_short"] is True
    assert payload["verdict"]["is_alert"] is False


def test_the_same_flow_later_in_the_capture_alerts(scorer, publisher, tcp_frame):
    """A probe with no SYN (a FIN or NULL scan) is excused only at the very start."""
    agent = SensorAgent(scorer, publisher)
    agent.run(iter([
        (1000.0, tcp_frame(dpkt.tcp.TH_SYN, sport=40000)),
        (1000.1, tcp_frame(dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK, to_server=False, sport=40000)),
        (1030.0, tcp_frame(dpkt.tcp.TH_ACK)),
        (1030.1, tcp_frame(dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK, to_server=False)),
    ]))
    assert [payload["verdict"]["is_alert"] for _k, payload in publisher.published] == [True, True]


def test_stop_ends_the_loop_early(scorer, publisher, frames):
    agent = SensorAgent(scorer, publisher)

    def stopping_stream():
        for index, packet in enumerate(frames):
            if index == 2:
                agent.stop()
            yield packet

    stats = agent.run(stopping_stream())
    # Three packets consumed, then the remaining flows flushed.
    assert stats.packets == 3


def test_stats_report_rates(scorer, publisher, pcap_path, expected_flows):
    agent = SensorAgent(scorer, publisher)
    stats = run(agent, pcap_path)
    reported = stats.as_dict()
    assert reported["flows"] == expected_flows
    assert reported["packets_per_second"] > 0


def test_flow_payload_separates_the_vector_from_the_verdict(scorer, pcap_path):
    """The verdict is metadata about the flow, not a feature of it."""
    agent = SensorAgent(scorer, CollectingPublisher())
    run(agent, pcap_path)

    features = scorer.scored[0]
    payload = flow_payload(features, scorer.score(features), "test", scorer.models)
    assert set(payload) == {"flow", "verdict", "models", "contract"}
    # risk_score is denormalised onto the flow row for ClickHouse, but the feature vector
    # itself must not contain it.
    assert "risk_score" not in SCALAR_FIELDS
    assert payload["verdict"]["threshold"] == 0.5


def test_a_file_publisher_writes_what_the_writer_replays(scorer, pcap_path, expected_flows, tmp_path):
    """One JSON object per line, read back exactly as netsentinel-writer --replay does."""
    import json

    from netsentinel_sensor.publisher import FilePublisher

    out = tmp_path / "flows.jsonl"
    publisher = FilePublisher(str(out))
    run(SensorAgent(scorer, publisher), pcap_path)
    publisher.close()

    with open(out, encoding="utf-8") as handle:
        payloads = [json.loads(line) for line in handle if line.strip()]
    assert len(payloads) == expected_flows
    assert {"flow", "verdict", "models", "contract"} <= set(payloads[0])
