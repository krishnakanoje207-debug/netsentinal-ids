"""The sensor agent.

The assertion that matters most is that an undecided flow is still published. The sensor
is the only place the feature vector exists; dropping a flow because no active model
scored it would mean the flow never reaches storage, and a shadow-mode deployment would
quietly record nothing at all.
"""

from __future__ import annotations

import pytest

from netsentinel_core.features.contract import FEATURE_ORDER, SCALAR_FIELDS
from netsentinel_sensor.agent import SensorAgent, flow_payload
from netsentinel_sensor.capture import from_pcap_file
from netsentinel_sensor.publisher import CollectingPublisher

from conftest import EXPECTED_FLOWS, TCP_DPORT


@pytest.fixture
def publisher() -> CollectingPublisher:
    return CollectingPublisher()


def run(agent: SensorAgent, pcap_path: str):
    return agent.run(from_pcap_file(pcap_path))


def test_every_flow_is_published(scorer, publisher, pcap_path):
    agent = SensorAgent(scorer, publisher)
    stats = run(agent, pcap_path)

    assert stats.flows == EXPECTED_FLOWS
    assert len(publisher.published) == EXPECTED_FLOWS
    assert stats.packets == 5


def test_undecided_flows_are_still_published(shadow_scorer, publisher, pcap_path):
    """Shadow mode must record everything, or it records nothing."""
    agent = SensorAgent(shadow_scorer, publisher)
    stats = run(agent, pcap_path)

    assert stats.undecided == EXPECTED_FLOWS
    assert stats.decided == 0
    assert len(publisher.published) == EXPECTED_FLOWS
    for _key, payload in publisher.published:
        assert payload["verdict"]["undecided"] is True
        assert payload["verdict"]["risk_score"] is None
        # Absence of a score must not be published as zero.
        assert payload["flow"]["risk_score"] is None


def test_alerts_are_counted_but_not_acted_on(scorer, publisher, pcap_path):
    agent = SensorAgent(scorer, publisher)
    stats = run(agent, pcap_path)
    # Risk 0.8 over a 0.5 threshold on every flow.
    assert stats.alerts == EXPECTED_FLOWS
    assert all(payload["verdict"]["is_alert"] for _k, payload in publisher.published)


def test_payload_carries_the_whole_feature_vector(scorer, publisher, pcap_path):
    """The SHAP writer needs the exact values that produced the verdict."""
    agent = SensorAgent(scorer, publisher)
    run(agent, pcap_path)

    _key, payload = publisher.published[0]
    for feature in FEATURE_ORDER:
        assert feature in payload["flow"], f"{feature} missing from the published flow"
    assert payload["contract"]["features"] == len(FEATURE_ORDER)


def test_payload_is_keyed_by_flow(scorer, publisher, pcap_path):
    agent = SensorAgent(scorer, publisher)
    run(agent, pcap_path)

    keys = [key for key, _payload in publisher.published]
    # The key is src:sport-dst:dport-proto.
    assert any(f":{TCP_DPORT}-6" in key for key in keys)
    # One record per flow, so keys are unique in this capture.
    assert len(set(keys)) == len(keys)


def test_sensor_name_is_stamped_on_every_flow(scorer, publisher, pcap_path):
    agent = SensorAgent(scorer, publisher, sensor_name="lab-bridge")
    run(agent, pcap_path)
    assert all(payload["flow"]["sensor"] == "lab-bridge" for _k, payload in publisher.published)


def test_open_flows_are_emitted_at_shutdown(scorer, publisher):
    """A long-lived connection must not be lost because the process stopped."""
    from conftest import _to_server, _tcp, TCP_SPORT

    import dpkt

    # A handshake that never closes: no FIN, no idle timeout reached.
    frames = [
        (1000.0, _to_server(_tcp(TCP_SPORT, TCP_DPORT, dpkt.tcp.TH_SYN))),
        (1000.01, _to_server(_tcp(TCP_SPORT, TCP_DPORT, dpkt.tcp.TH_ACK))),
    ]
    agent = SensorAgent(scorer, publisher)
    stats = agent.run(iter(frames))

    assert stats.flows == 1, "the open flow should be flushed on exit"
    assert publisher.flushed >= 1


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


def test_stats_report_rates(scorer, publisher, pcap_path):
    agent = SensorAgent(scorer, publisher)
    stats = run(agent, pcap_path)
    reported = stats.as_dict()
    assert reported["flows"] == EXPECTED_FLOWS
    assert reported["packets_per_second"] > 0


def test_flow_payload_separates_the_vector_from_the_verdict(scorer, pcap_path):
    """The verdict is metadata about the flow, not a feature of it."""
    agent = SensorAgent(scorer, CollectingPublisher())
    run(agent, pcap_path)

    features = scorer.scored[0]
    payload = flow_payload(features, scorer.score(features), "test")
    assert set(payload) == {"flow", "verdict", "contract"}
    # risk_score is denormalised onto the flow row for ClickHouse, but the feature vector
    # itself must not contain it.
    assert "risk_score" not in SCALAR_FIELDS
    assert payload["verdict"]["threshold"] == 0.5
