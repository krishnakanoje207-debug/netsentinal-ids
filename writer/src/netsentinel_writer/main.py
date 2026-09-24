"""The writer process: scored flows in, explained detections out.

    python -m netsentinel_writer --card artefacts/tier_a/model_card.json \
        --sensor-id 1 --brokers localhost:9092

Everything it needs is resolved before the first message is read, so a
misconfiguration is a startup failure rather than a silence that looks like quiet
traffic:

* the booster loads and matches the hash in its card,
* the model is registered in ``ml_models``, because a detection has to point at a row
  rather than at a file,
* the sensor row exists.

``--sensor-id`` is given rather than read from the message because ``sensors`` is
keyed by the host it runs on (M2 3.1), not by a name the payload could carry. Telling
the writer which row it is consuming for beats guessing from a string.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys

from netsentinel_api.config import get_settings
from netsentinel_api.db.models import MLModel, Sensor
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.soar import forwarder_from
from sqlalchemy import select

from netsentinel_writer.consumer import Consumer, RedpandaConsumer, ReplayConsumer
from netsentinel_writer.explain import ExplainerError, load_explainer
from netsentinel_writer.technique import LabellerError, load_labeller
from netsentinel_writer.writer import DetectionWriter

logger = logging.getLogger("netsentinel.writer")


class StartupError(RuntimeError):
    """The writer cannot start. The message says what is missing."""


def resolve_model_id(session, name: str, version: str) -> int:
    model = session.scalar(
        select(MLModel).where(MLModel.name == name, MLModel.version == version)
    )
    if model is None:
        raise StartupError(
            f"{name}:{version} is not in ml_models. Register the card first: "
            f"netsentinel-register-model <card>."
        )
    return model.model_id


def resolve_sensor_id(session, sensor_id: int) -> int:
    if session.get(Sensor, sensor_id) is None:
        raise StartupError(f"no sensor with sensor_id {sensor_id}")
    return sensor_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write explained detections to PostgreSQL")
    parser.add_argument("--card", required=True, help="model card of the explaining tier")
    parser.add_argument("--booster", help="override the booster path from the card")
    parser.add_argument("--brokers", default="localhost:9092")
    parser.add_argument("--group-id", default="netsentinel-writer")
    parser.add_argument(
        "--sensor-id", type=int, required=True, help="the sensors row this stream is from"
    )
    parser.add_argument(
        "--from-beginning",
        action="store_true",
        help="replay the retained topic from the start, for a newly trained model",
    )
    parser.add_argument(
        "--replay",
        metavar="JSONL",
        help="read scored flows from a file, one message per line, instead of the bus "
        "(see lab/replay)",
    )
    parser.add_argument(
        "--family-card",
        help="attack-family model card; with it, confident ML alerts carry a MITRE technique",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    try:
        explainer = load_explainer(args.card, args.booster)
    except ExplainerError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    labeller = None
    if args.family_card:
        try:
            labeller = load_labeller(args.family_card)
        except LabellerError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 2

    session_factory = get_sessionmaker()
    try:
        with session_factory() as session:
            model_id = resolve_model_id(session, explainer.name, explainer.version)
            sensor_id = resolve_sensor_id(session, args.sensor_id)
    except StartupError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    logger.info(
        "explaining with tier %s %s (model_id %s) for sensor_id %s",
        explainer.tier,
        explainer.identity,
        model_id,
        sensor_id,
    )

    forwarder = forwarder_from(get_settings())
    if forwarder is None:
        logger.info("Keep is not configured; alerts will be stored but not forwarded")

    writer = DetectionWriter(
        session_factory, explainer, sensor_id, model_id, forwarder, labeller=labeller
    )
    if args.replay:
        with open(args.replay, encoding="utf-8") as handle:
            payloads = [json.loads(line) for line in handle if line.strip()]
        consumer: Consumer = ReplayConsumer(payloads)
    else:
        consumer = RedpandaConsumer(
            args.brokers, group_id=args.group_id, from_beginning=args.from_beginning
        )
        # SIGTERM is how Docker stops a container. Stopping, not closing, ends the
        # loop after the message in flight and still lets its offset be committed;
        # a closed consumer cannot commit, and the message would be written again.
        for signal_name in ("SIGINT", "SIGTERM"):
            if hasattr(signal, signal_name):
                signal.signal(getattr(signal, signal_name), lambda *_: consumer.stop())

    try:
        stats = writer.run(consumer)
    finally:
        consumer.close()
    logger.info("finished: %s", stats.as_dict())
    return 0


if __name__ == "__main__":
    sys.exit(main())
