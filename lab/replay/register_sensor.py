"""Give the replayed stream a sensors row to belong to.

    uv run python lab/replay/register_sensor.py

The writer refuses to start without ``--sensor-id`` naming a real row, because a
detection has to say where it was seen. On the VM that row describes the capture host;
for the dataset replay it describes the replay itself, and is named so, so nobody reads
a replayed detection as one seen on the wire. Idempotent: prints the existing id on a
second run.
"""

from __future__ import annotations

from sqlalchemy import select

from netsentinel_api.db.models import Asset, Criticality, Sensor, SensorStatus, SensorType
from netsentinel_api.db.session import get_sessionmaker

HOSTNAME = "dataset-replay"


def main() -> None:
    with get_sessionmaker()() as session:
        asset = session.scalar(select(Asset).where(Asset.hostname == HOSTNAME))
        if asset is None:
            # TEST-NET-1: an address that cannot collide with anything on the estate.
            asset = Asset(hostname=HOSTNAME, ip_address="192.0.2.1", os="replay",
                          criticality=Criticality.low)
            session.add(asset)
            session.flush()
        sensor = session.scalar(select(Sensor).where(Sensor.host_asset_id == asset.asset_id))
        if sensor is None:
            sensor = Sensor(type=SensorType.early_flow, host_asset_id=asset.asset_id,
                            status=SensorStatus.online)
            session.add(sensor)
            session.flush()
        session.commit()
        print(sensor.sensor_id)


if __name__ == "__main__":
    main()
