# The streaming pipeline image: the sensor, the Tier C window scorer, the detection
# writer, both ClickHouse sinks and the Suricata importer. One image, one process per
# container, chosen by the compose service's command.
#
#   docker compose -f infra/docker-compose.yml \
#       --profile storage --profile bus --profile pipeline up -d --build
#
# Built from the repository root. Only the members those processes import are
# installed - sensors and writer, and through them core, scoring and backend (the
# writer inserts through the API's ORM classes) - with the bus extra. The default
# dependency groups are left out: they would pull torch, which nothing here runs.
# Model artefacts are not baked in; compose mounts artefacts/ read-only at /artefacts,
# so a retrained model is a file swap and a restart, not a rebuild.

FROM ghcr.io/astral-sh/uv:0.11.28 AS uv

FROM python:3.11-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /src
COPY pyproject.toml uv.lock ./
# --locked checks the whole workspace against uv.lock, so the members this image does
# not install still need their pyproject.toml present.
COPY copilot/pyproject.toml copilot/pyproject.toml
COPY training/pyproject.toml training/pyproject.toml
COPY core core
COPY scoring scoring
COPY sensors sensors
COPY backend backend
COPY writer writer
RUN uv sync --locked --no-default-groups --no-editable \
        --package netsentinel-sensor --package netsentinel-writer --extra bus

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

# tcpdump: the sensor reads its pcap stream (see sensors/capture.py). The file
# capabilities let it open the interface as the unprivileged user below; the container
# still needs NET_RAW and NET_ADMIN in cap_add. libgomp1: LightGBM's OpenMP runtime,
# for the writer's TreeSHAP.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump libcap2-bin libgomp1 \
    && setcap cap_net_raw,cap_net_admin+eip "$(command -v tcpdump)" \
    && apt-get purge -y libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /app netsentinel

COPY --from=build /opt/venv /opt/venv

USER netsentinel
WORKDIR /app
# No CMD default worth having: every service names its own process.
CMD ["netsentinel-sensor", "--help"]
