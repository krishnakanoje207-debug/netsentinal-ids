# The API image: FastAPI plus the one shared package it depends on.
#
#   docker compose -f infra/docker-compose.yml --profile app up -d --build
#
# Built from the repository root so core/ is in the context. Only core and backend
# are installed: LightGBM, torch and the LLM client belong to other members and must
# never be importable from the process that serves requests.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY core /app/core
COPY backend /app/backend
RUN pip install /app/core /app/backend \
    && useradd --system --home /app netsentinel

USER netsentinel
WORKDIR /app/backend
EXPOSE 8000

# Migrate, then seed roles and the administrator, then serve. Bootstrap is idempotent
# and never resets a password, so a restart is always safe; on the first start it
# prints a generated admin password once, in `docker compose logs api`.
CMD ["sh", "-c", "alembic upgrade head && netsentinel-bootstrap && exec uvicorn netsentinel_api.app:app --host 0.0.0.0 --port 8000"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2)"
