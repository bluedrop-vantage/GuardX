FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build context = repo root (see deploy/compose/docker-compose.yml).
COPY control/pyproject.toml ./
RUN pip install --upgrade pip && pip install -e .

COPY control/guardx_control ./guardx_control
COPY control/alembic.ini ./alembic.ini
COPY control/alembic ./alembic
COPY schemas /schemas

ENV GUARDX_SCHEMAS_DIR=/schemas \
    GUARDX_SIGNING_KEY_PATH=/data/dev-signing-key.ed25519

VOLUME ["/data"]
EXPOSE 8080

CMD ["sh", "-c", "alembic upgrade head && uvicorn guardx_control.api.app:app --host 0.0.0.0 --port 8080"]
