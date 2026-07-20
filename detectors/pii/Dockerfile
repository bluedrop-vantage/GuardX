FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build context = repo root.
COPY detectors/pii/pyproject.toml ./
RUN pip install --upgrade pip && pip install -e .

COPY detectors/pii/pii_detector ./pii_detector
COPY entity_packs /entity_packs

ENV GUARDX_ENTITY_PACKS_DIR=/entity_packs

EXPOSE 9100

CMD ["uvicorn", "pii_detector.service:app", "--host", "0.0.0.0", "--port", "9100"]
