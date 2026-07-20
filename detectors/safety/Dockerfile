FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build context = repo root.
COPY detectors/llm_judge ./_llm_judge
COPY detectors/safety/pyproject.toml ./
RUN pip install --upgrade pip && pip install -e ./_llm_judge && pip install -e .

COPY detectors/safety/safety_detector ./safety_detector
COPY detectors/llm_judge/rubrics /rubrics
COPY config /config

ENV GUARDX_RUBRICS_DIR=/rubrics \
    GUARDX_PROVIDERS_FILE=/config/providers.yaml

EXPOSE 9200

CMD ["uvicorn", "safety_detector.service:app", "--host", "0.0.0.0", "--port", "9200"]
