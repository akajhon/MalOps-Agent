FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -u 10001 -m appuser

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

ENV DB_PATH=/data/analyses.db
EXPOSE 8000
USER appuser

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD curl -fsS http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]