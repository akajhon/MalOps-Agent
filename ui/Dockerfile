FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -u 10001 -m appuser

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY ui ./ui
COPY README.md ./README.md
COPY logo_malops.png ./logo_malops.png

EXPOSE 8501
USER appuser

ENV API_BASE=http://api:8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD curl -fsS http://localhost:8501/ || exit 1

CMD ["streamlit", "run", "ui/app.py", "--server.port=8501", "--server.address=0.0.0.0"]