---
title: Getting Started
---

# Getting Started

## Prerequisites
- Python 3.10+
- Optional: Docker & Docker Compose

## Run API locally

Install dependencies and run the FastAPI app (Uvicorn suggested):

```bash
pip install -r requirements.txt
uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000
```

Health check: `GET http://localhost:8000/healthz`

OpenAPI/Swagger UI: `http://localhost:8000/docs`

## Run with Docker Compose

```bash
docker compose up --build
```

- UI: `http://localhost:8501`
- API: `http://localhost:8000`

## Analyze examples

Analyze a file path:

```bash
curl -X POST http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"file_path":"samples/malware.bin", "hint":"unpacked", "model":"gemini-2.0-flash"}'
```

Analyze via file upload:

```bash
curl -X POST http://localhost:8000/analyze/upload \
  -F 'file=@samples/malware.bin' \
  -F 'hint=unpacked' \
  -F 'model=gemini-2.0-flash'
```

## Configuration

Set environment variables in `.env` (used by both API and Compose). See `src/config.py` for supported settings. Logs and artifacts are written to `./logs` by default.

