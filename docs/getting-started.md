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

Analyze via file upload:

```bash
curl -X POST http://localhost:8000/analyze/upload \
  -F 'file=@samples/malware.bin' \
  -F 'hint=unpacked' \
  -F 'model=gemini-2.0-flash'
```

Threat Intel lookup by hash (sha256 or md5):

```bash
curl -X POST http://localhost:8000/ti/hash \
  -H 'Content-Type: application/json' \
  -d '{"hash":"<sha256-or-md5>"}'
```

## Configuration

Create a `.env` at repo root. Supported variables (see `src/config.py`):

```ini
# Logging and cache
LOG_LEVEL=INFO
DB_PATH=  # optional: path to SQLite DB (default: embedded path)

# LLM
GEMINI_API_KEY=

# Threat Intelligence providers
VT_API_KEY=
ABUSE_API_KEY=
OTX_API_KEY=
HA_API_KEY=

# Scanners
YARA_RULES_DIR=rules/yara-rules-full.yar    # single file or directory
CAPA_RULES_DIR=                             # optional; defaults to flare-capa rules
CAPA_SIGNATURES_DIR=                        # optional; comma-separated paths

# Timeouts
DEFAULT_TIMEOUT=60
```

Notes:

- YARA requires `YARA_RULES_DIR` to point to a `.yar/.yara` file or a directory of rules. If unset, the YARA step will be skipped with a warning in the result.
- CAPA uses the bundled flare-capa rule set by default; set `CAPA_RULES_DIR`/`CAPA_SIGNATURES_DIR` to override.
- The API caches results by sha256 in SQLite; use the `/analyses` endpoints to list/fetch/purge.