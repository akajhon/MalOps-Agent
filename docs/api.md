---
title: API
---

# API

Base URL (local): `http://localhost:8000`

## Health
- Method: `GET`
- Path: `/healthz`
- Response: `{ "status": "ok" }`

## Analyze via Upload
- Method: `POST`
- Path: `/analyze/upload`
- Form fields:
  - `file` (file, required)
  - `hint` (string, optional)
  - `model` (string, optional, default `gemini-2.0-flash`)

Example:
```bash
curl -X POST http://localhost:8000/analyze/upload \
  -F 'file=@samples/malware.bin' \
  -F 'hint=unpacked' \
  -F 'model=gemini-2.0-flash'
```

Response: JSON report with hashes, static analysis, YARA/CAPA summaries, CTI data, and final supervisor summary. Results are cached by sha256.

## Threat Intel by Hash
- Method: `POST`
- Path: `/ti/hash`
- Body (JSON): `{ "hash": "<sha256|md5>" }`
- Notes: sha256 queries VT, HA, MB, OTX; md5 queries MB, OTX.

Example:
```bash
curl -X POST http://localhost:8000/ti/hash \
  -H 'Content-Type: application/json' \
  -d '{"hash":"d2c7...<sha256>"}'
```

## Analyses (Cache)

List (paginated):
- Method: `GET`
- Path: `/analyses`
- Query: `page`, `page_size` (1–200), optional filters `sha256`, `sha1`, `md5`, `date_from`, `date_to` (ISO8601)

Fetch latest by sha256:
- Method: `GET`
- Path: `/analyses/sha256/{hash}`

Fetch by id:
- Method: `GET`
- Path: `/analyses/{id}`

Delete by id:
- Method: `DELETE`
- Path: `/analyses/{id}`

Purge all by sha256:
- Method: `POST`
- Path: `/analyses/purge`
- Query: `sha256`

## Notes
- Results are cached in SQLite; see `src/api/storage.py`.
- Orchestration graph lives in `src/agent/graph.py`.
- OpenAPI UI is available at `/docs` when the server is running.
