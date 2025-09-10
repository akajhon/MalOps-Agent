---
title: API
---

# API

Base URL (local): `http://localhost:8000`

## Health
- Method: `GET`
- Path: `/healthz`
- Response: `{ "status": "ok" }`

## Analyze by Path
- Method: `POST`
- Path: `/analyze`
- Body (JSON):
  - `file_path` (string, required): absolute or relative path
  - `hint` (string, optional): analyst hint/context
  - `model` (string, optional, default `gemini-2.0-flash`)

Example:
```bash
curl -X POST http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"file_path":"samples/malware.bin", "hint":"unpacked", "model":"gemini-2.0-flash"}'
```

Response: JSON report with hashes, static analysis, IOCs, YARA/CAPA summaries, TI data, and final summary.

## Analyze via Upload
- Method: `POST`
- Path: `/analyze/upload`
- Form fields:
  - `file` (file, required)
  - `hint` (string, optional)
  - `model` (string, optional)

Example:
```bash
curl -X POST http://localhost:8000/analyze/upload \
  -F 'file=@samples/malware.bin' \
  -F 'hint=unpacked' \
  -F 'model=gemini-2.0-flash'
```

Response: Same JSON shape as `/analyze`.

## Notes
- The API caches the last result for a given `sha256` (SQLite, see `src/api/storage.py`).
- Supervisor and graph logic live in `src/agent/graph.py`.
- OpenAPI UI is available when the server is running at `/docs`.

