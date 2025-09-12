---
title: MalOps Agent
---

# MalOps Agent

MalOps Agent is a malware triage service that combines static analysis tools, YARA/CAPA rule scanning, and external Threat Intelligence into a unified, LLM-supervised pipeline exposed via a FastAPI backend. It also includes a simple UI (Streamlit) and Docker Compose orchestration for local use.

- FastAPI endpoints for file-path analysis and file uploads
- Modular tools layer (hashing, PE parsing, IOC extraction, YARA, CAPA)
- Threat Intelligence lookups (VirusTotal, MalwareBazaar, AlienVault OTX, etc.)
- Supervisor step that merges evidence into a final, human-readable summary

See Architecture for a high-level diagram and API for endpoint details and usage examples.

Quick links:
- API: [API](api.md)
- Architecture: [Architecture](architecture.md)
- Python Reference: [Reference](reference/api_app.md)