---
title: MalOps Agent
---

# MalOps Agent

MalOps Agent is a malware triage service that combines static analysis (hashing, PE parsing, IOC extraction, YARA, CAPA) with external Threat Intelligence into a single pipeline orchestrated by a lightweight agent graph and summarized by an LLM-backed supervisor. It ships with a FastAPI backend, a simple Streamlit UI, and Docker Compose for convenience.

- API endpoints for file uploads, TI lookups, and retrieving cached analyses
- Modular tools layer (hashes, PE basics, imports/sections, strings/IOCs, code signatures, YARA, CAPA)
- CTI integrations (VirusTotal, MalwareBazaar, Hybrid Analysis, AlienVault OTX)
- Supervisor step merges evidence into a final JSON summary

See Architecture for a high-level diagram and API for endpoint details and examples.

Quick links:

- API: [API](api.md)
- Architecture: [Architecture](architecture.md)
- Python Reference: [Reference](reference/api_app.md)