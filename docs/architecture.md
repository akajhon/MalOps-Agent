---
title: Architecture
---

# Architecture

The system orchestrates multiple analysis steps and TI lookups in a graph. The final supervisor merges evidence and emits a structured JSON summary.

```mermaid
flowchart TD
    A[Client/UI] --> B[FastAPI /analyze]
    A --> B2[FastAPI /analyze/upload]
    B --> C{Graph Orchestrator}
    B2 --> C
    C --> H[Hashes]
    C --> P[Static Analysis]
    C --> I[IOC Extraction]
    C --> Y[YARA Scan]
    C --> K[CAPA Scan]
    C --> T[Threat Intel from SHA256]
    H --> S[Supervisor]
    P --> S
    I --> S
    Y --> S
    K --> S
    T --> S
    S --> R[Final JSON Report]
    R --> DB[(SQLite Cache)]
```

Key components:
- FastAPI app (`src/api/app.py`) exposes endpoints and invokes the graph.
- Storage (`src/api/storage.py`) persists and retrieves cached results by sha256.
- Graph (`src/agent/graph.py`) composes the pipeline nodes and supervisor.
- Tools (`src/tools/*.py`) provide hashing, string/IOC extraction, YARA and CAPA integration, etc.

