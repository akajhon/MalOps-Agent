---
title: Architecture
---

# Architecture

The system orchestrates multiple analysis steps and TI lookups in a graph. The final supervisor merges evidence and emits a structured JSON summary.

```mermaid
---
config:
  flowchart:
    curve: linear
---
flowchart TD
  %% Entry points and API
  A[Client/UI] -->|POST /analyze| B[FastAPI]
  A -->|POST /analyze/upload| B2[FastAPI]
  B --> C{{Graph Orchestrator}}
  B2 --> C

  %% Internal graph orchestration
  subgraph C_Graph[Graph Orchestrator]
    direction TB

    IFP[init_file_path]

    %% ---- Static Analysis agent ----
    subgraph SA[Static Analysis Agent]
      direction TB
      SA_START[[Start]] --> H[Hashes + Basic PE] --> IMP[Imports / Sections / Version] --> STR[Strings + IOC Extraction] --> SIG[Code Signatures] --> Y[YARA Scan] --> K[CAPA Scan] --> ADV[Advanced Indicators / Anti-Analysis] --> SA_END[[Summary]]
    end

    %% ---- CTI Analysis ----
    subgraph CTI[CTI Analysis]
      direction TB
      VT[VirusTotal]
      MB[MalwareBazaar]
      HA[Hybrid Analysis]
      OTX[AlienVault OTX]
      CTI_AGG[(CTI Results)]
      VT --> CTI_AGG
      MB --> CTI_AGG
      HA --> CTI_AGG
      OTX --> CTI_AGG
    end

    %% Wiring between nodes (not subgraph IDs)
    IFP --> SA_START
    IFP --> VT
    IFP --> MB
    IFP --> HA
    IFP --> OTX

    SA_END --> SUP[Supervisor - LLM]
    CTI_AGG --> SUP
    SUP --> OUT[Final JSON Report]
  end

  C --> IFP
  OUT --> DB[(SQLite Cache)]
```

```mermaid
---
config:
  flowchart:
    curve: linear
---
graph TD;
	__start__([<p>__start__</p>]):::first
	init_file_path(init_file_path)
	static_agent(static_agent)
	cti_analysis(cti_analysis)
	supervisor(supervisor)
	__end__([<p>__end__</p>]):::last
	__start__ --> init_file_path;
	cti_analysis --> supervisor;
	init_file_path --> cti_analysis;
	init_file_path --> static_agent;
	static_agent --> supervisor;
	supervisor --> __end__;
```

Key components:
- FastAPI app (`src/api/app.py`) exposes endpoints and invokes the graph.
- Storage (`src/api/storage.py`) persists and retrieves cached results by sha256.
- Graph (`src/agent/graph.py`) composes the pipeline nodes and supervisor.
- Tools (`src/tools/*.py`) provide hashing, string/IOC extraction, YARA and CAPA integration, etc.
