# MalOps Agent — v5 (Hybrid: Multi-Agente + Paralelo)


# MalOps Agent — v3 (LangGraph Single, Multi-Agents & Parallel Nodes)

Agente de triagem de malware com Tools modulares e três modos de orquestração:

- **Single-Agent (graph.py)**: LLM com ToolNode decide as chamadas.
- **Multi-Agentes (multi_agents.py)**: StaticAnalysis → ThreatIntel → Supervisor.
- **Multi-node Paralelo (parallel_graph.py)**: nós independentes (hashes, PE, entropia, IOCs, YARA, CAPA, TI) convergem para o nó de resumo.

## Endpoints (FastAPI) — Hybrid only
- `POST /analyze/file-path` — single-agent (graph.py)
- `POST /analyze/upload` — single-agent via upload
- `POST /analyze` — grafo híbrido (multi-agente + paralelo)
- `POST /analyze/upload` — upload → grafo híbrido

## Diagrama (pedido do usuário)
```mermaid
flowchart TD
    A[API Call] --> B(Analyze)
    B --> C{Tools}
    C -->|One| D[Compute Hashes]
    C -->|Two| E[PE Basic Info]
    C -->|Three| F[File Entropy]
    C -->|Four| G[Extract IOCs]
    C -->|Five| H[YARA Rules Scan]
    C -->|Six| I[CAPA Rules Scan]
    C -->|Seven| J[Threat Intel Analysis - VT, MalwareBazaar, AbuseIPDB, ThreatFox]
    D --> K(Summarized JSON Report)
    E --> K
    F --> K
    G --> K
    H --> K
    I --> K
    J --> K
```

## Streamlit UI

```bash
streamlit run ui/app.py
```

> UI: `streamlit run ui/app.py`
