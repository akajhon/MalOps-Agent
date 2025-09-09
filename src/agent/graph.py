from typing import Optional, TypedDict
import logging
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableLambda

# tools locais simples
from ..tools import compute_hashes, extract_iocs
from ..logging_config import configure_logging
log = logging.getLogger("agent.graph")

# agentes separados
from .static_agent import run_static_agent
from .cti_agent import ti_from_hash, normalize_ti

# --------- STATE (simples) ---------
class State(TypedDict, total=False):
    file_path: str
    hint: str
    model: str
    hashes: dict
    sha256: str
    iocs: dict
    static_summary: dict
    ti_vt: dict
    ti_mb: dict
    ti_ha: dict
    ti_otx: dict
    threat_intel: dict
    final: dict

# --------- NODES BÁSICOS ---------
def _bootstrap(state: State) -> State:
    # garante file_path de aliases simples
    fp = state.get("file_path") or state.get("path") or state.get("temp_path")
    if not fp:
        raise KeyError("file_path não informado.")
    log.info("bootstrap: file_path=%s", fp)
    return {"file_path": fp}

def _hashes(state: State) -> State:
    h = compute_hashes.func(state["file_path"])
    log.info("hashes: sha256=%s", h.get("sha256"))
    return {"hashes": h, "sha256": h.get("sha256")}

def _iocs(state: State) -> State:
    iocs = extract_iocs.func(state["file_path"])  # type: ignore[attr-defined]
    log.info("iocs: urls=%s domains=%s ips=%s", len(iocs.get("urls", [])), len(iocs.get("domains", [])), len(iocs.get("ipv4s", [])))
    return {"iocs": iocs}

# --------- NODES: AGENTES ---------
def _static_agent(state: State) -> State:
    out = run_static_agent(
        file_path=state["file_path"],
        hint=state.get("hint", ""),
        model=state.get("model", "gemini-2.0-flash"),
    )
    log.info("static_agent completed")
    return {"static_summary": out}

def _ti_hash(state: State) -> State:
    out = ti_from_hash(state.get("sha256", ""))
    log.info("ti_hash completed")
    return {"ti_vt": out.get("ti_vt", {}), "ti_mb": out.get("ti_mb", {}), "ti_ha": out.get("ti_ha", {}), "ti_otx": out.get("ti_otx", {})}

# def _ti_iocs(state: State) -> State:
#     i = state.get("iocs") or {}
#     out = ti_from_iocs(
#         urls=i.get("urls", []),
#         domains=i.get("domains", []),
#         ips=i.get("ipv4s", []),
#     )
#     log.info("ti_iocs completed")
#     return {"ti_tf": out["ti_tf"], "ti_abuse": out["ti_abuse"]}

def _ti_normalize(state: State) -> State:
    log.info("ti_normalize starting")
    return {
        "threat_intel": normalize_ti(
            state.get("ti_vt"), state.get("ti_mb"), state.get("ti_ha"), state.get("ti_otx"),
            state.get("sha256", "")
        )
    }

# --------- SUPERVISOR (LLM resumidor) ---------
import os, json
from pathlib import Path
from datetime import datetime
from langchain_google_genai import ChatGoogleGenerativeAI as ChatLLM
from langchain_core.messages import SystemMessage, HumanMessage
from .prompts import static_analysis_prompt2

def _supervisor(state: State) -> State:
    # Build structured payload object (kept for debugging/dumps)
    payload = {
        "static_summary": state.get("static_summary"),
        "threat_intel": state.get("threat_intel"),
        "hashes": state.get("hashes"),
        "iocs": state.get("iocs"),
        "hint": state.get("hint", ""),
        "path": state.get("file_path", "")
    }
    llm = ChatLLM(model=state.get("model", "gemini-2.0-flash"),
                  temperature=0,
                  google_api_key=os.getenv("GEMINI_API_KEY"))
    payload_json = json.dumps(payload, ensure_ascii=False)
    # Persist the full payload to a file for inspection
    try:
        dump_dir_env = os.getenv("SUPERVISOR_DUMP_DIR", "").strip()
        if dump_dir_env:
            dump_dir = Path(dump_dir_env)
        else:
            # default: <project_root>/logs
            dump_dir = Path(__file__).resolve().parents[2] / "logs"
        dump_dir.mkdir(parents=True, exist_ok=True)
        sha = (state.get("sha256") or "na")[:12]
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        dump_path = dump_dir / f"supervisor_payload_{ts}_{sha}.json"
        with dump_path.open("w", encoding="utf-8") as f:
            f.write(payload_json)
        log.info("supervisor payload written to %s", dump_path)
    except Exception as e:
        log.warning("failed to write supervisor payload: %s", e)
    # Log what we send to the LLM (possibly large). Truncate for safety.
    max_len = 4000
    shown = payload_json if len(payload_json) <= max_len else payload_json[:max_len] + "... [truncated]"
    log.info("supervisor request payload: %s", shown)

    # Build human-readable data block to pair with static_analysis_prompt2()
    ss = (state.get("static_summary") or {}) if isinstance(state.get("static_summary"), dict) else {}
    ti = (state.get("threat_intel") or {}) if isinstance(state.get("threat_intel"), dict) else {}
    hashes = (state.get("hashes") or {}) if isinstance(state.get("hashes"), dict) else {}
    iocs = (state.get("iocs") or {}) if isinstance(state.get("iocs"), dict) else {}

    def _fmt_list(items, sep="\n", limit=None):
        vals = items or []
        if limit is not None:
            vals = vals[:limit]
        return sep.join(str(x) for x in vals)

    sha256 = state.get("sha256") or hashes.get("sha256") or "unknown"
    basic = ss.get("basic_info") or {}
    imports = ss.get("imports", {}).get("imports") if isinstance(ss.get("imports"), dict) else ss.get("imports")
    sections = ss.get("sections", {}).get("sections") if isinstance(ss.get("sections"), dict) else ss.get("sections")
    version = ss.get("version_info")
    strings = ss.get("stable_strings") if isinstance(ss.get("stable_strings"), list) else ss.get("stable_strings", [])
    signatures = ss.get("code_signatures") if isinstance(ss.get("code_signatures"), list) else ss.get("code_signatures", [])
    advanced = ss.get("advanced_indicators") or {}
    yara = ss.get("yara") or {}
    capa = ss.get("capa") or {}

    imports_summary = "\n".join(f"- {k}: {', '.join(v)}" for k, v in (imports or {}).items()) if isinstance(imports, dict) else str(imports)
    sections_summary = "\n".join(
        f"- {s.get('name')} size={s.get('raw_size')} ent={s.get('entropy')} flags={','.join(s.get('characteristics', []))}"
        for s in (sections or [])
    ) if isinstance(sections, list) else str(sections)
    version_summary = json.dumps(version, ensure_ascii=False) if isinstance(version, dict) else str(version)
    strings_summary = _fmt_list(strings, sep="\n", limit=50)
    iocs_summary = json.dumps({
        "urls": (iocs.get("urls") or [])[:50],
        "domains": (iocs.get("domains") or [])[:50],
        "ipv4s": (iocs.get("ipv4s") or [])[:50],
        "btc_addresses": (iocs.get("btc_addresses") or [])[:50],
        "eth_addresses": (iocs.get("eth_addresses") or [])[:50],
    }, ensure_ascii=False)
    signatures_summary = _fmt_list([f"{s.get('label')} @ {s.get('file_offset')}" for s in (signatures or [])], sep="\n")
    advanced_summary = json.dumps(advanced, ensure_ascii=False)
    yara_summary = json.dumps({
        "match_count": yara.get("match_count"),
        "rules": [m.get("rule") for m in (yara.get("matches") or [])][:20]
    }, ensure_ascii=False)
    capa_summary = json.dumps({
        "namespaces": list((capa.get("CAPABILITY") or {}).keys()),
        "capability_counts": {k: len(v) for k, v in (capa.get("CAPABILITY") or {}).items()},
        "attck_tactics": list((capa.get("ATTCK") or {}).keys())
    }, ensure_ascii=False)
    ti_summary = json.dumps(ti.get("summary", ti), ensure_ascii=False)

    human_content = (
        f"=== BASIC PE FACTS ===\n"
        f"SHA256: {sha256}\n"
        f"File Size: {basic.get('size_bytes', 'unknown')} bytes\n"
        f"Architecture: {basic.get('architecture', 'unknown')}\n"
        f"Compile Timestamp: {basic.get('compile_timestamp', 'unknown')}\n"
        f"Subsystem: {basic.get('subsystem', 'unknown')}\n\n"
        f"=== IMPORTS ANALYSIS ===\n{imports_summary}\n\n"
        f"=== SECTIONS ANALYSIS ===\n{sections_summary}\n\n"
        f"=== VERSION INFORMATION ===\n{version_summary}\n\n"
        f"=== STABLE STRINGS (Relevant for Analysis) ===\n{strings_summary}\n\n"
        f"=== IOCs FOUND (Found in Stable Strings) ===\n{iocs_summary}\n\n"
        f"=== CODE SIGNATURES ===\n{signatures_summary}\n\n"
        f"=== ADVANCED INDICATORS ===\n{advanced_summary}\n\n"
        f"=== YARA SCAN ===\n{yara_summary}\n\n"
        f"=== CAPA SCAN ===\n{capa_summary}\n\n"
        f"=== CTI ANALYSIS (Results from VirusTotal, MalwareBazaar, Hybrid-Analysis and Alienvault) ===\n{ti_summary}\n"
    )

    # Persist the final prompt text as well
    try:
        dump_dir_env = os.getenv("SUPERVISOR_DUMP_DIR", "").strip()
        dump_dir = Path(dump_dir_env) if dump_dir_env else (Path(__file__).resolve().parents[2] / "logs")
        dump_dir.mkdir(parents=True, exist_ok=True)
        sha = (state.get("sha256") or "na")[:12]
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        prompt_path = dump_dir / f"supervisor_prompt_{ts}_{sha}.txt"
        with prompt_path.open("w", encoding="utf-8") as f:
            f.write(static_analysis_prompt2())
            f.write("\n\n")
            f.write(human_content)
        log.info("supervisor prompt written to %s", prompt_path)
    except Exception as e:
        log.warning("failed to write supervisor prompt: %s", e)

    out = llm.invoke([
        SystemMessage(content=static_analysis_prompt2()),
        HumanMessage(content=human_content)
    ]).content
    try:
        parsed = json.loads(out)
        log.info("supervisor returned JSON result")
        return {"final": parsed}
    except Exception:
        log.warning("supervisor returned non-JSON content")
        return {"final": {"raw": out}}

# --------- BUILD/RUN ---------
def build_graph():
    g = StateGraph(State)

    # nós
    g.add_node("bootstrap", RunnableLambda(_bootstrap))
    g.add_node("hashes", RunnableLambda(_hashes))
    g.add_node("iocs", RunnableLambda(_iocs))
    g.add_node("static_agent", RunnableLambda(_static_agent))
    g.add_node("ti_hash", RunnableLambda(_ti_hash))
    g.add_node("ti_normalize", RunnableLambda(_ti_normalize))
    g.add_node("supervisor", RunnableLambda(_supervisor))

    # entrada
    g.set_entry_point("bootstrap")

    # edges principais
    g.add_edge("bootstrap", "hashes")
    g.add_edge("bootstrap", "iocs")
    g.add_edge("iocs", "static_agent")
    g.add_edge("hashes", "ti_hash")
    g.add_edge("ti_hash", "ti_normalize")
    g.add_edge("static_agent", "supervisor")
    g.add_edge("ti_normalize", "supervisor")
    g.add_edge("supervisor", END)

    return g.compile()

def run_hybrid(file_path: str, hint: Optional[str] = None, model: str = "gemini-2.0-flash") -> dict:
    # Ensure logging is configured for non-API callers
    try:
        configure_logging(None)
    except Exception:
        pass
    app = build_graph()
    # Always export the graph artifacts on each run for visibility
    try:
        export_graph_artifacts(None)
    except Exception as e:
        log.warning("Graph export failed: %s", e)
    init: State = {"file_path": file_path, "hint": hint or "", "model": model}
    log.info("run_hybrid init: file_path=%s model=%s", init["file_path"], model)
    return app.invoke(init).get("final", {})

# --------- GRAPH EXPORT (image/mermaid) ---------
def _graph_nodes() -> list[str]:
    return [
        "bootstrap",
        "hashes",
        "iocs",
        "static_agent",
        "ti_hash",
        "ti_normalize",
        "supervisor",
    ]


def _graph_edges() -> list[tuple[str, str]]:
    return [
        ("bootstrap", "hashes"),
        ("bootstrap", "iocs"),
        ("iocs", "static_agent"),
        ("hashes", "ti_hash"),
        ("ti_hash", "ti_normalize"),
        ("static_agent", "supervisor"),
        ("ti_normalize", "supervisor"),
    ]


def export_graph_artifacts(out_dir: Optional[str] = None) -> dict:
    """Export the current DAG to Mermaid and, if possible, a PNG image.

    - Mermaid saved as `graph.mmd`
    - PNG saved as `graph.png` when `graphviz` Python package is available
    Returns dict with written paths.
    """
    try:
        base = Path(out_dir) if out_dir else (Path(__file__).resolve().parents[2] / "logs")
        base.mkdir(parents=True, exist_ok=True)

        # Prefer LangGraph's built-in mermaid rendering if available
        app = build_graph()
        try:
            gobj = app.get_graph()
        except Exception:
            gobj = None

        mmd_path = base / "graph.mmd"
        png_path = None

        if gobj is not None:
            try:
                # Mermaid source
                mermaid_src = gobj.draw_mermaid()
                mmd_path.write_text(mermaid_src, encoding="utf-8")
            except Exception as e:
                log.info("draw_mermaid() unavailable, building simple mermaid: %s", e)
                mermaid = ["graph TD"]
                for u, v in _graph_edges():
                    mermaid.append(f"  {u} --> {v}")
                mmd_path.write_text("\n".join(mermaid), encoding="utf-8")

            # Try direct PNG rendering from LangGraph (if runtime supports it)
            try:
                png_bytes = gobj.draw_mermaid_png()
                png_path = base / "graph.png"
                with png_path.open("wb") as f:
                    f.write(png_bytes)
            except Exception as e:
                log.info("draw_mermaid_png() unavailable: %s", e)
        else:
            # Fallback minimal mermaid
            mermaid = ["graph TD"]
            for u, v in _graph_edges():
                mermaid.append(f"  {u} --> {v}")
            mmd_path.write_text("\n".join(mermaid), encoding="utf-8")

        # Final fallback: Graphviz if present and no PNG yet
        if png_path is None:
            try:
                import graphviz  # type: ignore
                dot = graphviz.Digraph("MalOpsAgent", format="png")
                for n in _graph_nodes():
                    dot.node(n, n)
                for u, v in _graph_edges():
                    dot.edge(u, v)
                out = dot.render(filename="graph", directory=str(base), cleanup=True)
                png_path = Path(out)
            except Exception as e:
                log.info("Graphviz not available or failed to render: %s", e)

        written = {"mermaid": str(mmd_path)}
        if png_path:
            written["png"] = str(png_path)
        log.info("Graph artifacts written: %s", written)
        return written
    except Exception as e:
        log.warning("export_graph_artifacts failed: %s", e)
        return {"error": str(e)}


def render_graph_mermaid_png() -> bytes:
    """Return the graph rendered as a Mermaid PNG using LangGraph, if supported.

    Useful in notebooks: e.g., display(Image(render_graph_mermaid_png())).
    Raises if the runtime cannot render directly.
    """
    app = build_graph()
    gobj = app.get_graph()
    return gobj.draw_mermaid_png()
