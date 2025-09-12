
import streamlit as st
import requests
from pathlib import Path
import os, json, hashlib
from typing import Any, Dict
import pandas as pd
from collections import Counter

LOGO_PATH = Path(__file__).resolve().parent.parent / "assets" / "logo_malops.png"
st.set_page_config(page_title="MalOps Agent", page_icon=str(LOGO_PATH), layout="centered")

st.title("🔍 MalOps Agent - Analyze Malware Samples")
st.caption("Autonomous, Graph-Orchestrated Agentic System for Malware Analysis and Threat Intelligence")

st.markdown(
    """
    <style>
      .badge{display:inline-block;padding:2px 8px;border-radius:999px;
        border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.06);
        margin-right:6px;font-weight:600;font-size:.8rem}
      .card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
        padding:10px 14px;border-radius:10px}
      .label{opacity:.7;font-size:.85rem}
      .hash{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        font-size:.9rem}
    </style>
    """,
    unsafe_allow_html=True,
)

API_BASE_DEFAULT = os.getenv("API_BASE", "http://mal_ops_api:8000")
api_base = API_BASE_DEFAULT
hint = st.text_input("Hint/Context (optional):", value="")
model = st.text_input("LLM Model:", value="gemini-2.0-flash")
file = st.file_uploader("Select the sample:", type=None)

def _compute_hashes(buf: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(buf).hexdigest(),
        "sha1": hashlib.sha1(buf).hexdigest(),
        "sha256": hashlib.sha256(buf).hexdigest(),
    }
def _human_size(n: int) -> str:
    s = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if s < 1024 or u == "TB":
            return f"{int(s)} {u}" if u == "B" else f"{s:.1f} {u}"
        s /= 1024.0

if file is not None:
    b = file.getvalue()
    hs = _compute_hashes(b)

    st.subheader("📄 Selected File")
    with st.container():
        st.markdown(
            f"""
            <div class="card">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:.75rem;flex-wrap:wrap;">
                <div style="font-weight:700;font-size:1.05rem">{file.name}</div>
                <div>
                  <span class="badge">Size: {_human_size(len(b))}</span>
                  <span class="badge">Ext: {Path(file.name).suffix or '—'}</span>
                </div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")  # spacing
    st.subheader("🔐 Hashes")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("<div class='label'>MD5</div>", unsafe_allow_html=True)
        st.code(hs["md5"], language=None)
    with c2:
        st.markdown("<div class='label'>SHA1</div>", unsafe_allow_html=True)
        st.code(hs["sha1"], language=None)
    with c3:
        st.markdown("<div class='label'>SHA256</div>", unsafe_allow_html=True)
        st.code(hs["sha256"], language=None)

    with st.expander("Show details", expanded=False):
        st.markdown("**Name:** " + file.name)
        st.markdown("**Extension:** " + (Path(file.name).suffix or "—"))
        st.markdown("**Size:** " + _human_size(len(b)))

def render_result(result: Dict[str, Any]) -> None:
    st.markdown("""
    <style>
      .fam-card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
        padding:10px 14px;border-radius:10px}
      .fam-label{font-size:.82rem;opacity:.7;margin-bottom:6px}
      .fam-chips{display:flex;flex-wrap:wrap;gap:.4rem}
      .fam-chip{padding:.15rem .55rem;border-radius:999px;background:rgba(255,255,255,.06);
        border:1px solid rgba(255,255,255,.15);font-weight:600}
    </style>
    """, unsafe_allow_html=True)

    def strip_code_fences(s: str) -> str:
        s = s.strip()
        if s.startswith("```"):
            nl = s.find("\n")
            if nl != -1: s = s[nl+1:]
        if s.endswith("```"): s = s[:-3]
        return s.strip()

    def coerce(obj):
        if isinstance(obj, dict) and any(k in obj for k in ("summary","technical_analysis","mitre_attack","ioc_inventory")):
            return obj
        if isinstance(obj, dict):
            for k in ("raw","data","result","output","payload"):
                v = obj.get(k)
                if isinstance(v, dict):
                    c = coerce(v)
                    if c: return c
                if isinstance(v, str):
                    try: return json.loads(strip_code_fences(v))
                    except Exception: pass
        if isinstance(obj, str):
            try: return json.loads(strip_code_fences(obj))
            except Exception: return {}
        return {}

    data = coerce(result) or {}
    if not data:
        st.error("The API answer was not interpretable.")
        st.json(result)
        return
    
    def as_list(x):
        if x is None: return []
        return x if isinstance(x, list) else [x]

    def listdict(x) -> pd.DataFrame:
        if x is None: return pd.DataFrame()
        if isinstance(x, list):
            if not x: return pd.DataFrame()
            if all(isinstance(i, dict) for i in x):
                flat=[]
                for row in x:
                    r=dict(row)
                    for k,v in list(r.items()):
                        if isinstance(v, list) and all(not isinstance(i, dict) for i in v):
                            r[k]=", ".join(map(str,v))
                    flat.append(r)
                return pd.DataFrame(flat)
            return pd.DataFrame({"value":[str(i) for i in x]})
        if isinstance(x, dict): return pd.DataFrame([x])
        return pd.DataFrame({"value":[str(x)]})

    def bar_from_counts(counts: Dict[str,int], title: str):
        if not counts: return
        df = pd.DataFrame({"item": list(counts.keys()), "count": list(counts.values())})
        st.markdown(f"**{title}**")
        st.bar_chart(df.set_index("item").sort_index())

    # ---------- download ----------
    st.download_button(
        "⬇️ Download JSON",
        data=json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"),
        file_name="analysis.json",
        mime="application/json",
        width='stretch',
    )

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Summary", "Technical Analysis", "ATT&CK", "IOCs", "JSON"])

    with tab1:
        summary = data.get("summary", {}) or {}
        c1, c2, c3 = st.columns([1, 3, 1])
        with c1:
            st.metric("Risco", summary.get("overall_risk_level", "-"))
        with c2:
            fam_list = as_list(summary.get("most_likely_family_or_category"))
            chips = "".join(f'<span class="fam-chip">{str(f)}</span>' for f in fam_list) or "—"
            st.markdown(f"""
                <div class="fam-card">
                  <div class="fam-label">Família/Categoria</div>
                  <div class="fam-chips">{chips}</div>
                </div>
            """, unsafe_allow_html=True)
        with c3:
            st.metric("Confidence", summary.get("confidence", "-"))

        if summary.get("one_paragraph_summary"):
            st.write(summary["one_paragraph_summary"])

        df_inds = listdict(data.get("key_indicators"))
        if not df_inds.empty:
            st.subheader("📌 Key Indicators:")
            st.dataframe(df_inds, width='stretch')

        for title, key in [
            ("🔧 Recommendations", "recommendations_priority_ordered"),
            ("➡️ Next steps", "recommended_next_steps"),
        ]:
            vals = as_list(data.get(key))
            if vals:
                with st.expander(title, expanded=False):
                    for i, v in enumerate(vals, 1):
                        st.markdown(f"{i}. {v}" if title.startswith("🔧") else f"- {v}")

    with tab2:
        tech = data.get("technical_analysis", {}) or {}
        hs = tech.get("high_signal_features", {}) or {}

        def section_list(title, values):
            st.subheader(title)
            vals = as_list(values)
            if vals:
                st.dataframe(pd.DataFrame({"value": [str(i) for i in vals]}), width='stretch')
            else:
                st.write("—")

        section_list("Imports", hs.get("imports"))
        section_list("Sections/Entropy/Anomalies", hs.get("sections_entropy_anomalies"))
        section_list("Interesting Strings", hs.get("strings_of_interest"))
        section_list("Code signatures", hs.get("code_signatures"))
        section_list("YARA hits", hs.get("yara_hits"))
        section_list("CAPA findings", hs.get("capa_findings"))
        section_list("Advanced indicators", hs.get("advanced_indicators"))

        for t, k in [("Infered Capabilities","capabilities"),
                    ("Evasion / Anti-analysis","evasion_anti_analysis"),
                    ("Persistence","persistence")]:
            df = listdict(tech.get(k))
            if not df.empty:
                st.subheader(t)
                st.dataframe(df, width='stretch')

        net = tech.get("networking_exfiltration", {}) or {}
        if isinstance(net, dict) and any(net.values()):
            st.subheader("Networking & Exfiltration")
            endpoints = net.get("c2_endpoints") or []
            if endpoints:
                df_endp = listdict([
                    {
                        "value": e.get("value"),
                        "type": e.get("type"),
                        "scope": e.get("scope"),
                        "sources": ", ".join(e.get("sources", [])) if isinstance(e.get("sources"), list) else e.get("sources"),
                        "notes": e.get("notes"),
                    }
                    for e in endpoints if isinstance(e, dict)
                ])
                if not df_endp.empty:
                    st.markdown("**C2 Endpoints**")
                    st.dataframe(df_endp, width='stretch')

            protos = net.get("protocols_ports_uris") or []
            if protos:
                df_ppu = listdict([
                    {
                        "protocol": p.get("protocol"),
                        "port": p.get("port"),
                        "uri_path": p.get("uri_path"),
                        "sources": ", ".join(p.get("sources", [])) if isinstance(p.get("sources"), list) else p.get("sources"),
                    }
                    for p in protos if isinstance(p, dict)
                ])
                if not df_ppu.empty:
                    st.markdown("**Protocols / Ports / URIs**")
                    st.dataframe(df_ppu, width='stretch')

            notes = net.get("behavioral_notes") or []
            if notes:
                st.markdown("**Behavioral Notes**")
                for n in as_list(notes):
                    st.markdown(f"- {n}")

        capa_raw = as_list(hs.get("capa_findings"))
        if capa_raw:
            namespaces = [str(x).split("/")[0] if "/" in str(x) else str(x) for x in capa_raw]
            bar_from_counts(dict(Counter(namespaces)), "CAPA — Namespace Count")

    with tab3:
        df_mitre = listdict(data.get("mitre_attack"))
        if not df_mitre.empty:
            st.dataframe(df_mitre, width='stretch')
            if "tactic" in df_mitre.columns:
                tcounts = df_mitre["tactic"].fillna("UNKNOWN").astype(str).value_counts().to_dict()
                bar_from_counts(tcounts, "Tactics (count)")

    with tab4:
        inv = data.get("ioc_inventory", {}) or {}
        def section(title, values):
            vals = as_list(values)
            if vals:
                st.subheader(title)
                st.dataframe(pd.DataFrame({"value": vals}), width='stretch')
        section("hashes", inv.get("hashes"))
        section("domains", inv.get("domains"))
        section("ips", inv.get("ips"))
        section("urls", inv.get("urls"))
        section("filenames_paths", inv.get("filenames_paths"))
        section("registry_keys", inv.get("registry_keys"))
        section("mutexes_named_pipes", inv.get("mutexes_named_pipes"))

    with tab5:
        st.json(data)
        
if st.button("Analyze", disabled=(file is None)):
    if not file:
        st.warning("Select a file first!")
    else:
        files = {"file": (file.name, file.getvalue())}
        data = {"hint": hint, "model": model}
        try:
            url = f"{api_base}/analyze/upload"
            with st.spinner("Analizing..."):
                r = requests.post(url, files=files, data=data)
            if r.status_code == 200:
                st.success("Analysis Finished!")
                try:
                    result = r.json()
                except Exception:
                    st.error("Answer was not a JSON")
                    st.text(r.text[:2000])
                else:
                    render_result(result)
            else:
                st.error(f"HTTP Error: {r.status_code}")
                st.text(r.text[:2000])
        except Exception as e:
            st.error(f"Failure calling the API: {e}")
