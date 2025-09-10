
import streamlit as st
import requests
from pathlib import Path
import io, os, json, hashlib
from typing import Any, Dict, List
import pandas as pd
from collections import Counter

st.set_page_config(page_title="MalOps Agent", layout="centered")
st.title("🔍 MalOps Agent — Upload & Analyze (Hybrid: Multi-Agente + Paralelo)")
st.caption("YARA, CAPA, IOCs e Threat Intel (VT, MalwareBazaar, ThreatFox, AbuseIPDB)")

API_BASE_DEFAULT = os.getenv("API_BASE", "http://localhost:8000")
api_base = st.text_input("API base URL", value=API_BASE_DEFAULT)
hint = st.text_input("Hint/Contexto (opcional)", value="")
model = st.text_input("Modelo LLM", value="gemini-2.0-flash")
file = st.file_uploader("Selecione o arquivo de amostra", type=None)

# Preview: file info + local hashes (pre-upload)
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

    # ---- Preview minimalista ----
    st.subheader("📄 Arquivo selecionado")
    st.markdown(f"{file.name}")

    st.write("")  # espaçamento
    st.markdown(f"**Tamanho:** {_human_size(len(b))}")
    st.markdown(f"**Nome:** {file.name}")
    st.markdown(f"**Extensão:** {Path(file.name).suffix or '—'}")

    st.write("")  # espaçamento
    st.subheader("🔐 Hashes")
    st.markdown(f"**MD5:** {hs['md5']}")
    st.markdown(f"**SHA1:** {hs['sha1']}")
    st.markdown(f"**SHA256:** {hs['sha256']}")

def render_result(result: Dict[str, Any]) -> None:
    # ---------- estilos (card + chips) ----------
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

    # ---------- coerção do JSON (lida com `raw` e ```json ... ```) ----------
    def _strip_code_fences(s: str) -> str:
        s = s.strip()
        if s.startswith("```"):
            nl = s.find("\n")
            if nl != -1: s = s[nl+1:]
        if s.endswith("```"): s = s[:-3]
        return s.strip()

    def _coerce(obj):
        if isinstance(obj, dict) and any(k in obj for k in ("summary","technical_analysis","mitre_attack","ioc_inventory")):
            return obj
        if isinstance(obj, dict):
            for k in ("raw","data","result","output","payload"):
                v = obj.get(k)
                if isinstance(v, dict):
                    c = _coerce(v)
                    if c: return c
                if isinstance(v, str):
                    try: return json.loads(_strip_code_fences(v))
                    except Exception: pass
        if isinstance(obj, str):
            try: return json.loads(_strip_code_fences(obj))
            except Exception: return {}
        return {}

    data = _coerce(result) or {}
    if not data:
        st.error("Não consegui interpretar a resposta da API.")
        st.json(result)
        return

    # ---------- helpers ----------
    def _as_list(x):
        if x is None: return []
        return x if isinstance(x, list) else [x]

    def _df_listdict(x) -> pd.DataFrame:
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

    def _bar_from_counts(counts: Dict[str,int], title: str):
        if not counts: return
        df = pd.DataFrame({"item": list(counts.keys()), "count": list(counts.values())})
        st.markdown(f"**{title}**")
        st.bar_chart(df.set_index("item").sort_index())

    # ---------- download ----------
    st.download_button(
        "⬇️ Baixar JSON",
        data=json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"),
        file_name="analysis.json",
        mime="application/json",
        use_container_width=True,
    )

    # ---------- abas ----------
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Sumário", "Técnico", "ATT&CK", "IOCs", "JSON"])

    # ========== SUMÁRIO ==========
    with tab1:
        summary = data.get("summary", {}) or {}
        # colunas 1–3–1 (famílias central, larga)
        c1, c2, c3 = st.columns([1, 3, 1])
        with c1:
            st.metric("Risco", summary.get("overall_risk_level", "-"))
        with c2:
            fam_list = _as_list(summary.get("most_likely_family_or_category"))
            chips = "".join(f'<span class="fam-chip">{str(f)}</span>' for f in fam_list) or "—"
            st.markdown(f"""
                <div class="fam-card">
                  <div class="fam-label">Família/Categoria</div>
                  <div class="fam-chips">{chips}</div>
                </div>
            """, unsafe_allow_html=True)
        with c3:
            st.metric("Confiança", summary.get("confidence", "-"))

        if summary.get("one_paragraph_summary"):
            st.write(summary["one_paragraph_summary"])

        df_inds = _df_listdict(data.get("key_indicators"))
        if not df_inds.empty:
            st.subheader("📌 Indicadores chave")
            st.dataframe(df_inds, use_container_width=True)

        for title, key in [
            ("🔧 Recomendações (prioritárias)", "recommendations_priority_ordered"),
            ("⚠️ Gaps de qualidade de dados", "data_quality_gaps"),
            ("➡️ Próximos passos recomendados", "recommended_next_steps"),
        ]:
            vals = _as_list(data.get(key))
            if vals:
                with st.expander(title, expanded=False):
                    for i, v in enumerate(vals, 1):
                        st.markdown(f"{i}. {v}" if title.startswith("🔧") else f"- {v}")

    # ========== TÉCNICO (linear, sem colunas) ==========
    with tab2:
        tech = data.get("technical_analysis", {}) or {}
        hs = tech.get("high_signal_features", {}) or {}

        def section_list(title, values):
            st.subheader(title)
            vals = _as_list(values)
            if vals:
                st.dataframe(pd.DataFrame({"value": [str(i) for i in vals]}), use_container_width=True)
            else:
                st.write("—")

        # um abaixo do outro:
        section_list("Imports", hs.get("imports"))
        section_list("Sections/Entropy/Anomalias", hs.get("sections_entropy_anomalies"))
        section_list("Strings de Interesse", hs.get("strings_of_interest"))
        section_list("Code signatures", hs.get("code_signatures"))
        section_list("YARA hits", hs.get("yara_hits"))
        section_list("CAPA findings", hs.get("capa_findings"))
        section_list("Advanced indicators", hs.get("advanced_indicators"))

        # tabelas estruturadas
        for t, k in [("Capacidades inferidas","capabilities"),
                     ("Evasão / Anti-análise","evasion_anti_analysis"),
                     ("Persistência","persistence")]:
            df = _df_listdict(tech.get(k))
            if not df.empty:
                st.subheader(t)
                st.dataframe(df, use_container_width=True)

        net = tech.get("networking_exfiltration", {})
        if isinstance(net, dict) and any(net.values()):
            st.subheader("Networking & Exfiltration")
            st.write(net)

        # Gráfico CAPA por namespace
        capa_raw = _as_list(hs.get("capa_findings"))
        if capa_raw:
            namespaces = [str(x).split("/")[0] if "/" in str(x) else str(x) for x in capa_raw]
            _bar_from_counts(dict(Counter(namespaces)), "CAPA — contagem por namespace")

    # ========== ATT&CK ==========
    with tab3:
        df_mitre = _df_listdict(data.get("mitre_attack"))
        if not df_mitre.empty:
            st.dataframe(df_mitre, use_container_width=True)
            if "tactic" in df_mitre.columns:
                tcounts = df_mitre["tactic"].fillna("UNKNOWN").astype(str).value_counts().to_dict()
                _bar_from_counts(tcounts, "Táticas (contagem)")

    # ========== IOCs ==========
    with tab4:
        inv = data.get("ioc_inventory", {}) or {}
        def _section(title, values):
            vals = _as_list(values)
            if vals:
                st.subheader(title)
                st.dataframe(pd.DataFrame({"value": vals}), use_container_width=True)
        _section("hashes", inv.get("hashes"))
        _section("domains", inv.get("domains"))
        _section("ips", inv.get("ips"))
        _section("urls", inv.get("urls"))
        _section("filenames_paths", inv.get("filenames_paths"))
        _section("registry_keys", inv.get("registry_keys"))
        _section("mutexes_named_pipes", inv.get("mutexes_named_pipes"))

    # ========== JSON ==========
    with tab5:
        st.json(data)
        
if st.button("Enviar e Analisar", disabled=(file is None)):
    if not file:
        st.warning("Selecione um arquivo primeiro.")
    else:
        files = {"file": (file.name, file.getvalue())}
        data = {"hint": hint, "model": model}
        try:
            url = f"{api_base}/analyze/upload"
            with st.spinner("Analisando..."):
                r = requests.post(url, files=files, data=data, timeout=120)
            if r.status_code == 200:
                st.success("Análise concluída")
                try:
                    result = r.json()
                except Exception:
                    st.error("Resposta não é JSON")
                    st.text(r.text[:2000])
                else:
                    render_result(result)
            else:
                st.error(f"Erro HTTP {r.status_code}")
                st.text(r.text[:2000])
        except Exception as e:
            st.error(f"Falha ao chamar API: {e}")
