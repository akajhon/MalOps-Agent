
import streamlit as st
import requests

st.set_page_config(page_title="MalOps Agent", layout="centered")
st.title("🔍 MalOps Agent — Upload & Analyze (Hybrid: Multi-Agente + Paralelo)")
st.caption("YARA, CAPA, IOCs e Threat Intel (VT, MalwareBazaar, ThreatFox, AbuseIPDB)")

api_base = st.text_input("API base URL", value="http://localhost:8000")
hint = st.text_input("Hint/Contexto (opcional)", value="")
model = st.text_input("Modelo LLM", value="gemini-2.0-flash")
file = st.file_uploader("Selecione o arquivo de amostra", type=None)

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
                st.json(r.json())
            else:
                st.error(f"Erro HTTP {r.status_code}")
                st.text(r.text[:2000])
        except Exception as e:
            st.error(f"Falha ao chamar API: {e}")
