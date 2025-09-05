# Agente de análise estática: usa LLM + tools (hashes, PE, entropia, IOCs, YARA, CAPA)
import os, json
from langchain_google_genai import ChatGoogleGenerativeAI as ChatLLM
from langchain_core.messages import SystemMessage, HumanMessage

# importa suas ferramentas locais
from ..tools import compute_hashes, pe_basic_info, file_head_entropy, extract_iocs, yara_scan, capa_scan

STATIC_TOOLS = [compute_hashes, pe_basic_info, file_head_entropy, extract_iocs, yara_scan, capa_scan]

def _static_prompt() -> str:
    # prompt curto e direto
    return "Faça análise estática (hashes, PE, entropia, IOCs, YARA, CAPA) e responda um JSON resumido."

def run_static_agent(file_path: str, hint: str = "", model: str = "gemini-2.0-flash") -> dict:
    # LLM com tools
    llm = ChatLLM(model=model, temperature=0, google_api_key=os.getenv("GEMINI_API_KEY"))
    llm_tools = llm.bind_tools(STATIC_TOOLS)

    msgs = [
        SystemMessage(content=_static_prompt()),
        HumanMessage(content=f"Target: {file_path}\nHint: {hint}")
    ]
    ai = llm_tools.invoke(msgs)
    # tenta interpretar como JSON
    try:
        return json.loads(ai.content)
    except Exception:
        return {"raw": ai.content}
