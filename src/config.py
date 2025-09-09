import os
from pathlib import Path
from dotenv import load_dotenv

# Resolve project-level .env regardless of CWD
ENV_FILE = str((Path(__file__).resolve().parent.parent / ".env").resolve())

def load_env() -> None:
    """Load .env once from the project root."""
    load_dotenv(dotenv_path=ENV_FILE, override=False)

def get_settings():
    """Return settings as a simple dictionary."""
    load_env()
    return {
        "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
        "DB_PATH": os.getenv("DB_PATH", str((Path(__file__).resolve().parent.parent / "data" / "analyses.db").resolve())),
        "GEMINI_API_KEY": os.getenv("GEMINI_API_KEY", ""),
        "VT_API_KEY": os.getenv("VT_API_KEY", ""),
        "ABUSE_API_KEY": os.getenv("ABUSE_API_KEY", ""),
        "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
        "HA_API_KEY": os.getenv("HA_API_KEY", ""),
        "YARA_RULES_DIR": os.getenv("YARA_RULES_DIR", ""),
        "CAPA_RULES_DIR": os.getenv("CAPA_RULES_DIR", ""),
        "CAPA_SIGNATURES_DIR": os.getenv("CAPA_SIGNATURES_DIR", ""),
    }
