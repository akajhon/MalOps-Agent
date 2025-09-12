import os
from pathlib import Path
from dotenv import load_dotenv

ENV_FILE = str((Path(__file__).resolve().parent.parent / ".env").resolve())

def load_env():
    """Load .env once from the project root."""
    load_dotenv(dotenv_path=ENV_FILE, override=True)

def get_settings():
    """Return settings as a simple dictionary."""
    load_env()
    def _int_env(name: str, default: int) -> int:
        val = os.getenv(name, str(default))
        try:
            return int(val)
        except Exception:
            return default

    return {
        "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
        "DB_PATH": os.getenv("DB_PATH", ""),
        "GEMINI_API_KEY": os.getenv("GEMINI_API_KEY", ""),
        "VT_API_KEY": os.getenv("VT_API_KEY", ""),
        "ABUSE_API_KEY": os.getenv("ABUSE_API_KEY", ""),
        "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
        "HA_API_KEY": os.getenv("HA_API_KEY", ""),
        "YARA_RULES_DIR": os.getenv("YARA_RULES_DIR", ""),
        "CAPA_RULES_DIR": os.getenv("CAPA_RULES_DIR", ""),
        "CAPA_SIGNATURES_DIR": os.getenv("CAPA_SIGNATURES_DIR", ""),
        "DEFAULT_TIMEOUT": _int_env("DEFAULT_TIMEOUT", 12),
        "SUPERVISOR_DUMP_DIR": os.getenv("SUPERVISOR_DUMP_DIR", ""),
    }
