import os
from dotenv import load_dotenv

ENV_FILE = "../.env"

def load_env() -> None:
    """ Carrega o .env UMA vez, da raiz do projeto. """
    load_dotenv(dotenv_path=ENV_FILE, override=False)

def get_settings():
    """ Retorna configurações em um dicionário simples. """
    load_env()
    return {
        "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
        "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY", ""),
        "VT_API_KEY": os.getenv("VT_API_KEY", ""),
        "MALWAREBAZAAR_API_KEY": os.getenv("MALWAREBAZAAR_API_KEY", ""),
        "ABUSEIPDB_KEY": os.getenv("ABUSEIPDB_KEY", ""),
        "YARA_RULES_DIR": os.getenv("YARA_RULES_DIR", ""),
        "CAPA_RULES_DIR": os.getenv("CAPA_RULES_DIR", ""),
    }