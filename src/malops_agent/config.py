
import os
from dotenv import load_dotenv
load_dotenv()

class Settings:
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY","")
    YARA_RULES_DIR: str = os.getenv("YARA_RULES_DIR","rules")
    CAPA_RULES_DIR: str = os.getenv("CAPA_RULES_DIR","rules")
    CAPA_SIGNATURES_DIR: str = os.getenv("CAPA_SIGNATURES_DIR","").strip()

settings = Settings()
