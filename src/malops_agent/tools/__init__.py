
from .file_hashes import compute_hashes
from .strings import extract_strings
from .iocs import extract_iocs
from .pe_info import pe_basic_info
from .entropy import file_head_entropy
from .yara_tool import yara_scan
from .capa_tool import capa_scan
from .askjoe_ai_triage import askjoe_ai_triage
from .askjoe_capa_tool import askjoe_capa_summary
from .askjoe_threatintel_tool import askjoe_threat_intel

TOOLS = [compute_hashes, extract_strings, extract_iocs, pe_basic_info, file_head_entropy, yara_scan, capa_scan,
         askjoe_ai_triage, askjoe_capa_summary, askjoe_threat_intel]

__all__ = ["TOOLS",
           "compute_hashes","extract_strings","extract_iocs","pe_basic_info","file_head_entropy","yara_scan","capa_scan",
           "askjoe_ai_triage","askjoe_capa_summary","askjoe_threat_intel"]
