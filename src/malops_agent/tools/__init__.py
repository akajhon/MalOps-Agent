from .file_hashes import compute_hashes
from .strings import extract_strings
from .iocs import extract_iocs
from .pe_info import pe_basic_info
from .entropy import file_head_entropy
from .yara_tool import yara_scan
from .capa_tool import capa_scan

# Coleção genérica (alguns fluxos usam itens individualmente; manter tudo aqui ajuda)
TOOLS = [
    compute_hashes,
    extract_strings,
    extract_iocs,
    pe_basic_info,
    file_head_entropy,
    yara_scan,
    capa_scan
]


__all__ = ["TOOLS","compute_hashes","extract_strings","extract_iocs","pe_basic_info","file_head_entropy","yara_scan","capa_scan"]
