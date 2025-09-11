from typing import TypedDict

class State(TypedDict, total=False):
    file_path: str
    hint: str
    model: str
    hashes: dict
    sha256: str
    iocs: dict
    static_summary: dict
    ti_vt: dict
    ti_mb: dict
    ti_ha: dict
    ti_otx: dict
    threat_intel: dict
    final: dict