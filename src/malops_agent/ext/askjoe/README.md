
# AskJOE integration notes

Os scripts AskJOE originais usam PyGhidra/Ghidra e um pacote `AskJOE.*`. Para portabilidade, criamos Tools equivalentes:
- `askjoe_ai_triage` — agrega Tools locais (hashes, entropia, PE, IOCs, YARA, CAPA).
- `askjoe_capa_summary` — resumo do CAPA.
- `askjoe_threat_intel` — esqueleto para TI (plugar VT/MalwareBazaar/AbuseIPDB/ThreatFox).

Coloque os scripts aqui se quiser acoplar via subprocess ou adaptar a API deles.
