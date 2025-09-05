#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yara_ns_fullprint.py — YARA scan com namespaces por arquivo de regra e impressão direta.
- pip install yara-python [python-magic-bin OU python-magic]
- Regras: passe um ou mais -r (cada arquivo vira um namespace distinto; diretórios são varridos)
- Alvos: um ou mais caminhos (arquivos ou diretórios)
- Saída: texto "cru" (regra, namespace, tags, meta e strings que bateram)
- Exit code: 0 = nenhum match, 1 = houve match, 2+ = erros
"""

from __future__ import annotations
import os
import sys
import argparse
from typing import Dict, Iterable, List, Tuple, Optional

try:
    import yara  # type: ignore
except Exception as e:
    print(f"[erro] 'yara-python' não instalado: {e}", file=sys.stderr)
    sys.exit(2)

# --- opcional: filetype (magic) ---
def _get_filetype(path: str, include_type: bool) -> str:
    if not include_type:
        return ""
    try:
        import magic  # type: ignore
        m = magic.from_file(path)
        return (m.split()[0] if m else "") or ""
    except Exception:
        return ""

class FakeMatch(object):
    """Match "vazio" para indicar ausência de match (mantém fluxo consistente)."""
    rule = None
    namespace = None
    strings = None
    tags: List[str] = []
    meta: Dict[str, str] = {}

# ---------- Externals helpers ----------
def make_externals(
    filepath: str = "",
    filename: str = "",
    fileext: str = "",
    base_externals: Optional[Dict[str, str]] = None,
    include_type: bool = False,
) -> Dict[str, str]:
    d: Dict[str, str] = {}
    if base_externals:
        d.update(base_externals)

    if not filepath and filename:
        # se veio só filename, não tentar adivinhar diretório
        pass
    if not fileext:
        if filename:
            _, fileext = os.path.splitext(filename)
        elif filepath:
            _, fileext = os.path.splitext(filepath)
    if not filename and filepath:
        _, filename = os.path.split(filepath)

    ftype = _get_filetype(filepath, include_type) if filepath else ""
    d.update({"filepath": filepath, "filename": filename, "extension": fileext, "filetype": ftype})
    return d

# ---------- Regras ----------
def collect_rule_files(rule_inputs: List[str]) -> List[str]:
    """Expande diretórios e mantém arquivos .yar/.yara; retorna paths absolutos."""
    out: List[str] = []
    for ri in rule_inputs:
        rp = os.path.abspath(ri)
        if os.path.isdir(rp):
            for root, _, files in os.walk(rp):
                for fn in files:
                    if fn.lower().endswith((".yar", ".yara")):
                        out.append(os.path.join(root, fn))
        elif os.path.isfile(rp) and rp.lower().endswith((".yar", ".yara")):
            out.append(rp)
    # remove duplicatas mantendo ordem
    seen = set(); uniq: List[str] = []
    for p in out:
        if p not in seen:
            seen.add(p); uniq.append(p)
    return uniq

def compile_with_namespaces(rule_files: List[str], base_externals: Optional[Dict[str, str]], raise_on_warn: bool=False):
    """Compila cada arquivo de regra no seu próprio namespace (caminho absoluto)."""
    if not rule_files:
        raise RuntimeError("nenhuma regra .yar/.yara encontrada")
    filepaths_map: Dict[str, str] = {rf: rf for rf in rule_files}
    externals = make_externals(base_externals=base_externals)
    warnings: List[str] = []
    try:
        rules = yara.compile(filepaths=filepaths_map, externals=externals, error_on_warning=True)
        return warnings, rules
    except yara.WarningError as e:
        # recompila aceitando warnings e registra
        rules = yara.compile(filepaths=filepaths_map, externals=externals)
        warnings.append(str(e))
        if raise_on_warn:
            raise
        return warnings, rules

# ---------- Matching ----------
def iter_targets(paths: List[str]) -> Iterable[str]:
    for p in paths:
        ap = os.path.abspath(p)
        if os.path.isdir(ap):
            for root, _, files in os.walk(ap):
                for fn in files:
                    yield os.path.join(root, fn)
        elif os.path.isfile(ap):
            yield ap

def yara_matches(compiled, filepath: str, externals: Optional[Dict[str, str]]):
    try:
        if externals:
            ms = compiled.match(filepath, externals=externals)
        else:
            ms = compiled.match(filepath)
    except yara.Error as e:
        print(f"[erro] exception matching '{filepath}': {e}", file=sys.stderr)
        raise
    if not ms:
        yield FakeMatch(), filepath
    for m in ms:
        yield m, filepath

# ---------- CLI ----------
def parse_kv_list(values: List[str]) -> Dict[str, str]:
    """Converte ['k=v','a=b'] em dict; ignora itens malformados."""
    out: Dict[str, str] = {}
    for item in values or []:
        if "=" in item:
            k, v = item.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def main():
    ap = argparse.ArgumentParser(description="YARA scan com namespaces e print direto (biblioteca pura).")
    ap.add_argument("-r", "--rules", action="append", required=True,
                    help="Arquivo .yar/.yara ou diretório com regras (pode repetir -r múltiplas vezes).")
    ap.add_argument("-e", "--external", action="append", default=[],
                    help="Externals adicionais no formato chave=valor (pode repetir).")
    ap.add_argument("--include-type", action="store_true",
                    help="Incluir 'filetype' (usa python-magic se disponível).")
    ap.add_argument("--timeout", type=int, default=15, help="Timeout de match (s).")
    ap.add_argument("--no-strings", action="store_true", help="Não imprimir strings (somente nome da regra).")
    ap.add_argument("--raise-on-warn", action="store_true", help="Falhar se houver warnings de compilação.")
    ap.add_argument("targets", nargs="+", help="Arquivos/pastas para escanear.")
    args = ap.parse_args()

    # Coleta regras
    rule_files = collect_rule_files(args.rules)
    if not rule_files:
        print("[erro] nenhuma regra .yar/.yara encontrada nos paths fornecidos.", file=sys.stderr)
        sys.exit(3)

    # Externals base
    externals = parse_kv_list(args.external)

    # Compila
    try:
        warns, compiled = compile_with_namespaces(rule_files, externals, raise_on_warn=args.raise_on_warn)
    except Exception as e:
        print(f"[erro] falha ao compilar regras: {e}", file=sys.stderr)
        sys.exit(4)

    if warns:
        print("[aviso] warnings de compilação:")
        for w in warns:
            print(f"  - {w}")

    # Varre alvos
    any_match = False
    for fp in iter_targets(args.targets):
        # monta externals específicos do arquivo
        fname = os.path.basename(fp)
        ext = make_externals(filepath=fp, filename=fname, base_externals=externals, include_type=args.include_type)

        try:
            for m, f in yara_matches(compiled, fp, ext):
                if m.rule is None:
                    # no-match "fake"
                    print(f"\n[0] {f}")
                    print("    (sem matches)")
                    continue

                any_match = True
                ns = getattr(m, "namespace", "") or ""
                tags = list(getattr(m, "tags", []) or [])
                meta = dict(getattr(m, "meta", {}) or {})
                strings = list(getattr(m, "strings", []) or [])
                print(f"\n[+] {f}")
                print(f"    Regra: {m.rule}")
                if ns:
                    print(f"    Namespace: {ns}")
                if tags:
                    print(f"    Tags: {', '.join(tags)}")
                if meta:
                    print("    Meta:")
                    for k, v in meta.items():
                        print(f"      - {k}: {v}")

        except yara.Error as e:
            print(f"[erro] falha ao escanear '{fp}': {e}", file=sys.stderr)
            continue

    sys.exit(1 if any_match else 0)

if __name__ == "__main__":
    main()
