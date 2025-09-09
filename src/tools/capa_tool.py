#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import annotations
import os
import json
import collections
from typing import Any, Iterable, List, Optional, Set
import logging
from pathlib import Path
from langchain_core.tools import tool
import capa.main
import capa.rules
import capa.engine
import capa.loader
import capa.features
import capa.render.json
import capa.render.utils as rutils
import capa.render.default
import capa.capabilities.common
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.features.common import OS_AUTO, FORMAT_AUTO
from ..logging_config import log_tool
log = logging.getLogger("tools.capa")

# --- Carrega .env do projeto (idempotente)
try:
    from ..config import load_env
    load_env()
except Exception:
    pass

# --- Imports CAPA


# =========================
# Render helpers (compatíveis)
# =========================
def _render_meta(doc: rd.ResultDocument, result: dict) -> None:
    result["md5"] = doc.meta.sample.md5
    result["sha1"] = doc.meta.sample.sha1
    result["sha256"] = doc.meta.sample.sha256
    result["path"] = doc.meta.sample.path

def _find_subrule_matches(doc: rd.ResultDocument) -> Set[str]:
    """
    Coleta nomes de regras que entraram como submatches, para suprimir duplicatas
    excessivamente específicas na listagem final.
    """
    matches: Set[str] = set()

    def rec(node: rd.Match) -> None:
        if not node.success:
            return
        if isinstance(node.node, rd.StatementNode):
            for child in node.children:
                rec(child)
        elif isinstance(node.node, rd.FeatureNode):
            if isinstance(node.node.feature, frzf.MatchFeature):
                matches.add(node.node.feature.match)

    for rule in rutils.capability_rules(doc):
        for _, node in rule.matches:
            rec(node)

    return matches

def _render_capabilities(doc: rd.ResultDocument, result: dict) -> None:
    """
    Produz um dicionário CAPABILITY com chaves = namespaces e valores = lista de capacidades.
    Quando uma regra tem múltiplos matches, anexa " (N matches)" ao nome.
    """
    subrule_matches = _find_subrule_matches(doc)
    result["CAPABILITY"] = {}
    for rule in rutils.capability_rules(doc):
        if rule.meta.name in subrule_matches:
            continue
        count = len(rule.matches)
        capability = rule.meta.name if count == 1 else f"{rule.meta.name} ({count} matches)"
        result["CAPABILITY"].setdefault(rule.meta.namespace, [])
        result["CAPABILITY"][rule.meta.namespace].append(capability)

def _render_attack(doc: rd.ResultDocument, result: dict) -> None:
    """
    Gera estrutura ATTCK (mesma grafia usada pelo renderer do capa) agrupada por tática.
    """
    result["ATTCK"] = {}
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule.meta.attack:
            continue
        for attack in rule.meta.attack:
            tactics[attack.tactic].add((attack.technique, attack.subtechnique, attack.id))

    for tactic, techniques in sorted(tactics.items()):
        rows = []
        for technique, subtechnique, tid in sorted(techniques):
            rows.append(f"{technique} {tid}" if subtechnique is None else f"{technique}::{subtechnique} {tid}")
        result["ATTCK"].setdefault(tactic.upper(), rows)

def _render_mbc(doc: rd.ResultDocument, result: dict) -> None:
    """
    Gera estrutura MBC agrupada por objective.
    """
    result["MBC"] = {}
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule.meta.mbc:
            continue
        for mbc in rule.meta.mbc:
            objectives[mbc.objective].add((mbc.behavior, mbc.method, mbc.id))

    for objective, behaviors in sorted(objectives.items()):
        rows = []
        for behavior, method, mid in sorted(behaviors):
            rows.append(f"{behavior} [{mid}]" if method is None else f"{behavior}::{method} [{mid}]")
        result["MBC"].setdefault(objective.upper(), rows)

def _render_dictionary(doc: rd.ResultDocument) -> dict:
    """
    Replica a composição do dicionário consolidando meta, ATT&CK, MBC e Capabilities.
    """
    result: dict[str, Any] = {}
    _render_meta(doc, result)
    _render_attack(doc, result)
    _render_mbc(doc, result)
    _render_capabilities(doc, result)
    return result

# =========================
# Núcleo: execução do CAPA
# =========================
def _split_paths(value: Optional[str]) -> List[Path]:
    if not value:
        return []
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return [Path(p) for p in parts]

def _resolve_rules_path() -> Path:
    env_rules = os.getenv("CAPA_RULES_DIR", "").strip()
    if env_rules:
        p = Path(env_rules)
        if not p.exists():
            raise FileNotFoundError(f"CAPA_RULES_DIR não encontrado: {p}")
        return p
    # fallback para a instalação padrão do capa
    return capa.main.get_default_root() / "rules"

def _resolve_signatures_paths() -> List[Path]:
    env_sigs = os.getenv("CAPA_SIGNATURES_DIR", "").strip()
    paths = _split_paths(env_sigs)
    # não falha se vazio; assinaturas são opcionais
    for p in paths:
        if not p.exists():
            raise FileNotFoundError(f"Diretório de assinaturas não encontrado: {p}")
    return paths

def _build_result_document(
    rules_path: Path,
    input_file: Path,
    signature_paths: Optional[List[Path]] = None,
) -> tuple[rd.ResultDocument, capa.rules.RuleSet, capa.capabilities.common.CapabilitiesResult, Any]:
    """
    Executa extração, matching e empacota metadata/layout, retornando o ResultDocument
    e estruturas necessárias para diferentes renderers.
    """
    # Carrega regras
    rules = capa.rules.get_rules([rules_path])

    # Extrator (Vivisect) + assinaturas (opcional)
    signature_paths = signature_paths or []
    extractor = capa.loader.get_extractor(
        input_file,
        FORMAT_AUTO,
        OS_AUTO,
        capa.main.BACKEND_VIV,
        signature_paths,
        should_save_workspace=False,
        disable_progress=True,
    )

    # Matching de capacidades
    capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)

    # Metadata e layout (necessários aos renderers)
    meta = capa.loader.collect_metadata([], input_file, FORMAT_AUTO, OS_AUTO, [rules_path], extractor, capabilities)
    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

    # Document
    doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
    return doc, rules, capabilities, meta

@tool
@log_tool("capa_scan")
def capa_scan(
    path: str,
    output_format: str = "summary",
) -> Any:
    """
    Executa o CAPA sobre `path` usando regras/assinaturas do .env e retorna a saída no formato solicitado.

    Args:
      path: caminho do arquivo PE/ELF/etc. a analisar
      output_format: "json" (default), "dictionary" ou "texttable"

    Returns:
      - "json": str JSON idêntico ao capa.render.json.render
      - "dictionary": dict com META/ATTCK/MBC/CAPABILITY
      - "texttable": str tabela humana (mesmo renderer default do capa)

    Raises:
      FileNotFoundError, ValueError, Exception específicos do fluxo
    """
    log.info("CAPA: scanning path=%s format=%s", path, output_format)
    input_file = Path(path)
    if not input_file.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {input_file}")

    rules_path = _resolve_rules_path()
    sigs_paths = _resolve_signatures_paths()

    doc, rules, capabilities, meta = _build_result_document(rules_path, input_file, sigs_paths)

    if output_format == "json":
        result = json.loads(capa.render.json.render(meta, rules, capabilities.matches))
        log.info("CAPA: completed (full json) capabilities=%d", sum(len(v) for v in result.get("CAPABILITY", {}).values()) if isinstance(result, dict) else -1)
        return result

    # Build dictionary and optionally trim for summary
    d = _render_dictionary(doc)
    if output_format in ("dictionary", "dict"):
        log.info("CAPA: completed (dict) capabilities=%d", sum(len(v) for v in d.get("CAPABILITY", {}).values()))
        return d

    # summary: keep only sha256 + pruned ATTCK/MBC/CAPABILITY lists
    cap = {k: v[:12] for k, v in (d.get("CAPABILITY") or {}).items()}
    att = {k: v[:10] for k, v in (d.get("ATTCK") or {}).items()}
    mbc = {k: v[:10] for k, v in (d.get("MBC") or {}).items()}
    out = {
        "sha256": d.get("sha256"),
        "CAPABILITY": cap,
        "ATTCK": att,
        "MBC": mbc,
    }
    log.info("CAPA: completed (summary) caps_namespaces=%d", len(cap))
    return out

# Note: this module is intended for use as a tool; not a standalone script.
