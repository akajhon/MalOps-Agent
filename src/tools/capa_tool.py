from __future__ import annotations
import json, collections, logging
import capa.main
import capa.rules
import capa.loader
import capa.render.json
import capa.render.utils as rutils
import capa.capabilities.common
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.features.common import OS_AUTO, FORMAT_AUTO
from typing import Any, List, Optional, Set
from pathlib import Path
from langchain_core.tools import tool
from ..logging_config import log_tool
from ..config import get_settings

log = logging.getLogger("tools.capa")

CAPA_RULES_DIR = get_settings().get("CAPA_RULES_DIR", "")
CAPA_SIGNATURES_DIR = get_settings().get("CAPA_SIGNATURES_DIR", "")

def silence_vivisect_logging() -> None:
    """Reduce noise from vivisect/viv-utils/envi by lowering their logger levels and preventing propagation."""
    for name in ("vivisect", "viv_utils", "viv", "capa.loader.viv", "envi", "envi.codeflow"):
        try:
            lg = logging.getLogger(name)
            lg.setLevel(logging.ERROR)
            lg.propagate = False
            has_null = any(isinstance(h, logging.NullHandler) for h in lg.handlers)
            if not has_null:
                lg.addHandler(logging.NullHandler())
        except Exception:
            pass

def render_meta(doc: rd.ResultDocument, result: dict) -> None:
    result["md5"] = doc.meta.sample.md5
    result["sha1"] = doc.meta.sample.sha1
    result["sha256"] = doc.meta.sample.sha256
    result["path"] = doc.meta.sample.path

def find_subrule_matches(doc: rd.ResultDocument) -> Set[str]:
    """Colects Submatches rule names"""
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

def render_capabilities(doc: rd.ResultDocument, result: dict) -> None:
    """Builds a CAPABILITY dictionary with keys = namespaces and values = a list of capabilities."""
    subrule_matches = find_subrule_matches(doc)
    result["CAPABILITY"] = {}
    for rule in rutils.capability_rules(doc):
        if rule.meta.name in subrule_matches:
            continue
        count = len(rule.matches)
        capability = rule.meta.name if count == 1 else f"{rule.meta.name} ({count} matches)"
        result["CAPABILITY"].setdefault(rule.meta.namespace, [])
        result["CAPABILITY"][rule.meta.namespace].append(capability)

def render_attack(doc: rd.ResultDocument, result: dict) -> None:
    """Generates ATT&CK structure grouped by tactic"""
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

def render_mbc(doc: rd.ResultDocument, result: dict) -> None:
    """Generates MBC Structure"""
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

def render_dictionary(doc: rd.ResultDocument) -> dict:
    """Consolidates the final dictionary with meta, ATT&CK, MBC and Capabilities."""
    result: dict[str, Any] = {}
    render_meta(doc, result)
    render_attack(doc, result)
    render_mbc(doc, result)
    render_capabilities(doc, result)
    return result

# CAPA Execution

def split_paths(value: Optional[str]) -> List[Path]:
    if not value:
        return []
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return [Path(p) for p in parts]

def get_rules_path() -> Path:
    env_rules = CAPA_RULES_DIR.strip()
    if env_rules:
        p = Path(env_rules)
        if not p.exists():
            raise FileNotFoundError(f"CAPA Rule Directory not found: {p}")
        return p
    return capa.main.get_default_root() / "rules"

def get_signatures_path() -> List[Path]:
    env_sigs = CAPA_SIGNATURES_DIR.strip()
    paths = split_paths(env_sigs)
    for p in paths:
        if not p.exists():
            raise FileNotFoundError(f"CAPA Signature Directory not found: {p}")
    return paths

def build_result_document(
    rules_path: Path,
    input_file: Path,
    signature_paths: Optional[List[Path]] = None,
) -> tuple[rd.ResultDocument, capa.rules.RuleSet, capa.capabilities.common.CapabilitiesResult, Any]:
    """
    Performs extraction and matching, packages metadata/layout.
    Returns the ResultDocument and the structures needed for different renderers.
    """
    silence_vivisect_logging()
    rules = capa.rules.get_rules([rules_path])
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

    capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)
    meta = capa.loader.collect_metadata([], input_file, FORMAT_AUTO, OS_AUTO, [rules_path], extractor, capabilities)
    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)
    doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
    return doc, rules, capabilities, meta

@tool
@log_tool("capa_scan")
def capa_scan(
        path: str,
        output_format: str = "summary",
        ) -> Any:
    """Executes a CAPA Scan and returns a summarized JSON"""
    log.info("CAPA: scanning path=%s format=%s", path, output_format)
    input_file = Path(path)
    if not input_file.exists():
        raise FileNotFoundError(f"File not found: {input_file}")

    rules_path = get_rules_path()
    sigs_paths = get_signatures_path()

    doc, rules, capabilities, meta = build_result_document(rules_path, input_file, sigs_paths)

    if output_format == "json":
        result = json.loads(capa.render.json.render(meta, rules, capabilities.matches))
        log.info("CAPA: completed (full json) capabilities=%d", sum(len(v) for v in result.get("CAPABILITY", {}).values()) if isinstance(result, dict) else -1)
        return result

    d = render_dictionary(doc)
    if output_format in ("dictionary", "dict"):
        log.info("CAPA: completed (dict) capabilities=%d", sum(len(v) for v in d.get("CAPABILITY", {}).values()))
        return d

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
