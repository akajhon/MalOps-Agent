
from langchain_core.tools import tool
import os, json, subprocess
from ..config import settings
from ..logging_config import log_tool
from typing import Dict, Any, Optional
import os, logging
import argparse
import capa
import capa.main
import capa.loader
import capa.capabilities.common
import capa.render.result_document as rd
def _exists(p:str)->bool: return os.path.isfile(p)

@tool
@log_tool("capa_scan")
def capa_scan(path: str, rules_dir: Optional[str] = None, backend: str = "auto", os_hint: str = "auto") -> Dict[str, Any]:
    """Run CAPA using flare-capa and return full ResultDocument."""
    if not os.path.isfile(path):
        return {"error": f"file not found: {path}"}
    parser = argparse.ArgumentParser(description="detect capabilities in programs.")
    capa.main.install_common_args(parser, wanted={"rules", "format", "os", "backend", "input_file"})
    argv = ["--format", "json", "--backend", backend, "--os", os_hint, path]
    if rules_dir: argv = ["--rules", rules_dir] + argv
    try:
        args = parser.parse_args(args=argv)
        capa.main.handle_common_args(args)
        capa.main.ensure_input_exists_from_cli(args)
        input_format = capa.main.get_input_format_from_cli(args)
        rules = capa.main.get_rules_from_cli(args)
        backend_obj = capa.main.get_backend_from_cli(args, input_format)
        sample_path = capa.main.get_sample_path_from_cli(args, backend_obj)
        os_detected = "unknown" if sample_path is None else capa.loader.get_os(sample_path)
        extractor = capa.main.get_extractor_from_cli(args, input_format, backend_obj)
        caps = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)
        meta = capa.loader.collect_metadata(argv, args.input_file, "json", os_detected, [], extractor, caps)
        meta.analysis.layout = capa.loader.compute_layout(rules, extractor, caps.matches)
        doc = rd.ResultDocument.from_capa(meta, rules, caps.matches)
        raw = doc.model_dump()
        return {"path": os.path.abspath(path), "result": raw}
    except Exception as e:
        return {"error": f"capa library error: {e}"}
