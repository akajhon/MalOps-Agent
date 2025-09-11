from __future__ import annotations
from pathlib import Path
from typing import Optional, Union
from .graph import build_graph

def export_graph_png(output_path: Optional[Union[str, Path]] = None) -> Path:
    """Compile the agent graph and write a Mermaid-rendered PNG to disk."""
    app = build_graph()
    png_bytes = app.get_graph().draw_mermaid_png()

    if output_path is None:
        output_path = Path(__file__).resolve().parents[2] / "logs" / "graph.png"

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(png_bytes)
    return out


def export_graph_mermaid(output_path: Optional[Union[str, Path]] = None) -> Path:
    """Compile the agent graph and write the Mermaid definition (.mmd) to disk."""
    app = build_graph()
    mermaid = app.get_graph().draw_mermaid()

    if output_path is None:
        output_path = Path(__file__).resolve().parents[2] / "logs" / "graph.mmd"

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(mermaid, encoding="utf-8")
    return out
