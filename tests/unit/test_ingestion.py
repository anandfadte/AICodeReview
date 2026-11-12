"""Unit tests for Phase 1 ingestion: git diff, Python AST graph, and Node-RED parser."""

from __future__ import annotations

from pathlib import Path

from backend.reviewer.ingestion.flow_parser import parse_flow_file
from backend.reviewer.ingestion.github_diff import ingest_local_repo, is_docs_only_change, parse_unified_diff
from backend.reviewer.ingestion.graph import CodeGraph


def test_parse_unified_diff_extracts_file_lines() -> None:
    diff = (
        "diff --git a/api.py b/api.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/api.py\n"
        "+++ b/api.py\n"
        "@@ -5,2 +5,4 @@ def setpoint():\n"
        "     x = 1\n"
        "+    plc.write_register('SPINDLE_SPEED', speed)\n"
        "+    return {'ok': True}\n"
    )
    res = parse_unified_diff(diff)
    assert len(res.changed_files) == 1
    assert res.changed_files[0].file_lines == ["api.py:6", "api.py:7"]
    assert res.is_docs_only is False


def test_docs_only_detection() -> None:
    assert is_docs_only_change(["README.md", "docs/notes.txt"]) is True
    assert is_docs_only_change(["README.md", "backend/app.py"]) is False


def test_ingest_sample_repo() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    diff_res = ingest_local_repo(repo_root / "sample_repo")
    assert {"api.py", "ask.py", "flows.json", "genealogy.py", "oee.py", "secret.py"}.issubset(set(diff_res.file_paths()))


def test_flow_parser_builds_graph_edges() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    res = parse_flow_file(repo_root / "sample_repo" / "flows.json")
    assert res.findings == []
    assert len(res.write_edges) == 2
    safe_edge, unsafe_edge = res.write_edges
    assert safe_edge.plc_tag == "SPINDLE_SPEED"
    assert safe_edge.path_node_ids == ["n1", "n2", "n3"]
    assert safe_edge.downstream_node_ids == ["n4"]
    assert unsafe_edge.plc_tag == "FEED_RATE"


def test_graph_blast_radius_filters_to_neighbors() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    graph = CodeGraph.build(repo_root / "sample_repo")
    br = graph.explain_blast_radius(["flows.json"])
    assert "flows.json" in br.blast_radius_files
    assert "api.py" in br.blast_radius_files
    assert "ask.py" not in br.blast_radius_files
    assert "secret.py" not in br.blast_radius_files
    assert br.file_ratio < 0.5
