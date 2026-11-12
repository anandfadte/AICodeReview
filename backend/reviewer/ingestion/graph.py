"""Python AST + Node-RED call & data-flow graph builder and blast-radius filter.

Uses pure Python `ast` + `json` (no external native parser binaries required).
Limits LLM context to changed files + 1-hop callers/callees + files sharing
DB tables, MQTT topics, or PLC tags (~35% target per Spec P9).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from backend.reviewer.ingestion.flow_parser import is_flow_candidate, parse_flow_file
from backend.reviewer.ingestion.github_diff import SKIP_DIRS

_SQL_TABLE_RE = re.compile(r"\b(?:FROM|INTO|UPDATE|JOIN)\s+([a-zA-Z_][a-zA-Z0-9_]*)", re.I)
_MQTT_TOPIC_RE = re.compile(r"^[a-zA-Z0-9_+.#-]+/[a-zA-Z0-9_+.#/-]+$")
_ROUTE_ENTITY_RE = re.compile(r"@?(?:app|router)\.\w+\(\s*[\"']([^\"']+)[\"']")
_KNOWN_PLC_TAGS = {"SPINDLE_SPEED", "FEED_RATE", "COOLANT_ON", "CLAMP_PRESSURE", "OVEN_TEMP", "CONVEYOR_SPEED"}
_DB_OBJ_CALL_RE = re.compile(
    r"\b(audit_log|db|session|orders|parts|lots|genealogy|downtime)\.(insert|save|query|execute|add|commit|update)\b",
    re.I,
)


@dataclass
class FunctionSymbol:
    file: str
    name: str
    start_line: int
    end_line: int
    calls: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)


@dataclass
class BlastRadiusReport:
    changed_files: list[str]
    blast_radius_files: list[str]
    one_hop_callers: list[str]
    one_hop_callees: list[str]
    shared_data_neighbors: dict[str, list[str]]
    total_files: int
    total_loc: int
    selected_loc: int

    @property
    def file_ratio(self) -> float:
        return len(self.blast_radius_files) / max(1, self.total_files)

    @property
    def loc_ratio(self) -> float:
        return self.selected_loc / max(1, self.total_loc)


class CodeGraph:
    """Repository call graph + data-flow graph built with Python ast and flow_parser."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self.files: list[str] = []
        self.loc_by_file: dict[str, int] = {}
        self.functions_by_file: dict[str, list[FunctionSymbol]] = defaultdict(list)
        self.defs_to_files: dict[str, set[str]] = defaultdict(set)
        self.call_edges: dict[str, set[str]] = defaultdict(set)
        self.rev_call_edges: dict[str, set[str]] = defaultdict(set)
        self.resources_by_file: dict[str, set[str]] = defaultdict(set)
        self.files_by_resource: dict[str, set[str]] = defaultdict(set)

    def _normalize(self, file_path: str | Path) -> str:
        p = Path(file_path)
        if p.is_absolute():
            try:
                return p.resolve().relative_to(self.repo_root).as_posix()
            except ValueError:
                return p.as_posix()
        rel = p.as_posix().lstrip("./")
        if rel in self.files:
            return rel
        for candidate in self.files:
            if candidate == rel or candidate.endswith(f"/{rel}") or Path(candidate).name == Path(rel).name:
                return candidate
        return rel

    @classmethod
    def build(cls, repo_root: str | Path) -> "CodeGraph":
        root = Path(repo_root).resolve()
        graph = cls(root)
        if not root.exists():
            raise FileNotFoundError(f"Repository path not found: {repo_root}")

        all_paths = sorted(
            p for p in root.rglob("*")
            if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(root).parts)
        )
        for p in all_paths:
            if p.suffix.lower() not in {".py", ".json", ".ts", ".tsx", ".js", ".jsx", ".sql"}:
                continue
            rel = p.relative_to(root).as_posix()
            graph.files.append(rel)
            try:
                text = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = ""
            graph.loc_by_file[rel] = max(1, len(text.splitlines()))

            if p.suffix.lower() == ".py":
                graph._parse_python_ast(rel, text)
            elif p.suffix.lower() == ".json":
                graph._parse_json_flow(rel, p, text)

        for src_file, funcs in graph.functions_by_file.items():
            for fn in funcs:
                for callee_name in fn.calls:
                    base_name = callee_name.split(".")[-1]
                    for dst_file in graph.defs_to_files.get(base_name, ()):
                        if dst_file != src_file:
                            graph.call_edges[src_file].add(dst_file)
                            graph.rev_call_edges[dst_file].add(src_file)

        for src_file in graph.files:
            if not src_file.endswith(".py"):
                continue
            try:
                src_text = (root / src_file).read_text(encoding="utf-8")
            except Exception:
                continue
            for other in graph.files:
                if other == src_file or not other.endswith(".py"):
                    continue
                mod_name = Path(other).stem
                if re.search(rf"\b(?:from|import)\s+(?:[\w.]*\.)?{re.escape(mod_name)}\b", src_text):
                    graph.call_edges[src_file].add(other)
                    graph.rev_call_edges[other].add(src_file)

        return graph

    def _add_resource(self, rel_file: str, resource: str) -> None:
        self.resources_by_file[rel_file].add(resource)
        self.files_by_resource[resource].add(rel_file)

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = CodeGraph._call_name(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        return ""

    def _parse_python_ast(self, rel_file: str, text: str) -> None:
        try:
            tree = ast.parse(text, filename=rel_file)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls = [
                    self._call_name(sub.func)
                    for sub in ast.walk(node)
                    if isinstance(sub, ast.Call)
                ]
                calls = [c for c in calls if c]
                decs = [ast.get_source_segment(text, d) or "" for d in node.decorator_list]
                sym = FunctionSymbol(
                    file=rel_file,
                    name=node.name,
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    calls=calls,
                    decorators=decs,
                )
                self.functions_by_file[rel_file].append(sym)
                self.defs_to_files[node.name].add(rel_file)

                for dec in decs:
                    m_route = _ROUTE_ENTITY_RE.search(dec)
                    if m_route:
                        route = m_route.group(1).lower()
                        for seg in [s for s in route.split("/") if s and not s.startswith("{")]:
                            if seg in {"order", "orders", "oee", "genealogy", "part", "parts", "setpoint", "downtime"}:
                                self._add_resource(rel_file, f"domain:{seg.rstrip('s') if seg != 'oee' else 'oee'}")
                for key in ("oee", "genealogy", "setpoint", "order", "downtime"):
                    if key in node.name.lower():
                        self._add_resource(rel_file, f"domain:{key}")

            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                raw = node.value
                if raw in _KNOWN_PLC_TAGS:
                    self._add_resource(rel_file, f"plc:{raw}")
                elif _MQTT_TOPIC_RE.match(raw) and not raw.startswith("/"):
                    if any(seg in raw.lower() for seg in ("plant", "line", "machine", "telemetry", "setpoint", "cmd")):
                        self._add_resource(rel_file, f"mqtt:{raw}")
                        if "setpoint" in raw.lower():
                            self._add_resource(rel_file, "domain:setpoint")
                for m in _SQL_TABLE_RE.finditer(raw):
                    self._add_resource(rel_file, f"db:{m.group(1).lower()}")

        for m in _DB_OBJ_CALL_RE.finditer(text):
            self._add_resource(rel_file, f"db:{m.group(1).lower()}")

    def _parse_json_flow(self, rel_file: str, abs_path: Path, text: str) -> None:
        try:
            data = json.loads(text)
        except Exception:
            data = None

        if is_flow_candidate(abs_path, data):
            res = parse_flow_file(abs_path)
            for edge in res.write_edges:
                if edge.plc_tag:
                    self._add_resource(rel_file, f"plc:{edge.plc_tag}")
                if edge.mqtt_topic:
                    self._add_resource(rel_file, f"mqtt:{edge.mqtt_topic}")
                    if "setpoint" in edge.mqtt_topic.lower():
                        self._add_resource(rel_file, "domain:setpoint")
            for ep in res.mqtt_endpoints:
                if ep.topic:
                    self._add_resource(rel_file, f"mqtt:{ep.topic}")
                    if "setpoint" in ep.topic.lower():
                        self._add_resource(rel_file, "domain:setpoint")

    def explain_blast_radius(self, changed_files: list[str]) -> BlastRadiusReport:
        normalized_changed = []
        for cf in changed_files:
            norm = self._normalize(cf)
            if norm not in normalized_changed:
                normalized_changed.append(norm)

        callers: set[str] = set()
        callees: set[str] = set()
        shared_neighbors: dict[str, set[str]] = defaultdict(set)

        for cf in normalized_changed:
            for callee in self.call_edges.get(cf, ()):
                if callee not in normalized_changed:
                    callees.add(callee)
            for caller in self.rev_call_edges.get(cf, ()):
                if caller not in normalized_changed:
                    callers.add(caller)
            for res in self.resources_by_file.get(cf, ()):
                for peer in self.files_by_resource.get(res, ()):
                    if peer not in normalized_changed:
                        shared_neighbors[peer].add(res)

        all_selected = sorted(set(normalized_changed) | callers | callees | set(shared_neighbors.keys()))
        total_loc = sum(self.loc_by_file.values())
        selected_loc = sum(self.loc_by_file.get(f, 0) for f in all_selected)

        return BlastRadiusReport(
            changed_files=normalized_changed,
            blast_radius_files=all_selected,
            one_hop_callers=sorted(callers),
            one_hop_callees=sorted(callees),
            shared_data_neighbors={k: sorted(v) for k, v in sorted(shared_neighbors.items())},
            total_files=len(self.files),
            total_loc=total_loc,
            selected_loc=selected_loc,
        )

    def blast_radius(self, changed_files: list[str]) -> list[str]:
        return self.explain_blast_radius(changed_files).blast_radius_files


def blast_radius(changed_files: list[str], repo_root: str | Path = ".") -> list[str]:
    return CodeGraph.build(repo_root).blast_radius(changed_files)


def main() -> None:
    ap = argparse.ArgumentParser(description="Build Python AST call + data-flow graph and print blast radius.")
    ap.add_argument("repo", nargs="?", default="sample_repo", help="Repository path")
    ap.add_argument("--repo", dest="repo_flag", help="Optional repository path override")
    ap.add_argument("--changed", nargs="*", help="Changed file(s) for blast radius")
    args = ap.parse_args()

    repo_path = Path(args.repo_flag or args.repo)
    graph = CodeGraph.build(repo_path)

    print(f"=== CodeGraph Summary: {repo_path} ({len(graph.files)} files, {sum(graph.loc_by_file.values())} LOC) ===")
    for f in graph.files:
        fns = [fn.name for fn in graph.functions_by_file.get(f, [])]
        res = sorted(graph.resources_by_file.get(f, set()))
        print(f"  - {f} ({graph.loc_by_file.get(f, 0)} LOC) | funcs={fns} | resources={res}")

    targets = args.changed if args.changed else ([f for f in graph.files if f.endswith("flows.json")] or graph.files[:1])
    report = graph.explain_blast_radius(targets)
    print(f"\nBlast radius for changed={targets}:")
    print(f"  Changed files        : {report.changed_files}")
    print(f"  1-hop callers        : {report.one_hop_callers}")
    print(f"  1-hop callees        : {report.one_hop_callees}")
    print(f"  Shared data neighbors: {report.shared_data_neighbors}")
    print(f"  Blast radius files   : {report.blast_radius_files}")
    print(f"  Code kept for LLM    : {len(report.blast_radius_files)}/{report.total_files} files ({report.file_ratio:.1%}), {report.selected_loc}/{report.total_loc} LOC ({report.loc_ratio:.1%})")


if __name__ == "__main__":
    main()
