"""Strict read-only tool allow-list enforcement (Spec P4)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

ALLOWLIST = frozenset({"read_file", "run_scanner", "run_graph", "query_findings"})


class ToolNotAllowedError(PermissionError):
    """Raised when an agent attempts to call any tool outside the read-only allow-list."""


class ToolGuard:
    """Enforces read-only ALLOWLIST and repo-root confinement."""

    def __init__(self, repo_root: str | Path = ".", db_url: str | None = None):
        self.repo_root = Path(repo_root).resolve()
        self.db_url = db_url
        self.audit_trail: list[dict[str, Any]] = []

    def assert_allowed(self, tool_name: str) -> None:
        if tool_name not in ALLOWLIST:
            self.audit_trail.append({"tool": tool_name, "allowed": False, "reason": "NOT_IN_ALLOWLIST"})
            raise ToolNotAllowedError(
                f"BLOCKED tool call '{tool_name}': only read-only tools {sorted(ALLOWLIST)} are allowed."
            )

    def invoke(self, tool_name: str, **kwargs: Any) -> Any:
        self.assert_allowed(tool_name)
        self.audit_trail.append({"tool": tool_name, "allowed": True})

        if tool_name == "read_file":
            return self.read_file(kwargs["path"])
        if tool_name == "run_scanner":
            from backend.reviewer.deterministic.scanners import run_scanner

            return run_scanner(
                kwargs["name"],
                kwargs["changed_files"],
                repo_root=kwargs.get("repo_root", self.repo_root),
                airgap=kwargs.get("airgap", False),
            )
        if tool_name == "run_graph":
            from backend.reviewer.ingestion.graph import CodeGraph

            graph = CodeGraph.build(kwargs.get("repo_root", self.repo_root))
            changed = kwargs.get("changed_files")
            return graph.explain_blast_radius(changed) if changed is not None else graph
        if tool_name == "query_findings":
            from backend.reviewer.findings.store import FindingStore

            store = FindingStore(db_url=kwargs.get("db_url", self.db_url))
            return store.get_findings(pr_id=kwargs.get("pr_id"), audit_id=kwargs.get("audit_id"))
        raise ToolNotAllowedError(f"Unhandled tool: {tool_name}")

    def read_file(self, rel_or_abs_path: str | Path) -> str:
        p = Path(rel_or_abs_path)
        target = p.resolve() if p.is_absolute() else (self.repo_root / p).resolve()
        try:
            target.relative_to(self.repo_root)
        except ValueError as exc:
            raise ToolNotAllowedError(f"BLOCKED read_file outside repository root: {rel_or_abs_path}") from exc
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {rel_or_abs_path}")
        return target.read_text(encoding="utf-8", errors="replace")
