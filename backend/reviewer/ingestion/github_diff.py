"""PR diff and local repository ingestion (read-only, Spec P4/P5)."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
}

DOCS_EXTENSIONS = {".md", ".rst", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf"}

SOURCE_EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".json",
    ".yml",
    ".yaml",
    ".sql",
    ".toml",
    ".env",
    ".example",
}

_DIFF_FILE_RE = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<b>.+)$")
_HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)


@dataclass
class DiffHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    removed_lines: list[tuple[int, str]] = field(default_factory=list)
    header: str = ""
    raw: str = ""


@dataclass
class ChangedFile:
    path: str
    status: str  # added | modified | deleted | renamed
    hunks: list[DiffHunk] = field(default_factory=list)
    changed_lines: list[int] = field(default_factory=list)
    file_lines: list[str] = field(default_factory=list)


@dataclass
class DiffResult:
    repo_root: str
    changed_files: list[ChangedFile] = field(default_factory=list)
    file_lines_map: dict[str, list[str]] = field(default_factory=dict)
    is_docs_only: bool = False

    def file_paths(self) -> list[str]:
        return [cf.path for cf in self.changed_files if cf.status != "deleted"]


def is_docs_only_change(paths: Iterable[str]) -> bool:
    path_list = [p for p in paths if p]
    if not path_list:
        return False
    return all(Path(rel).suffix.lower() in DOCS_EXTENSIONS for rel in path_list)


def _normalize_rel_path(path_str: str) -> str:
    return path_str.replace("\\", "/").lstrip("./")


def parse_unified_diff(diff_text: str, repo_root: str | Path = ".") -> DiffResult:
    root = Path(repo_root)
    changed_files: list[ChangedFile] = []
    file_lines_map: dict[str, list[str]] = {}

    current_file: ChangedFile | None = None
    current_hunk: DiffHunk | None = None
    new_lineno = 0
    old_lineno = 0

    for raw_line in diff_text.splitlines():
        m_diff = _DIFF_FILE_RE.match(raw_line)
        if m_diff:
            if current_hunk and current_file:
                current_file.hunks.append(current_hunk)
                current_hunk = None
            if current_file:
                changed_files.append(current_file)
            rel_path = _normalize_rel_path(m_diff.group("b"))
            current_file = ChangedFile(path=rel_path, status="modified")
            continue

        if current_file is None:
            continue

        if raw_line.startswith("new file mode"):
            current_file.status = "added"
            continue
        if raw_line.startswith("deleted file mode"):
            current_file.status = "deleted"
            continue
        if raw_line.startswith("--- ") or raw_line.startswith("+++ "):
            if raw_line.startswith("+++ b/"):
                current_file.path = _normalize_rel_path(raw_line[6:])
            elif raw_line.startswith("+++ /dev/null"):
                current_file.status = "deleted"
            continue

        m_hunk = _HUNK_HEADER_RE.match(raw_line)
        if m_hunk:
            if current_hunk:
                current_file.hunks.append(current_hunk)
            old_start = int(m_hunk.group("old_start"))
            old_count = int(m_hunk.group("old_count") or "1")
            new_start = int(m_hunk.group("new_start"))
            new_count = int(m_hunk.group("new_count") or "1")
            current_hunk = DiffHunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                header=raw_line,
                raw=raw_line + "\n",
            )
            old_lineno = old_start
            new_lineno = new_start
            continue

        if current_hunk is None:
            continue

        current_hunk.raw += raw_line + "\n"
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_hunk.added_lines.append((new_lineno, raw_line[1:]))
            current_file.changed_lines.append(new_lineno)
            current_file.file_lines.append(f"{current_file.path}:{new_lineno}")
            new_lineno += 1
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            current_hunk.removed_lines.append((old_lineno, raw_line[1:]))
            old_lineno += 1
        elif raw_line.startswith(" "):
            old_lineno += 1
            new_lineno += 1

    if current_hunk and current_file:
        current_file.hunks.append(current_hunk)
    if current_file:
        changed_files.append(current_file)

    for cf in changed_files:
        file_lines_map[cf.path] = cf.file_lines
        if cf.status != "deleted" and (root / cf.path).is_file() and not cf.changed_lines:
            cf.file_lines = [f"{cf.path}:1"]
            file_lines_map[cf.path] = cf.file_lines

    return DiffResult(
        repo_root=str(root),
        changed_files=changed_files,
        file_lines_map=file_lines_map,
        is_docs_only=is_docs_only_change(cf.path for cf in changed_files),
    )


def load_git_diff(repo_path: str | Path, base_ref: str = "HEAD~1", head_ref: str = "HEAD") -> DiffResult:
    root = Path(repo_path)
    cmd = ["git", "-C", str(root), "diff", "--unified=3", base_ref, head_ref]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed ({proc.returncode}): {proc.stderr.strip()}")
    return parse_unified_diff(proc.stdout, repo_root=root)


def _should_skip(path: Path, root: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.relative_to(root).parts)


def ingest_local_repo(repo_path: str | Path, include_files: list[str] | None = None) -> DiffResult:
    root = Path(repo_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Repository path does not exist: {repo_path}")

    include_set = {_normalize_rel_path(p) for p in include_files} if include_files else None
    changed_files: list[ChangedFile] = []
    file_lines_map: dict[str, list[str]] = {}

    if root.is_file():
        candidates = [root]
        root = root.parent
    else:
        candidates = sorted(p for p in root.rglob("*") if p.is_file() and not _should_skip(p, root))

    for file_path in candidates:
        rel = _normalize_rel_path(str(file_path.relative_to(root)))
        if include_set is not None and rel not in include_set:
            continue
        if file_path.suffix.lower() not in SOURCE_EXTENSIONS and file_path.name not in {"Dockerfile"}:
            continue
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        lines = text.splitlines()
        line_count = max(1, len(lines))
        hunk = DiffHunk(
            old_start=0,
            old_count=0,
            new_start=1,
            new_count=line_count,
            added_lines=[(idx + 1, ln) for idx, ln in enumerate(lines)],
            header=f"@@ -0,0 +1,{line_count} @@",
            raw="\n".join(f"+{ln}" for ln in lines),
        )
        changed_lines = [idx + 1 for idx in range(len(lines))] or [1]
        file_lines = [f"{rel}:{ln}" for ln in changed_lines]
        changed_files.append(
            ChangedFile(
                path=rel,
                status="added",
                hunks=[hunk],
                changed_lines=changed_lines,
                file_lines=file_lines,
            )
        )
        file_lines_map[rel] = file_lines

    return DiffResult(
        repo_root=str(root),
        changed_files=changed_files,
        file_lines_map=file_lines_map,
        is_docs_only=is_docs_only_change(cf.path for cf in changed_files),
    )


def iter_file_lines(diff_result: DiffResult) -> list[str]:
    out: list[str] = []
    for cf in diff_result.changed_files:
        out.extend(cf.file_lines)
    return out
