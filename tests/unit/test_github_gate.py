"""Unit tests for Phase 5 GitHub Actions workflow (SQLite MVP), Check Gate, and PR comment."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from backend.reviewer.agents.orchestrator import run_review
from backend.reviewer.reporting.github import build_github_check_payload, format_pr_comment


def test_github_workflow_uses_sqlite_no_postgres_service() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    wf = (repo_root / ".github" / "workflows" / "review.yml").read_text(encoding="utf-8")
    assert "pull_request" in wf
    assert "runs-on: ubuntu-latest" in wf
    assert "alembic upgrade head" in wf
    assert "sqlite:///./reviewer.db" in wf
    assert "postgres:" not in wf.lower()
    assert "docker-compose" not in wf.lower()
    assert "psycopg2" not in wf.lower()


def test_fake_git_pr_blocks_unsafe_write_and_passes_docs_at_zero_cost(tmp_path: Path) -> None:
    repo = tmp_path / "linetrack_fake"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "dev@linetrack.local"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Dev"], cwd=repo, check=True)

    (repo / "README.md").write_text("# LineTrack MES\n", encoding="utf-8")
    (repo / "safe_plc.py").write_text(
        '@require_role("Supervisor")\n'
        'def set_spindle(speed: int):\n'
        '    if speed not in range(500, 3001): raise ValueError("oob")\n'
        '    check_interlock()\n'
        '    audit_log.insert(tag="SPINDLE_SPEED", value=speed)\n'
        '    plc.write_register("SPINDLE_SPEED", speed)\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True)

    subprocess.run(["git", "checkout", "-b", "pr/unsafe-plc"], cwd=repo, check=True, capture_output=True)
    (repo / "unsafe_write.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'def write_feed(rate: int):\n'
        '    plc.write_register("FEED_RATE", rate)\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "unsafe plc pr"], cwd=repo, check=True, capture_output=True)

    unsafe_state = run_review(repo_root=repo, base_ref="main", head_ref="pr/unsafe-plc", mode="pr")
    assert unsafe_state["verdict"] == "BLOCK"
    assert unsafe_state["exit_code"] == 2
    assert build_github_check_payload(unsafe_state, head_sha="pr/unsafe-plc")["conclusion"] == "failure"
    comment_md = format_pr_comment(unsafe_state)
    assert "## LineTrack Review Gate — **BLOCK**" in comment_md
    assert "unsafe_write.py" in comment_md
    assert "AKIAIOSFODNN7EXAMPLE" not in comment_md

    subprocess.run(["git", "checkout", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "checkout", "-b", "pr/docs-only"], cwd=repo, check=True, capture_output=True)
    (repo / "README.md").write_text("# LineTrack MES\nUpdated docs.\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "docs only"], cwd=repo, check=True, capture_output=True)

    docs_state = run_review(repo_root=repo, base_ref="main", head_ref="pr/docs-only", mode="pr")
    assert docs_state["verdict"] == "PASS"
    assert docs_state["exit_code"] == 0
    assert docs_state["cost_summary"]["llm_calls"] == 0
    assert docs_state["cost_summary"]["total_cost_usd"] == 0.0
    assert build_github_check_payload(docs_state, head_sha="pr/docs-only")["conclusion"] == "success"

    subprocess.run(["git", "checkout", "pr/unsafe-plc"], cwd=repo, check=True, capture_output=True)
    cli_proc = subprocess.run(
        [sys.executable, "-m", "backend.reviewer.reporting.github", "--repo", str(repo), "--base", "main", "--head", "pr/unsafe-plc"],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cli_proc.returncode == 2
    assert "LineTrack Review Gate — **BLOCK**" in cli_proc.stdout
    assert "AKIAIOSFODNN7EXAMPLE" not in cli_proc.stdout
