"""Unit tests for Phase 8 air-gap mode, hardening controls, ADRs, and MVP Postgres-free proof."""

from __future__ import annotations

import importlib.metadata
import subprocess
import sys
from pathlib import Path

import pytest

from backend.reviewer.agents.orchestrator import run_review
from backend.reviewer.guardrails.redact import contains_secret, redact_secrets
from backend.reviewer.guardrails.tool_allowlist import ALLOWLIST, ToolGuard, ToolNotAllowedError
from tests.golden.golden_set import GOLDEN_CASES


def test_airgap_mode_offline_ignores_azure_and_judges_medium_plus(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-openai-must-not-be-called")
    monkeypatch.setenv("AZURE_OPENAI_KEY", "sk-fake-must-not-be-called")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://nonexistent.invalid")

    repo_root = Path(__file__).resolve().parents[2]
    res = run_review(repo_root=repo_root / "sample_repo", mode="airgap", airgap=True)
    assert res["verdict"] == "BLOCK"
    assert res["exit_code"] == 2
    assert res["cost_summary"]["total_cost_usd"] == 0.0
    judged_rules = {entry["rule"] for entry in res["judge_log"]}
    assert "GENEALOGY-NO-AUDIT-LOG" in judged_rules
    assert "PLC-WRITE-NO-CLAMP" in judged_rules


def test_mvp_has_no_docker_compose_and_no_psycopg_or_pgvector() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    assert not (repo_root / "docker-compose.yml").exists()
    req_txt = (repo_root / "requirements.txt").read_text(encoding="utf-8").lower()
    assert "psycopg" not in req_txt
    assert "pgvector" not in req_txt
    pyproj = (repo_root / "pyproject.toml").read_text(encoding="utf-8").lower()
    assert "psycopg" not in pyproj
    assert "pgvector" not in pyproj


def test_docs_adrs_and_migration_plans_exist() -> None:
    docs_dir = Path(__file__).resolve().parents[2] / "docs"
    for fname in ("ADR-01-deterministic-first.md", "ADR-02-sqlite-mvp-postgres-prod.md", "ADR-03-self-hosted-runner.md"):
        content = (docs_dir / fname).read_text(encoding="utf-8")
        for heading in ("## Context", "## Options", "## Decision", "## Consequences", "## Reverse-if"):
            assert heading in content, f"{fname} missing {heading}"
    assert (docs_dir / "MIGRATION_SQLite_to_Postgres.md").is_file()
    mig_prod = (docs_dir / "MIGRATION_TO_PRODUCTION.md").read_text(encoding="utf-8")
    assert "DATABASE_URL" in mig_prod
    assert "alembic upgrade head" in mig_prod
    assert "self-hosted" in mig_prod


def test_hardening_allowlist_redaction_and_all_5_injections_blocked(tmp_path: Path) -> None:
    guard = ToolGuard(repo_root=tmp_path)
    assert ALLOWLIST == frozenset({"read_file", "run_scanner", "run_graph", "query_findings"})
    for disallowed in ("write_file", "edit_file", "plc_write", "mqtt_publish", "db_execute", "shell"):
        with pytest.raises(ToolNotAllowedError):
            guard.invoke(disallowed)

    for s in (
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        'DB_PASSWORD = "supersecretpassword"',
        'OPENAI_KEY = "sk-proj1234567890abcdef"',
        'GH = "ghp_1234567890abcdefghij12345"',
        "DATABASE_URL = 'postgresql://reviewer:secretpw@db:5432/reviewer'",
    ):
        assert contains_secret(s)
        assert not contains_secret(redact_secrets(s))

    inj_cases = [c for c in GOLDEN_CASES if c.category == "prompt_injection"]
    assert len(inj_cases) == 5
    for c in inj_cases:
        cdir = tmp_path / c.case_id
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / c.filename).write_text(c.code, encoding="utf-8")
        res = run_review(repo_root=cdir, changed_files=[c.filename], pr_text=c.pr_text, mode="airgap")
        assert res["verdict"] == "BLOCK"
        assert any(f.rule == "INJECTION_ATTEMPT" for f in res["final_findings"])


def test_airgap_cli_offline() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, "-m", "backend.reviewer.agents.orchestrator", "--repo", "sample_repo", "--mode", "airgap"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "Verdict: BLOCK (exit 2)" in proc.stdout
    assert "Cost: $0.000000" in proc.stdout


def test_env_is_gitignored_and_no_real_openai_key_in_source() -> None:
    import re

    repo_root = Path(__file__).resolve().parents[2]
    gitignore = (repo_root / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in [line.strip() for line in gitignore]
    real_key_re = re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}")
    for path in repo_root.rglob("*"):
        if not path.is_file() or path.name == ".env" or any(p in {".venv", ".git", "__pycache__", ".pytest_cache"} for p in path.parts):
            continue
        if path.suffix.lower() in {".py", ".md", ".yml", ".yaml", ".json", ".html", ".toml", ".txt", ".example"}:
            txt = path.read_text(encoding="utf-8", errors="ignore")
            assert not real_key_re.search(txt), f"Hardcoded OpenAI key leaked in {path}"
