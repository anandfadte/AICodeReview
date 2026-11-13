"""Unit tests for Phase 3 SQLite findings store, Alembic portability, suppressions, and SARIF."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text

from backend.models import Base
from backend.reviewer.findings.sarif import SARIF_SCHEMA_URL, export_sarif
from backend.reviewer.findings.schema import Finding
from backend.reviewer.findings.store import FindingStore


def _make_sample_findings() -> list[Finding]:
    specs = [
        ("OT-001", "High", "flows.json", 56, "PLC-WRITE-NO-CLAMP"),
        ("MES-001", "High", "oee.py", 8, "OEE-DIV-BY-ZERO"),
        ("MES-002", "High", "genealogy.py", 2, "GENEALOGY-ORPHAN-PART"),
        ("SEC-001", "High", "api.py", 6, "RBAC-MISSING-ROLE-CHECK"),
        ("PRIV-001", "Medium", "operator.py", 12, "DPDP-PII-NO-PURPOSE-RETENTION"),
    ]
    return [
        Finding(
            id=f"f-{idx}",
            check_id=cid,
            severity=sev,
            confidence=0.95,
            file=fpath,
            line=line,
            rule=rule,
            evidence=f"evidence for {rule}",
            blast_radius=[fpath],
            standards=["IEC 62443 SR 3.3"],
            fix=f"Fix {rule}",
            message=f"Detected {rule}",
        )
        for idx, (cid, sev, fpath, line, rule) in enumerate(specs, start=1)
    ]


def test_models_use_only_portable_column_types() -> None:
    allowed_types = (String, Text, Integer, Float, Boolean, DateTime)
    for table in Base.metadata.tables.values():
        for col in table.columns:
            assert isinstance(col.type, allowed_types), f"Non-portable column {table.name}.{col.name}: {col.type!r}"


def test_save_suppress_sarif_and_expiry_simulation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_file = tmp_path / "reviewer_test.db"
    db_url = f"sqlite:///{db_file}"
    monkeypatch.setenv("DATABASE_URL", db_url)

    repo_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "backend" / "alembic"))
    command.upgrade(cfg, "head")
    assert db_file.is_file()

    store = FindingStore(db_url=db_url)
    store.repo.save_run(run_id="pr-101", repo="sample_repo", verdict="BLOCK", exit_code=2, branch="feat/spindle")
    saved_ids = store.save_findings(_make_sample_findings(), pr_id="pr-101")
    assert len(saved_ids) == 5

    t0 = datetime(2026, 11, 11, 10, 0, tzinfo=timezone.utc)
    sup_meta = store.suppress_finding(saved_ids[4], owner="qa-lead", reason="Sprint sign-off", now=t0)
    assert sup_meta["owner"] == "qa-lead"
    assert (datetime.fromisoformat(sup_meta["expires_at"]) - t0).days == 30

    # Active suppression: 4 OPEN + 1 SUPPRESSED; SARIF omits suppressed finding
    loaded_active = store.get_findings(pr_id="pr-101", now=t0 + timedelta(days=5))
    assert len(loaded_active) == 5
    assert sum(1 for f in loaded_active if f.status == "SUPPRESSED") == 1
    sarif_path = tmp_path / "findings.sarif"
    sarif_active = export_sarif(loaded_active, output_path=sarif_path, now=t0 + timedelta(days=5))
    assert sarif_active["$schema"] == SARIF_SCHEMA_URL
    assert sarif_active["version"] == "2.1.0"
    assert len(sarif_active["runs"][0]["results"]) == 4

    # Simulate expiry (+31 days): suppression disappears and all 5 return to OPEN & SARIF
    loaded_expired = store.get_findings(pr_id="pr-101", now=t0 + timedelta(days=31))
    assert sum(1 for f in loaded_expired if f.status == "SUPPRESSED") == 0
    assert sum(1 for f in loaded_expired if f.status == "OPEN") == 5
    sarif_expired = export_sarif(loaded_expired, now=t0 + timedelta(days=31))
    assert len(sarif_expired["runs"][0]["results"]) == 5
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_suppression_requires_owner_and_reason(tmp_path: Path) -> None:
    db_file = tmp_path / "req.db"
    store = FindingStore(db_url=f"sqlite:///{db_file}", auto_create=True)
    fid = store.save_finding(_make_sample_findings()[0], pr_id="pr-1")
    with pytest.raises(ValueError):
        store.suppress_finding(fid, owner="", reason="missing owner")
    with pytest.raises(ValueError):
        store.suppress_finding(fid, owner="lead", reason="   ")


def test_suppression_revocation_and_list(tmp_path: Path) -> None:
    db_file = tmp_path / "rev.db"
    db_url = f"sqlite:///{db_file}"
    from backend.store import ReviewerStore

    store = ReviewerStore(db_url=db_url, auto_create=True)
    store.save_run(run_id="run-rev-1", repo="sample_repo", verdict="BLOCK", exit_code=2)
    saved_ids = store.save_findings(_make_sample_findings(), run_id="run-rev-1")
    target_id = saved_ids[0]

    # Suppress finding
    sup = store.suppress_finding(target_id, owner="qa-architect", reason="Temporary risk waiver")
    assert sup["owner"] == "qa-architect"

    # List suppressions
    sups = store.get_suppressions(active_only=True)
    assert len(sups) == 1
    assert sups[0]["finding_id"] == target_id
    assert sups[0]["owner"] == "qa-architect"
    assert sups[0]["days_remaining"] >= 29

    # Revoke suppression
    revoked = store.revoke_suppression(target_id)
    assert revoked is True

    # Active suppressions should now be 0
    active_sups = store.get_suppressions(active_only=True)
    assert len(active_sups) == 0

    # Historical suppressions should show it as inactive
    all_sups = store.get_suppressions(active_only=False)
    assert len(all_sups) == 1
    assert all_sups[0]["active"] is False

    # Finding status should be reverted to OPEN
    f_list = store.get_findings(run_id="run-rev-1")
    reopened = next(f for f in f_list if f["id"] == target_id)
    assert reopened["status"] == "OPEN"
