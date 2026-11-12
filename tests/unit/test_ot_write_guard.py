"""Unit tests for Phase 1 OT Write Guard (OT-001) and API SQLite persistence."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.reviewer.deterministic.ot_write_guard import OTSafetyAgent, analyze_write_paths, summarize_ot_checks


def test_safe_file_no_finding(tmp_path: Path) -> None:
    safe_py = tmp_path / "safe.py"
    safe_py.write_text(
        '@require_role("Supervisor")\n'
        'def set_spindle(speed: int):\n'
        '    if speed < 500 or speed > 3000:\n'
        '        raise ValueError("out of range")\n'
        '    check_interlock()\n'
        '    audit_log.insert(who="supervisor", tag="SPINDLE_SPEED", value=speed)\n'
        '    plc.write_register("SPINDLE_SPEED", speed)\n',
        encoding="utf-8",
    )
    findings, verdict = OTSafetyAgent(safe_py).run(quiet=True)
    assert findings == []
    assert verdict == "PASS"
    assert all(v == "PASS" for v in summarize_ot_checks(findings).values())


def test_unsafe_file_3_highs(tmp_path: Path) -> None:
    unsafe_py = tmp_path / "unsafe.py"
    unsafe_py.write_text(
        'def set_spindle(speed: int):\n'
        '    audit_log.insert(who="unknown", tag="SPINDLE_SPEED", value=speed)\n'
        '    plc.write_register("SPINDLE_SPEED", speed)\n',
        encoding="utf-8",
    )
    findings, verdict = OTSafetyAgent(unsafe_py).run(quiet=True)
    highs = [f for f in findings if f.severity == "High"]
    assert len(highs) == 3
    assert {f.rule for f in highs} == {"PLC-WRITE-NO-CLAMP", "PLC-WRITE-NO-AUTH", "PLC-WRITE-NO-INTERLOCK"}
    assert verdict == "BLOCK"


@pytest.mark.parametrize(
    "case_name,code,expected_rule",
    [
        (
            "not_allowlisted",
            '@require_role("Supervisor")\n'
            'def fn(v: int):\n'
            '    if v < 0 or v > 10: raise ValueError("oob")\n'
            '    check_interlock()\n'
            '    audit_log.insert(v)\n'
            '    plc.write_register("ROGUE_TAG", v)\n',
            "PLC-WRITE-NOT-ALLOWLISTED",
        ),
        (
            "no_clamp",
            '@require_role("Supervisor")\n'
            'def fn(v: int):\n'
            '    check_interlock()\n'
            '    audit_log.insert(v)\n'
            '    plc.write_register("SPINDLE_SPEED", v)\n',
            "PLC-WRITE-NO-CLAMP",
        ),
        (
            "no_auth",
            'def fn(v: int):\n'
            '    if v < 500 or v > 3000: raise ValueError("oob")\n'
            '    check_interlock()\n'
            '    audit_log.insert(v)\n'
            '    plc.write_register("SPINDLE_SPEED", v)\n',
            "PLC-WRITE-NO-AUTH",
        ),
        (
            "no_interlock",
            '@require_role("Supervisor")\n'
            'def fn(v: int):\n'
            '    if v < 500 or v > 3000: raise ValueError("oob")\n'
            '    audit_log.insert(v)\n'
            '    plc.write_register("SPINDLE_SPEED", v)\n',
            "PLC-WRITE-NO-INTERLOCK",
        ),
        (
            "no_audit",
            '@require_role("Supervisor")\n'
            'def fn(v: int):\n'
            '    if v < 500 or v > 3000: raise ValueError("oob")\n'
            '    check_interlock()\n'
            '    plc.write_register("SPINDLE_SPEED", v)\n',
            "PLC-WRITE-NO-AUDIT",
        ),
    ],
)
def test_missing_any_of_5_is_high_and_blocks(tmp_path: Path, case_name: str, code: str, expected_rule: str) -> None:
    p = tmp_path / f"{case_name}.py"
    p.write_text(code, encoding="utf-8")
    findings, verdict = OTSafetyAgent(p).run(quiet=True)
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert findings[0].rule == expected_rule
    assert verdict == "BLOCK"


def test_not_in_clamp_no_false_positive(tmp_path: Path) -> None:
    p = tmp_path / "not_in_safe.py"
    p.write_text(
        '@require_role("Supervisor")\n'
        'def set_spindle(speed: int):\n'
        '    if speed not in range(500, 3001):\n'
        '        raise ValueError("out of range")\n'
        '    check_interlock()\n'
        '    audit_log.insert(tag="SPINDLE_SPEED", value=speed)\n'
        '    plc.write_register("SPINDLE_SPEED", speed)\n',
        encoding="utf-8",
    )
    assert analyze_write_paths(p) == []


def test_role_not_in_does_not_count_as_clamp(tmp_path: Path) -> None:
    p = tmp_path / "role_only.py"
    p.write_text(
        'def set_spindle(speed: int, role: str):\n'
        '    if role not in ["Supervisor", "Plant Head"]:\n'
        '        raise PermissionError("forbidden")\n'
        '    check_interlock()\n'
        '    audit_log.insert(tag="SPINDLE_SPEED", value=speed)\n'
        '    plc.write_register("SPINDLE_SPEED", speed)\n',
        encoding="utf-8",
    )
    assert [f.rule for f in analyze_write_paths(p)] == ["PLC-WRITE-NO-CLAMP"]


def test_sample_repo_nodered_flows_and_api_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from alembic import command
    from alembic.config import Config

    db_path = tmp_path / "test_phase1.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    repo_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "backend" / "alembic"))
    command.upgrade(cfg, "head")

    findings, verdict = OTSafetyAgent(repo_root / "sample_repo" / "flows.json").run(quiet=True)
    assert verdict == "BLOCK"
    assert len(findings) == 4
    assert all("Unsafe feed write" in f.message for f in findings)

    client = TestClient(app)
    res = client.post("/api/review", json={"repo_path": "sample_repo", "mode": "pr"})
    assert res.status_code == 200
    body = res.json()
    assert body["verdict"] == "BLOCK"
    assert body["exit_code"] == 2
    assert body["ot_checks"]["clamp"] == "FAIL"
    assert body["ot_checks"]["allowlist"] == "PASS"


def test_unparsable_flow_fails_closed(tmp_path: Path) -> None:
    broken = tmp_path / "broken_flow.json"
    broken.write_text("{ invalid json !!", encoding="utf-8")
    findings, verdict = OTSafetyAgent(broken).run(quiet=True)
    assert verdict == "BLOCK"
    assert any(f.rule == "UNPARSABLE_FLOW" and f.severity == "High" for f in findings)


def test_cli_exit_code_2_on_sample_repo() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, "-m", "backend.reviewer.deterministic.ot_write_guard", "--path", "sample_repo"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
