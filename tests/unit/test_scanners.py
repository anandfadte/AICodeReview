"""Unit tests for Phase 2 deterministic scanners and MES checks."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from backend.reviewer.deterministic.mes_checks import check_genealogy_file, check_oee_file
from backend.reviewer.deterministic.scanners import run_all_scanners, run_scanner


def test_sample_repo_scanners_find_all_planted_bugs() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sample_dir = repo_root / "sample_repo"
    findings = run_all_scanners([sample_dir], repo_root=sample_dir)
    serialized = json.dumps([f.to_dict() for f in findings])

    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert "password123" not in serialized
    assert "REDACTED_" in serialized

    check_ids = {f.check_id for f in findings}
    rules = {f.rule for f in findings}
    assert {"SUP-001", "MES-001", "MES-002", "OT-001", "SEC-001", "LLM-001"}.issubset(check_ids)
    assert {"OEE-DIV-BY-ZERO", "OEE-OUT-OF-RANGE", "GENEALOGY-ORPHAN-PART", "RBAC-MISSING-ROLE-CHECK", "IDOR-MISSING-OWNERSHIP", "LLM-UNDELIMITED-LOGS"}.issubset(rules)


def test_oee_safe_function_no_finding(tmp_path: Path) -> None:
    p = tmp_path / "safe_oee.py"
    p.write_text(
        "def calc_oee(planned_time: float, downtime: float, ideal_rate: float, actual_output: float, good_parts: float) -> float:\n"
        "    if planned_time <= 0 or ideal_rate <= 0 or actual_output <= 0:\n"
        "        return 0.0\n"
        "    availability = max(0.0, min(1.0, (planned_time - downtime) / planned_time))\n"
        "    performance = max(0.0, min(1.0, actual_output / ideal_rate))\n"
        "    quality = max(0.0, min(1.0, good_parts / actual_output))\n"
        "    return max(0.0, min(1.0, availability * performance * quality))\n",
        encoding="utf-8",
    )
    assert check_oee_file(p) == []


def test_genealogy_safe_function_no_finding(tmp_path: Path) -> None:
    p = tmp_path / "safe_gen.py"
    p.write_text(
        "def save_part(part_id: str, machine: str, order_id: str, lot_id: str):\n"
        "    if not lot_id or not machine or not order_id:\n"
        "        raise ValueError('Missing link')\n"
        "    audit_log.insert({'part_id': part_id})\n"
        "    return {'part_id': part_id, 'machine': machine, 'order_id': order_id, 'lot_id': lot_id}\n",
        encoding="utf-8",
    )
    assert check_genealogy_file(p) == []


def test_run_scanner_cli_sample_prints_valid_json() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, "-m", "backend.reviewer.deterministic.scanners", "--sample"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert any(d["check_id"] == "SUP-001" for d in data)
    assert any(d["check_id"] == "MES-001" for d in data)
    assert any(d["check_id"] == "MES-002" for d in data)
    assert "AKIAIOSFODNN7EXAMPLE" not in proc.stdout
    assert "password123" not in proc.stdout


def test_native_scanner_cli_parsers_merge_and_redact(tmp_path: Path, monkeypatch) -> None:
    import shutil
    import subprocess as sp

    target_py = tmp_path / "app_sample.py"
    target_py.write_text(
        'from fastapi import FastAPI\napp = FastAPI()\n'
        '@app.post("/admin/setpoint")\n'
        'def setpoint():\n'
        '    return eval("1+1")\n',
        encoding="utf-8",
    )
    secret_py = tmp_path / "secret_sample.py"
    secret_py.write_text('CUSTOM_TOKEN = "very_secret_custom_value_987"\nDB_PASSWORD = "password123"\n', encoding="utf-8")
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("pyyaml==5.3\n", encoding="utf-8")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")

    def fake_run(cmd, **kwargs):
        exe = Path(cmd[0]).name
        if exe == "semgrep":
            out = json.dumps({
                "results": [{
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": str(target_py),
                    "start": {"line": 5},
                    "extra": {"severity": "ERROR", "message": "Detected eval()", "lines": "return eval('1+1')"},
                }]
            })
            return sp.CompletedProcess(cmd, 0, stdout=out, stderr="")
        if exe == "gitleaks":
            rp = Path(cmd[cmd.index("--report-path") + 1])
            rp.write_text(json.dumps([{
                "RuleID": "generic-api-key",
                "File": "secret_sample.py",
                "StartLine": 1,
                "Match": 'CUSTOM_TOKEN = "very_secret_custom_value_987"',
                "Secret": "very_secret_custom_value_987",
            }]), encoding="utf-8")
            return sp.CompletedProcess(cmd, 1, stdout="", stderr="")
        if exe == "trivy":
            out = json.dumps({
                "Results": [{
                    "Target": "requirements.txt",
                    "Vulnerabilities": [{
                        "VulnerabilityID": "CVE-2020-14343",
                        "PkgName": "pyyaml",
                        "InstalledVersion": "5.3",
                        "FixedVersion": "5.4",
                        "Severity": "CRITICAL",
                    }],
                }]
            })
            return sp.CompletedProcess(cmd, 0, stdout=out, stderr="")
        return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sp, "run", fake_run)

    # Semgrep merges native rule + LineTrack RBAC AST check
    sem_hits = run_scanner("semgrep", [target_py], repo_root=tmp_path)
    sem_rules = {f.rule for f in sem_hits}
    assert "eval-detected" in sem_rules
    assert "RBAC-MISSING-ROLE-CHECK" in sem_rules

    # Gitleaks redacts raw Secret AND merges password fallback
    git_hits = run_scanner("gitleaks", [secret_py], repo_root=tmp_path)
    git_json = json.dumps([f.to_dict() for f in git_hits])
    assert "very_secret_custom_value_987" not in git_json
    assert "password123" not in git_json
    assert "REDACTED_SECRET" in git_json
    assert any(f.rule == "GITLEAKS-HARDCODED-PASSWORD" for f in git_hits)

    # Trivy parses CVE AND preserves MISSING-SBOM
    trivy_hits = run_scanner("trivy", [req_txt], repo_root=tmp_path)
    trivy_rules = {f.rule for f in trivy_hits}
    assert "CVE-2020-14343" in trivy_rules
    assert "MISSING-SBOM" in trivy_rules
