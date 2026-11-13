"""Unit tests for Phase 6 full-audit mode on SQLite, HTML/PDF/SARIF reports, and UNVERIFIED controls."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import app
from backend.reviewer.reporting.audit import run_full_audit


def test_full_audit_produces_html_pdf_sarif_and_unverified_on_sqlite(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    html_path = tmp_path / "audit.html"
    pdf_path = tmp_path / "audit.pdf"
    sarif_path = tmp_path / "findings.sarif"

    report = run_full_audit(
        repo_root=repo_root / "sample_repo",
        mode="full",
        html_out=html_path,
        pdf_out=pdf_path,
        sarif_out=sarif_path,
    )

    assert html_path.is_file()
    html_txt = html_path.read_text(encoding="utf-8")
    assert "UNVERIFIED" in html_txt
    assert "AKIAIOSFODNN7EXAMPLE" not in html_txt

    assert pdf_path.is_file() and pdf_path.stat().st_size > 1500
    assert sarif_path.is_file()
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) >= 5

    assert len(report["unverified"]) >= 4
    assert all(u["status"] == "UNVERIFIED" for u in report["unverified"])
    assert any("GAP" in t["status"] for t in report["traceability"])
    assert len(report["check_catalogue"]) == 10


def test_report_api_endpoint_json_and_html_download() -> None:
    client = TestClient(app)
    res_json = client.get("/api/report")
    assert res_json.status_code == 200
    data = res_json.json()
    assert len(data["unverified"]) >= 4
    res_html = client.get("/api/report?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "UNVERIFIED Controls" in res_html.text


def test_api_patch_and_suppression_endpoints() -> None:
    client = TestClient(app)
    # Patch endpoint in diff and json formats
    patch_diff = client.get("/api/patch")
    assert patch_diff.status_code in (200, 404)
    if patch_diff.status_code == 200:
        assert "text/x-diff" in patch_diff.headers["content-type"]
        assert "attachment" in patch_diff.headers["content-disposition"]

    patch_json = client.get("/api/patch?format=json")
    assert patch_json.status_code in (200, 404)
    if patch_json.status_code == 200:
        data = patch_json.json()
        assert "patch" in data
        assert "files_count" in data

    # Suppressions list endpoint
    sups_res = client.get("/api/suppressions")
    assert sups_res.status_code == 200
    assert isinstance(sups_res.json(), list)


def test_full_audit_cli_produces_all_3_artifacts(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    html_p = tmp_path / "cli_audit.html"
    pdf_p = tmp_path / "cli_audit.pdf"
    sarif_p = tmp_path / "cli_findings.sarif"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "backend.reviewer.reporting.audit",
            "--mode",
            "full",
            "--repo",
            "sample_repo",
            "--html-out",
            str(html_p),
            "--pdf-out",
            str(pdf_p),
            "--sarif-out",
            str(sarif_p),
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "UNVERIFIED : 5 item(s)" in proc.stdout
    assert html_p.is_file() and pdf_p.is_file() and sarif_p.is_file()
