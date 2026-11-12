"""Deterministic scanner wrappers (read-only, 60s timeout, writes restricted to /tmp/reviewer/).

Merges native CLI scanner findings (Semgrep, Gitleaks, Trivy) with LineTrack
domain AST/secret/SBOM checks so enabling binaries enriches detection without
losing domain coverage or leaking secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable

from backend.reviewer.deterministic.mes_checks import (
    check_ask_linetrack_file,
    check_dpdp_pii_file,
    check_genealogy_file,
    check_mqtt_acl_file,
    check_oee_file,
    check_opcua_file,
    check_rbac_idor_file,
)
from backend.reviewer.deterministic.ot_write_guard import analyze_write_paths
from backend.reviewer.findings.schema import Finding, make_finding_id, normalize_severity
from backend.reviewer.guardrails.redact import redact_secrets
from backend.reviewer.ingestion.github_diff import SKIP_DIRS

REVIEWER_TMP_DIR = Path("/tmp/reviewer")
SCANNER_TIMEOUT_SEC = 60

_SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    ("GITLEAKS-AWS-KEY", "Critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Remove hardcoded AWS key; use environment variable or vault."),
    ("GITLEAKS-API-KEY", "High", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,})\b"), "Revoke exposed token and load from environment."),
    (
        "GITLEAKS-HARDCODED-PASSWORD",
        "High",
        re.compile(r"""(?i)\b(?:db_password|password|passwd|pwd|secret|api_key|azure_openai_key)\b\s*[:=]\s*["']([^"'\r\n]{4,})["']"""),
        "Move password/secret to environment variable; never hardcode credentials.",
    ),
]


def _ensure_tmp_dir() -> Path:
    REVIEWER_TMP_DIR.mkdir(parents=True, exist_ok=True)
    return REVIEWER_TMP_DIR


def _resolve_files(changed_files: Iterable[str | Path], repo_root: str | Path = ".") -> list[Path]:
    root = Path(repo_root).resolve()
    resolved: list[Path] = []
    for item in changed_files:
        p = Path(item)
        cand = p if p.is_absolute() else (root / p)
        if not cand.exists() and p.exists():
            cand = p.resolve()
        if cand.is_file():
            resolved.append(cand)
        elif cand.is_dir():
            for child in sorted(cand.rglob("*")):
                if child.is_file() and not any(part in SKIP_DIRS for part in child.relative_to(cand).parts):
                    resolved.append(child)
    seen: set[Path] = set()
    unique: list[Path] = []
    for p in resolved:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            unique.append(rp)
    return unique


def _rel_str(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _dedupe_findings(items: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, int]] = set()
    out: list[Finding] = []
    for f in items:
        key = (f.check_id, f.rule, f.file, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _run_semgrep(files: list[Path], repo_root: Path, airgap: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    semgrep_bin = shutil.which("semgrep")
    project_rules = Path(__file__).resolve().parents[3] / "checks" / "semgrep"
    local_rules = (repo_root / "checks" / "semgrep") if (repo_root / "checks" / "semgrep").is_dir() else project_rules

    if semgrep_bin and files and (not airgap or local_rules.is_dir()):
        tmp_dir = _ensure_tmp_dir()
        env = dict(os.environ)
        env["TMPDIR"] = str(tmp_dir)
        env["SEMGREP_SEND_METRICS"] = "off"
        env["DO_NOT_TRACK"] = "1"
        config_arg = str(local_rules) if local_rules.is_dir() else "auto"
        cmd = [semgrep_bin, "--config", config_arg, "--json", "--metrics", "off", "--no-git-ignore", *[str(f) for f in files]]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCANNER_TIMEOUT_SEC, env=env, check=False)
            if proc.stdout.strip():
                payload = json.loads(proc.stdout)
                for res in payload.get("results", []):
                    fpath = _rel_str(Path(res.get("path", "unknown")), repo_root)
                    line = int((res.get("start") or {}).get("line", 1))
                    rule = str(res.get("check_id", "SEMGREP-RULE")).split(".")[-1]
                    extra = res.get("extra") or {}
                    findings.append(
                        Finding(
                            id=make_finding_id("SEC-001", rule, fpath, line),
                            check_id="SEC-001",
                            severity=normalize_severity(str(extra.get("severity", "Medium"))),
                            confidence=0.85,
                            file=fpath,
                            line=line,
                            rule=rule,
                            evidence=str(extra.get("lines", "")),
                            blast_radius=[fpath],
                            standards=["OWASP ASVS 4.1", "ISO 27001 A.9"],
                            fix=f"Resolve Semgrep rule `{rule}` at {fpath}:{line}.",
                            message=str(extra.get("message", rule)),
                        )
                    )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass

    # Always run deterministic LineTrack AST checks and merge with Semgrep CLI hits
    for f in files:
        rel = _rel_str(f, repo_root)
        for item in (
            check_rbac_idor_file(f)
            + check_ask_linetrack_file(f)
            + check_opcua_file(f)
            + check_mqtt_acl_file(f)
            + check_dpdp_pii_file(f)
        ):
            item.file = rel
            item.blast_radius = [rel]
            findings.append(item)
    return _dedupe_findings(findings)


def _redact_gitleaks_evidence(match_text: str, raw_secret: str) -> str:
    masked = match_text or ""
    if raw_secret and raw_secret in masked:
        masked = masked.replace(raw_secret, "REDACTED_SECRET")
    masked = redact_secrets(masked)
    if raw_secret and raw_secret in masked:
        masked = "REDACTED_SECRET"
    return masked


def _run_gitleaks(files: list[Path], repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    gitleaks_bin = shutil.which("gitleaks")
    scannable_files = [f for f in files if f.name != ".env" and not f.name.startswith(".env.")]

    if gitleaks_bin and scannable_files:
        tmp_dir = _ensure_tmp_dir()
        report_file = tmp_dir / "gitleaks.json"
        if report_file.exists():
            report_file.unlink()

        # Restrict scan source to repo_root while applying .gitleaks.toml exclusions (.env, .venv)
        cfg_candidates = [
            repo_root / ".gitleaks.toml",
            Path(__file__).resolve().parents[3] / ".gitleaks.toml",
        ]
        cfg_file = next((c for c in cfg_candidates if c.is_file()), None)
        cmd = [
            gitleaks_bin,
            "detect",
            "--source",
            str(repo_root),
            "--no-git",
            "--report-format",
            "json",
            "--report-path",
            str(report_file),
        ]
        if cfg_file is not None:
            cmd.extend(["--config", str(cfg_file)])
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=SCANNER_TIMEOUT_SEC, check=False)
            if report_file.is_file():
                leaks = json.loads(report_file.read_text(encoding="utf-8") or "[]")
                target_rels = {_rel_str(f, repo_root) for f in scannable_files}
                for leak in leaks:
                    fpath = str(leak.get("File", "")).replace("\\", "/").lstrip("./")
                    # Normalize absolute or relative path reported by Gitleaks
                    cand_path = Path(fpath) if Path(fpath).is_absolute() else (repo_root / fpath)
                    rel_path = _rel_str(cand_path, repo_root)
                    if rel_path == ".env" or rel_path.startswith(".env."):
                        continue
                    if target_rels and rel_path not in target_rels:
                        continue
                    line = int(leak.get("StartLine", 1) or 1)
                    rule = f"GITLEAKS-{str(leak.get('RuleID', 'SECRET')).upper()}"
                    evidence = _redact_gitleaks_evidence(str(leak.get("Match", "")), str(leak.get("Secret", "")))
                    findings.append(
                        Finding(
                            id=make_finding_id("SUP-001", rule, rel_path, line),
                            check_id="SUP-001",
                            severity="Critical",
                            confidence=1.0,
                            file=rel_path,
                            line=line,
                            rule=rule,
                            evidence=evidence,
                            blast_radius=[rel_path],
                            standards=["ISO 27001 A.8", "OWASP ASVS 10"],
                            fix="Revoke secret and move to env vars / secret vault.",
                            message=f"Secret detected by Gitleaks ({rule}) at {rel_path}:{line} (redacted).",
                        )
                    )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass

    # Merge deterministic secret patterns (covers weak/low-entropy password literals too)
    covered_locations = {(f.file, f.line) for f in findings}
    for f in scannable_files:
        if f.suffix.lower() in {".png", ".jpg", ".pdf", ".db", ".sqlite", ".sarif"}:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except Exception:
            continue
        rel = _rel_str(f, repo_root)
        for lineno, line_text in enumerate(text.splitlines(), start=1):
            if (rel, lineno) in covered_locations:
                continue
            stripped = line_text.strip()
            if not stripped or stripped.startswith("#") or "os.getenv" in line_text or "os.environ" in line_text or "REDACTED_" in line_text:
                continue
            for rule, sev, pat, fix_msg in _SECRET_PATTERNS:
                if pat.search(line_text):
                    findings.append(
                        Finding(
                            id=make_finding_id("SUP-001", rule, rel, lineno),
                            check_id="SUP-001",
                            severity=sev,
                            confidence=1.0,
                            file=rel,
                            line=lineno,
                            rule=rule,
                            evidence=redact_secrets(stripped),
                            blast_radius=[rel],
                            standards=["ISO 27001 A.8", "OWASP ASVS 10"],
                            fix=fix_msg,
                            message=f"Hardcoded secret detected ({rule}) at {rel}:{lineno} (redacted).",
                        )
                    )
                    covered_locations.add((rel, lineno))
                    break
    return _dedupe_findings(findings)


def _run_trivy(files: list[Path], repo_root: Path, airgap: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    trivy_bin = shutil.which("trivy")
    manifests = [f for f in files if f.name in {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json"}]

    if trivy_bin and (manifests or any(f.is_file() for f in files)):
        tmp_dir = _ensure_tmp_dir()
        cache_dir = tmp_dir / "trivy-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env["TRIVY_CACHE_DIR"] = str(cache_dir)
        env["TRIVY_DISABLE_VEX_NOTICE"] = "1"
        cmd = [trivy_bin, "fs", "--format", "json", "--quiet"]
        if airgap:
            cmd.extend(["--offline-scan", "--skip-db-update"])
        cmd.append(str(repo_root))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCANNER_TIMEOUT_SEC, env=env, check=False)
            if proc.stdout.strip():
                report = json.loads(proc.stdout)
                for result in report.get("Results", []):
                    target = str(result.get("Target", "dependencies")).replace("\\", "/")
                    for vuln in result.get("Vulnerabilities", []) or []:
                        vid = str(vuln.get("VulnerabilityID", "TRIVY-CVE"))
                        pkg = str(vuln.get("PkgName", "package"))
                        findings.append(
                            Finding(
                                id=make_finding_id("SUP-001", vid, target, 1),
                                check_id="SUP-001",
                                severity=normalize_severity(str(vuln.get("Severity", "Medium"))),
                                confidence=0.95,
                                file=target,
                                line=1,
                                rule=vid,
                                evidence=f"{pkg} {vuln.get('InstalledVersion', '')} -> {vid}",
                                blast_radius=[target],
                                standards=["ISO 27001 A.8", "OWASP ASVS 10"],
                                fix=f"Upgrade {pkg} to {vuln.get('FixedVersion', 'latest')}.",
                                message=f"Vulnerable dependency {pkg} ({vid}).",
                            )
                        )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass

    # Always verify SBOM presence when dependency manifests exist
    has_sbom = any((repo_root / n).is_file() for n in ("sbom.json", "bom.json", "sbom.cdx.json"))
    if manifests and not has_sbom:
        rel = _rel_str(manifests[0], repo_root)
        findings.append(
            Finding(
                id=make_finding_id("SUP-001", "MISSING-SBOM", rel, 1),
                check_id="SUP-001",
                severity="Medium",
                confidence=0.9,
                file=rel,
                line=1,
                rule="MISSING-SBOM",
                evidence=f"Manifest {rel} present without CycloneDX/SPDX SBOM.",
                blast_radius=[rel],
                standards=["ISO 27001 A.8", "OWASP ASVS 10"],
                fix="Generate CycloneDX SBOM via `trivy fs --format cyclonedx -o sbom.cdx.json .`.",
                message="No SBOM artifact found for repository dependencies.",
            )
        )
    return _dedupe_findings(findings)


def _run_mes(files: list[Path], repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if f.suffix.lower() != ".py":
            continue
        rel = _rel_str(f, repo_root)
        for item in check_oee_file(f) + check_genealogy_file(f):
            item.file = rel
            item.blast_radius = [rel]
            findings.append(item)
    return findings


def _run_ot_guard(files: list[Path], repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        rel = _rel_str(f, repo_root)
        for otf in analyze_write_paths(f):
            findings.append(
                Finding(
                    id=make_finding_id("OT-001", otf.rule, rel, otf.line),
                    check_id="OT-001",
                    severity=otf.severity,
                    confidence=1.0,
                    file=rel,
                    line=otf.line,
                    rule=otf.rule,
                    evidence=otf.evidence,
                    blast_radius=[rel],
                    standards=[s.strip() for s in otf.standard.split(";") if s.strip()],
                    fix=otf.fix,
                    message=otf.message,
                )
            )
    return findings


def run_scanner(
    name: str,
    changed_files: Iterable[str | Path],
    repo_root: str | Path = ".",
    airgap: bool = False,
) -> list[Finding]:
    root = Path(repo_root).resolve()
    files = _resolve_files(changed_files, root)
    key = name.strip().lower()
    if key == "semgrep":
        return _run_semgrep(files, root, airgap=airgap)
    if key == "gitleaks":
        return _run_gitleaks(files, root)
    if key == "trivy":
        return _run_trivy(files, root, airgap=airgap)
    if key in {"mes", "mes_checks", "custom"}:
        return _run_mes(files, root)
    if key in {"ot_guard", "ot_write_guard", "ot"}:
        return _run_ot_guard(files, root)
    raise ValueError(f"Unknown scanner name: {name!r}")


def run_all_scanners(
    changed_files: Iterable[str | Path],
    repo_root: str | Path = ".",
    airgap: bool = False,
) -> list[Finding]:
    all_hits: list[Finding] = []
    for scanner_name in ("ot_guard", "mes_checks", "semgrep", "gitleaks", "trivy"):
        all_hits.extend(run_scanner(scanner_name, changed_files, repo_root=repo_root, airgap=airgap))
    return _dedupe_findings(all_hits)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run LineTrack deterministic scanners.")
    ap.add_argument("--sample", action="store_true", help="Scan sample_repo/ and print findings JSON")
    ap.add_argument("--path", default="sample_repo", help="Target directory or file")
    ap.add_argument("--scanner", default="all", help="Scanner name")
    ap.add_argument("--airgap", action="store_true", help="Offline mode")
    args = ap.parse_args()

    target = Path("sample_repo") if args.sample else Path(args.path)
    repo_root = target if target.is_dir() else target.parent
    findings = (
        run_all_scanners([target], repo_root=repo_root, airgap=args.airgap)
        if args.scanner == "all"
        else run_scanner(args.scanner, [target], repo_root=repo_root, airgap=args.airgap)
    )
    print(json.dumps([f.to_dict() for f in findings], indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
