"""Full-Audit mode (SQLite MVP, Spec P6/P12): map-reduce + invariants + traceability + HTML/PDF/SARIF."""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.reviewer.agents.orchestrator import evaluate_gate, run_review
from backend.reviewer.deterministic.mes_checks import load_mqtt_acl, load_rbac_matrix
from backend.reviewer.findings.sarif import export_sarif
from backend.reviewer.findings.schema import Finding, make_finding_id
from backend.reviewer.ingestion.flow_parser import is_flow_candidate, parse_flow_file
from backend.reviewer.ingestion.github_diff import SKIP_DIRS, ingest_local_repo
from backend.reviewer.reporting.html_report import render_audit_html
from backend.reviewer.reporting.pdf import generate_audit_pdf
from backend.store import ReviewerStore

UNVERIFIED_CONTROLS: list[dict[str, str]] = [
    {
        "control": "Network segmentation (OT PLC VLAN vs IT/corporate LAN)",
        "status": "UNVERIFIED",
        "owner": "OT Infrastructure Lead",
        "due_date": "Week 6 (Pre-rollout)",
        "required_evidence": "Firewall ACL ruleset + VLAN diagram + Nmap isolation test log",
    },
    {
        "control": "Physical & hardware safety interlocks (E-stop / guard relays)",
        "status": "UNVERIFIED",
        "owner": "Plant Maintenance / OT SME",
        "due_date": "Week 6 (Pre-commissioning)",
        "required_evidence": "Signed PLC hardware interlock protocol + staging out-of-range rejection log",
    },
    {
        "control": "SAP Business One reconciliation (orders / inventory / lots)",
        "status": "UNVERIFIED",
        "owner": "SAP / ERP Integration Lead",
        "due_date": "Week 7 (UAT)",
        "required_evidence": "Reconciliation report comparing SAP Service Layer totals vs LineTrack DB",
    },
    {
        "control": "Database & Node-RED backup restore verification (AUD-001)",
        "status": "UNVERIFIED",
        "owner": "Plant SRE / DB Admin",
        "due_date": "Week 7 (DR Drill)",
        "required_evidence": "Dated restore verification log with RPO/RTO timing",
    },
    {
        "control": "Operator shop-floor workflow & shift handover controls",
        "status": "UNVERIFIED",
        "owner": "Plant Head / Quality Lead",
        "due_date": "Week 8 (Rollout Gate)",
        "required_evidence": "Signed SOP & IATF 16949 shop-floor audit checklist",
    },
]


def _load_check_catalogue(path: str | Path | None = None) -> list[dict[str, Any]]:
    candidates = [Path(path)] if path else []
    candidates.extend([Path.cwd() / "checks" / "check_catalogue.json", Path(__file__).resolve().parents[3] / "checks" / "check_catalogue.json"])
    for c in candidates:
        if c.is_file():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except Exception:
                pass
    return []


def _validate_cross_cutting_invariants(repo: Path, files: list[str]) -> tuple[dict[str, Any], list[Finding]]:
    extra_findings: list[Finding] = []
    rbac = load_rbac_matrix()
    mqtt_acl = load_mqtt_acl()

    discovered_routes: list[tuple[str, str, int]] = []
    route_re = re.compile(r"@(?:app|router)\.(get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']", re.I)
    for rel in files:
        if not rel.endswith(".py"):
            continue
        txt = (repo / rel).read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(txt.splitlines(), start=1):
            m = route_re.search(line)
            if m:
                discovered_routes.append((f"{m.group(1).upper()} {m.group(2)}", rel, lineno))

    rbac_endpoints = set((rbac.get("endpoints") or {}).keys())
    unmapped_routes = [
        r for r in discovered_routes
        if r[0] not in rbac_endpoints and not any(r[0].startswith(ep.split("{")[0]) for ep in rbac_endpoints)
    ]
    for route_sig, rel, lineno in unmapped_routes:
        extra_findings.append(
            Finding(
                id=make_finding_id("SEC-001", "RBAC-ENDPOINT-UNMAPPED", rel, lineno),
                check_id="SEC-001",
                severity="Medium",
                confidence=0.9,
                file=rel,
                line=lineno,
                rule="RBAC-ENDPOINT-UNMAPPED",
                evidence=route_sig,
                blast_radius=[rel],
                standards=["OWASP ASVS 4.1", "ISO 27001 A.9"],
                fix=f"Add `{route_sig}` to allow_lists/rbac_matrix.json with explicit 5-role permissions.",
                message=f"Endpoint `{route_sig}` is missing from allow_lists/rbac_matrix.json.",
            )
        )

    mqtt_topics: list[tuple[str, str, str, int]] = []
    for rel in files:
        fpath = repo / rel
        if rel.endswith(".json") and is_flow_candidate(fpath):
            for ep in parse_flow_file(fpath).mqtt_endpoints:
                mqtt_topics.append((ep.direction, ep.topic, rel, ep.line))

    allowed_pubs, allowed_subs = set(), set()
    for perms in mqtt_acl.values():
        if isinstance(perms, dict):
            allowed_pubs.update(perms.get("publish", []))
            allowed_subs.update(perms.get("subscribe", []))

    def _topic_matches(pattern: str, topic: str) -> bool:
        p_parts, t_parts = pattern.split("/"), topic.split("/")
        return len(p_parts) == len(t_parts) and all(pp == "+" or pp == tp for pp, tp in zip(p_parts, t_parts))

    unmatched_mqtt = 0
    for direction, topic, rel, lineno in mqtt_topics:
        allowed_set = allowed_pubs if direction == "publish" else allowed_subs
        if not topic or "#" in topic or (allowed_set and not any(_topic_matches(pat, topic) for pat in allowed_set)):
            unmatched_mqtt += 1
            extra_findings.append(
                Finding(
                    id=make_finding_id("OT-002", "MQTT-TOPIC-NOT-ALLOWLISTED", rel, lineno),
                    check_id="OT-002",
                    severity="High",
                    confidence=0.95,
                    file=rel,
                    line=lineno,
                    rule="MQTT-TOPIC-NOT-ALLOWLISTED",
                    evidence=f"{direction} topic={topic}",
                    blast_radius=[rel],
                    standards=["IEC 62443 SR 2.1", "IEC 62443 SR 3.3"],
                    fix="Restrict MQTT topic to allow_lists/mqtt_acl.json patterns.",
                    message=f"MQTT {direction} topic `{topic}` violates allow_lists/mqtt_acl.json.",
                )
            )

    genealogy_files = [rel for rel in files if "genealogy" in rel.lower() or "part" in (repo / rel).read_text(encoding="utf-8", errors="replace").lower()]
    invariants = {
        "rbac_summary": f"{len(discovered_routes)} route(s) scanned; {len(unmapped_routes)} unmapped in rbac_matrix.json",
        "mqtt_summary": f"{len(mqtt_topics)} MQTT endpoint(s) scanned; {unmatched_mqtt} ACL violation(s)",
        "genealogy_summary": f"{len(genealogy_files)} genealogy-related file(s) inspected for lot+machine+order+audit linkage",
    }
    return invariants, extra_findings


def _build_traceability_matrix(
    repo: Path,
    catalogue: list[dict[str, Any]],
    files: list[str],
    findings: list[Finding],
) -> list[dict[str, Any]]:
    test_files = [
        p.relative_to(repo).as_posix()
        for p in sorted(repo.rglob("test_*.py"))
        if not any(part in SKIP_DIRS for part in p.relative_to(repo).parts)
    ]
    test_contents = {tf: (repo / tf).read_text(encoding="utf-8", errors="replace").lower() for tf in test_files}

    hints: dict[str, tuple[str, list[str]]] = {
        "MES-001": ("OEE calculation", ["oee"]),
        "MES-002": ("Lot genealogy tracking", ["genealogy", "lot_id"]),
        "OT-001": ("PLC write-back safety gate", ["spindle", "feed_rate", "flows.json", "plc"]),
        "OT-002": ("MQTT topic ACL", ["mqtt"]),
        "OT-003": ("OPC UA session security", ["opcua"]),
        "SEC-001": ("RBAC & IDOR protection", ["rbac", "idor", "api.py"]),
        "LLM-001": ("Ask LineTrack prompt isolation", ["ask", "injection"]),
        "PRIV-001": ("DPDP PII handling", ["pii", "dpdp", "operator"]),
        "SUP-001": ("Secrets & SBOM hygiene", ["secret", "sbom"]),
        "AUD-001": ("Audit trail & backup restore", ["audit_log", "restore"]),
    }

    traceability: list[dict[str, Any]] = []
    for chk in catalogue:
        cid = chk["id"]
        label, keywords = hints.get(cid, (chk.get("name", cid), [cid.lower()]))
        impls = [f for f in files if any(k in f.lower() or k in (repo / f).read_text(encoding="utf-8", errors="replace").lower() for k in keywords)]
        matching_tests = [tf for tf, txt in test_contents.items() if cid.lower() in txt or any(k in txt for k in keywords)]
        related_findings = [f for f in findings if f.check_id == cid]

        if cid == "AUD-001" and not matching_tests:
            status = "GAP / UNVERIFIED (no test & no backup restore log)"
        elif not matching_tests:
            status = f"GAP (no test; {len(related_findings)} finding(s))"
        elif related_findings:
            status = f"FAIL ({len(related_findings)} finding(s))"
        else:
            status = "PASS (tested)"

        traceability.append({
            "requirement": f"{cid}: {label}",
            "implementation": ", ".join(impls) if impls else "NONE",
            "test": ", ".join(matching_tests) if matching_tests else "NONE",
            "status": status,
        })
    return traceability


def build_audit_metadata(repo_root: str | Path, existing_findings: list[Finding] | None = None) -> dict[str, Any]:
    """Build cross-cutting invariants, check catalogue status, traceability, and UNVERIFIED list."""
    repo = Path(repo_root).resolve()
    ingested = ingest_local_repo(repo)
    all_files = ingested.file_paths()
    findings = list(existing_findings or [])
    invariants, inv_findings = _validate_cross_cutting_invariants(repo, all_files)

    seen = {(f.check_id, f.rule, f.file, f.line) for f in findings}
    for inf in inv_findings:
        key = (inf.check_id, inf.rule, inf.file, inf.line)
        if key not in seen:
            seen.add(key)
            findings.append(inf)

    catalogue = _load_check_catalogue()
    traceability = _build_traceability_matrix(repo, catalogue, all_files, findings)
    by_check: dict[str, list[Finding]] = {}
    for f in findings:
        by_check.setdefault(f.check_id, []).append(f)
    for chk in catalogue:
        cid = chk["id"]
        if cid == "AUD-001":
            chk["status"] = "UNVERIFIED (restore log missing)"
        elif by_check.get(cid):
            chk["status"] = f"FAIL ({len(by_check[cid])} finding(s))"
        elif any(t["requirement"].startswith(cid) and "GAP" in t["status"] for t in traceability):
            chk["status"] = "GAP (no tests)"
        else:
            chk["status"] = "PASS"

    return {
        "findings": findings,
        "invariants": invariants,
        "check_catalogue": catalogue,
        "traceability": traceability,
        "unverified": list(UNVERIFIED_CONTROLS),
    }


def run_full_audit(
    repo_root: str | Path = "sample_repo",
    mode: str = "full",
    shard_size: int = 4,
    html_out: str | Path = "audit.html",
    pdf_out: str | Path = "audit.pdf",
    sarif_out: str | Path = "findings.sarif",
    db_url: str | None = None,
    persist: bool = False,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    ingested = ingest_local_repo(repo)
    all_files = ingested.file_paths()
    shards = [all_files[i : i + shard_size] for i in range(0, len(all_files), shard_size)] or [all_files]

    merged_findings: list[Finding] = []
    total_cost = 0.0
    total_llm_calls = 0
    total_duration = 0.0
    is_airgap = mode == "airgap"

    for shard in shards:
        res = run_review(
            repo_root=repo,
            changed_files=shard,
            mode="airgap" if is_airgap else "full",
            airgap=is_airgap,
        )
        merged_findings.extend(res.get("final_findings", []))
        c = res.get("cost_summary") or {}
        total_cost += float(c.get("total_cost_usd", 0.0))
        total_llm_calls += int(c.get("llm_calls", 0))
        total_duration += float(res.get("duration_sec", 0.0))

    meta = build_audit_metadata(repo, existing_findings=merged_findings)
    unique_findings: list[Finding] = meta["findings"]
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    unique_findings.sort(key=lambda x: (sev_rank.get(x.severity, 9), x.file, x.line))

    verdict, exit_code = evaluate_gate(unique_findings)
    cost_summary = {"llm_calls": total_llm_calls, "total_cost_usd": round(total_cost, 6)}
    run_id = f"audit-{uuid.uuid4().hex[:10]}"

    report: dict[str, Any] = {
        "run_id": run_id,
        "repo": str(repo_root),
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "verdict": verdict,
        "exit_code": exit_code,
        "findings": unique_findings,
        "unverified": meta["unverified"],
        "check_catalogue": meta["check_catalogue"],
        "traceability": meta["traceability"],
        "invariants": meta["invariants"],
        "cost_summary": cost_summary,
        "duration_sec": round(total_duration, 3),
    }

    export_sarif(unique_findings, output_path=sarif_out)
    render_audit_html(report, output_path=html_out)
    generate_audit_pdf(report, output_path=pdf_out)

    if persist or db_url:
        store = ReviewerStore(db_url=db_url, auto_create=False)
        store.save_run(
            run_id=run_id,
            repo=str(repo_root),
            mode=mode,
            verdict=verdict,
            exit_code=exit_code,
            cost_usd=cost_summary["total_cost_usd"],
            duration_sec=report["duration_sec"],
            summary={"full_audit": True},
        )
        for f in unique_findings:
            store.save_finding(f.to_dict(), run_id=run_id, audit_id=run_id)
        serializable = dict(report)
        serializable["findings"] = [f.to_dict() for f in unique_findings]
        store.save_audit(
            audit_id=run_id,
            run_id=run_id,
            repo=str(repo_root),
            mode=mode,
            verdict=verdict,
            unverified_count=len(meta["unverified"]),
            cost_usd=cost_summary["total_cost_usd"],
            report=serializable,
        )

    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Run LineTrack Full Audit -> audit.html + audit.pdf + findings.sarif")
    ap.add_argument("--mode", choices=["full", "airgap"], default="full")
    ap.add_argument("--repo", default="sample_repo")
    ap.add_argument("--html-out", default="audit.html")
    ap.add_argument("--pdf-out", default="audit.pdf")
    ap.add_argument("--sarif-out", default="findings.sarif")
    ap.add_argument("--save", action="store_true", help="Persist full audit to SQLite reviewer.db")
    args = ap.parse_args()

    report = run_full_audit(
        repo_root=args.repo,
        mode=args.mode,
        html_out=args.html_out,
        pdf_out=args.pdf_out,
        sarif_out=args.sarif_out,
        persist=args.save,
    )
    gaps = sum(1 for t in report["traceability"] if "GAP" in t["status"])
    print(f"=== Full Audit Complete: {report['verdict']} ===")
    print(f"Findings   : {len(report['findings'])}")
    print(f"UNVERIFIED : {len(report['unverified'])} item(s) (never assumed pass)")
    print(f"Test GAPs  : {gaps}")
    print(f"Artifacts  : {args.html_out}, {args.pdf_out}, {args.sarif_out}")
    sys.exit(0)


if __name__ == "__main__":
    main()
