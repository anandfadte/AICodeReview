"""FastAPI application for LineTrack Reviewer (pure JSON REST API; UI migrates separately)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

# Support running directly via `python backend/app.py` from repo root
_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))
load_dotenv(_ROOT_DIR / ".env", override=False)

from backend.schemas import (
    FindingOut,
    HealthOut,
    ReportOut,
    ReviewRequest,
    ReviewRunOut,
    SuppressRequest,
)
from backend.store import ReviewerStore
from backend.reviewer.agents.orchestrator import run_review
from backend.reviewer.findings.sarif import export_sarif

app = FastAPI(title="LineTrack Reviewer API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def _get_store() -> ReviewerStore:
    return ReviewerStore(auto_create=False)


@app.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    store = _get_store()
    return HealthOut(status="ok", db=store.db_backend_name(), version="0.1.0")


@app.post("/api/review", response_model=ReviewRunOut)
def create_review(req: ReviewRequest) -> ReviewRunOut:
    """Execute Plan -> Scanners -> Graph -> Agents -> Judge -> Gate and persist to SQLite."""
    store = _get_store()
    run_id = f"run-{uuid.uuid4().hex[:10]}"
    repo_raw = req.repo_path.strip()

    if repo_raw.startswith(("http://", "https://", "git@")):
        # Clone Git repository into temporary directory
        repo_name = re.sub(r"[^a-zA-Z0-9_-]", "_", repo_raw.split("/")[-1].replace(".git", ""))
        clone_dir = Path("/tmp/reviewer/cloned") / repo_name
        if clone_dir.exists():
            shutil.rmtree(clone_dir, ignore_errors=True)
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone", "--depth", "1"]
        if req.branch:
            cmd.extend(["--branch", req.branch])
        cmd.extend([repo_raw, str(clone_dir)])
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
            repo_target = clone_dir
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            err_msg = getattr(exc, "stderr", "") or str(exc)
            raise HTTPException(status_code=400, detail=f"Failed to clone git repository '{repo_raw}': {err_msg}") from exc
    else:
        repo_target = Path(repo_raw)
        if not repo_target.is_absolute():
            repo_target = (_ROOT_DIR / repo_target).resolve()
        if not repo_target.exists():
            raise HTTPException(status_code=404, detail=f"Target repository path not found: {repo_target}")

    run_review(
        repo_root=repo_target,
        changed_files=req.changed_files,
        pr_text=req.pr_text,
        pr_number=req.pr_number,
        branch=req.branch,
        run_id=run_id,
        mode=req.mode,
        airgap=(req.mode == "airgap"),
        persist=True,
    )
    run = store.get_run(run_id)
    assert run is not None
    return ReviewRunOut(**run)


@app.get("/api/runs/{run_id}", response_model=ReviewRunOut)
def get_run(run_id: str) -> ReviewRunOut:
    store = _get_store()
    run = store.get_latest_run() if run_id == "latest" else store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
    return ReviewRunOut(**run)


@app.get("/api/findings", response_model=list[FindingOut])
def list_findings(run_id: str = Query(default="")) -> list[FindingOut]:
    store = _get_store()
    target_run = run_id or (store.get_latest_run() or {}).get("run_id")
    if not target_run:
        return []
    rows = store.get_findings(run_id=target_run)
    return [FindingOut(**r) for r in rows]


@app.post("/api/findings/{finding_id}/suppress")
def suppress_finding_endpoint(finding_id: str, body: SuppressRequest) -> dict[str, Any]:
    store = _get_store()
    try:
        sup = store.suppress_finding(finding_id=finding_id, owner=body.owner, reason=body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"finding_id": finding_id, "status": "SUPPRESSED", "suppression": sup}


@app.get("/api/sarif")
def get_sarif(run_id: str = Query(default="")) -> dict[str, Any]:
    store = _get_store()
    target_run = run_id or (store.get_latest_run() or {}).get("run_id")
    findings = store.get_findings(run_id=target_run, include_suppressed=False) if target_run else []
    return export_sarif(findings, include_suppressed=False)


@app.get("/api/report", response_model=ReportOut)
def get_report(run_id: str = Query(default=""), format: str = Query(default="json")):
    from backend.reviewer.findings.schema import Finding
    from backend.reviewer.reporting.audit import build_audit_metadata
    from backend.reviewer.reporting.html_report import render_audit_html

    store = _get_store()
    target_run = run_id or (store.get_latest_run() or {}).get("run_id")
    if not target_run:
        empty = ReportOut(run_id="none", repo="sample_repo", mode="pr", verdict="PASS")
        if format == "html":
            return Response(
                content=render_audit_html(empty.model_dump()),
                media_type="text/html",
                headers={"Content-Disposition": 'attachment; filename="audit.html"'},
            )
        return empty

    run = store.get_run(target_run) or {"repo": "sample_repo", "mode": "pr", "verdict": "PASS", "cost_usd": 0.0}
    findings_dicts = store.get_findings(run_id=target_run)
    audit_data = store.get_audit_by_run(target_run)

    if not audit_data:
        repo_path = Path(run.get("repo", "sample_repo"))
        if not repo_path.is_absolute():
            repo_path = (_ROOT_DIR / repo_path).resolve()
        f_objs = [
            Finding(
                id=fd["id"],
                check_id=fd["check_id"],
                severity=fd["severity"],
                confidence=fd["confidence"],
                file=fd["file"],
                line=fd["line"],
                rule=fd["rule"],
                evidence=fd["evidence"],
                blast_radius=fd["blast_radius"],
                standards=fd["standards"],
                fix=fd["fix"],
                status=fd["status"],
                suppression=fd["suppression"],
                message=fd["message"],
                verified_deterministically=fd["verified_deterministically"],
            )
            for fd in findings_dicts
        ]
        audit_data = build_audit_metadata(repo_path, existing_findings=f_objs) if repo_path.exists() else {}

    report = ReportOut(
        run_id=target_run,
        repo=run.get("repo", "sample_repo"),
        mode=run.get("mode", "pr"),
        verdict=run.get("verdict", "PASS"),
        findings=[FindingOut(**f) for f in findings_dicts],
        check_catalogue=audit_data.get("check_catalogue", []),
        traceability=audit_data.get("traceability", []),
        unverified=audit_data.get("unverified", []),
        invariants=audit_data.get("invariants", {}),
        cost_summary=audit_data.get("cost_summary", {"total_cost_usd": run.get("cost_usd", 0.0)}),
    )
    if format == "html":
        html_body = render_audit_html(
            {
                **report.model_dump(),
                "generated_at": run.get("created_at", ""),
            }
        )
        return Response(
            content=html_body,
            media_type="text/html",
            headers={"Content-Disposition": 'attachment; filename="audit.html"'},
        )
    return report


@app.get("/api/eval")
def get_eval() -> dict[str, Any]:
    from backend.reviewer.evaluation.eval import evaluate_golden_set

    metrics = evaluate_golden_set()
    return {k: v for k, v in metrics.items() if k != "outcomes"}


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("backend.app:app", host="0.0.0.0", port=port, reload=False)
