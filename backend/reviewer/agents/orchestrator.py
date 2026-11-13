"""Plain-Python Review Orchestrator (Plan -> Scanners -> Graph -> Agents (parallel) -> Judge -> Gate).

No LangGraph dependency in MVP; saves runs and findings strictly via SQLAlchemy
repository layer (`ReviewerStore`) into SQLite (`reviewer.db`).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from backend.reviewer.agents.judge import JudgeAgent
from backend.reviewer.agents.llm_agent import CostTracker, FindingCandidate, LLMRouter, ReviewContext
from backend.reviewer.agents.mes_correctness import MESCorrectnessAgent
from backend.reviewer.agents.ot_safety import OTSafetyAgent
from backend.reviewer.agents.privacy import PrivacyAgent
from backend.reviewer.agents.security import SecurityAgent
from backend.reviewer.deterministic.ot_write_guard import summarize_ot_checks
from backend.reviewer.findings.sarif import export_sarif
from backend.reviewer.findings.schema import Finding, infer_tool
from backend.reviewer.guardrails.injection_guard import injection_findings, wrap_untrusted_data
from backend.reviewer.guardrails.redact import redact_secrets
from backend.reviewer.guardrails.tool_allowlist import ToolGuard
from backend.reviewer.ingestion.github_diff import ingest_local_repo, is_docs_only_change, load_git_diff, parse_unified_diff
from backend.reviewer.memory.store import MemoryStoreStub
from backend.store import ReviewerStore


def evaluate_gate(findings: list[Finding], is_docs_only: bool = False) -> tuple[str, int]:
    """Plain Python release gate: BLOCK (exit 2) if any OT High or any Critical/High remains."""
    if is_docs_only and not findings:
        return ("PASS", 0)
    active = [f for f in findings if f.status != "SUPPRESSED"]
    ot_highs = [
        f for f in active
        if (f.check_id in {"OT-001", "OT-002", "OT-003"} or f.rule == "UNPARSABLE_FLOW")
        and f.severity in {"Critical", "High"}
    ]
    any_highs = [f for f in active if f.severity in {"Critical", "High"}]
    return ("BLOCK", 2) if (ot_highs or any_highs) else ("PASS", 0)


def compute_tool_breakdown(findings: list[Finding]) -> dict[str, Any]:
    """White-box developer telemetry: breakdown of findings across static & domain tools."""
    tools: dict[str, dict[str, Any]] = {
        "OT Write Guard": {"total": 0, "high_critical": 0, "rules": []},
        "Gitleaks": {"total": 0, "high_critical": 0, "rules": []},
        "Trivy": {"total": 0, "high_critical": 0, "rules": []},
        "Semgrep": {"total": 0, "high_critical": 0, "rules": []},
        "MES Domain Checks": {"total": 0, "high_critical": 0, "rules": []},
        "Injection Guard": {"total": 0, "high_critical": 0, "rules": []},
    }
    for f in findings:
        t_name = f.tool or infer_tool(f.check_id, f.rule)
        if t_name not in tools:
            tools[t_name] = {"total": 0, "high_critical": 0, "rules": []}
        tools[t_name]["total"] += 1
        if f.severity in {"Critical", "High"} and f.status != "SUPPRESSED":
            tools[t_name]["high_critical"] += 1
        if f.rule not in tools[t_name]["rules"]:
            tools[t_name]["rules"].append(f.rule)
    return tools


def run_review(
    repo_root: str | Path = "sample_repo",
    changed_files: list[str] | None = None,
    diff_text: str | None = None,
    base_ref: str | None = None,
    head_ref: str | None = None,
    pr_text: str = "",
    pr_number: str = "",
    branch: str = "",
    run_id: str | None = None,
    mode: str = "pr",
    airgap: bool = False,
    llm_client: Any = None,
    db_url: str | None = None,
    persist: bool = False,
) -> dict[str, Any]:
    """Execute Plan -> Scanners -> Graph -> Agents (parallel) -> Judge -> Gate."""
    t_start = time.perf_counter()
    root = Path(repo_root).resolve()
    effective_airgap = airgap or (mode == "airgap")
    active_run_id = run_id or f"run-{uuid.uuid4().hex[:10]}"
    cost_tracker = CostTracker()
    router = LLMRouter(airgap=effective_airgap, cost_tracker=cost_tracker, client=llm_client)
    tool_guard = ToolGuard(repo_root=root, db_url=db_url)
    memory = MemoryStoreStub(db_url=db_url, persist=False)

    # 1. PLAN
    if diff_text is not None:
        diff_res = parse_unified_diff(diff_text, repo_root=root)
        initial_changed = diff_res.file_paths()
        docs_only = diff_res.is_docs_only
    elif base_ref and head_ref:
        diff_res = load_git_diff(root, base_ref=base_ref, head_ref=head_ref)
        initial_changed = diff_res.file_paths()
        docs_only = diff_res.is_docs_only
    elif changed_files is not None:
        initial_changed = [c.replace("\\", "/") for c in changed_files]
        docs_only = is_docs_only_change(initial_changed)
    else:
        diff_res = ingest_local_repo(root)
        initial_changed = diff_res.file_paths()
        docs_only = diff_res.is_docs_only

    if docs_only:
        elapsed = round(time.perf_counter() - t_start, 4)
        ot_checks = {k: "PASS" for k in ("allowlist", "clamp", "auth", "interlock", "audit")}
        cost_summary = cost_tracker.summary()
        state: dict[str, Any] = {
            "run_id": active_run_id,
            "repo": str(repo_root),
            "mode": mode,
            "is_docs_only": True,
            "changed_files": initial_changed,
            "blast_radius_files": [],
            "blast_ratio": 0.0,
            "ot_checks": ot_checks,
            "final_findings": [],
            "judge_log": [],
            "injection_detected": False,
            "verdict": "PASS",
            "exit_code": 0,
            "cost_summary": cost_summary,
            "duration_sec": elapsed,
        }
        if persist:
            _persist_run(state, db_url=db_url, branch=branch, pr_number=pr_number)
        return state

    # 2. SCANNERS (deterministic first)
    target_list = initial_changed or [str(root)]
    raw_findings: list[Finding] = []
    for scanner_name in ("ot_guard", "mes_checks", "semgrep", "gitleaks", "trivy"):
        raw_findings.extend(
            tool_guard.invoke(
                "run_scanner",
                name=scanner_name,
                changed_files=target_list,
                repo_root=root,
                airgap=effective_airgap,
            )
        )
    if pr_text:
        raw_findings.extend(injection_findings(pr_text, "PR_DESCRIPTION"))

    seen: set[tuple[str, str, str, int]] = set()
    scanner_findings: list[Finding] = []
    for f in raw_findings:
        key = (f.check_id, f.rule, f.file, f.line)
        if key not in seen:
            seen.add(key)
            scanner_findings.append(f)

    # 3. GRAPH (blast radius filter, ~35% target)
    br = tool_guard.invoke("run_graph", repo_root=root, changed_files=initial_changed)
    br_files = list(br.blast_radius_files)
    flagged_files = {f.file for f in scanner_findings}
    llm_scope = br_files
    if len(initial_changed) == br.total_files and br.total_files > 4:
        priority = [f for f in br_files if f in flagged_files]
        cap = max(1, round(br.total_files * 0.35))
        llm_scope = priority[:cap] if len(priority) >= cap else priority

    snippets: dict[str, str] = {}
    for rel in br_files:
        if rel not in set(llm_scope) and rel not in flagged_files:
            continue
        if (root / rel).is_file():
            try:
                raw = tool_guard.invoke("read_file", path=rel)
                snippets[rel] = wrap_untrusted_data(rel, redact_secrets(raw))
            except Exception:
                continue

    hints: list[str] = []
    for f in scanner_findings[:5]:
        for m in memory.search(f"{f.check_id} {f.rule} {f.file}", top_k=2):
            hints.append(f"{m.title}: {m.content}")

    # 4. AGENTS (parallel)
    ctx = ReviewContext(
        repo_root=str(root),
        changed_files=initial_changed,
        blast_radius_files=llm_scope,
        file_snippets=snippets,
        scanner_findings=scanner_findings,
        memory_hints=hints,
        airgap=effective_airgap,
        pr_text=pr_text,
    )
    specialists = [
        SecurityAgent(router=router),
        OTSafetyAgent(router=router),
        MESCorrectnessAgent(router=router),
        PrivacyAgent(router=router),
    ]
    all_candidates: list[FindingCandidate] = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for res in pool.map(lambda ag: ag.review(ctx), specialists):
            all_candidates.extend(res)

    # 5. JUDGE (deterministic re-verification)
    judge = JudgeAgent(router=router, repo_root=root, airgap=effective_airgap)
    final_findings, judge_log = judge.judge(all_candidates, tool_guard=tool_guard, pr_text=pr_text)

    # 6. GATE (plain Python)
    verdict, exit_code = evaluate_gate(final_findings, is_docs_only=False)
    ot_checks = summarize_ot_checks([f for f in final_findings if f.check_id == "OT-001" or f.rule == "UNPARSABLE_FLOW"])  # type: ignore[arg-type]
    elapsed = round(time.perf_counter() - t_start, 4)
    cost_summary = cost_tracker.summary()
    tool_breakdown = compute_tool_breakdown(final_findings)

    state = {
        "run_id": active_run_id,
        "repo": str(repo_root),
        "mode": mode,
        "is_docs_only": False,
        "changed_files": initial_changed,
        "blast_radius_files": llm_scope,
        "blast_ratio": round(br.file_ratio, 3),
        "ot_checks": ot_checks,
        "final_findings": final_findings,
        "judge_log": judge_log,
        "injection_detected": any(f.rule == "INJECTION_ATTEMPT" for f in final_findings),
        "verdict": verdict,
        "exit_code": exit_code,
        "cost_summary": cost_summary,
        "tool_breakdown": tool_breakdown,
        "duration_sec": elapsed,
    }
    if persist:
        _persist_run(state, db_url=db_url, branch=branch, pr_number=pr_number)
    return state


def _persist_run(state: dict[str, Any], db_url: str | None = None, branch: str = "", pr_number: str = "") -> None:
    store = ReviewerStore(db_url=db_url, auto_create=False)
    run_id = state["run_id"]
    repo_name = state.get("repo", "sample_repo")
    for f in state.get("final_findings", []):
        f_dict = f.to_dict()
        if not f_dict.get("repo"):
            f_dict["repo"] = repo_name
        store.save_finding(f_dict, run_id=run_id)
    tool_breakdown = state.get("tool_breakdown") or compute_tool_breakdown(state.get("final_findings", []))
    store.save_run(
        run_id=run_id,
        repo=state["repo"],
        branch=branch,
        pr_number=pr_number,
        mode=state["mode"],
        verdict=state["verdict"],
        exit_code=state["exit_code"],
        cost_usd=float((state.get("cost_summary") or {}).get("total_cost_usd", 0.0)),
        duration_sec=float(state.get("duration_sec", 0.0)),
        judge_log=state.get("judge_log", []),
        ot_checks=state.get("ot_checks", {}),
        summary={
            "is_docs_only": state.get("is_docs_only", False),
            "blast_ratio": state.get("blast_ratio", 0.0),
            "tool_breakdown": tool_breakdown,
            "cost_summary": state.get("cost_summary", {}),
        },
    )


def main() -> None:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[3] / ".env", override=False)
    ap = argparse.ArgumentParser(description="Run LineTrack Review Orchestrator (Plain Python)")
    ap.add_argument("--repo", default="sample_repo", help="Target repository path")
    ap.add_argument("--changed", nargs="*", help="Changed file(s)")
    ap.add_argument("--pr-text", default="", help="Untrusted PR description")
    ap.add_argument("--mode", choices=["pr", "full", "airgap"], default="airgap")
    ap.add_argument("--sarif", help="Optional SARIF output path")
    ap.add_argument("--save", action="store_true", help="Save run & findings into SQLite reviewer.db")
    args = ap.parse_args()

    result = run_review(
        repo_root=args.repo,
        changed_files=args.changed,
        pr_text=args.pr_text,
        mode=args.mode,
        airgap=(args.mode == "airgap"),
        persist=args.save,
    )
    findings: list[Finding] = result.get("final_findings", [])
    if args.sarif:
        export_sarif(findings, output_path=args.sarif)

    cost = result["cost_summary"]["total_cost_usd"]
    highs = sum(1 for f in findings if f.severity in {"Critical", "High"})
    print(f"=== LineTrack Reviewer Verdict: {result['verdict']} (exit {result['exit_code']}) ===")
    print(f"Findings: {len(findings)} total, {highs} Critical/High | Cost: ${cost:.6f} | Time: {result['duration_sec']}s")
    print("\n--- Judge Log ---")
    print(json.dumps(result["judge_log"], indent=2))
    sys.exit(int(result["exit_code"]))


if __name__ == "__main__":
    main()
