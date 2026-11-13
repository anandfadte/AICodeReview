"""GitHub Checks & PR Comment reporting for LineTrack Review Gate (SQLite MVP)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

from backend.reviewer.agents.orchestrator import run_review
from backend.reviewer.findings.sarif import export_sarif
from backend.reviewer.findings.schema import Finding
from backend.reviewer.guardrails.redact import redact_secrets


def format_pr_comment(review_state: dict[str, Any]) -> str:
    verdict = str(review_state.get("verdict", "PASS"))
    findings: list[Finding] = list(review_state.get("final_findings", []))
    cost_summary = review_state.get("cost_summary") or {"total_cost_usd": 0.0, "llm_calls": 0}
    duration = float(review_state.get("duration_sec") or 0.0)
    is_docs_only = bool(review_state.get("is_docs_only", False))

    highs = [f for f in findings if f.severity in {"Critical", "High"} and f.status != "SUPPRESSED"]
    mediums = [f for f in findings if f.severity == "Medium" and f.status != "SUPPRESSED"]
    lows = [f for f in findings if f.severity in {"Low", "Info"} and f.status != "SUPPRESSED"]

    badge = "BLOCKED (Merge Denied)" if verdict == "BLOCK" else "PASSED"
    lines = [
        f"## LineTrack Review Gate — **{verdict}** ({badge})",
        "",
        f"- **Docs-only fast path:** `{is_docs_only}`",
        f"- **Findings:** {len(highs)} Critical/High | {len(mediums)} Medium | {len(lows)} Low/Info",
        f"- **LLM Cost:** `${cost_summary.get('total_cost_usd', 0.0):.6f}` ({cost_summary.get('llm_calls', 0)} calls) | **Time:** `{duration:.3f}s`",
        "",
    ]

    if highs:
        lines.append("### Blocking Critical / High Findings (Judge-Verified)")
        lines.append("| Check | Rule | Location | Fix |")
        lines.append("|---|---|---|---|")
        for f in highs:
            fix_txt = redact_secrets(f.fix).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{f.check_id}` | `{f.rule}` | `{f.file}:{f.line}` | {fix_txt} |")
        lines.append("")
    else:
        lines.append("### Critical / High Findings\nNone.\n")

    if mediums:
        lines.append("### Medium Findings Summary")
        for f in mediums:
            lines.append(f"- `{f.file}:{f.line}` **{f.check_id}/{f.rule}** — {redact_secrets(f.message)}")
        lines.append("")

    if lows:
        lines.append(f"### Low / Info Summary\n{len(lows)} advisory item(s) recorded in SARIF.")

    return redact_secrets("\n".join(lines).strip() + "\n")


def build_github_check_payload(
    review_state: dict[str, Any],
    head_sha: str = "HEAD",
    name: str = "LineTrack Review Gate",
) -> dict[str, Any]:
    verdict = str(review_state.get("verdict", "PASS"))
    conclusion = "failure" if verdict == "BLOCK" else "success"
    findings: list[Finding] = list(review_state.get("final_findings", []))
    highs = sum(1 for f in findings if f.severity in {"Critical", "High"} and f.status != "SUPPRESSED")
    mediums = sum(1 for f in findings if f.severity == "Medium" and f.status != "SUPPRESSED")
    return {
        "name": name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": redact_secrets(f"{verdict}: {highs} Critical/High, {mediums} Medium"),
            "summary": format_pr_comment(review_state),
        },
    }


def post_github_check(payload: dict[str, Any], repo: str | None = None, token: str | None = None) -> dict[str, Any]:
    gh_repo = repo or os.getenv("GITHUB_REPOSITORY", "")
    gh_token = token or os.getenv("GITHUB_TOKEN", "")
    if not gh_repo or not gh_token:
        return {"posted": False, "reason": "dry_run_no_github_credentials", "payload": payload}
    url = f"https://api.github.com/repos/{gh_repo}/check-runs"
    headers = {"Authorization": f"Bearer {gh_token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return {"posted": True, "status_code": resp.status_code, "data": resp.json()}


def post_pr_comment(comment_body: str, pr_number: int | str, repo: str | None = None, token: str | None = None) -> dict[str, Any]:
    safe_body = redact_secrets(comment_body)
    gh_repo = repo or os.getenv("GITHUB_REPOSITORY", "")
    gh_token = token or os.getenv("GITHUB_TOKEN", "")
    if not gh_repo or not gh_token or not pr_number:
        return {"posted": False, "reason": "dry_run_no_github_credentials", "body": safe_body}
    url = f"https://api.github.com/repos/{gh_repo}/issues/{pr_number}/comments"
    headers = {"Authorization": f"Bearer {gh_token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url, json={"body": safe_body}, headers=headers)
        resp.raise_for_status()
        return {"posted": True, "status_code": resp.status_code, "data": resp.json()}


def main() -> None:
    ap = argparse.ArgumentParser(description="Run LineTrack PR review and emit GitHub Check + PR comment.")
    ap.add_argument("--repo", default=".", help="Repository path")
    ap.add_argument("--base", help="Base git ref")
    ap.add_argument("--head", help="Head git ref")
    ap.add_argument("--changed", nargs="*", help="Explicit changed files")
    ap.add_argument("--pr-number", default="", help="PR number")
    ap.add_argument("--pr-text", default="", help="PR description")
    ap.add_argument("--mode", choices=["pr", "full", "airgap"], default="airgap")
    ap.add_argument("--sarif", help="Output SARIF path")
    ap.add_argument("--comment-out", help="Output PR comment markdown path")
    ap.add_argument("--check-out", help="Output GitHub Check JSON path")
    ap.add_argument("--save", action="store_true", help="Persist run to SQLite")
    args = ap.parse_args()

    state = run_review(
        repo_root=args.repo,
        changed_files=args.changed,
        base_ref=args.base,
        head_ref=args.head,
        pr_text=args.pr_text,
        pr_number=args.pr_number,
        mode=args.mode,
        persist=args.save,
    )
    findings: list[Finding] = list(state.get("final_findings", []))
    comment_md = format_pr_comment(state)
    check_payload = build_github_check_payload(state, head_sha=args.head or "HEAD")

    if args.sarif:
        export_sarif(findings, output_path=args.sarif)
    if args.comment_out:
        Path(args.comment_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.comment_out).write_text(comment_md, encoding="utf-8")
    if args.check_out:
        Path(args.check_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.check_out).write_text(json.dumps(check_payload, indent=2), encoding="utf-8")

    post_github_check(check_payload)
    if args.pr_number:
        post_pr_comment(comment_md, pr_number=args.pr_number)

    print(comment_md)
    sys.exit(int(state.get("exit_code", 0)))


if __name__ == "__main__":
    main()
