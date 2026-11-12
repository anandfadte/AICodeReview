"""Independent JudgeAgent — deterministic re-verification for High/Critical (and Medium+ in airgap)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.reviewer.agents.llm_agent import FindingCandidate, LLMRouter, load_prompt
from backend.reviewer.deterministic.scanners import run_scanner
from backend.reviewer.findings.schema import Finding
from backend.reviewer.guardrails.injection_guard import injection_findings
from backend.reviewer.guardrails.tool_allowlist import ToolGuard


class JudgeAgent:
    def __init__(
        self,
        router: LLMRouter | None = None,
        repo_root: str | Path = ".",
        prompts_dir: str | Path | None = None,
        airgap: bool = False,
    ):
        self.router = router or LLMRouter(airgap=airgap)
        self.repo_root = Path(repo_root).resolve()
        self.prompts_dir = prompts_dir
        self.airgap = airgap

    def _reproduce_deterministically(self, finding: Finding, pr_text: str = "") -> tuple[bool, str]:
        if finding.rule == "INJECTION_ATTEMPT":
            if finding.file == "PR_DESCRIPTION":
                hits = injection_findings(pr_text, "PR_DESCRIPTION")
                return (any(h.rule == "INJECTION_ATTEMPT" for h in hits), "injection_guard(PR_DESCRIPTION)")
            target = self.repo_root / finding.file
            if target.is_file():
                hits = injection_findings(target.read_text(encoding="utf-8", errors="replace"), finding.file)
                return (any(h.rule == "INJECTION_ATTEMPT" for h in hits), f"injection_guard({finding.file})")
            return (False, "injection_guard(missing_file)")

        target_path = self.repo_root / finding.file
        if not target_path.exists():
            return (False, f"missing_file({finding.file})")

        probe_map = {
            "OT-001": "ot_guard",
            "MES-001": "mes_checks",
            "MES-002": "mes_checks",
            "SUP-001": "gitleaks" if "GITLEAKS" in finding.rule else "trivy",
            "SEC-001": "semgrep",
            "OT-002": "semgrep",
            "OT-003": "semgrep",
            "LLM-001": "semgrep",
            "PRIV-001": "semgrep",
        }
        scanner_name = probe_map.get(finding.check_id, "semgrep")
        re_hits = run_scanner(scanner_name, [finding.file], repo_root=self.repo_root, airgap=self.airgap)
        reproduced = any(
            h.check_id == finding.check_id and (h.rule == finding.rule or h.line == finding.line)
            for h in re_hits
        )
        return (reproduced, f"run_scanner({scanner_name}, {finding.file})")

    def judge(
        self,
        candidates: list[FindingCandidate],
        tool_guard: ToolGuard | None = None,
        pr_text: str = "",
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        judge_prompt = load_prompt("judge", prompts_dir=self.prompts_dir)
        judge_model = self.router.model_for_tier("judge")
        reviewer_model = self.router.model_for_tier("review")
        assert judge_model != reviewer_model, "Judge must use a different model than reviewer."

        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        dedup: dict[tuple[str, str, str, int], FindingCandidate] = {}
        for cand in candidates:
            f = cand.finding
            key = (f.check_id, f.rule, f.file, f.line)
            prev = dedup.get(key)
            if prev is None or sev_rank.get(f.severity, 9) < sev_rank.get(prev.finding.severity, 9):
                dedup[key] = cand

        final_findings: list[Finding] = []
        judge_log: list[dict[str, Any]] = []
        reproduced_batch: list[str] = []

        for cand in dedup.values():
            f = cand.finding
            needs_judge = f.severity in {"Critical", "High"} or (self.airgap and f.severity == "Medium")
            if not needs_judge:
                final_findings.append(f)
                continue

            reproduced, probe_name = self._reproduce_deterministically(f, pr_text=pr_text)
            if f.severity in {"Critical", "High"} and not reproduced:
                initial_sev = f.severity
                if f.confidence < 0.5:
                    judge_log.append({
                        "finding_id": f.id, "check_id": f.check_id, "rule": f.rule, "file": f.file, "line": f.line,
                        "initial_severity": initial_sev, "final_severity": "DROPPED", "decision": "DROP",
                        "reproduced": False, "deterministic_probe": probe_name, "model": judge_model,
                        "reason": "Deterministic probe failed to reproduce low-confidence High; dropped per Spec P1.",
                    })
                    continue

                f.severity = "Medium"
                f.verified_deterministically = False
                f.message = f"[Downgraded by Judge from {initial_sev} — unverified deterministically] {f.message}"
                final_findings.append(f)
                judge_log.append({
                    "finding_id": f.id, "check_id": f.check_id, "rule": f.rule, "file": f.file, "line": f.line,
                    "initial_severity": initial_sev, "final_severity": "Medium", "decision": "DOWNGRADE",
                    "reproduced": False, "deterministic_probe": probe_name, "model": judge_model,
                    "reason": "Deterministic probe failed to reproduce; downgraded to Medium per Spec P1.",
                })
                continue

            f.verified_deterministically = reproduced
            reproduced_batch.append(f"{f.check_id}/{f.rule} @ {f.file}:{f.line} ({probe_name})")
            final_findings.append(f)
            judge_log.append({
                "finding_id": f.id, "check_id": f.check_id, "rule": f.rule, "file": f.file, "line": f.line,
                "initial_severity": f.severity, "final_severity": f.severity,
                "decision": "APPROVE" if reproduced else "HUMAN_REVIEW",
                "reproduced": reproduced, "deterministic_probe": probe_name, "model": judge_model,
                "reason": f"Reproduced deterministically by {probe_name}." if reproduced else "Air-gap Medium routed to human gate.",
            })

        if reproduced_batch:
            self.router.complete(
                "judge",
                judge_prompt,
                "Deterministically reproduced High/Critical findings:\n" + "\n".join(reproduced_batch),
                label="judge-batch",
            )

        final_findings.sort(key=lambda x: (sev_rank.get(x.severity, 9), x.file, x.line))
        return final_findings, judge_log
