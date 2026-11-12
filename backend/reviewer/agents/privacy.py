"""PrivacyAgent: owns PRIV-001 (DPDP PII) and LLM-001 (Ask LineTrack + prompt injection guard)."""

from __future__ import annotations

from backend.reviewer.agents.llm_agent import BaseSpecialistAgent, FindingCandidate, ReviewContext
from backend.reviewer.guardrails.injection_guard import injection_findings


class PrivacyAgent(BaseSpecialistAgent):
    name = "PrivacyAgent"
    prompt_name = "privacy_agent"
    check_ids = ("PRIV-001", "LLM-001")

    def _extra_candidates(self, context: ReviewContext) -> list[FindingCandidate]:
        extras: list[FindingCandidate] = []
        if context.pr_text:
            for f in injection_findings(context.pr_text, "PR_DESCRIPTION"):
                extras.append(FindingCandidate(self.name, f, "Injection pattern in PR text.", "deterministic"))
        for fname, snippet in context.file_snippets.items():
            raw_text = snippet
            if raw_text.startswith("<UNTRUSTED_DATA") and "\n" in raw_text:
                lines = raw_text.splitlines()
                if len(lines) >= 2 and lines[-1].strip() == "</UNTRUSTED_DATA>":
                    raw_text = "\n".join(lines[1:-1])
            for f in injection_findings(raw_text, fname):
                extras.append(FindingCandidate(self.name, f, f"Injection pattern in {fname}.", "deterministic"))
        return extras
