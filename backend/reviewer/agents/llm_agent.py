"""LLM client, prompt loader, model router, cost tracker, and shared specialist base."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from backend.reviewer.findings.schema import Finding
from backend.reviewer.guardrails.injection_guard import scan_for_injection, wrap_untrusted_data
from backend.reviewer.guardrails.redact import redact_secrets

MODEL_PRICING_PER_1M: dict[str, tuple[float, float]] = {
    "mini": (0.15, 0.60),
    "review": (2.50, 10.00),
    "judge": (5.00, 15.00),
}


@dataclass
class ReviewContext:
    repo_root: str
    changed_files: list[str]
    blast_radius_files: list[str]
    file_snippets: dict[str, str]
    scanner_findings: list[Finding] = field(default_factory=list)
    memory_hints: list[str] = field(default_factory=list)
    airgap: bool = False
    pr_text: str = ""


@dataclass
class FindingCandidate:
    agent: str
    finding: Finding
    rationale: str = ""
    model_tier: str = "deterministic"


@dataclass
class CostRecord:
    tier: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float


class CostTracker:
    def __init__(self) -> None:
        self.records: list[CostRecord] = []

    def add(self, tier: str, model: str, prompt_tokens: int, completion_tokens: int, free: bool = False) -> float:
        if free:
            cost = 0.0
        else:
            in_rate, out_rate = MODEL_PRICING_PER_1M.get(tier, (2.50, 10.00))
            cost = (prompt_tokens * in_rate + completion_tokens * out_rate) / 1_000_000.0
        self.records.append(CostRecord(tier, model, prompt_tokens, completion_tokens, cost))
        return cost

    @property
    def total_cost_usd(self) -> float:
        return round(sum(r.cost_usd for r in self.records), 6)

    @property
    def llm_calls(self) -> int:
        return len(self.records)

    def summary(self) -> dict[str, Any]:
        return {
            "llm_calls": self.llm_calls,
            "total_cost_usd": self.total_cost_usd,
            "by_tier": [
                {
                    "tier": r.tier,
                    "model": r.model,
                    "prompt_tokens": r.prompt_tokens,
                    "completion_tokens": r.completion_tokens,
                    "cost_usd": round(r.cost_usd, 6),
                }
                for r in self.records
            ],
        }


def load_prompt(prompt_name: str, prompts_dir: str | Path | None = None) -> str:
    candidates = [Path(prompts_dir) / f"{prompt_name}.md"] if prompts_dir else []
    candidates.extend([Path.cwd() / "prompts" / f"{prompt_name}.md", Path(__file__).resolve().parents[3] / "prompts" / f"{prompt_name}.md"])
    for path in candidates:
        if path.is_file():
            return path.read_text(encoding="utf-8")
    raise FileNotFoundError(f"Prompt template not found: prompts/{prompt_name}.md")


MAX_RUN_SPEND_USD = float(os.getenv("MAX_RUN_SPEND_USD", "0.05"))
MAX_RUN_LLM_CALLS = int(os.getenv("MAX_RUN_LLM_CALLS", "3"))


class LLMRouter:
    """Routes mini / review / judge calls to OpenAI, Azure OpenAI, local Ollama (airgap), or rule-only $0 fallback."""

    def __init__(self, airgap: bool = False, cost_tracker: CostTracker | None = None, client: Any = None):
        self.airgap = airgap
        self.cost_tracker = cost_tracker or CostTracker()
        self._injected_client = client
        self._ollama_reachable: bool | None = None
        use_openai = bool(os.getenv("OPENAI_API_KEY", "").strip())
        if use_openai:
            self.models = {
                "mini": os.getenv("OPENAI_MODEL_MINI", "gpt-4o-mini"),
                "review": os.getenv("OPENAI_MODEL_REVIEW", "gpt-4o-mini"),
                "judge": os.getenv("OPENAI_MODEL_JUDGE", "gpt-4o-mini"),
            }
        else:
            self.models = {
                "mini": os.getenv("AZURE_DEPLOYMENT_MINI", "gpt-4o-mini"),
                "review": os.getenv("AZURE_DEPLOYMENT_REVIEW", "gpt-4o-mini"),
                "judge": os.getenv("AZURE_DEPLOYMENT_JUDGE", "gpt-4o-mini"),
            }
        if self.models["judge"] == self.models["review"]:
            self.models["judge"] = "gpt-4.1" if use_openai else f"{self.models['judge']}-frontier"

    def model_for_tier(self, tier: str) -> str:
        return self.models.get(tier, self.models["review"])

    def complete(self, tier: str, system_prompt: str, user_data: str, label: str = "context") -> dict[str, Any]:
        safe_data = wrap_untrusted_data(label, redact_secrets(user_data))
        inj_scan = scan_for_injection(user_data, source=label)
        model_name = self.model_for_tier(tier)

        if self._injected_client is not None:
            resp = self._injected_client(tier=tier, model=model_name, system_prompt=system_prompt, user_prompt=safe_data)
            self.cost_tracker.add(
                tier,
                model_name,
                int(resp.get("prompt_tokens", max(1, len(safe_data) // 4))),
                int(resp.get("completion_tokens", 120)),
                free=self.airgap,
            )
            return resp

        if self.airgap:
            ollama_resp = self._try_ollama(system_prompt, safe_data)
            if ollama_resp is not None:
                self.cost_tracker.add(tier, ollama_resp["model"], len(safe_data) // 4, len(ollama_resp["text"]) // 4, free=True)
                return ollama_resp
            return {
                "mode": "airgap_rule_only",
                "model": "rule-only-fallback",
                "text": "Offline air-gap rule-only verification.",
                "injection_detected": inj_scan.detected,
                "candidates": [],
            }

        # Cost Guard Circuit Breaker: Cap total spend and total calls per run
        if self.cost_tracker.total_cost_usd >= MAX_RUN_SPEND_USD or self.cost_tracker.llm_calls >= MAX_RUN_LLM_CALLS:
            return {
                "mode": "circuit_breaker_tripped",
                "model": f"{model_name} (budget-cap-offline)",
                "text": f"Budget circuit breaker tripped (${self.cost_tracker.total_cost_usd:.4f} >= ${MAX_RUN_SPEND_USD:.2f} or {self.cost_tracker.llm_calls} calls). Deterministic fallback ($0.00).",
                "injection_detected": inj_scan.detected,
                "candidates": [],
            }

        openai_key = os.getenv("OPENAI_API_KEY", "").strip()
        azure_key = os.getenv("AZURE_OPENAI_KEY", "").strip()
        azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip()

        if openai_key:
            from openai import OpenAI

            client = OpenAI(api_key=openai_key, timeout=20.0)
            provider_mode = "openai"
        elif azure_key and azure_endpoint:
            from openai import AzureOpenAI

            client = AzureOpenAI(
                api_key=azure_key,
                azure_endpoint=azure_endpoint,
                api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21"),
                timeout=20.0,
            )
            provider_mode = "azure_openai"
        else:
            return {
                "mode": "deterministic_offline",
                "model": f"{model_name} (no-key-rule-only)",
                "text": "OPENAI_API_KEY not set; deterministic candidates only (Cost $0).",
                "injection_detected": inj_scan.detected,
                "candidates": [],
            }

        try:
            kwargs: dict[str, Any] = {
                "model": model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": safe_data},
                ],
                "max_completion_tokens": 220,
            }
            if not model_name.startswith(("o1", "o3", "o4")):
                kwargs["temperature"] = 0.0
            completion = client.chat.completions.create(**kwargs)
            usage = getattr(completion, "usage", None)
            pt = int(getattr(usage, "prompt_tokens", len(safe_data) // 4) or 0)
            ct = int(getattr(usage, "completion_tokens", 128) or 0)
            self.cost_tracker.add(tier, model_name, pt, ct)
            content = completion.choices[0].message.content or ""
            return {
                "mode": provider_mode,
                "model": model_name,
                "text": redact_secrets(content),
                "injection_detected": inj_scan.detected,
                "candidates": [],
            }
        except Exception as exc:
            return {
                "mode": f"{provider_mode}_fallback",
                "model": model_name,
                "text": f"LLM call skipped (deterministic preserved): {redact_secrets(str(exc))[:160]}",
                "injection_detected": inj_scan.detected,
                "candidates": [],
            }

    def _try_ollama(self, system_prompt: str, safe_data: str) -> dict[str, Any] | None:
        if self._ollama_reachable is False:
            return None
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        if not (host.startswith("http://localhost") or host.startswith("http://127.0.0.1")):
            self._ollama_reachable = False
            return None
        local_model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
        try:
            with httpx.Client(timeout=httpx.Timeout(0.4, read=3.0)) as client:
                r = client.post(
                    f"{host}/api/generate",
                    json={"model": local_model, "prompt": f"{system_prompt}\n\n{safe_data}", "stream": False},
                )
                if r.status_code == 200:
                    self._ollama_reachable = True
                    data = r.json()
                    return {"mode": "ollama_airgap", "model": local_model, "text": redact_secrets(str(data.get("response", ""))), "candidates": []}
        except Exception:
            self._ollama_reachable = False
            return None
        return None


class BaseSpecialistAgent:
    name: str = "BaseAgent"
    prompt_name: str = "llm_agent"
    check_ids: tuple[str, ...] = ()

    def __init__(self, router: LLMRouter | None = None, prompts_dir: str | Path | None = None):
        self.router = router or LLMRouter()
        self.prompts_dir = prompts_dir

    def _extra_candidates(self, context: ReviewContext) -> list[FindingCandidate]:
        return []

    def review(self, context: ReviewContext) -> list[FindingCandidate]:
        prompt_text = load_prompt(self.prompt_name, prompts_dir=self.prompts_dir)
        relevant_scanner = [f for f in context.scanner_findings if not self.check_ids or f.check_id in self.check_ids]
        candidates: list[FindingCandidate] = [
            FindingCandidate(
                agent=self.name,
                finding=f,
                rationale=f"Deterministic check {f.check_id}/{f.rule}.",
                model_tier="deterministic",
            )
            for f in relevant_scanner
        ]
        candidates.extend(self._extra_candidates(context))

        snippet_blob = "\n\n".join(f"FILE: {fn}\n{snip}" for fn, snip in sorted(context.file_snippets.items()))
        if not snippet_blob:
            return candidates

        triage_input = (
            f"Changed files: {context.changed_files}\n"
            f"Blast radius files: {context.blast_radius_files}\n"
            f"Scanner hits ({len(relevant_scanner)}): {[f.rule for f in relevant_scanner]}\n"
            f"Memory hints: {context.memory_hints[:3]}"
        )
        self.router.complete("mini", prompt_text, triage_input, label=f"{self.name}-triage")

        review_input = (
            f"Scanner findings:\n{json.dumps([f.to_dict() for f in relevant_scanner], indent=2)}\n\n"
            f"Graph-filtered code ({len(context.file_snippets)} files):\n{snippet_blob}"
        )
        review_resp = self.router.complete("review", prompt_text, review_input, label=f"{self.name}-review")

        for raw_cand in review_resp.get("candidates", []) or []:
            if not isinstance(raw_cand, dict):
                continue
            try:
                cand_finding = Finding(
                    id=str(raw_cand.get("id", "")),
                    check_id=str(raw_cand.get("check_id", self.check_ids[0] if self.check_ids else "SEC-001")),
                    severity=str(raw_cand.get("severity", "Medium")),
                    confidence=float(raw_cand.get("confidence", 0.6)),
                    file=str(raw_cand.get("file", context.changed_files[0] if context.changed_files else "unknown")),
                    line=int(raw_cand.get("line", 1)),
                    rule=str(raw_cand.get("rule", "LLM-CANDIDATE")),
                    evidence=str(raw_cand.get("evidence", "")),
                    blast_radius=list(raw_cand.get("blast_radius", context.blast_radius_files)),
                    standards=list(raw_cand.get("standards", [])),
                    fix=str(raw_cand.get("fix", "Verify with deterministic test.")),
                    message=str(raw_cand.get("message", "LLM candidate finding")),
                    verified_deterministically=False,
                )
                candidates.append(
                    FindingCandidate(
                        agent=self.name,
                        finding=cand_finding,
                        rationale=str(raw_cand.get("rationale", review_resp.get("text", ""))),
                        model_tier=str(review_resp.get("model", "review")),
                    )
                )
            except Exception:
                continue
        return candidates
