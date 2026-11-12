"""MESCorrectnessAgent: owns MES-001 (OEE), MES-002 (Genealogy), AUD-001 (Audit trail)."""

from __future__ import annotations

from backend.reviewer.agents.llm_agent import BaseSpecialistAgent


class MESCorrectnessAgent(BaseSpecialistAgent):
    name = "MESCorrectnessAgent"
    prompt_name = "mes_correctness_agent"
    check_ids = ("MES-001", "MES-002", "AUD-001")
