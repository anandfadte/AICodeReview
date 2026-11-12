"""SecurityAgent: owns SEC-001 (RBAC/IDOR) and SUP-001 (Secrets/SBOM)."""

from __future__ import annotations

from backend.reviewer.agents.llm_agent import BaseSpecialistAgent


class SecurityAgent(BaseSpecialistAgent):
    name = "SecurityAgent"
    prompt_name = "security_agent"
    check_ids = ("SEC-001", "SUP-001")
