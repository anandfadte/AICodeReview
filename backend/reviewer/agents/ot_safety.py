"""OTSafetyAgent: owns OT-001 (PLC write gate), OT-002 (MQTT ACL), OT-003 (OPC UA)."""

from __future__ import annotations

from backend.reviewer.agents.llm_agent import BaseSpecialistAgent


class OTSafetyAgent(BaseSpecialistAgent):
    name = "OTSafetyAgent"
    prompt_name = "ot_safety_agent"
    check_ids = ("OT-001", "OT-002", "OT-003")
