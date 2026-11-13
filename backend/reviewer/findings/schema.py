"""Canonical Finding schema (Spec Sec. 4) with SARIF 2.1.0 conversion and secret redaction."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from backend.reviewer.guardrails.redact import redact_secrets

VALID_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
VALID_STATUSES = ("OPEN", "SUPPRESSED", "TP", "FP")


def normalize_severity(sev: str) -> str:
    low = (sev or "Medium").strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "error": "High",
        "medium": "Medium",
        "warning": "Medium",
        "low": "Low",
        "note": "Low",
        "info": "Info",
    }.get(low, "Medium")


def infer_tool(check_id: str, rule: str) -> str:
    r = (rule or "").upper()
    c = (check_id or "").upper()
    if r.startswith("GITLEAKS-") or "SECRET" in r or "AWS-KEY" in r or "PASSWORD" in r:
        return "Gitleaks"
    if r.startswith("CVE-") or r in {"MISSING-SBOM"}:
        return "Trivy"
    if r.startswith("SEMGREP-") or r.startswith("LINETRACK-"):
        return "Semgrep"
    if c == "OT-001" or r.startswith("PLC-WRITE-"):
        return "OT Write Guard"
    if r.startswith("INJECTION_"):
        return "Injection Guard"
    return "MES Domain Checks"


def make_finding_id(check_id: str, rule: str, file: str, line: int) -> str:
    raw = f"{check_id}:{rule}:{file}:{line}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12]


@dataclass
class Finding:
    id: str
    check_id: str
    severity: str
    confidence: float
    file: str
    line: int
    rule: str
    evidence: str
    blast_radius: list[str]
    standards: list[str]
    fix: str
    status: str = "OPEN"
    suppression: dict[str, Any] | None = None
    message: str = ""
    verified_deterministically: bool = True
    tool: str = ""

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.file = str(self.file).replace("\\", "/")
        self.line = max(1, int(self.line or 1))
        self.evidence = redact_secrets(self.evidence or "")[:500]
        self.fix = redact_secrets(self.fix or "")
        self.message = redact_secrets(self.message or self.rule)
        if not self.tool:
            self.tool = infer_tool(self.check_id, self.rule)
        if self.status not in VALID_STATUSES:
            raise ValueError(f"Invalid status {self.status!r}; expected one of {VALID_STATUSES}")
        if not self.id:
            self.id = make_finding_id(self.check_id, self.rule, self.file, self.line)
        if not self.blast_radius:
            self.blast_radius = [self.file]

    def is_suppression_active(self, now: datetime | None = None) -> bool:
        if self.status != "SUPPRESSED" or not self.suppression:
            return False
        exp_raw = self.suppression.get("expires_at")
        if not exp_raw:
            return False
        exp = datetime.fromisoformat(str(exp_raw).replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        ref = now or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        return ref < exp

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_sarif_result(self) -> dict[str, Any]:
        level_map = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
        return {
            "ruleId": f"{self.check_id}/{self.rule}",
            "level": level_map.get(self.severity, "warning"),
            "message": {"text": f"[{self.check_id}] {self.message} — Fix: {self.fix}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.file},
                        "region": {"startLine": self.line},
                    }
                }
            ],
            "properties": {
                "id": self.id,
                "check_id": self.check_id,
                "severity": self.severity,
                "confidence": self.confidence,
                "standards": self.standards,
                "blast_radius": self.blast_radius,
                "evidence": self.evidence,
                "tool": self.tool,
                "status": self.status,
                "verified_deterministically": self.verified_deterministically,
            },
        }
