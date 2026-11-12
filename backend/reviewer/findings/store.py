"""Findings persistence wrapper delegating strictly to backend.store.ReviewerStore (SQLite MVP)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.reviewer.findings.schema import Finding
from backend.store import ReviewerStore


class FindingStore:
    """Thin findings facade over ReviewerStore (portable SQLAlchemy + Alembic)."""

    def __init__(self, db_url: str | None = None, auto_create: bool = False):
        self.repo = ReviewerStore(db_url=db_url, auto_create=auto_create)

    def save_finding(self, finding: Finding, pr_id: str = "default", audit_id: str | None = None) -> str:
        return self.repo.save_finding(finding.to_dict(), run_id=pr_id, audit_id=audit_id)

    def save_findings(self, findings: list[Finding], pr_id: str = "default", audit_id: str | None = None) -> list[str]:
        return [self.save_finding(f, pr_id=pr_id, audit_id=audit_id) for f in findings]

    def suppress_finding(
        self,
        finding_id: str,
        owner: str,
        reason: str,
        now: datetime | None = None,
        ttl_days: int = 30,
    ) -> dict[str, Any]:
        return self.repo.suppress_finding(
            finding_id=finding_id,
            owner=owner,
            reason=reason,
            now=now,
            ttl_days=ttl_days,
        )

    def get_findings(
        self,
        pr_id: str | None = None,
        audit_id: str | None = None,
        now: datetime | None = None,
        include_suppressed: bool = True,
    ) -> list[Finding]:
        rows = self.repo.get_findings(
            run_id=pr_id,
            audit_id=audit_id,
            now=now,
            include_suppressed=include_suppressed,
        )
        return [
            Finding(
                id=r["id"],
                check_id=r["check_id"],
                severity=r["severity"],
                confidence=r["confidence"],
                file=r["file"],
                line=r["line"],
                rule=r["rule"],
                evidence=r["evidence"],
                blast_radius=r["blast_radius"],
                standards=r["standards"],
                fix=r["fix"],
                status=r["status"],
                suppression=r["suppression"],
                message=r["message"],
                verified_deterministically=r["verified_deterministically"],
            )
            for r in rows
        ]


def save_finding(finding: Finding, pr_id: str = "default", db_url: str | None = None) -> str:
    return FindingStore(db_url=db_url).save_finding(finding, pr_id=pr_id)


def get_findings(
    pr_id: str = "default",
    db_url: str | None = None,
    now: datetime | None = None,
    include_suppressed: bool = True,
) -> list[Finding]:
    return FindingStore(db_url=db_url).get_findings(pr_id=pr_id, now=now, include_suppressed=include_suppressed)


def suppress_finding(
    finding_id: str,
    owner: str,
    reason: str,
    db_url: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    return FindingStore(db_url=db_url).suppress_finding(finding_id=finding_id, owner=owner, reason=reason, now=now)
