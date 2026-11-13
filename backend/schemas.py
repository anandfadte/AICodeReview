"""Pydantic schemas for frozen LineTrack Reviewer REST API contract."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HealthOut(BaseModel):
    status: str = "ok"
    db: str = "sqlite"
    version: str = "0.1.0"


class ReviewRequest(BaseModel):
    repo_path: str = "sample_repo"
    mode: str = "pr"  # pr | full | airgap
    changed_files: list[str] | None = None
    pr_text: str = ""
    pr_number: str = ""
    branch: str = ""


class FindingOut(BaseModel):
    id: str
    run_id: str = "default"
    check_id: str
    severity: str
    confidence: float
    file: str
    line: int
    rule: str
    evidence: str
    blast_radius: list[str] = Field(default_factory=list)
    standards: list[str] = Field(default_factory=list)
    fix: str
    status: str = "OPEN"
    suppression: dict[str, Any] | None = None
    message: str = ""
    tool: str = "LineTrack"
    verified_deterministically: bool = True


class ReviewRunOut(BaseModel):
    run_id: str
    repo: str
    branch: str = ""
    pr_number: str = ""
    mode: str = "pr"
    verdict: str
    exit_code: int
    cost_usd: float = 0.0
    duration_sec: float = 0.0
    findings_count: int = 0
    high_count: int = 0
    ot_checks: dict[str, str] = Field(default_factory=dict)
    judge_log: list[dict[str, Any]] = Field(default_factory=list)
    injection_detected: bool = False
    summary: dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""


class SuppressRequest(BaseModel):
    owner: str
    reason: str


class ReportOut(BaseModel):
    run_id: str
    repo: str
    mode: str
    verdict: str
    findings: list[FindingOut] = Field(default_factory=list)
    check_catalogue: list[dict[str, Any]] = Field(default_factory=list)
    traceability: list[dict[str, Any]] = Field(default_factory=list)
    unverified: list[dict[str, Any]] = Field(default_factory=list)
    invariants: dict[str, Any] = Field(default_factory=dict)
    cost_summary: dict[str, Any] = Field(default_factory=dict)
