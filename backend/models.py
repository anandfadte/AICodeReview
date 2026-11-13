"""Portable SQLAlchemy ORM models (works identically on SQLite MVP and Postgres Production).

Strictly uses generic SQLAlchemy column types ONLY:
  String, Text, Integer, Float, Boolean, DateTime.
No JSONB, ARRAY, pgvector, ILIKE, or raw sqlite3 pragmas.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class PRRunModel(Base):
    __tablename__ = "pr_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repo: Mapped[str] = mapped_column(String(256), default="")
    branch: Mapped[str] = mapped_column(String(128), default="")
    pr_number: Mapped[str] = mapped_column(String(32), default="")
    mode: Mapped[str] = mapped_column(String(32), default="pr")
    verdict: Mapped[str] = mapped_column(String(32), default="PASS")
    exit_code: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    duration_sec: Mapped[float] = mapped_column(Float, default=0.0)
    judge_log_json: Mapped[str] = mapped_column(Text, default="[]")
    ot_checks_json: Mapped[str] = mapped_column(Text, default="{}")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditModel(Base):
    __tablename__ = "audits"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    repo: Mapped[str] = mapped_column(String(256), default="")
    mode: Mapped[str] = mapped_column(String(32), default="full")
    verdict: Mapped[str] = mapped_column(String(32), default="PASS")
    unverified_count: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    report_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    audit_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    check_id: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    file: Mapped[str] = mapped_column(String(512))
    line: Mapped[int] = mapped_column(Integer, default=1)
    rule: Mapped[str] = mapped_column(String(128))
    evidence: Mapped[str] = mapped_column(Text, default="")
    blast_radius_json: Mapped[str] = mapped_column(Text, default="[]")
    standards_json: Mapped[str] = mapped_column(Text, default="[]")
    fix: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    tool: Mapped[str] = mapped_column(String(64), default="LineTrack")
    category: Mapped[str] = mapped_column(String(64), default="MES Industrial Logic")
    repo: Mapped[str] = mapped_column(String(256), default="")
    verified_deterministically: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SuppressionModel(Base):
    __tablename__ = "suppressions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), index=True)
    owner: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)


class MemoryEntryModel(Base):
    """MVP memory stub table (portable Text storage; pgvector adapter added in Production)."""

    __tablename__ = "memory_entries"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    memory_type: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(256))
    content: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
