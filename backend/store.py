"""Repository layer — the ONLY place with database access.

Uses portable SQLAlchemy ORM over `DATABASE_URL` (default `sqlite:///./reviewer.db`).
Migrating from SQLite (MVP) to Postgres (Production) requires ONLY changing
`DATABASE_URL` and running `alembic upgrade head`.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.models import (
    AuditModel,
    Base,
    FindingModel,
    MemoryEntryModel,
    PRRunModel,
    SuppressionModel,
)
from backend.reviewer.findings.schema import infer_category, infer_tool
from backend.reviewer.guardrails.redact import redact_secrets

DEFAULT_DATABASE_URL = "sqlite:///./reviewer.db"


def get_database_url(db_url: str | None = None) -> str:
    return db_url or os.getenv("DATABASE_URL") or DEFAULT_DATABASE_URL


def create_portable_engine(db_url: str | None = None):
    url = get_database_url(db_url)
    kwargs: dict[str, Any] = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


def _utc(dt: datetime | None = None) -> datetime:
    val = dt or datetime.now(timezone.utc)
    if val.tzinfo is None:
        return val.replace(tzinfo=timezone.utc)
    return val


class ReviewerStore:
    """Portable SQLAlchemy repository for runs, findings, suppressions, audits, and memory."""

    def __init__(self, db_url: str | None = None, auto_create: bool = True):
        self.db_url = get_database_url(db_url)
        self.engine = create_portable_engine(self.db_url)
        if auto_create:
            Base.metadata.create_all(self.engine)
        self._ensure_columns()
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    def _ensure_columns(self) -> None:
        """Lightweight column migration to keep SQLite / Postgres schemas up-to-date."""
        try:
            with self.engine.connect() as conn:
                res = conn.execute(select(FindingModel).limit(0))
        except Exception:
            pass
        try:
            with self.engine.connect() as conn:
                # Check for 'tool', 'category', 'repo' columns in findings
                cols = []
                if self.engine.dialect.name == "sqlite":
                    cols = [c[1] for c in conn.exec_driver_sql("PRAGMA table_info(findings)").fetchall()]
                if cols:
                    if "tool" not in cols:
                        conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN tool VARCHAR(64) DEFAULT 'LineTrack'")
                    if "category" not in cols:
                        conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN category VARCHAR(64) DEFAULT 'MES Industrial Logic'")
                    if "repo" not in cols:
                        conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN repo VARCHAR(256) DEFAULT ''")
                    conn.commit()
        except Exception:
            pass

    def db_backend_name(self) -> str:
        return self.engine.dialect.name

    def save_run(
        self,
        *,
        run_id: str,
        repo: str,
        verdict: str,
        exit_code: int,
        mode: str = "pr",
        branch: str = "",
        pr_number: str = "",
        cost_usd: float = 0.0,
        duration_sec: float = 0.0,
        judge_log: list[dict[str, Any]] | None = None,
        ot_checks: dict[str, str] | None = None,
        summary: dict[str, Any] | None = None,
    ) -> str:
        with self.SessionLocal() as session:
            row = session.get(PRRunModel, run_id)
            if row is None:
                row = PRRunModel(
                    id=run_id,
                    repo=repo,
                    branch=branch,
                    pr_number=pr_number,
                    mode=mode,
                    verdict=verdict,
                    exit_code=exit_code,
                    cost_usd=cost_usd,
                    duration_sec=duration_sec,
                    judge_log_json=json.dumps(judge_log or []),
                    ot_checks_json=json.dumps(ot_checks or {}),
                    summary_json=json.dumps(summary or {}),
                )
                session.add(row)
            else:
                row.verdict = verdict
                row.exit_code = exit_code
                row.mode = mode
                row.cost_usd = cost_usd
                row.duration_sec = duration_sec
                row.judge_log_json = json.dumps(judge_log or [])
                row.ot_checks_json = json.dumps(ot_checks or {})
                row.summary_json = json.dumps(summary or {})
            session.commit()
        return run_id

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.SessionLocal() as session:
            row = session.get(PRRunModel, run_id)
            if row is None:
                return None
            findings = self.get_findings(run_id=run_id)
            highs = sum(1 for f in findings if f["severity"] in {"Critical", "High"} and f["status"] != "SUPPRESSED")
            inj = any(f["rule"] == "INJECTION_ATTEMPT" for f in findings)
            return {
                "run_id": row.id,
                "repo": row.repo,
                "branch": row.branch,
                "pr_number": row.pr_number,
                "mode": row.mode,
                "verdict": row.verdict,
                "exit_code": row.exit_code,
                "cost_usd": row.cost_usd,
                "duration_sec": row.duration_sec,
                "findings_count": len(findings),
                "high_count": highs,
                "ot_checks": json.loads(row.ot_checks_json or "{}"),
                "judge_log": json.loads(row.judge_log_json or "[]"),
                "injection_detected": inj,
                "summary": json.loads(row.summary_json or "{}"),
                "created_at": _utc(row.created_at).isoformat(),
            }

    def get_latest_run(self) -> dict[str, Any] | None:
        with self.SessionLocal() as session:
            row = session.scalars(select(PRRunModel).order_by(PRRunModel.created_at.desc())).first()
            if row is None:
                return None
            return self.get_run(row.id)

    def save_finding(
        self,
        finding: Any,
        run_id: str = "default",
        audit_id: str | None = None,
    ) -> str:
        if hasattr(finding, "to_dict"):
            finding = finding.to_dict()
        elif not isinstance(finding, dict) and hasattr(finding, "__dict__"):
            finding = vars(finding)
        fid = str(finding.get("id") or uuid.uuid4().hex[:12])
        # Keep ID unique per run if identical rule appears in multiple runs
        row_id = f"{run_id}:{fid}" if ":" not in fid else fid
        evidence_safe = redact_secrets(str(finding.get("evidence") or ""))[:500]
        fix_safe = redact_secrets(str(finding.get("fix") or ""))
        msg_safe = redact_secrets(str(finding.get("message") or finding.get("rule") or ""))
        tool_val = str(finding.get("tool") or infer_tool(str(finding.get("check_id", "")), str(finding.get("rule", ""))))
        category_val = str(finding.get("category") or infer_category(str(finding.get("check_id", "")), str(finding.get("rule", ""))))
        repo_val = str(finding.get("repo") or "")

        with self.SessionLocal() as session:
            if not repo_val and run_id:
                r_row = session.get(PRRunModel, run_id)
                if r_row:
                    repo_val = r_row.repo

            row = session.get(FindingModel, row_id)
            if row is None:
                row = FindingModel(
                    id=row_id,
                    run_id=run_id,
                    audit_id=audit_id,
                    check_id=str(finding["check_id"]),
                    severity=str(finding["severity"]),
                    confidence=float(finding.get("confidence", 1.0)),
                    file=str(finding["file"]).replace("\\", "/"),
                    line=int(finding.get("line", 1) or 1),
                    rule=str(finding["rule"]),
                    evidence=evidence_safe,
                    blast_radius_json=json.dumps(finding.get("blast_radius") or [finding["file"]]),
                    standards_json=json.dumps(finding.get("standards") or []),
                    fix=fix_safe,
                    status=str(finding.get("status", "OPEN")),
                    message=msg_safe,
                    tool=tool_val,
                    category=category_val,
                    repo=repo_val,
                    verified_deterministically=bool(finding.get("verified_deterministically", True)),
                )
                session.add(row)
            else:
                row.severity = str(finding["severity"])
                row.confidence = float(finding.get("confidence", 1.0))
                row.evidence = evidence_safe
                row.fix = fix_safe
                row.message = msg_safe
                row.status = str(finding.get("status", row.status))
                row.tool = tool_val
                row.category = category_val
                if repo_val:
                    row.repo = repo_val
                row.verified_deterministically = bool(finding.get("verified_deterministically", True))
            session.commit()
        return row_id

    def save_findings(
        self,
        findings: list[dict[str, Any]],
        run_id: str = "default",
        audit_id: str | None = None,
    ) -> list[str]:
        return [self.save_finding(f, run_id=run_id, audit_id=audit_id) for f in findings]

    def suppress_finding(
        self,
        finding_id: str,
        owner: str,
        reason: str,
        now: datetime | None = None,
        ttl_days: int = 30,
    ) -> dict[str, Any]:
        if not owner or not owner.strip():
            raise ValueError("Suppression requires a non-empty owner.")
        if not reason or not reason.strip():
            raise ValueError("Suppression requires a non-empty reason.")

        created = _utc(now)
        expires = created + timedelta(days=ttl_days)
        sup_id = uuid.uuid4().hex[:16]

        with self.SessionLocal() as session:
            row = session.get(FindingModel, finding_id)
            if row is None:
                raise KeyError(f"Finding not found: {finding_id}")

            prev = session.scalars(
                select(SuppressionModel).where(
                    SuppressionModel.finding_id == finding_id,
                    SuppressionModel.active.is_(True),
                )
            ).all()
            for item in prev:
                item.active = False

            sup = SuppressionModel(
                id=sup_id,
                finding_id=finding_id,
                owner=owner.strip(),
                reason=redact_secrets(reason.strip()),
                created_at=created,
                expires_at=expires,
                active=True,
            )
            session.add(sup)
            row.status = "SUPPRESSED"
            session.commit()
            return {
                "owner": sup.owner,
                "reason": sup.reason,
                "created_at": created.isoformat(),
                "expires_at": expires.isoformat(),
            }

    def expire_suppressions(self, now: datetime | None = None) -> int:
        ref = _utc(now)
        count = 0
        with self.SessionLocal() as session:
            active_sups = session.scalars(
                select(SuppressionModel).where(SuppressionModel.active.is_(True))
            ).all()
            for sup in active_sups:
                if _utc(sup.expires_at) <= ref:
                    sup.active = False
                    f_row = session.get(FindingModel, sup.finding_id)
                    if f_row is not None and f_row.status == "SUPPRESSED":
                        f_row.status = "OPEN"
                    count += 1
            session.commit()
        return count

    def revoke_suppression(self, finding_id: str) -> bool:
        """Revoke an active suppression and re-open the finding."""
        with self.SessionLocal() as session:
            row = session.get(FindingModel, finding_id)
            if row is None:
                raise KeyError(f"Finding not found: {finding_id}")
            sups = session.scalars(
                select(SuppressionModel).where(
                    SuppressionModel.finding_id == finding_id,
                    SuppressionModel.active.is_(True),
                )
            ).all()
            for s in sups:
                s.active = False
            row.status = "OPEN"
            session.commit()
            return True

    def get_suppressions(self, active_only: bool = True, now: datetime | None = None) -> list[dict[str, Any]]:
        """List suppressions with linked finding metadata and expiration details."""
        self.expire_suppressions(now=now)
        ref = _utc(now)
        with self.SessionLocal() as session:
            stmt = select(SuppressionModel).order_by(SuppressionModel.created_at.desc())
            if active_only:
                stmt = stmt.where(SuppressionModel.active.is_(True))
            rows = session.scalars(stmt).all()
            out: list[dict[str, Any]] = []
            for s in rows:
                f_row = session.get(FindingModel, s.finding_id)
                exp = _utc(s.expires_at)
                delta = exp - ref
                days_left = max(0, delta.days)
                out.append(
                    {
                        "id": s.id,
                        "finding_id": s.finding_id,
                        "owner": s.owner,
                        "reason": s.reason,
                        "active": s.active,
                        "created_at": _utc(s.created_at).isoformat(),
                        "expires_at": exp.isoformat(),
                        "days_remaining": days_left,
                        "check_id": f_row.check_id if f_row else "",
                        "rule": f_row.rule if f_row else "",
                        "file": f_row.file if f_row else "",
                        "line": f_row.line if f_row else 1,
                        "severity": f_row.severity if f_row else "Medium",
                    }
                )
            return out

    def get_findings(
        self,
        run_id: str | None = None,
        audit_id: str | None = None,
        repo: str | None = None,
        category: str | None = None,
        now: datetime | None = None,
        include_suppressed: bool = True,
    ) -> list[dict[str, Any]]:
        self.expire_suppressions(now=now)
        with self.SessionLocal() as session:
            stmt = select(FindingModel)
            if run_id is not None:
                stmt = stmt.where(FindingModel.run_id == run_id)
            if audit_id is not None:
                stmt = stmt.where(FindingModel.audit_id == audit_id)
            if repo is not None and repo.strip() and repo.strip() != "All":
                stmt = stmt.where(FindingModel.repo == repo.strip())
            if category is not None and category.strip() and category.strip() != "All":
                stmt = stmt.where(FindingModel.category == category.strip())
            rows = session.scalars(stmt).all()

            active_sups = {
                s.finding_id: {
                    "owner": s.owner,
                    "reason": s.reason,
                    "created_at": _utc(s.created_at).isoformat(),
                    "expires_at": _utc(s.expires_at).isoformat(),
                }
                for s in session.scalars(select(SuppressionModel).where(SuppressionModel.active.is_(True))).all()
            }

            run_cache: dict[str, Any] = {}
            out: list[dict[str, Any]] = []
            for r in rows:
                if not include_suppressed and r.status == "SUPPRESSED":
                    continue
                cat_val = getattr(r, "category", None)
                if not cat_val or cat_val == "MES Industrial Logic":
                    cat_val = infer_category(r.check_id, r.rule)
                repo_val = getattr(r, "repo", None)
                if not repo_val and r.run_id:
                    if r.run_id not in run_cache:
                        run_cache[r.run_id] = session.get(PRRunModel, r.run_id)
                    run_obj = run_cache.get(r.run_id)
                    if run_obj:
                        repo_val = run_obj.repo
                tool_val = getattr(r, "tool", None)
                if not tool_val or tool_val in {"LineTrack", "MES Domain Checks"}:
                    tool_val = infer_tool(r.check_id, r.rule)
                out.append(
                    {
                        "id": r.id,
                        "run_id": r.run_id,
                        "check_id": r.check_id,
                        "severity": r.severity,
                        "confidence": r.confidence,
                        "file": r.file,
                        "line": r.line,
                        "rule": r.rule,
                        "evidence": r.evidence,
                        "blast_radius": json.loads(r.blast_radius_json or "[]"),
                        "standards": json.loads(r.standards_json or "[]"),
                        "fix": r.fix,
                        "status": r.status,
                        "suppression": active_sups.get(r.id) if r.status == "SUPPRESSED" else None,
                        "message": r.message,
                        "tool": tool_val,
                        "category": cat_val,
                        "repo": repo_val or "sample_repo",
                        "verified_deterministically": r.verified_deterministically,
                    }
                )
            return out

    def get_projects(self) -> list[dict[str, Any]]:
        """List distinct projects / repositories recorded in reviewer.db."""
        with self.SessionLocal() as session:
            runs = session.scalars(select(PRRunModel).order_by(PRRunModel.created_at.desc())).all()
            projects: dict[str, dict[str, Any]] = {}
            for r in runs:
                r_name = (r.repo or "sample_repo").strip()
                if not r_name:
                    r_name = "sample_repo"
                if r_name not in projects:
                    projects[r_name] = {
                        "repo": r_name,
                        "runs_count": 0,
                        "latest_run_id": r.id,
                        "latest_verdict": r.verdict,
                        "latest_mode": r.mode,
                        "latest_cost_usd": r.cost_usd,
                        "latest_created_at": _utc(r.created_at).isoformat(),
                    }
                projects[r_name]["runs_count"] += 1
            if not projects:
                projects["sample_repo"] = {
                    "repo": "sample_repo",
                    "runs_count": 0,
                    "latest_run_id": "",
                    "latest_verdict": "PASS",
                    "latest_mode": "airgap",
                    "latest_cost_usd": 0.0,
                    "latest_created_at": datetime.now(timezone.utc).isoformat(),
                }
            return list(projects.values())

    def save_audit(
        self,
        *,
        audit_id: str,
        run_id: str,
        repo: str,
        mode: str,
        verdict: str,
        unverified_count: int,
        cost_usd: float,
        report: dict[str, Any],
    ) -> str:
        with self.SessionLocal() as session:
            row = session.get(AuditModel, audit_id)
            payload = json.dumps(report)
            if row is None:
                row = AuditModel(
                    id=audit_id,
                    run_id=run_id,
                    repo=repo,
                    mode=mode,
                    verdict=verdict,
                    unverified_count=unverified_count,
                    cost_usd=cost_usd,
                    report_json=payload,
                )
                session.add(row)
            else:
                row.verdict = verdict
                row.unverified_count = unverified_count
                row.cost_usd = cost_usd
                row.report_json = payload
            session.commit()
        return audit_id

    def get_audit_by_run(self, run_id: str) -> dict[str, Any] | None:
        with self.SessionLocal() as session:
            row = session.scalars(select(AuditModel).where(AuditModel.run_id == run_id)).first()
            if row is None:
                return None
            return json.loads(row.report_json or "{}")

    def upsert_memory_entry(
        self,
        entry_id: str,
        memory_type: str,
        title: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self.SessionLocal() as session:
            row = session.get(MemoryEntryModel, entry_id)
            safe_content = redact_secrets(content)
            if row is None:
                session.add(
                    MemoryEntryModel(
                        id=entry_id,
                        memory_type=memory_type,
                        title=title,
                        content=safe_content,
                        metadata_json=json.dumps(metadata or {}),
                    )
                )
            else:
                row.title = title
                row.content = safe_content
                row.metadata_json = json.dumps(metadata or {})
            session.commit()

    def list_memory_entries(self, memory_type: str | None = None) -> list[dict[str, Any]]:
        with self.SessionLocal() as session:
            stmt = select(MemoryEntryModel)
            if memory_type:
                stmt = stmt.where(MemoryEntryModel.memory_type == memory_type)
            rows = session.scalars(stmt).all()
            return [
                {
                    "id": r.id,
                    "memory_type": r.memory_type,
                    "title": r.title,
                    "content": r.content,
                    "metadata": json.loads(r.metadata_json or "{}"),
                }
                for r in rows
            ]
