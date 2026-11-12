"""SARIF 2.1.0 exporter for LineTrack Reviewer findings."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from backend.reviewer.findings.schema import Finding

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"


def export_sarif(
    findings: Iterable[Finding | dict[str, Any]],
    output_path: str | Path | None = None,
    include_suppressed: bool = False,
    now: datetime | None = None,
    tool_name: str = "linetrack-reviewer",
    tool_version: str = "0.1.0",
) -> dict[str, Any]:
    normalized: list[Finding] = []
    for item in findings:
        if isinstance(item, Finding):
            normalized.append(item)
        else:
            normalized.append(
                Finding(
                    id=str(item.get("id", "")),
                    check_id=str(item["check_id"]),
                    severity=str(item["severity"]),
                    confidence=float(item.get("confidence", 1.0)),
                    file=str(item["file"]),
                    line=int(item.get("line", 1)),
                    rule=str(item["rule"]),
                    evidence=str(item.get("evidence", "")),
                    blast_radius=list(item.get("blast_radius") or [item["file"]]),
                    standards=list(item.get("standards") or []),
                    fix=str(item.get("fix", "")),
                    status=str(item.get("status", "OPEN")),
                    suppression=item.get("suppression"),
                    message=str(item.get("message", item["rule"])),
                    verified_deterministically=bool(item.get("verified_deterministically", True)),
                )
            )

    selected: list[Finding] = []
    for f in normalized:
        actively_suppressed = f.is_suppression_active(now=now) or (f.status == "SUPPRESSED" and not f.suppression)
        if not include_suppressed and actively_suppressed:
            continue
        selected.append(f)

    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in selected:
        rule_id = f"{f.check_id}/{f.rule}"
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": f.rule,
                "shortDescription": {"text": f"[{f.check_id}] {f.rule}"},
                "help": {"text": f.fix},
                "properties": {"standards": f.standards},
            }
        res = f.to_sarif_result()
        if include_suppressed and f.status == "SUPPRESSED" and f.suppression:
            res["suppressions"] = [
                {
                    "kind": "external",
                    "justification": f.suppression.get("reason", ""),
                    "properties": {
                        "owner": f.suppression.get("owner", ""),
                        "expires_at": f.suppression.get("expires_at", ""),
                    },
                }
            ]
        results.append(res)

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "version": tool_version, "rules": list(rules_by_id.values())}},
                "results": results,
            }
        ],
    }

    if output_path is not None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
    return sarif_doc
