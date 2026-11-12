"""ot_write_guard.py — Deterministic OT safety gate for PLC write edges (OT-001).

Checks EVERY PLC write edge (Python AST + Node-RED graph) for ALL 5 controls:
  (a) allow-listed PLC tag (allow_lists/plc_allowlist.json)
  (b) min/max clamp (`not in` numeric range/set counts; `role not in` excluded)
  (c) auth / role check (authorized role for tag)
  (d) interlock check
  (e) audit log write

Missing ANY of the 5 or an unparsable flow -> High -> BLOCK (exit 2).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from backend.reviewer.ingestion.flow_parser import is_flow_candidate, parse_flow_file
from backend.reviewer.ingestion.github_diff import SKIP_DIRS

DEFAULT_ALLOWLIST: dict[str, dict[str, Any]] = {
    "SPINDLE_SPEED": {"min": 500, "max": 3000, "roles": ["Supervisor", "Plant Head"], "requires_interlock": True, "requires_audit": True},
    "FEED_RATE": {"min": 10, "max": 200, "roles": ["Supervisor", "Plant Head"], "requires_interlock": True, "requires_audit": True},
    "COOLANT_ON": {"min": 0, "max": 1, "roles": ["Supervisor", "Operator"], "requires_interlock": False, "requires_audit": True},
}

WRITE_CALLS = {
    "write_register", "write_coil", "write_tag", "write_value",
    "write_node", "set_value", "write_multiple", "modbus_write", "opcua_write",
}
NON_PLC_WRITE_RECEIVERS = {"log", "logger", "audit", "audit_log", "f", "fp", "file", "fh", "stream", "stdout", "stderr", "buf", "io"}

_NUMERIC_CLAMP_PATTERNS = re.compile(
    r"\b(clamp|in_range|validate_range|check_bounds|check_range)\b"
    r"|(?<!\w)(?:min|max)\s*\("
    r"|(?:\w+\s*(?:<=|>=|<|>)\s*-?\d+(?:\.\d+)?)"
    r"|(?:-?\d+(?:\.\d+)?\s*(?:<=|>=|<|>)\s*\w+)"
    r"|\bnot\s+in\s+(?:range\s*\(|[\(\[\{]\s*-?\d+)"
    r"|\bnot\s+in\s+[A-Z_]*RANGE\b"
    r"|\bout\s+of\s+range\b",
    re.I,
)
_ROLE_NOT_IN_RE = re.compile(r"\b(?:role|roles|user_role|x_role)\s+not\s+in\b", re.I)

AUTH_PATTERNS = re.compile(
    r"require_role|require_auth|@.*auth|Depends\(.*auth|has_role|is_supervisor|check_role|permission"
    r"|\b(?:role|user_role|x_role)\s+(?:not\s+in|in|==|!=)\b",
    re.I,
)
INTERLOCK_PATTERNS = re.compile(
    r"\b(check_interlock|verify_interlock|require_interlock|interlock_ok|interlock_active|safety_interlock|interlock|e_stop|estop_ok)\b",
    re.I,
)
AUDIT_PATTERNS = re.compile(
    r"\b(audit_log|audit\.insert|log\.write|log_write|record_change|write_audit|audit_logger)\b|insert\s+into\s+audit",
    re.I,
)
_ROLE_LIT_RE = re.compile(r"""(?:require_role|has_role)\(\s*["']([^"']+)["']""", re.I)


@dataclass
class OTFinding:
    severity: str
    rule: str
    file: str
    line: int
    message: str
    evidence: str
    fix: str
    standard: str = "IEC 62443 SR 3.3"
    check_id: str = "OT-001"
    blast_radius: list[str] = field(default_factory=list)


Finding = OTFinding


def load_plc_allowlist(allowlist_path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    candidates = []
    if allowlist_path:
        candidates.append(Path(allowlist_path))
    candidates.extend(
        [
            Path.cwd() / "allow_lists" / "plc_allowlist.json",
            Path(__file__).resolve().parents[3] / "allow_lists" / "plc_allowlist.json",
        ]
    )
    for cand in candidates:
        if cand.is_file():
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data:
                    return data
            except Exception:
                break
    return dict(DEFAULT_ALLOWLIST)


def has_clamp_check(text: str) -> bool:
    cleaned = _ROLE_NOT_IN_RE.sub("", text)
    if _NUMERIC_CLAMP_PATTERNS.search(cleaned):
        return True
    m = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_\[\]\"']*)\s+not\s+in\s+([a-zA-Z0-9_\(\[\{\s,.\-]+)", cleaned)
    if m:
        lhs = m.group(1).lower()
        if "role" not in lhs and "perm" not in lhs and "user" not in lhs:
            return True
    return False


def _check_all_5(
    *,
    file_str: str,
    line: int,
    base_label: str,
    tag: str | None,
    upstream_text: str,
    audit_text: str,
    decorators: str,
    evidence: str,
    allowlist: dict[str, dict[str, Any]],
) -> list[OTFinding]:
    findings: list[OTFinding] = []
    snippet = evidence[:500]
    tag_cfg = allowlist.get(tag) if tag else None

    if not tag or tag == "DYNAMIC":
        findings.append(
            OTFinding("High", "PLC-WRITE-DYNAMIC-TAG", file_str, line,
                      f"{base_label} — tag is dynamic or missing, not a literal allow-listed tag.",
                      snippet, "Use a static literal tag present in allow_lists/plc_allowlist.json.",
                      "IEC 62443 SR 2.1, SR 3.3", blast_radius=[file_str])
        )
    elif tag not in allowlist:
        findings.append(
            OTFinding("High", "PLC-WRITE-NOT-ALLOWLISTED", file_str, line,
                      f"{base_label} — tag '{tag}' is not in allow_lists/plc_allowlist.json.",
                      snippet, f"Reject writes to '{tag}' or add reviewed bounds/roles to allow_lists/plc_allowlist.json.",
                      "IEC 62443 SR 2.1", blast_radius=[file_str])
        )

    if not has_clamp_check(upstream_text):
        bounds = f"[{tag_cfg.get('min')}, {tag_cfg.get('max')}]" if tag_cfg else "allow-list min/max"
        findings.append(
            OTFinding("High", "PLC-WRITE-NO-CLAMP", file_str, line,
                      f"{base_label} — no min/max clamp or range validation before PLC write.",
                      snippet, f"Validate bounds ({bounds}) via min/max comparison or `not in range(...)` before write.",
                      "IEC 62443 SR 3.3", blast_radius=[file_str])
        )

    combined_auth_src = f"{decorators}\n{upstream_text}"
    if not (AUTH_PATTERNS.search(decorators) or AUTH_PATTERNS.search(upstream_text)):
        allowed_roles = tag_cfg.get("roles", ["Supervisor", "Plant Head"]) if tag_cfg else ["Supervisor", "Plant Head"]
        findings.append(
            OTFinding("High", "PLC-WRITE-NO-AUTH", file_str, line,
                      f"{base_label} — missing role/authorization check before PLC write.",
                      snippet, f"Enforce @require_role or explicit role check permitting only {allowed_roles}.",
                      "IEC 62443 SR 2.1; ISO 27001 A.9; OWASP ASVS 4.1", blast_radius=[file_str])
        )
    elif tag_cfg and "roles" in tag_cfg:
        allowed_roles = set(tag_cfg["roles"])
        for m in _ROLE_LIT_RE.finditer(combined_auth_src):
            role_used = m.group(1)
            if role_used not in allowed_roles:
                findings.append(
                    OTFinding("High", "PLC-WRITE-UNAUTHORIZED-ROLE", file_str, line,
                              f"{base_label} — permits role '{role_used}' outside allowed roles {sorted(allowed_roles)}.",
                              snippet, f"Restrict write access for '{tag}' to roles {sorted(allowed_roles)}.",
                              "IEC 62443 SR 2.1; OWASP ASVS 4.1", blast_radius=[file_str])
                )

    if not (INTERLOCK_PATTERNS.search(decorators) or INTERLOCK_PATTERNS.search(upstream_text)):
        findings.append(
            OTFinding("High", "PLC-WRITE-NO-INTERLOCK", file_str, line,
                      f"{base_label} — missing safety interlock check before PLC write.",
                      snippet, "Call `check_interlock()` / verify safety interlock before issuing PLC write.",
                      "IEC 62443 SR 3.3", blast_radius=[file_str])
        )

    if not AUDIT_PATTERNS.search(audit_text):
        findings.append(
            OTFinding("High", "PLC-WRITE-NO-AUDIT", file_str, line,
                      f"{base_label} — missing append-only audit log write (who, when, tag, value).",
                      snippet, "Record every PLC write in append-only audit_log (`audit_log.insert(...)` or `log.write(...)`).",
                      "IEC 62443 SR 2.8; ISO 27001 A.12; IATF 16949 8.5.2", blast_radius=[file_str])
        )

    return findings


def _scan_python_file(path: Path, allowlist: dict[str, dict[str, Any]]) -> list[OTFinding]:
    file_str = str(path)
    try:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=file_str)
    except SyntaxError as exc:
        return [
            OTFinding("High", "PARSE-FAIL", file_str, exc.lineno or 1,
                      f"Could not parse Python file — cannot prove OT safety: {exc}",
                      str(exc)[:500], "Fix Python syntax error so OT checks can verify write paths.")
        ]

    findings: list[OTFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = ast.get_source_segment(text, node) or ""
        decorators = " ".join(ast.get_source_segment(text, d) or "" for d in node.decorator_list)
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            fname = ""
            recv_name = ""
            if isinstance(sub.func, ast.Attribute):
                fname = sub.func.attr
                if isinstance(sub.func.value, ast.Name):
                    recv_name = sub.func.value.id.lower()
            elif isinstance(sub.func, ast.Name):
                fname = sub.func.id

            is_explicit = fname in WRITE_CALLS
            is_generic = "write" in fname.lower() and recv_name not in NON_PLC_WRITE_RECEIVERS and "audit" not in fname.lower() and "log" not in fname.lower()
            if not (is_explicit or is_generic):
                continue

            tag = "DYNAMIC"
            if sub.args and isinstance(sub.args[0], ast.Constant) and isinstance(sub.args[0].value, str):
                tag = sub.args[0].value
            else:
                for kw in sub.keywords:
                    if kw.arg in {"tag", "register", "node", "name"} and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        tag = kw.value.value
                        break

            line = getattr(sub, "lineno", node.lineno)
            findings.extend(
                _check_all_5(
                    file_str=file_str,
                    line=line,
                    base_label=f"Write to PLC tag '{tag}' in {node.name}()",
                    tag=tag,
                    upstream_text=src,
                    audit_text=src,
                    decorators=decorators,
                    evidence=src,
                    allowlist=allowlist,
                )
            )
    return findings


def _scan_nodered_file(path: Path, allowlist: dict[str, dict[str, Any]]) -> list[OTFinding]:
    parsed = parse_flow_file(path)
    findings: list[OTFinding] = []

    for ff in parsed.findings:
        findings.append(
            OTFinding("High", ff.rule, ff.file, ff.line, ff.message, ff.evidence, ff.fix, ff.standard, blast_radius=[ff.file])
        )

    for edge in parsed.write_edges:
        if not edge.is_plc_write:
            continue
        combined_audit = f"{edge.upstream_code}\n{edge.downstream_code}"
        findings.extend(
            _check_all_5(
                file_str=edge.file,
                line=edge.line,
                base_label=f"Node-RED flow '{edge.flow_name}' edge ({edge.edge_summary})",
                tag=edge.plc_tag,
                upstream_text=edge.upstream_code,
                audit_text=combined_audit,
                decorators="",
                evidence=f"{edge.edge_summary} | code={edge.upstream_code}",
                allowlist=allowlist,
            )
        )
        if re.search(r"\b(eval|exec)\s*\(", edge.upstream_code):
            findings.append(
                OTFinding("High", "NODERED-EVAL", edge.file, edge.line,
                          f"Node-RED flow '{edge.flow_name}' executes dynamic eval/exec on PLC path.",
                          edge.upstream_code[:500], "Remove eval/exec; use static allow-listed tag and numeric clamp.",
                          "OWASP ASVS 5.2; IEC 62443 SR 3.3", blast_radius=[edge.file])
            )
    return findings


def analyze_write_paths(root: str | Path, allowlist_path: str | Path | None = None) -> list[OTFinding]:
    target = Path(root)
    allowlist = load_plc_allowlist(allowlist_path)
    findings: list[OTFinding] = []

    if target.is_file():
        if target.suffix.lower() == ".py":
            return _scan_python_file(target, allowlist)
        if target.suffix.lower() == ".json":
            return _scan_nodered_file(target, allowlist)
        return []

    py_files = sorted(
        p for p in target.rglob("*.py")
        if not any(part in SKIP_DIRS for part in p.relative_to(target).parts) and p.name != "ot_write_guard.py"
    )
    for py in py_files:
        findings.extend(_scan_python_file(py, allowlist))

    json_files = sorted(
        p for p in target.rglob("*.json")
        if not any(part in SKIP_DIRS for part in p.relative_to(target).parts)
    )
    for jf in json_files:
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except Exception:
            data = None
        if is_flow_candidate(jf, data):
            findings.extend(_scan_nodered_file(jf, allowlist))

    return findings


def summarize_ot_checks(findings: list[OTFinding]) -> dict[str, str]:
    """Summarize the 5 mandatory OT Write Guard checks as PASS/FAIL for API & UI."""
    rules = {f.rule for f in findings}
    return {
        "allowlist": "FAIL" if ({"PLC-WRITE-NOT-ALLOWLISTED", "PLC-WRITE-DYNAMIC-TAG", "UNPARSABLE_FLOW"} & rules) else "PASS",
        "clamp": "FAIL" if "PLC-WRITE-NO-CLAMP" in rules else "PASS",
        "auth": "FAIL" if ({"PLC-WRITE-NO-AUTH", "PLC-WRITE-UNAUTHORIZED-ROLE"} & rules) else "PASS",
        "interlock": "FAIL" if "PLC-WRITE-NO-INTERLOCK" in rules else "PASS",
        "audit": "FAIL" if "PLC-WRITE-NO-AUDIT" in rules else "PASS",
    }


class OTSafetyAgent:
    def __init__(self, root: str | Path, allowlist_path: str | Path | None = None):
        self.root = Path(root)
        self.allowlist_path = allowlist_path

    def run(self, quiet: bool = False) -> tuple[list[OTFinding], str]:
        findings = analyze_write_paths(self.root, allowlist_path=self.allowlist_path)
        seen: set[tuple[str, str, int]] = set()
        deduped: list[OTFinding] = []
        for f in findings:
            key = (f.rule, f.file, f.line)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        deduped.sort(key=lambda x: sev_order.get(x.severity.lower(), 9))
        highs = sum(1 for f in deduped if f.severity.lower() in {"high", "critical"})
        verdict = "BLOCK" if highs else ("ADVISORY" if deduped else "PASS")

        if not quiet:
            for f in deduped:
                print(f"[{f.severity.upper()}] {f.file}:{f.line}  {f.rule}  {f.message}")
            print(f"\nVerdict: {verdict} - {highs} High, {len(deduped) - highs} other.")
        return deduped, verdict


def main() -> None:
    ap = argparse.ArgumentParser(description="OT Safety Gate — Deterministic PLC write guard")
    ap.add_argument("--path", default="sample_repo", help="Repo or file to scan")
    ap.add_argument("--output", help="Write findings JSON to file")
    args = ap.parse_args()

    agent = OTSafetyAgent(args.path)
    findings, verdict = agent.run()
    if args.output:
        Path(args.output).write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")
    sys.exit(2 if verdict == "BLOCK" else (1 if findings else 0))


if __name__ == "__main__":
    main()
