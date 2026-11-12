"""Deterministic MES & Compliance checks (MES-001, MES-002, SEC-001, OT-002, OT-003, LLM-001, PRIV-001)."""

from __future__ import annotations

import ast
import json
import operator
import re
from pathlib import Path
from typing import Any

from backend.reviewer.findings.schema import Finding, make_finding_id
from backend.reviewer.ingestion.flow_parser import is_flow_candidate, parse_flow_file
from backend.reviewer.ingestion.github_diff import SKIP_DIRS

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg, ast.Not: operator.not_}
_CMP_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}
_SAFE_FUNCS = {"min": min, "max": max, "abs": abs, "round": round, "float": float, "int": int}

OEE_PROPERTY_CASES: list[tuple[str, dict[str, float]]] = [
    ("normal_shift", {"planned_time": 480.0, "downtime": 60.0, "ideal_rate": 100.0, "actual_output": 90.0, "good_parts": 85.0}),
    ("zero_planned_time", {"planned_time": 0.0, "downtime": 0.0, "ideal_rate": 100.0, "actual_output": 0.0, "good_parts": 0.0}),
    ("zero_ideal_rate", {"planned_time": 480.0, "downtime": 60.0, "ideal_rate": 0.0, "actual_output": 50.0, "good_parts": 50.0}),
    ("zero_actual_output", {"planned_time": 480.0, "downtime": 480.0, "ideal_rate": 100.0, "actual_output": 0.0, "good_parts": 0.0}),
    ("over_ideal_output", {"planned_time": 480.0, "downtime": 0.0, "ideal_rate": 100.0, "actual_output": 150.0, "good_parts": 150.0}),
    ("excess_downtime", {"planned_time": 480.0, "downtime": 540.0, "ideal_rate": 100.0, "actual_output": 50.0, "good_parts": 50.0}),
]


class _PropertyReturn(Exception):
    def __init__(self, value: Any):
        self.value = value


def _eval_expr(node: ast.AST, env: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        if node.id in _SAFE_FUNCS:
            return _SAFE_FUNCS[node.id]
        raise KeyError(f"Unknown symbol {node.id}")
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        return _BIN_OPS[type(node.op)](_eval_expr(node.left, env), _eval_expr(node.right, env))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_eval_expr(node.operand, env))
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            val = True
            for v in node.values:
                val = _eval_expr(v, env)
                if not val:
                    return val
            return val
        if isinstance(node.op, ast.Or):
            val = False
            for v in node.values:
                val = _eval_expr(v, env)
                if val:
                    return val
            return val
    if isinstance(node, ast.Compare):
        left = _eval_expr(node.left, env)
        for op_node, comp in zip(node.ops, node.comparators):
            right = _eval_expr(comp, env)
            if not _CMP_OPS[type(op_node)](left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.IfExp):
        return _eval_expr(node.body if _eval_expr(node.test, env) else node.orelse, env)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _SAFE_FUNCS:
        return _SAFE_FUNCS[node.func.id](*[_eval_expr(a, env) for a in node.args])
    if isinstance(node, (ast.Tuple, ast.List)):
        return [_eval_expr(e, env) for e in node.elts]
    if isinstance(node, ast.Dict):
        return {_eval_expr(k, env): _eval_expr(v, env) for k, v in zip(node.keys, node.values) if k is not None}
    raise ValueError(f"Unsupported AST expression: {type(node).__name__}")


def _exec_stmts(stmts: list[ast.stmt], env: dict[str, Any]) -> None:
    for stmt in stmts:
        if isinstance(stmt, ast.Return):
            raise _PropertyReturn(_eval_expr(stmt.value, env) if stmt.value is not None else None)
        if isinstance(stmt, ast.Assign):
            val = _eval_expr(stmt.value, env)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env[target.id] = val
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None and isinstance(stmt.target, ast.Name):
            env[stmt.target.id] = _eval_expr(stmt.value, env)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name) and type(stmt.op) in _BIN_OPS:
            env[stmt.target.id] = _BIN_OPS[type(stmt.op)](env.get(stmt.target.id, 0), _eval_expr(stmt.value, env))
        elif isinstance(stmt, ast.If):
            _exec_stmts(stmt.body if _eval_expr(stmt.test, env) else stmt.orelse, env)
        elif isinstance(stmt, ast.Raise):
            raise ValueError("Validation error")


def _run_oee_function(fn: ast.FunctionDef, inputs: dict[str, float]) -> Any:
    param_names = [a.arg for a in fn.args.args]
    env: dict[str, Any] = {}
    alias_order = ["planned_time", "downtime", "ideal_rate", "actual_output", "good_parts"]
    for idx, pname in enumerate(param_names):
        low = pname.lower()
        if pname in inputs:
            env[pname] = inputs[pname]
        elif "calendar" in low or "planned" in low or "total" in low:
            env[pname] = inputs["planned_time"]
        elif "down" in low:
            env[pname] = inputs["downtime"]
        elif "ideal" in low:
            env[pname] = inputs["ideal_rate"]
        elif "actual" in low or "total_parts" in low:
            env[pname] = inputs["actual_output"]
        elif "good" in low:
            env[pname] = inputs["good_parts"]
        elif idx < len(alias_order):
            env[pname] = inputs[alias_order[idx]]
        else:
            env[pname] = 0.0
    try:
        _exec_stmts(fn.body, env)
    except _PropertyReturn as ret:
        return ret.value
    return None


def check_oee_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    file_str = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text, filename=file_str)
    except (SyntaxError, UnicodeDecodeError, OSError):
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        src = ast.get_source_segment(text, node) or ""
        if not ("oee" in node.name.lower() and ("availability" in src.lower() or "performance" in src.lower() or "quality" in src.lower() or "/" in src)):
            continue

        param_names = [a.arg.lower() for a in node.args.args]
        if any("calendar" in p for p in param_names) or re.search(r"\bcalendar_time\b", src):
            findings.append(
                Finding(
                    id=make_finding_id("MES-001", "OEE-CALENDAR-TIME", file_str, node.lineno),
                    check_id="MES-001",
                    severity="Medium",
                    confidence=0.95,
                    file=file_str,
                    line=node.lineno,
                    rule="OEE-CALENDAR-TIME",
                    evidence=src,
                    blast_radius=[file_str],
                    standards=["IATF 16949 8.5.1"],
                    fix="Compute Availability against scheduled `planned_time`, never calendar time.",
                    message=f"OEE function `{node.name}` references calendar time instead of planned time.",
                )
            )

        div_zero_cases: list[str] = []
        oob_cases: list[str] = []
        for case_name, inputs in OEE_PROPERTY_CASES:
            try:
                val = _run_oee_function(node, inputs)
            except ZeroDivisionError:
                div_zero_cases.append(case_name)
                continue
            except Exception:
                continue
            if isinstance(val, (int, float)) and not (0.0 <= float(val) <= 1.0):
                oob_cases.append(f"{case_name}={val:.3f}")

        if div_zero_cases:
            findings.append(
                Finding(
                    id=make_finding_id("MES-001", "OEE-DIV-BY-ZERO", file_str, node.lineno),
                    check_id="MES-001",
                    severity="High",
                    confidence=1.0,
                    file=file_str,
                    line=node.lineno,
                    rule="OEE-DIV-BY-ZERO",
                    evidence=src,
                    blast_radius=[file_str],
                    standards=["IATF 16949 8.5.1"],
                    fix="Guard all OEE denominators (`planned_time`, `ideal_rate`, `actual_output`) against 0.",
                    message=f"OEE property test failed with ZeroDivisionError on: {', '.join(div_zero_cases)}.",
                )
            )
        if oob_cases:
            findings.append(
                Finding(
                    id=make_finding_id("MES-001", "OEE-OUT-OF-RANGE", file_str, node.lineno),
                    check_id="MES-001",
                    severity="High",
                    confidence=1.0,
                    file=file_str,
                    line=node.lineno,
                    rule="OEE-OUT-OF-RANGE",
                    evidence=src,
                    blast_radius=[file_str],
                    standards=["IATF 16949 8.5.1"],
                    fix="Clamp Availability, Performance, Quality, and final OEE to [0.0, 1.0].",
                    message=f"OEE property test produced out-of-range OEE outside [0, 1]: {', '.join(oob_cases)}.",
                )
            )
    return findings


def check_genealogy_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    file_str = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text, filename=file_str)
    except (SyntaxError, UnicodeDecodeError, OSError):
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        src = ast.get_source_segment(text, node) or ""
        is_gen = any(k in node.name.lower() for k in ("save_part", "create_part", "record_part", "update_part", "genealogy")) or (
            "part_id" in src and ("lot_id" in src or "order_id" in src)
        )
        if not is_gen:
            continue

        defaults_offset = len(node.args.args) - len(node.args.defaults)
        nullable_required: list[str] = []
        param_names = {a.arg for a in node.args.args}
        missing_params = [f for f in ("lot_id", "order_id") if f not in param_names]
        if not any("machine" in p for p in param_names):
            missing_params.append("machine")

        for idx, arg in enumerate(node.args.args):
            if arg.arg in {"lot_id", "order_id", "machine", "machine_id"}:
                def_idx = idx - defaults_offset
                if def_idx >= 0 and isinstance(node.args.defaults[def_idx], ast.Constant) and node.args.defaults[def_idx].value is None:
                    nullable_required.append(arg.arg)

        has_validation = bool(
            re.search(r"if\s+not\s+(?:lot_id|order_id|machine)", src)
            or re.search(r"if\s+any\s*\(\s*not\s+", src)
            or re.search(r"if\s+.*is\s+None\b", src)
        )
        has_audit = bool(re.search(r"\b(audit_log|log\.write|log_write|audit\.insert|record_change)\b", src))

        if missing_params or (nullable_required and not has_validation):
            fields_desc = missing_params or nullable_required
            findings.append(
                Finding(
                    id=make_finding_id("MES-002", "GENEALOGY-ORPHAN-PART", file_str, node.lineno),
                    check_id="MES-002",
                    severity="High",
                    confidence=1.0,
                    file=file_str,
                    line=node.lineno,
                    rule="GENEALOGY-ORPHAN-PART",
                    evidence=src,
                    blast_radius=[file_str],
                    standards=["IATF 16949 8.5.2", "ISO 27001 A.12"],
                    fix=f"Require non-null {', '.join(fields_desc)} (`if not lot_id or not machine or not order_id: raise ValueError`) before save.",
                    message=f"Genealogy function `{node.name}` allows saving orphan part without validated {fields_desc}.",
                )
            )
        if not has_audit:
            findings.append(
                Finding(
                    id=make_finding_id("MES-002", "GENEALOGY-NO-AUDIT-LOG", file_str, node.lineno),
                    check_id="MES-002",
                    severity="Medium",
                    confidence=0.95,
                    file=file_str,
                    line=node.lineno,
                    rule="GENEALOGY-NO-AUDIT-LOG",
                    evidence=src,
                    blast_radius=[file_str],
                    standards=["IATF 16949 8.5.2", "ISO 27001 A.12"],
                    fix="Insert an append-only audit log entry (`audit_log.insert(...)`) on part save/update.",
                    message=f"Genealogy function `{node.name}` mutates traceability without an audit log.",
                )
            )
    return findings


def load_rbac_matrix(path: str | Path | None = None) -> dict[str, Any]:
    candidates = [Path(path)] if path else []
    candidates.extend([Path.cwd() / "allow_lists" / "rbac_matrix.json", Path(__file__).resolve().parents[3] / "allow_lists" / "rbac_matrix.json"])
    for c in candidates:
        if c.is_file():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {"roles": ["Admin", "Plant Head", "Supervisor", "Operator", "Quality"], "endpoints": {}}


def load_mqtt_acl(path: str | Path | None = None) -> dict[str, Any]:
    candidates = [Path(path)] if path else []
    candidates.extend([Path.cwd() / "allow_lists" / "mqtt_acl.json", Path(__file__).resolve().parents[3] / "allow_lists" / "mqtt_acl.json"])
    for c in candidates:
        if c.is_file():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {}


def check_rbac_idor_file(path: Path, rbac_matrix: dict[str, Any] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    file_str = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text, filename=file_str)
    except (SyntaxError, UnicodeDecodeError, OSError):
        return findings

    rbac = rbac_matrix or load_rbac_matrix()
    endpoints_cfg = rbac.get("endpoints", {})
    auth_re = re.compile(r"require_role|require_auth|has_role|Depends\(.*auth|role\s+not\s+in|role\s+in|HTTPException.*403", re.I)
    ownership_re = re.compile(r"(plant\s*==|plant_id\s*==|owner|x_plant\s*==|verify_plant|check_plant_access|403)", re.I)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = ast.get_source_segment(text, node) or ""
        code_no_comments = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
        for dec in node.decorator_list:
            dec_src = ast.get_source_segment(text, dec) or ""
            m_route = re.search(r"@?(?:app|router)\.(get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']", dec_src, re.I)
            if not m_route:
                continue
            method, route_path = m_route.group(1).upper(), m_route.group(2)
            key = f"{method} {route_path}"
            all_decs = " ".join(ast.get_source_segment(text, d) or "" for d in node.decorator_list)
            has_role_guard = bool(auth_re.search(all_decs) or auth_re.search(code_no_comments))

            matrix_entry = endpoints_cfg.get(key)
            requires_restricted = (
                any(v is False for k, v in matrix_entry.items() if k != "note")
                if isinstance(matrix_entry, dict)
                else ("/admin" in route_path or "/setpoint" in route_path or method in {"POST", "PUT", "DELETE", "PATCH"})
            )
            if requires_restricted and not has_role_guard:
                findings.append(
                    Finding(
                        id=make_finding_id("SEC-001", "RBAC-MISSING-ROLE-CHECK", file_str, node.lineno),
                        check_id="SEC-001",
                        severity="High",
                        confidence=0.95,
                        file=file_str,
                        line=node.lineno,
                        rule="RBAC-MISSING-ROLE-CHECK",
                        evidence=src,
                        blast_radius=[file_str],
                        standards=["OWASP ASVS 4.1", "ISO 27001 A.9"],
                        fix=f"Enforce `@require_role(...)` / FastAPI `Depends` on `{key}` matching allow_lists/rbac_matrix.json.",
                        message=f"Endpoint `{key}` lacks RBAC role check.",
                    )
                )

            if "{" in route_path and "}" in route_path and not ownership_re.search(code_no_comments):
                findings.append(
                    Finding(
                        id=make_finding_id("SEC-001", "IDOR-MISSING-OWNERSHIP", file_str, node.lineno),
                        check_id="SEC-001",
                        severity="High",
                        confidence=0.95,
                        file=file_str,
                        line=node.lineno,
                        rule="IDOR-MISSING-OWNERSHIP",
                        evidence=src,
                        blast_radius=[file_str],
                        standards=["OWASP ASVS 4.1", "ISO 27001 A.9"],
                        fix=f"Verify `record.plant == current_user.plant` (HTTP 403 otherwise) in `{key}`.",
                        message=f"Endpoint `{key}` fetches resource by ID without plant/ownership check (IDOR).",
                    )
                )
    return findings


def check_mqtt_acl_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    file_str = str(path)
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = None
        if is_flow_candidate(path, data):
            for ep in parse_flow_file(path).mqtt_endpoints:
                if "#" in (ep.topic or ""):
                    findings.append(
                        Finding(
                            id=make_finding_id("OT-002", "MQTT-WILDCARD-TOPIC", file_str, ep.line),
                            check_id="OT-002",
                            severity="High",
                            confidence=1.0,
                            file=file_str,
                            line=ep.line,
                            rule="MQTT-WILDCARD-TOPIC",
                            evidence=f"{ep.direction} topic={ep.topic}",
                            blast_radius=[file_str],
                            standards=["IEC 62443 SR 2.1", "IEC 62443 SR 3.3"],
                            fix="Replace '#' wildcard MQTT topic with scoped topic from allow_lists/mqtt_acl.json.",
                            message=f"Node-RED MQTT {ep.direction} uses forbidden '#' wildcard '{ep.topic}'.",
                        )
                    )
        return findings

    if path.suffix.lower() == ".py":
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            return findings
        for idx, line in enumerate(text.splitlines(), start=1):
            m = re.search(r"""\.(publish|subscribe)\(\s*["']([^"']+)["']""", line)
            if m and ("#" in m.group(2) or (m.group(1) == "publish" and "+" in m.group(2))):
                findings.append(
                    Finding(
                        id=make_finding_id("OT-002", "MQTT-WILDCARD-TOPIC", file_str, idx),
                        check_id="OT-002",
                        severity="High",
                        confidence=1.0,
                        file=file_str,
                        line=idx,
                        rule="MQTT-WILDCARD-TOPIC",
                        evidence=line.strip(),
                        blast_radius=[file_str],
                        standards=["IEC 62443 SR 2.1", "IEC 62443 SR 3.3"],
                        fix="Restrict MQTT topic to allow_lists/mqtt_acl.json without '#' wildcards.",
                        message=f"MQTT {m.group(1)} uses overly broad wildcard topic '{m.group(2)}'.",
                    )
                )
    return findings


def check_opcua_file(path: Path) -> list[Finding]:
    if path.suffix.lower() != ".py":
        return []
    file_str = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    if not re.search(r"\b(opcua|asyncua|set_security_string)\b", text, re.I):
        return []
    if "SignAndEncrypt" not in text or re.search(r"(SecurityPolicyNone|None,None|anonymous|AnonymousIdentityToken)", text, re.I):
        return [
            Finding(
                id=make_finding_id("OT-003", "OPCUA-INSECURE-SESSION", file_str, 1),
                check_id="OT-003",
                severity="High",
                confidence=0.95,
                file=file_str,
                line=1,
                rule="OPCUA-INSECURE-SESSION",
                evidence=text[:300],
                blast_radius=[file_str],
                standards=["IEC 62443 SR 3.1"],
                fix="Configure OPC UA session with `SignAndEncrypt` and disable anonymous login.",
                message="OPC UA session lacks SignAndEncrypt policy or allows anonymous access.",
            )
        ]
    return []


def check_ask_linetrack_file(path: Path) -> list[Finding]:
    if path.suffix.lower() != ".py":
        return []
    findings: list[Finding] = []
    file_str = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text, filename=file_str)
    except (SyntaxError, UnicodeDecodeError, OSError):
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        src = ast.get_source_segment(text, node) or ""
        if not ("prompt" in src.lower() and ("logs" in src.lower() or "ask" in node.name.lower())):
            continue
        code_no_comments = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
        body_src = "\n".join(code_no_comments.splitlines()[1:])
        has_delim = bool(re.search(r"(<DATA>|</DATA>|<UNTRUSTED|UNTRUSTED_DATA|logs are data|treat logs as data)", body_src, re.I))
        has_plant_filter = bool(re.search(r"(filter_by_plant|log\.plant\s*==|\.plant\s*==\s*user_plant|if\b[^#\n]*\buser_plant\b|where\s+plant\s*=)", body_src, re.I))

        if not has_delim:
            findings.append(
                Finding(
                    id=make_finding_id("LLM-001", "LLM-UNDELIMITED-LOGS", file_str, node.lineno),
                    check_id="LLM-001",
                    severity="High",
                    confidence=0.95,
                    file=file_str,
                    line=node.lineno,
                    rule="LLM-UNDELIMITED-LOGS",
                    evidence=src,
                    blast_radius=[file_str],
                    standards=["OWASP LLM Top 10 LLM01", "OWASP LLM Top 10 LLM02"],
                    fix="Wrap logs in `<UNTRUSTED_DATA>` delimiters and enforce data-only system hierarchy.",
                    message=f"Prompt builder `{node.name}` concatenates raw logs without delimiter or data-only instruction.",
                )
            )
        if ("user_plant" in src or "user_role" in src) and not has_plant_filter:
            findings.append(
                Finding(
                    id=make_finding_id("LLM-001", "LLM-CROSS-PLANT-LEAKAGE", file_str, node.lineno),
                    check_id="LLM-001",
                    severity="High",
                    confidence=0.9,
                    file=file_str,
                    line=node.lineno,
                    rule="LLM-CROSS-PLANT-LEAKAGE",
                    evidence=src,
                    blast_radius=[file_str],
                    standards=["OWASP LLM Top 10 LLM02", "DPDP"],
                    fix="Filter logs by `user_plant` and `user_role` before building the prompt.",
                    message=f"Prompt builder `{node.name}` does not filter logs by `user_plant`/`user_role`.",
                )
            )
    return findings


def check_dpdp_pii_file(path: Path) -> list[Finding]:
    if path.suffix.lower() not in {".py", ".sql"}:
        return []
    file_str = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    m = re.search(r"\b(operator_name|employee_id|productivity_scores?|attendance_log|aadhaar|phone_number|personal_email)\b", text, re.I)
    if m and not re.search(r"\b(retention_policy|dpdp_purpose|consent_id|anonymize)\b", text, re.I):
        lineno = text[: m.start()].count("\n") + 1
        return [
            Finding(
                id=make_finding_id("PRIV-001", "DPDP-PII-NO-PURPOSE-RETENTION", file_str, lineno),
                check_id="PRIV-001",
                severity="Medium",
                confidence=0.85,
                file=file_str,
                line=lineno,
                rule="DPDP-PII-NO-PURPOSE-RETENTION",
                evidence=text.splitlines()[lineno - 1].strip(),
                blast_radius=[file_str],
                standards=["DPDP Act", "ISO 27001 A.8"],
                fix="Add DPDP purpose binding and retention TTL (per policy, to be confirmed).",
                message=f"PII field `{m.group(1)}` handled without purpose/retention guard (retention: per policy, to be confirmed).",
            )
        ]
    return []


def run_mes_checks(root_or_files: str | Path | list[Path]) -> list[Finding]:
    if isinstance(root_or_files, (str, Path)):
        p = Path(root_or_files)
        files = [p] if p.is_file() else sorted(f for f in p.rglob("*.py") if not any(part in SKIP_DIRS for part in f.relative_to(p).parts))
    else:
        files = [Path(f) for f in root_or_files if Path(f).suffix.lower() == ".py"]

    findings: list[Finding] = []
    for py in files:
        findings.extend(check_oee_file(py))
        findings.extend(check_genealogy_file(py))
    return findings
