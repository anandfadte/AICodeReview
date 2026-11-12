"""Node-RED JSON flow graph parser (read-only, fail closed per Spec P2)."""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ENTRY_NODE_TYPES = {
    "http in",
    "http-in",
    "mqtt in",
    "mqtt-in",
    "websocket in",
    "inject",
    "tcp in",
    "udp in",
}

_TAG_LITERAL_RE = re.compile(
    r"""(?:write_register|write_coil|write_tag|write_value|write_node|set_value|modbus_write|opcua_write|plc\.write)\(\s*["']([A-Za-z0-9_.:-]+)["']""",
    re.I,
)
_SETPOINT_TOPIC_HINT_RE = re.compile(r"(setpoint|cmd|command|plc|write|recipe)", re.I)


@dataclass
class FlowNode:
    id: str
    type: str
    name: str = ""
    topic: str = ""
    code: str = ""
    line: int = 1
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class FlowWriteEdge:
    file: str
    line: int
    flow_id: str
    flow_name: str
    source_node_id: str
    source_node_type: str
    sink_node_id: str
    sink_node_type: str
    path_node_ids: list[str]
    downstream_node_ids: list[str]
    edge_summary: str
    plc_tag: str | None
    mqtt_topic: str
    upstream_code: str
    downstream_code: str
    sink_code: str
    is_plc_write: bool = True


@dataclass
class FlowFinding:
    rule: str
    severity: str
    file: str
    line: int
    message: str
    evidence: str
    fix: str
    standard: str = "IEC 62443 SR 3.3"


@dataclass
class MqttEndpoint:
    file: str
    line: int
    direction: str
    topic: str
    node_id: str
    node_name: str
    flow_id: str


@dataclass
class FlowParseResult:
    file: str
    write_edges: list[FlowWriteEdge] = field(default_factory=list)
    mqtt_endpoints: list[MqttEndpoint] = field(default_factory=list)
    findings: list[FlowFinding] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def is_flow_candidate(path: Path, data: Any = None) -> bool:
    norm = path.as_posix().lower()
    if "flow" in path.name.lower() or "/flows/" in f"/{norm}":
        return True
    if isinstance(data, dict) and isinstance(data.get("flows"), list):
        return True
    if isinstance(data, list) and data and isinstance(data[0], dict) and "type" in data[0]:
        return True
    return False


def _find_line(text: str, marker: str, default: int = 1) -> int:
    if not marker:
        return default
    escaped = re.escape(marker)
    m = re.search(rf'"id"\s*:\s*"{escaped}"', text) or re.search(escaped, text)
    if not m:
        return default
    return text[: m.start()].count("\n") + 1


def _node_code(raw: dict[str, Any]) -> str:
    return str(raw.get("code") or raw.get("func") or "")


def _is_write_sink(node: FlowNode, flow_target_tag: str | None) -> bool:
    ntype = node.type.lower().strip()
    if ntype in {"modbus-write", "modbus-flex-write", "opc-ua-write", "opcua-write", "plc-write", "s7 out"}:
        return True
    if ntype in {"mqtt out", "mqtt-out"}:
        return bool(flow_target_tag or _SETPOINT_TOPIC_HINT_RE.search(node.topic or node.name))
    if ntype == "function":
        low = node.code.lower()
        return any(tok in low for tok in ("plc.write", "write_register", "write_coil", "write_tag", "modbus_write", "opcua_write"))
    return False


def _extract_plc_tag(sink: FlowNode, upstream_nodes: list[FlowNode], flow_target_tag: str | None) -> str | None:
    if sink.raw.get("target_plc_tag"):
        return str(sink.raw["target_plc_tag"])
    if sink.raw.get("tag"):
        return str(sink.raw["tag"])
    for n in [sink, *reversed(upstream_nodes)]:
        m = _TAG_LITERAL_RE.search(n.code)
        if m:
            return m.group(1)
    if flow_target_tag:
        return str(flow_target_tag)
    return None


def _bfs_reachable(start_ids: list[str], adj: dict[str, list[str]]) -> list[str]:
    visited: list[str] = []
    seen: set[str] = set()
    q = deque(start_ids)
    while q:
        cur = q.popleft()
        if cur in seen:
            continue
        seen.add(cur)
        visited.append(cur)
        for nxt in adj.get(cur, []):
            if nxt not in seen:
                q.append(nxt)
    return visited


def _parse_single_flow_block(
    file_str: str,
    raw_text: str,
    flow_id: str,
    flow_name: str,
    raw_nodes: Any,
    raw_wires: Any,
    flow_target_tag: str | None,
    flat_mode: bool,
) -> tuple[list[FlowWriteEdge], list[MqttEndpoint], list[FlowFinding]]:
    write_edges: list[FlowWriteEdge] = []
    mqtt_endpoints: list[MqttEndpoint] = []
    findings: list[FlowFinding] = []

    if not isinstance(raw_nodes, list) or not raw_nodes:
        findings.append(
            FlowFinding(
                rule="UNPARSABLE_FLOW",
                severity="High",
                file=file_str,
                line=_find_line(raw_text, flow_id),
                message=f"Flow '{flow_name or flow_id}' has missing or empty 'nodes' list — cannot prove safety.",
                evidence=f"flow_id={flow_id}",
                fix="Provide a valid non-empty 'nodes' array with typed nodes and explicit 'wires' edges.",
            )
        )
        return write_edges, mqtt_endpoints, findings

    nodes_by_id: dict[str, FlowNode] = {}
    for idx, item in enumerate(raw_nodes):
        if not isinstance(item, dict):
            findings.append(
                FlowFinding(
                    rule="UNPARSABLE_FLOW",
                    severity="High",
                    file=file_str,
                    line=_find_line(raw_text, flow_id),
                    message=f"Flow '{flow_name or flow_id}' contains non-object node at index {idx}.",
                    evidence=str(item)[:300],
                    fix="Every Node-RED node must be a JSON object with 'id' and 'type'.",
                )
            )
            return write_edges, mqtt_endpoints, findings
        nid = str(item.get("id") or "").strip()
        ntype = str(item.get("type") or "").strip()
        if not nid or not ntype:
            findings.append(
                FlowFinding(
                    rule="UNPARSABLE_FLOW",
                    severity="High",
                    file=file_str,
                    line=_find_line(raw_text, nid or flow_id),
                    message=f"Node at index {idx} in flow '{flow_name or flow_id}' is missing 'id' or 'type'.",
                    evidence=json.dumps(item)[:300],
                    fix="Ensure every node defines non-empty 'id' and 'type'.",
                )
            )
            return write_edges, mqtt_endpoints, findings
        if ntype == "tab":
            continue
        nodes_by_id[nid] = FlowNode(
            id=nid,
            type=ntype,
            name=str(item.get("name") or ""),
            topic=str(item.get("topic") or ""),
            code=_node_code(item),
            line=_find_line(raw_text, nid),
            raw=item,
        )

    if not nodes_by_id:
        findings.append(
            FlowFinding(
                rule="UNPARSABLE_FLOW",
                severity="High",
                file=file_str,
                line=_find_line(raw_text, flow_id),
                message=f"Flow '{flow_name or flow_id}' has no executable nodes.",
                evidence=f"flow_id={flow_id}",
                fix="Add valid source, validation, and sink nodes or remove empty flow.",
            )
        )
        return write_edges, mqtt_endpoints, findings

    adj: dict[str, list[str]] = defaultdict(list)
    rev_adj: dict[str, list[str]] = defaultdict(list)

    if flat_mode:
        for nid, node in nodes_by_id.items():
            node_wires = node.raw.get("wires", [])
            if not isinstance(node_wires, list):
                findings.append(
                    FlowFinding(
                        rule="UNPARSABLE_FLOW",
                        severity="High",
                        file=file_str,
                        line=node.line,
                        message=f"Node '{nid}' has non-list 'wires' field.",
                        evidence=str(node_wires)[:300],
                        fix="Use standard Node-RED wires list of target ID lists.",
                    )
                )
                return write_edges, mqtt_endpoints, findings
            for port in node_wires:
                if not isinstance(port, list):
                    findings.append(
                        FlowFinding(
                            rule="UNPARSABLE_FLOW",
                            severity="High",
                            file=file_str,
                            line=node.line,
                            message=f"Node '{nid}' has malformed wire port.",
                            evidence=str(node_wires)[:300],
                            fix="Ensure each port in 'wires' is a list of valid node IDs.",
                        )
                    )
                    return write_edges, mqtt_endpoints, findings
                for dst in port:
                    dst_id = str(dst)
                    if dst_id not in nodes_by_id:
                        findings.append(
                            FlowFinding(
                                rule="UNPARSABLE_FLOW",
                                severity="High",
                                file=file_str,
                                line=node.line,
                                message=f"Wire from '{nid}' points to unknown node ID '{dst_id}'.",
                                evidence=f"{nid} -> {dst_id}",
                                fix="Fix dangling wire edge so all targets resolve to existing node IDs.",
                            )
                        )
                        return write_edges, mqtt_endpoints, findings
                    adj[nid].append(dst_id)
                    rev_adj[dst_id].append(nid)
    else:
        if raw_wires is None or not isinstance(raw_wires, list):
            findings.append(
                FlowFinding(
                    rule="UNPARSABLE_FLOW",
                    severity="High",
                    file=file_str,
                    line=_find_line(raw_text, flow_id),
                    message=f"Flow '{flow_name or flow_id}' is missing valid 'wires' edge list.",
                    evidence=f"flow_id={flow_id}",
                    fix="Provide 'wires': [[src_id, dst_id], ...] representing graph edges.",
                )
            )
            return write_edges, mqtt_endpoints, findings
        for edge in raw_wires:
            if not (isinstance(edge, list) and len(edge) >= 2):
                findings.append(
                    FlowFinding(
                        rule="UNPARSABLE_FLOW",
                        severity="High",
                        file=file_str,
                        line=_find_line(raw_text, flow_id),
                        message=f"Malformed wire edge {edge!r} in flow '{flow_name or flow_id}'.",
                        evidence=str(edge)[:300],
                        fix="Each wire edge must be a [source_id, target_id] pair.",
                    )
                )
                return write_edges, mqtt_endpoints, findings
            src_id, dst_id = str(edge[0]), str(edge[1])
            if src_id not in nodes_by_id or dst_id not in nodes_by_id:
                findings.append(
                    FlowFinding(
                        rule="UNPARSABLE_FLOW",
                        severity="High",
                        file=file_str,
                        line=_find_line(raw_text, flow_id),
                        message=f"Wire edge [{src_id} -> {dst_id}] references missing node.",
                        evidence=str(edge)[:300],
                        fix="Ensure both endpoints of every wire edge exist in 'nodes'.",
                    )
                )
                return write_edges, mqtt_endpoints, findings
            adj[src_id].append(dst_id)
            rev_adj[dst_id].append(src_id)

    for node in nodes_by_id.values():
        nt = node.type.lower().strip()
        if nt in {"mqtt in", "mqtt-in"}:
            mqtt_endpoints.append(
                MqttEndpoint(file_str, node.line, "subscribe", node.topic, node.id, node.name or node.id, flow_id)
            )
        elif nt in {"mqtt out", "mqtt-out"}:
            mqtt_endpoints.append(
                MqttEndpoint(file_str, node.line, "publish", node.topic, node.id, node.name or node.id, flow_id)
            )

    for node in nodes_by_id.values():
        if not _is_write_sink(node, flow_target_tag):
            continue

        upstream_ids = _bfs_reachable([node.id], rev_adj)
        upstream_ids.reverse()
        downstream_ids = [nid for nid in _bfs_reachable(adj.get(node.id, []), adj) if nid != node.id]

        entry_candidates = [
            nid for nid in upstream_ids
            if nodes_by_id[nid].type.lower().strip() in ENTRY_NODE_TYPES or not rev_adj.get(nid)
        ]
        source_node = nodes_by_id[entry_candidates[0]] if entry_candidates else nodes_by_id[upstream_ids[0]]

        upstream_nodes = [nodes_by_id[nid] for nid in upstream_ids]
        downstream_nodes = [nodes_by_id[nid] for nid in downstream_ids]
        plc_tag = _extract_plc_tag(node, upstream_nodes, flow_target_tag)

        if node.type.lower().strip() in {"modbus-write", "modbus-flex-write", "opc-ua-write", "opcua-write", "plc-write", "s7 out"} and not plc_tag:
            findings.append(
                FlowFinding(
                    rule="UNPARSABLE_FLOW",
                    severity="High",
                    file=file_str,
                    line=node.line,
                    message=f"PLC write node '{node.name or node.id}' ({node.type}) has no parseable target PLC tag.",
                    evidence=json.dumps(node.raw)[:300],
                    fix="Specify 'target_plc_tag' (from allow_lists/plc_allowlist.json) on the flow or node.",
                )
            )
            continue

        if node.type.lower().strip() in {"mqtt out", "mqtt-out"} and not node.topic and not plc_tag:
            findings.append(
                FlowFinding(
                    rule="UNPARSABLE_FLOW",
                    severity="High",
                    file=file_str,
                    line=node.line,
                    message=f"MQTT write node '{node.name or node.id}' has empty topic and no target PLC tag.",
                    evidence=json.dumps(node.raw)[:300],
                    fix="Set explicit MQTT 'topic' and 'target_plc_tag' for PLC write paths.",
                )
            )
            continue

        chain_labels = [
            f"{nodes_by_id[nid].name or nid} ({nodes_by_id[nid].type})"
            for nid in [*upstream_ids, *downstream_ids]
        ]
        if node.topic:
            chain_labels.append(f"MQTT[{node.topic}]")
        if plc_tag:
            chain_labels.append(f"PLC[{plc_tag}]")

        upstream_code = "\n".join(part for n in upstream_nodes for part in (n.code, n.name, n.topic) if part)
        downstream_code = "\n".join(part for n in downstream_nodes for part in (n.code, n.name, n.topic) if part)

        write_edges.append(
            FlowWriteEdge(
                file=file_str,
                line=node.line,
                flow_id=flow_id,
                flow_name=flow_name or flow_id,
                source_node_id=source_node.id,
                source_node_type=source_node.type,
                sink_node_id=node.id,
                sink_node_type=node.type,
                path_node_ids=upstream_ids,
                downstream_node_ids=downstream_ids,
                edge_summary=" -> ".join(chain_labels),
                plc_tag=plc_tag,
                mqtt_topic=node.topic,
                upstream_code=upstream_code,
                downstream_code=downstream_code,
                sink_code=node.code,
                is_plc_write=True,
            )
        )

    return write_edges, mqtt_endpoints, findings


def parse_flow_file(path: str | Path) -> FlowParseResult:
    p = Path(path)
    file_str = str(p)
    result = FlowParseResult(file=file_str)

    try:
        raw_text = p.read_text(encoding="utf-8")
    except Exception as exc:
        if is_flow_candidate(p):
            result.findings.append(
                FlowFinding("UNPARSABLE_FLOW", "High", file_str, 1, f"Could not read flow file: {exc}", str(exc)[:300], "Ensure UTF-8 JSON.")
            )
        return result

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        if is_flow_candidate(p):
            result.findings.append(
                FlowFinding(
                    "UNPARSABLE_FLOW",
                    "High",
                    file_str,
                    exc.lineno or 1,
                    f"Invalid JSON in Node-RED flow ({exc.msg}) — fail closed.",
                    raw_text[:300],
                    "Fix JSON syntax in Node-RED flow.",
                )
            )
        return result

    if not is_flow_candidate(p, data):
        return result

    if isinstance(data, dict) and "flows" in data:
        flows = data.get("flows")
        if not isinstance(flows, list) or not flows:
            result.findings.append(
                FlowFinding("UNPARSABLE_FLOW", "High", file_str, 1, "Flow file has empty or non-list 'flows'.", raw_text[:300], "Populate 'flows' with valid flow objects.")
            )
            return result
        for idx, flow in enumerate(flows):
            if not isinstance(flow, dict):
                result.findings.append(
                    FlowFinding("UNPARSABLE_FLOW", "High", file_str, 1, f"Flow entry at index {idx} is not an object.", str(flow)[:300], "Each flow must be an object.")
                )
                continue
            fid = str(flow.get("id") or f"flow-{idx}")
            fname = str(flow.get("name") or fid)
            edges, mqtts, ff = _parse_single_flow_block(
                file_str, raw_text, fid, fname, flow.get("nodes"), flow.get("wires"), flow.get("target_plc_tag"), False
            )
            result.write_edges.extend(edges)
            result.mqtt_endpoints.extend(mqtts)
            result.findings.extend(ff)
    elif isinstance(data, list):
        edges, mqtts, ff = _parse_single_flow_block(
            file_str, raw_text, p.stem, p.stem, data, None, None, True
        )
        result.write_edges.extend(edges)
        result.mqtt_endpoints.extend(mqtts)
        result.findings.extend(ff)
    else:
        result.findings.append(
            FlowFinding("UNPARSABLE_FLOW", "High", file_str, 1, "Unrecognized Node-RED flow schema.", raw_text[:300], "Use {'flows': [...]} or node array schema.")
        )

    result.tags = sorted({e.plc_tag for e in result.write_edges if e.plc_tag})
    return result
