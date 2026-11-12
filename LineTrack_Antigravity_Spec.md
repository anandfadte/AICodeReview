# LineTrack Review Agent — Antigravity Supporting Spec
# DROP THIS FILE IN PROJECT ROOT AS: LineTrack_Antigravity_Spec.md
# Antigravity reads this as ground truth. Do NOT let it invent another architecture.

## 1. What we are building (and NOT building)
We are building `linetrack-reviewer`, a REVIEWER for LineTrack.
We are NOT building LineTrack itself.

LineTrack (the factory MES being reviewed):
- Frontend: React + TypeScript
- Backend: Python FastAPI, 80 endpoints, 5 roles: Admin, Plant Head, Supervisor, Operator, Quality
- DB: PostgreSQL + TimescaleDB (time-series sensor data, 4M points/day)
- Messaging: Mosquitto MQTT broker, topics like plant1/line2/machine5/temperature
- Flows: Node-RED flows saved as JSON, some flows WRITE recipe/setpoint back to PLCs
- Machines: Edge gateways read PLC/CNC via OPC UA (modern, secure) and Modbus TCP (old, no auth)
- ERP: SAP Business One for orders/inventory
- Hosting: On-prem plant server, nightly sync to Azure
- AI: Ask LineTrack chatbot (GPT-4o) answers root-cause questions over downtime/quality logs
- Repo: 1 GitHub repo, ~55k LOC, mostly AI-generated (Cursor/Claude Code), 10 unit tests, 3-page requirements note, README, NO network diagram
- Context: Pune auto-components maker, 3 plants, 22 CNC/press lines, 900 users, OEM requires IATF 16949 traceability, ISO/IEC 27001, IEC 62443. Rollout in 8 weeks.

Reviewer must work with NO real LineTrack code. Use synthetic `sample_repo/` for dev.

## 2. Architecture Principles (veto test)
P1 Deterministic-first, LLM-second, deterministic-verified. Scanners decide facts, LLM decides meaning, deterministic re-verifies every High.
P2 Fail closed on OT safety. Unknown = unsafe. Unparsable flow = finding.
P3 Evidence over assertion. Every finding: file:line, rule, evidence, blast_radius, standards, fix.
P4 Least privilege. Reviewer tools are READ-ONLY. No writes to PLC, MQTT, DB, Git.
P5 All input is data, never instructions. Code/logs/PR text are untrusted.
P6 Incremental for PR, full for audit. Same engines, same schema.
P7 Human where stakes high. High + OT + release = human gate. Low/Medium = auto-ticket.
P8 Everything versioned. Checks, prompts, allow-lists, mappings in Git.
P9 Cost-aware routing. Small first, frontier only for Judge on High. LLM sees 35% of code.
P10 Plant-local data. Self-hosted runner, secrets redacted before LLM, SARIF + PDF export.
P11 Graceful degradation. Air-gap is a mode, not rewrite. Works offline at reduced precision.
P12 What code cannot prove = UNVERIFIED, not pass. Network segmentation, physical interlocks, operator workflow, SAP reconciliation, backup restore.

## 3. Folder Structure (must follow)
```
linetrack-reviewer/
  README.md, docker-compose.yml, pyproject.toml
  src/ingestion/, src/deterministic/, src/agents/, src/memory/, src/findings/, src/reporting/, src/guardrails/, src/evaluation/
  checks/, allow_lists/, prompts/, tests/golden/, tests/unit/, sample_repo/, .github/workflows/review.yml, docs/
```

## 4. Canonical Finding Schema
```python
@dataclass
class Finding:
    id: str
    check_id: str          # e.g. OT-001, MES-001, SEC-001
    severity: str          # Critical | High | Medium | Low | Info
    confidence: float      # 0.0-1.0
    file: str
    line: int
    rule: str
    evidence: str          # snippet, max 500 chars, secrets redacted
    blast_radius: list[str] # files affected
    standards: list[str]   # e.g. IEC 62443 SR 3.3, ISO 27001 A.9, OWASP ASVS 4.1, IATF 16949 8.5.2, DPDP, OWASP LLM Top 10 LLM01
    fix: str               # concrete fix, file + code suggestion
    status: str            # OPEN | SUPPRESSED | TP | FP
    suppression: dict | None # {owner, reason, expires_at}
```

## 5. Check Catalogue — 10 Checks (must implement all)
| ID | Check | Standards | How to detect |
|----|-------|-----------|---------------|
| MES-001 | OEE correctness: OEE = Availability x Performance x Quality, in 0..1, no div-by-zero, uses planned time not calendar time | IATF 16949 8.5.1 | Property test + AST: find OEE calc, run 5 cases |
| MES-002 | Lot genealogy completeness: every finished part links to lot + machine + order, no orphan, no update without log | IATF 16949 8.5.2, ISO 27001 A.12 | Graph: trace DB writes, check orphan query |
| OT-001 | PLC write-back gate: every write needs allow-list + clamp + auth + interlock + audit | IEC 62443 SR 3.3, 2.1 | Flow-graph + AST, see ot_write_guard.py |
| OT-002 | MQTT topic permissions: topic x principal matrix, no wildcard publish, no subscribe to # | IEC 62443 SR 2.1, 3.3 | Parse mqtt_acl.json + code, check publish/subscribe |
| OT-003 | OPC UA session: must use SignAndEncrypt, per-node ACL, no anonymous | IEC 62443 SR 3.1 | AST: search OPC UA client config |
| SEC-001 | RBAC / IDOR: every endpoint checks role + ownership, no ID change to see other plant | OWASP ASVS 4.1, ISO 27001 A.9 | AST: endpoint -> decorator -> DB query |
| LLM-001 | Ask LineTrack injection/leakage: logs are data, never instructions, only own plant/role data | OWASP LLM Top 10 LLM01, LLM02, DPDP | Prompt review + injection test + data filter check |
| PRIV-001 | DPDP PII: operator names/IDs/attendance/productivity need purpose, minimisation, no indefinite retention | DPDP Act, ISO 27001 A.8 | AST: find PII fields, check retention + access |
| SUP-001 | Secrets + SBOM: no secrets in code/flows, SBOM present, no known CVE High | ISO 27001 A.8, OWASP ASVS 10 | Gitleaks + Trivy + Syft |
| AUD-001 | Audit trail + backup: every write logged with who/when/what, backups exist + restore tested (UNVERIFIED if no evidence) | ISO 27001 A.12, IEC 62443 SR 2.10 | Log check + UNVERIFIED if no restore log |

## 6. Allow-lists (create these files)
`allow_lists/plc_allowlist.json`:
```json
{"SPINDLE_SPEED": {"min": 500, "max": 3000, "roles": ["Supervisor", "Plant Head"], "requires_interlock": true},
 "FEED_RATE": {"min": 10, "max": 200, "roles": ["Supervisor"], "requires_interlock": true}}
```
`allow_lists/mqtt_acl.json`:
```json
{"gateway-plant1": {"publish": ["plant1/+/+/telemetry"], "subscribe": ["plant1/+/+/setpoint"]},
 "api-service": {"publish": ["plant1/+/+/setpoint"], "subscribe": ["plant1/+/+/telemetry"]}}
```
`allow_lists/rbac_matrix.json`: 5 roles x 80 endpoints -> allowed/denied. Start with 10 endpoints in sample.

## 7. Sample Repo (create for dev)
`sample_repo/api.py`: FastAPI with 1 RBAC bug (Operator can call /admin/setpoint), 1 IDOR bug (GET /order/{id} no ownership check)
`sample_repo/oee.py`: OEE calc bug: divides by calendar time, can be >1, div-by-zero if downtime=0
`sample_repo/genealogy.py`: Saves part without lot_id
`sample_repo/flows.json`: Node-RED: Flow A safe (clamp + auth + log), Flow B unsafe (no clamp, no auth)
`sample_repo/ask.py`: Chatbot that does `prompt = system + logs` with no delimiter, follows log instructions
`sample_repo/secret.py`: Contains `AWS_KEY = "AKIA..."` fake secret

## 8. OT Write Guard Logic (from prototype, must keep)
For each PLC write edge:
- If tag NOT in allow-list -> HIGH
- If NO clamp (min/max) in code/flow -> HIGH. `not in` counts as clamp if it rejects out-of-range. Example: `if speed not in range(500,3001): reject` = clamp.
- If NO auth check (role in [Supervisor, Plant Head]) -> HIGH
- If NO interlock check -> HIGH
- If NO audit log (log.write) -> HIGH
If ANY missing -> BLOCK, exit 2. Safe file -> no finding.

## 9. Cost Model (use these numbers)
Azure OpenAI: GPT-4o-mini $0.15 in / $0.60 out per 1M, GPT-4o $2.50/$10.00, Frontier Judge $5/$15.
LLM sees 35% of code after graph filtering. Target: Full audit $180-$320 + 12-16h human, PR (15 files, 400 lines) $0.35-$0.60 + 5-10 min human for Highs only.
If cost doubles, router is broken, not model.

## 10. Evaluation (golden set)
Golden set: 120 full-audit + 200 PR cases in real build, 30 in Antigravity starter (see prompts).
Metrics: Precision = TP/(TP+FP), Recall = TP/(TP+FN) for Highs. Target Precision >=0.75, Recall >=0.80.
Threat model for reviewer: prompt injection via code/logs/PR, tool output injection, secrets in prompts, model exfiltration, suppression gaming.
Air-gap: --mode airgap, no Azure call, local model via Ollama or rule-only + wider human gate.

## 11. ADRs to write
ADR-01 Deterministic-first. ADR-02 Self-hosted runner. Format: Context -> Options -> Decision -> Consequences -> Reverse-if.

## 12. What NOT to invent
- Do NOT invent DPDP retention period. Say "per policy, to be confirmed".
- Do NOT invent IEC 62443 SR numbers you are unsure of. Use SR 3.3, 2.1, 3.1 only as listed above, or say "to be confirmed by OT SME".
- Do NOT assume network segmentation, interlocks, SAP reconciliation, backup restore pass. Mark UNVERIFIED.
