# ADR-01: Deterministic-First, LLM-Second, Deterministic-Verified Architecture

## Context
LineTrack is a safety-critical MES controlling CNC/press PLC setpoints (via OPC UA, Modbus TCP, MQTT, and Node-RED), tracking IATF 16949 lot genealogy, computing OEE, and exposing a FastAPI backend with 5 roles across 3 plants. Pure LLM review risks hallucinations, missed PLC write-back paths, and high token cost across 55k LOC.

## Options
1. **Pure LLM Reviewer:** Send code/PR diffs directly to LLMs to identify OT, MES, and security defects.
2. **Deterministic Scanners Only:** Run Semgrep, Gitleaks, Trivy, and AST rules without LLM context synthesis.
3. **Deterministic-First, LLM-Second, Deterministic-Verified Hybrid:** Run deterministic scanners (`ot_write_guard`, `mes_checks`, Semgrep, Gitleaks, Trivy) and AST call/data-flow blast-radius filtering (~35%) first; route `mini` (triage) -> `gpt-4o` (review) -> separate frontier `Judge` that re-runs deterministic checks/property tests before any `High`/`Critical` ships.

## Decision
Adopt **Option 3 (Deterministic-First, LLM-Second, Deterministic-Verified)**. Scanners and AST/flow-graph checks decide facts; LLMs explain meaning over 1-hop blast-radius code; the Judge MUST deterministically reproduce every `High`/`Critical` finding (downgrading or dropping any unverified LLM assertion).

## Consequences
- **Positive:** Zero unverified Highs ship to PR gates; OT PLC write checks fail closed deterministically; PR review works at `$0` when `AZURE_OPENAI_KEY` is absent or in `--mode airgap`.
- **Negative:** Requires maintaining deterministic AST and Node-RED flow-graph rules alongside versioned allow-lists in Git.

## Reverse-if
Reverse only if an empirical >=200-PR benchmark shows non-OT LLM-only checks reaching >=95% precision with zero safety regressions (OT-001 PLC write verification remains unconditionally deterministic).
