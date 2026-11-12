# ADR-03: Self-Hosted Plant-Local Runner for OT Data Sovereignty and Air-Gap Compliance

## Context
LineTrack is deployed across 3 manufacturing plants (Pune, India) operating 22 CNC and press lines. Under OEM automotive supply agreements, IATF 16949, ISO/IEC 27001 (A.8, A.12), and India's Digital Personal Data Protection (DPDP) Act, proprietary PLC setpoint tags, machine topology, credentials, and employee productivity telemetry cannot be freely exfiltrated to multi-tenant public cloud runners without strict data sovereignty controls. Furthermore, factory plant servers occasionally operate under restricted or air-gapped network conditions.

## Options
1. **Public Cloud-Hosted Runners Only (GitHub-Hosted):** Simplest to manage, but sends entire proprietary codebase, internal IP addresses, and Node-RED flows to public cloud virtual machines. Fails customer air-gap audit requirements.
2. **Third-Party SaaS Code Review Portals:** Requires uploading internal factory repository to external SaaS vendors, creating third-party supply-chain exposure and violating plant boundary rules.
3. **Plant-Local Self-Hosted Runner with Pre-Egress Secrets Redaction & Air-Gap Mode:** Run GitHub Actions / CI runners directly inside the plant server perimeter (on-prem server). Execute deterministic scanners locally, redact all credentials and PII prior to any optional LLM inference, and support complete `--mode airgap` execution at zero cloud egress.

## Decision
Adopt **Option 3**. The production LineTrack Reviewer will run on self-hosted plant-local runners:
- In MVP / Development: Lightweight local execution or GitHub-hosted runner with simulated air-gap mode.
- In Plant Production: Self-hosted runner installed on the plant edge server. Scanners (`ot_write_guard`, `semgrep`, `gitleaks`, `trivy`) execute strictly inside plant walls. All data leaving the plant boundary for Judge evaluation is stripped of secrets, wrapped as untrusted data, and can be completely eliminated by switching on `--mode airgap`.

## Consequences
- **Positive:** Complies with OEM IATF 16949 and IEC 62443 data sovereignty standards. Zero risk of PLC setpoint, IP, or credential leakage to unauthorized clouds. Allows complete offline operation when factory internet connectivity is severed.
- **Negative:** Requires local plant server administration and patch maintenance for the edge runner process.

## Reverse-if
Reverse and migrate to cloud-managed runners only if the OEM client explicitly approves a certified GovCloud / dedicated isolated sovereign cloud tenant with verified hardware-isolated enclaves.
