"""Standalone Tailwind HTML Audit Report generator (matches frontend/index.html style)."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from backend.reviewer.findings.schema import Finding
from backend.reviewer.guardrails.redact import redact_secrets


def _esc(val: Any) -> str:
    return html.escape(redact_secrets(str(val or "")))


def render_audit_html(audit_report: dict[str, Any], output_path: str | Path | None = None) -> str:
    findings = audit_report.get("findings", [])
    unverified = audit_report.get("unverified", [])
    catalogue = audit_report.get("check_catalogue", [])
    traceability = audit_report.get("traceability", [])
    cost = audit_report.get("cost_summary", {})
    verdict = str(audit_report.get("verdict", "BLOCK"))
    verdict_cls = (
        "bg-rose-950 text-rose-300 border-rose-700"
        if verdict == "BLOCK"
        else "bg-emerald-950 text-emerald-300 border-emerald-700"
    )

    finding_cards = []
    for f in findings:
        fd = f.to_dict() if isinstance(f, Finding) else dict(f)
        sev = fd.get("severity", "Medium")
        badge = "bg-rose-950 text-rose-300 border-rose-700" if sev in {"Critical", "High"} else "bg-amber-950 text-amber-300 border-amber-700"
        finding_cards.append(
            f"""
            <article class="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 text-xs font-semibold rounded border {badge}">{_esc(sev)}</span>
                  <span class="font-semibold text-white">{_esc(fd.get('check_id'))} / {_esc(fd.get('rule'))}</span>
                  <span class="font-mono text-xs text-sky-400">{_esc(fd.get('file'))}:{_esc(fd.get('line'))}</span>
                </div>
              </div>
              <p class="text-xs text-slate-300">{_esc(fd.get('message'))}</p>
              <pre class="p-3 rounded bg-slate-900 text-slate-300 font-mono text-xs overflow-x-auto border border-slate-800">{_esc(fd.get('evidence'))}</pre>
              <p class="text-xs text-emerald-300"><strong>Fix:</strong> {_esc(fd.get('fix'))}</p>
            </article>
            """
        )

    trace_rows = "".join(
        f"""<tr class="border-t border-slate-800">
          <td class="py-2 pr-3 font-medium text-white">{_esc(t.get('requirement'))}</td>
          <td class="py-2 pr-3 font-mono text-xs text-sky-400">{_esc(t.get('implementation'))}</td>
          <td class="py-2 pr-3 font-mono text-xs text-slate-300">{_esc(t.get('test'))}</td>
          <td class="py-2 text-xs font-semibold text-amber-300">{_esc(t.get('status'))}</td>
        </tr>"""
        for t in traceability
    )

    unv_rows = "".join(
        f"""<tr class="border-t border-slate-800">
          <td class="py-2 pr-3 text-white">{_esc(u.get('control'))}</td>
          <td class="py-2 pr-3"><span class="px-2 py-0.5 text-xs font-mono rounded bg-amber-950 text-amber-300 border border-amber-700">{_esc(u.get('status'))}</span></td>
          <td class="py-2 pr-3 text-xs text-slate-300">{_esc(u.get('owner'))}</td>
          <td class="py-2 pr-3 text-xs text-slate-300">{_esc(u.get('due_date'))}</td>
          <td class="py-2 text-xs text-slate-400">{_esc(u.get('required_evidence'))}</td>
        </tr>"""
        for u in unverified
    )

    cat_rows = "".join(
        f"""<tr class="border-t border-slate-800">
          <td class="py-2 pr-3 font-mono text-xs text-sky-400">{_esc(c.get('id'))}</td>
          <td class="py-2 pr-3 text-white">{_esc(c.get('name'))}</td>
          <td class="py-2 pr-3 text-xs text-slate-400">{_esc(', '.join(c.get('standards', [])))}</td>
          <td class="py-2 text-xs font-mono text-slate-200">{_esc(c.get('status', 'UNKNOWN'))}</td>
        </tr>"""
        for c in catalogue
    )

    doc_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>LineTrack Reviewer — Full Audit Report</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen font-sans">
  <header class="border-b border-slate-800 bg-slate-900">
    <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-white">LineTrack Reviewer — Full SDLC Audit Report</h1>
        <p class="text-xs text-slate-400">Repo: {_esc(audit_report.get('repo'))} | Mode: {_esc(audit_report.get('mode'))} | Generated: {_esc(audit_report.get('generated_at'))}</p>
      </div>
      <span class="px-3 py-1.5 text-sm font-semibold rounded-lg border {verdict_cls}">{_esc(verdict)}</span>
    </div>
  </header>

  <main class="max-w-6xl mx-auto px-6 py-8 space-y-6">
    <section class="grid grid-cols-2 sm:grid-cols-4 gap-4">
      <div class="p-4 rounded-xl bg-slate-900 border border-slate-800"><div class="text-xs text-slate-400">Findings</div><div class="text-xl font-bold mt-1">{len(findings)}</div></div>
      <div class="p-4 rounded-xl bg-slate-900 border border-slate-800"><div class="text-xs text-slate-400">UNVERIFIED Controls</div><div class="text-xl font-bold text-amber-300 mt-1">{len(unverified)}</div></div>
      <div class="p-4 rounded-xl bg-slate-900 border border-slate-800"><div class="text-xs text-slate-400">LLM Cost</div><div class="text-xl font-bold font-mono mt-1">${float(cost.get('total_cost_usd', 0.0)):.6f}</div></div>
      <div class="p-4 rounded-xl bg-slate-900 border border-slate-800"><div class="text-xs text-slate-400">Checks Catalogue</div><div class="text-xl font-bold mt-1">{len(catalogue)}</div></div>
    </section>

    <section class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-3">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-300">Findings</h2>
      <div class="space-y-3">{''.join(finding_cards) or '<p class="text-sm text-slate-400">None.</p>'}</div>
    </section>

    <section class="bg-slate-900 border border-slate-800 rounded-xl p-6 overflow-x-auto">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3">Traceability Matrix</h2>
      <table class="w-full text-left text-sm">
        <thead class="text-xs text-slate-400"><tr><th>Requirement</th><th>Endpoint / Flow</th><th>Test</th><th>Status</th></tr></thead>
        <tbody>{trace_rows}</tbody>
      </table>
    </section>

    <section class="bg-slate-900 border border-amber-800/70 rounded-xl p-6 overflow-x-auto">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-amber-300 mb-3">UNVERIFIED Controls (Never Assumed Pass)</h2>
      <table class="w-full text-left text-sm">
        <thead class="text-xs text-slate-400"><tr><th>Control</th><th>Status</th><th>Owner</th><th>Due Date</th><th>Required Evidence</th></tr></thead>
        <tbody>{unv_rows}</tbody>
      </table>
    </section>

    <section class="bg-slate-900 border border-slate-800 rounded-xl p-6 overflow-x-auto">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3">10-Check Catalogue</h2>
      <table class="w-full text-left text-sm">
        <thead class="text-xs text-slate-400"><tr><th>ID</th><th>Check</th><th>Standards</th><th>Status</th></tr></thead>
        <tbody>{cat_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""
    if output_path is not None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(doc_html, encoding="utf-8")
    return doc_html
