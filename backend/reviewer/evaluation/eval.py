"""Golden-set evaluation harness (Phase 7 / Spec Sec. 10, SQLite MVP)."""

from __future__ import annotations

import argparse
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from backend.reviewer.agents.orchestrator import run_review
from tests.golden.golden_set import GOLDEN_CASES, GoldenCase


@dataclass
class CaseOutcome:
    case_id: str
    category: str
    expected_verdict: str
    actual_verdict: str
    expected_rule: str
    matched_rules: list[str]
    high_count: int
    cost_usd: float
    duration_sec: float
    outcome: str
    rule_hit: bool


def evaluate_golden_set(cases: list[GoldenCase] = GOLDEN_CASES, airgap: bool = True) -> dict[str, Any]:
    outcomes: list[CaseOutcome] = []
    tp = fp = fn = tn = 0
    per_category: dict[str, dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "rule_hits": 0, "total": 0}
    )

    with tempfile.TemporaryDirectory(prefix="linetrack_eval_") as tmp:
        tmp_root = Path(tmp)
        for case in cases:
            case_dir = tmp_root / case.case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            (case_dir / case.filename).write_text(case.code, encoding="utf-8")

            res = run_review(
                repo_root=case_dir,
                changed_files=[case.filename],
                pr_text=case.pr_text,
                run_id=f"golden-{case.case_id}",
                mode="airgap" if airgap else "pr",
                airgap=airgap,
            )
            findings = res.get("final_findings", [])
            actual_verdict = str(res.get("verdict", "PASS"))
            matched_rules = [f.rule for f in findings]
            high_count = sum(1 for f in findings if f.severity in {"Critical", "High"})
            cost_usd = float((res.get("cost_summary") or {}).get("total_cost_usd", 0.0))
            duration_sec = float(res.get("duration_sec") or 0.0)

            expected_positive = case.expected_verdict == "BLOCK"
            predicted_positive = actual_verdict == "BLOCK" or high_count > 0

            if expected_positive and predicted_positive:
                label = "TP"
                tp += 1
                per_category[case.category]["tp"] += 1
            elif not expected_positive and predicted_positive:
                label = "FP"
                fp += 1
                per_category[case.category]["fp"] += 1
            elif expected_positive and not predicted_positive:
                label = "FN"
                fn += 1
                per_category[case.category]["fn"] += 1
            else:
                label = "TN"
                tn += 1
                per_category[case.category]["tn"] += 1

            rule_hit = (case.expected_rule == "NONE" and not matched_rules) or (case.expected_rule in matched_rules)
            per_category[case.category]["total"] += 1
            if rule_hit:
                per_category[case.category]["rule_hits"] += 1

            outcomes.append(
                CaseOutcome(
                    case_id=case.case_id,
                    category=case.category,
                    expected_verdict=case.expected_verdict,
                    actual_verdict=actual_verdict,
                    expected_rule=case.expected_rule,
                    matched_rules=matched_rules,
                    high_count=high_count,
                    cost_usd=cost_usd,
                    duration_sec=duration_sec,
                    outcome=label,
                    rule_hit=rule_hit,
                )
            )

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    avg_cost = sum(o.cost_usd for o in outcomes) / max(1, len(outcomes))
    avg_time = sum(o.duration_sec for o in outcomes) / max(1, len(outcomes))
    rule_accuracy = sum(1 for o in outcomes if o.rule_hit) / max(1, len(outcomes))

    return {
        "total_cases": len(outcomes),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fp_rate": round(fp_rate, 4),
        "rule_accuracy": round(rule_accuracy, 4),
        "avg_cost_per_pr_usd": round(avg_cost, 6),
        "avg_time_per_pr_sec": round(avg_time, 4),
        "per_category": dict(per_category),
        "outcomes": [asdict(o) for o in outcomes],
    }


def format_evaluation_table(metrics: dict[str, Any]) -> str:
    lines = [
        "=== LineTrack Reviewer — Golden Set Evaluation ===",
        f"Cases: {metrics['total_cases']} | TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} TN={metrics['tn']}",
        f"Precision (Highs) : {metrics['precision']:.3f}  (target >= 0.750)",
        f"Recall (Highs)    : {metrics['recall']:.3f}  (target >= 0.800)",
        f"FP Rate           : {metrics['fp_rate']:.3f}",
        f"Exact Rule Match  : {metrics['rule_accuracy']:.3f}",
        f"Avg Cost / PR     : ${metrics['avg_cost_per_pr_usd']:.6f}",
        f"Avg Time / PR     : {metrics['avg_time_per_pr_sec']:.4f}s",
        "",
        "| Category | Total | TP | FP | FN | TN | Rule Match |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for cat, stats in sorted(metrics["per_category"].items()):
        lines.append(
            f"| {cat} | {stats['total']} | {stats['tp']} | {stats['fp']} | {stats['fn']} | {stats['tn']} | {stats['rule_hits']}/{stats['total']} |"
        )
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate LineTrack Reviewer on 30-case golden set.")
    ap.add_argument("--airgap", action="store_true")
    args = ap.parse_args()
    metrics = evaluate_golden_set(airgap=args.airgap)
    print(format_evaluation_table(metrics))


if __name__ == "__main__":
    main()
