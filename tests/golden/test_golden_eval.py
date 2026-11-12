"""Pytest suite for Phase 7 30-case golden evaluation harness (SQLite MVP)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app import app
from backend.reviewer.evaluation.eval import evaluate_golden_set, format_evaluation_table
from tests.golden.golden_set import GOLDEN_CASES


def test_golden_set_has_30_balanced_cases() -> None:
    assert len(GOLDEN_CASES) == 30
    categories = [c.category for c in GOLDEN_CASES]
    assert categories.count("ot_write_safe") == 5
    assert categories.count("ot_write_unsafe") == 5
    assert categories.count("oee_bug") == 5
    assert categories.count("genealogy_gap") == 5
    assert categories.count("rbac_idor") == 5
    assert categories.count("prompt_injection") == 5


def test_golden_evaluation_meets_precision_and_recall_targets() -> None:
    metrics = evaluate_golden_set()
    print("\n" + format_evaluation_table(metrics))
    assert metrics["precision"] >= 0.75
    assert metrics["recall"] >= 0.80
    assert metrics["fp_rate"] == 0.0
    assert metrics["rule_accuracy"] >= 0.90


def test_eval_api_endpoint() -> None:
    client = TestClient(app)
    res = client.get("/api/eval")
    assert res.status_code == 200
    data = res.json()
    assert data["total_cases"] == 30
    assert data["precision"] >= 0.75
    assert data["recall"] >= 0.80
