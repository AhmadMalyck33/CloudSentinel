"""Evaluate detection precision and recall on the labeled event dataset."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "tests" / "data" / "labeled_events.jsonl"
REPORT = ROOT / "docs" / "evaluation.md"
sys.path.insert(0, str(ROOT))

from app.detection.rules import SecurityDetector


def _alert_key(alert: dict[str, Any]) -> tuple[Any, ...]:
    return (
        alert.get("alert_type"),
        alert.get("source_ip"),
        alert.get("destination_ip"),
    )


def evaluate_detection(
    dataset_path: str | Path = DATASET
) -> dict[str, float | int]:
    events = []
    expected = set()

    with Path(dataset_path).open(encoding="utf-8") as file:
        for line in file:
            event = json.loads(line)
            label = event.pop("label", "normal")
            events.append(event)

            if label.startswith("malicious:"):
                expected.add((
                    label.split(":", 1)[1],
                    event.get("source_ip"),
                    event.get("destination_ip"),
                ))

    detector = SecurityDetector()
    alerts = (
        detector.detect_brute_force(events)
        + detector.detect_port_scan(events)
    )
    predicted = {_alert_key(alert) for alert in alerts}

    true_positives = len(predicted & expected)
    false_positives = len(predicted - expected)
    false_negatives = len(expected - predicted)
    precision = (
        true_positives / len(predicted)
        if predicted
        else 0.0
    )
    recall = (
        true_positives / len(expected)
        if expected
        else 1.0
    )

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
    }


def _render_report(result: dict[str, float | int]) -> str:
    rows = [
        ("True positives", result["true_positives"]),
        ("False positives", result["false_positives"]),
        ("False negatives", result["false_negatives"]),
        ("Precision", f"{result['precision']:.3f}"),
        ("Recall", f"{result['recall']:.3f}"),
    ]
    table = [
        "| Metric | Value |",
        "|---|---:|",
        *[f"| {name} | {value} |" for name, value in rows],
    ]
    return "# Detection Evaluation\n\n" + "\n".join(table) + "\n"


def main() -> int:
    result = evaluate_detection()
    report = _render_report(result)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")

    print(report, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
