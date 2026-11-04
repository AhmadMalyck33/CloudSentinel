"""Evaluate detection precision and recall on the labeled event dataset."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "tests" / "data" / "labeled_events.jsonl"
REPORT = ROOT / "docs" / "evaluation.md"
sys.path.insert(0, str(ROOT))

from app.detection.rules import SecurityDetector


def _alert_key(alert: dict[str, Any]) -> tuple[Any, ...]:
    window_start = _parse_timestamp(alert.get("window_start"))
    return (
        alert.get("alert_type"),
        alert.get("source_ip"),
        alert.get("destination_ip"),
        window_start.replace(second=0, microsecond=0).isoformat()
        if window_start
        else None,
    )


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp


def _expected_keys(events: list[dict[str, Any]]) -> set[tuple[Any, ...]]:
    grouped: dict[tuple[Any, ...], list[datetime]] = {}
    for event in events:
        label = event.get("label", "normal")
        timestamp = _parse_timestamp(event.get("timestamp"))
        if not label.startswith("malicious:") or timestamp is None:
            continue
        alert_type = label.split(":", 1)[1]
        key = (
            alert_type,
            event.get("source_ip"),
            event.get("destination_ip")
        )
        grouped.setdefault(key, []).append(timestamp)

    expected = set()
    window = timedelta(minutes=5)
    for (alert_type, source_ip, destination_ip), timestamps in grouped.items():
        timestamps.sort()
        burst = []
        for timestamp in timestamps:
            if burst and timestamp - burst[-1] > window:
                first = burst[0].replace(second=0, microsecond=0)
                expected.add((
                    alert_type,
                    source_ip,
                    destination_ip,
                    first.isoformat()
                ))
                burst = []
            burst.append(timestamp)
        if burst:
            first = burst[0].replace(second=0, microsecond=0)
            expected.add((
                alert_type,
                source_ip,
                destination_ip,
                first.isoformat()
            ))
    return expected


def evaluate_detection(
    dataset_path: str | Path = DATASET
) -> dict[str, Any]:
    events = []

    with Path(dataset_path).open(encoding="utf-8") as file:
        for line in file:
            event = json.loads(line)
            label = event.get("label", "normal")
            event["label"] = label
            events.append(event)

    expected = _expected_keys(events)
    detector_events = [
        {key: value for key, value in event.items() if key != "label"}
        for event in events
    ]

    detector = SecurityDetector()
    alerts = (
        detector.detect_brute_force(detector_events)
        + detector.detect_port_scan(detector_events)
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
    true_negatives = sum(
        1 for event in events
        if not str(event.get("label", "normal")).startswith("malicious:")
    )
    total_cases = (
        true_positives
        + false_positives
        + false_negatives
        + true_negatives
    )
    accuracy = (
        (true_positives + true_negatives) / total_cases
        if total_cases
        else 1.0
    )

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "precision": precision,
        "recall": recall,
        "accuracy": accuracy,
        "events": len(events),
        "confusion_table": {
            "true_positive": true_positives,
            "false_positive": false_positives,
            "false_negative": false_negatives,
            "true_negative": true_negatives,
        },
    }


def _render_report(result: dict[str, float | int]) -> str:
    rows = [
        ("True positives", result["true_positives"]),
        ("False positives", result["false_positives"]),
        ("False negatives", result["false_negatives"]),
        ("True negatives", result["true_negatives"]),
        ("Events", result["events"]),
        ("Precision", f"{result['precision']:.3f}"),
        ("Recall", f"{result['recall']:.3f}"),
        ("Accuracy", f"{result['accuracy']:.3f}"),
    ]
    table = [
        "| Metric | Value |",
        "|---|---:|",
        *[f"| {name} | {value} |" for name, value in rows],
    ]
    return (
        "# Detection Evaluation\n\n"
        + "\n".join(table)
        + "\n\n"
        + "## Confusion table\n\n"
        + "| | Predicted alert | Predicted normal |\n"
        + "|---|---:|---:|\n"
        + f"| Actual alert | {result['true_positives']} | "
        f"{result['false_negatives']} |\n"
        + f"| Actual normal | {result['false_positives']} | "
        f"{result['true_negatives']} |\n\n"
        + "## Limitations\n\n"
        + "This dataset is synthetic and was written by the developer; "
        + "it does not represent production traffic or all real-world attack "
        + "patterns.\n"
    )


def main() -> int:
    result = evaluate_detection()
    report = _render_report(result)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")

    print(report, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
