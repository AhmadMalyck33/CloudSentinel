import json
from datetime import datetime, timedelta, timezone

from app.services.detection_service import DetectionService


def brute_force_events(start):
    return [
        {
            "event_type": "login_failure",
            "source_ip": "192.168.1.20",
            "timestamp": (
                start + timedelta(minutes=offset)
            ).isoformat()
        }
        for offset in [0, 1, 2]
    ]


def write_events(event_file, events):
    event_file.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8"
    )


def test_same_events_processed_twice_have_no_duplicates(tmp_path):
    event_file = tmp_path / "events.jsonl"
    database_file = tmp_path / "cloudsentinel.db"
    start = datetime(2026, 11, 4, tzinfo=timezone.utc)
    write_events(event_file, brute_force_events(start))
    service = DetectionService(event_file, database_file)

    first_result = service.process_events()
    second_result = service.process_events()

    assert first_result["alerts_saved"] == 1
    assert second_result["alerts_saved"] == 0
    assert len(service.alert_manager.get_alerts()) == 1


def test_second_attack_hours_later_creates_new_alert(tmp_path):
    event_file = tmp_path / "events.jsonl"
    database_file = tmp_path / "cloudsentinel.db"
    start = datetime(2026, 11, 4, tzinfo=timezone.utc)
    write_events(event_file, brute_force_events(start))
    service = DetectionService(event_file, database_file)

    service.process_events()
    write_events(
        event_file,
        brute_force_events(start)
        + brute_force_events(start + timedelta(hours=2))
    )

    result = service.process_events()

    assert result["alerts_saved"] == 1
    assert len(service.alert_manager.get_alerts()) == 2


def test_burst_spanning_two_runs_is_detected(tmp_path):
    event_file = tmp_path / "events.jsonl"
    database_file = tmp_path / "cloudsentinel.db"
    start = datetime(2026, 11, 4, tzinfo=timezone.utc)
    write_events(event_file, brute_force_events(start)[:2])
    service = DetectionService(event_file, database_file)

    first_result = service.process_events()
    assert first_result["alerts_saved"] == 0

    with event_file.open("a", encoding="utf-8") as file:
        file.write(json.dumps(brute_force_events(start)[2]) + "\n")

    second_result = service.process_events()

    assert second_result["alerts_saved"] == 1
