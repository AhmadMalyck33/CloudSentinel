import json
import sqlite3
import time

from app.services.alert_manager import AlertManager


def test_alerts_are_stored_and_updated_in_sqlite(tmp_path):
    database_file = tmp_path / "cloudsentinel.db"
    manager = AlertManager(database_file)

    assert manager.save_alerts([
        {
            "alert_type": "test_alert",
            "source_ip": "192.168.1.100",
            "severity": "high"
        }
    ]) == 1

    alert = manager.get_alerts()[0]
    updated = manager.update_alert_status(
        alert["alert_id"],
        "acknowledged"
    )

    assert updated["status"] == "acknowledged"

    with sqlite3.connect(database_file) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert {"alerts", "audit"} <= tables


def test_existing_alerts_jsonl_is_imported_once(tmp_path):
    database_file = tmp_path / "cloudsentinel.db"
    jsonl_file = tmp_path / "alerts.jsonl"
    alert = {
        "alert_id": "existing-alert",
        "alert_type": "brute_force_attempt",
        "source_ip": "192.168.1.20",
        "status": "resolved"
    }
    jsonl_file.write_text(json.dumps(alert) + "\n", encoding="utf-8")

    manager = AlertManager(database_file)
    jsonl_file.write_text("", encoding="utf-8")

    assert manager.get_alerts() == [alert]
    assert AlertManager(database_file).get_alerts() == [alert]


def test_get_alerts_does_not_modify_database(tmp_path):
    database_file = tmp_path / "cloudsentinel.db"
    manager = AlertManager(database_file)
    manager.save_alerts([{"alert_type": "test_alert"}])
    modified_at = database_file.stat().st_mtime_ns

    time.sleep(0.01)
    assert len(manager.get_alerts()) == 1

    assert database_file.stat().st_mtime_ns == modified_at
