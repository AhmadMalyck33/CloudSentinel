
import sqlite3

from app.services.log_collector import SecurityLogCollector


def test_collect_valid_events(tmp_path):
    log_file = tmp_path / "events.jsonl"

    log_file.write_text(
        '{"event_type": "login_failure", "source_ip": "192.168.1.20"}\n'
        '{"event_type": "port_connection_attempt", "source_ip": "192.168.1.50"}\n',
        encoding="utf-8"
    )

    collector = SecurityLogCollector(log_file)

    events = collector.collect_events()

    assert len(events) == 2
    assert events[0]["event_type"] == "login_failure"
    assert events[1]["event_type"] == "port_connection_attempt"


def test_missing_log_file(tmp_path):
    log_file = tmp_path / "missing_events.jsonl"

    collector = SecurityLogCollector(log_file)

    events = collector.collect_events()

    assert events == []


def test_invalid_json_is_skipped(tmp_path, capsys):
    log_file = tmp_path / "events.jsonl"

    log_file.write_text(
        '{"event_type": "login_failure"}\n'
        'invalid-json\n'
        '{"event_type": "port_connection_attempt"}\n',
        encoding="utf-8"
    )

    collector = SecurityLogCollector(log_file)

    events = collector.collect_events()

    assert len(events) == 2

    captured = capsys.readouterr()

    assert "Invalid JSON at line 2" in captured.out


def test_non_dictionary_json_is_ignored(tmp_path):
    log_file = tmp_path / "events.jsonl"

    log_file.write_text(
        '{"event_type": "login_failure"}\n'
        '["invalid", "event"]\n'
        '"just a string"\n'
        '123\n'
        'null\n',
        encoding="utf-8"
    )

    collector = SecurityLogCollector(log_file)

    events = collector.collect_events()

    assert len(events) == 1
    assert events[0]["event_type"] == "login_failure"


def test_empty_lines_are_ignored(tmp_path):
    log_file = tmp_path / "events.jsonl"

    log_file.write_text(
        '\n'
        '{"event_type": "login_failure"}\n'
        '\n'
        '   \n',
        encoding="utf-8"
    )

    collector = SecurityLogCollector(log_file)

    events = collector.collect_events()

    assert len(events) == 1


def test_collector_reads_only_appended_events(tmp_path):
    log_file = tmp_path / "events.jsonl"
    database_file = tmp_path / "cloudsentinel.db"
    log_file.write_text(
        '{"event_type": "login_failure", "timestamp": "2026-11-04T10:00:00Z"}\n',
        encoding="utf-8"
    )
    collector = SecurityLogCollector(log_file, database_file)

    assert len(collector.collect_events()) == 1
    with log_file.open("a", encoding="utf-8") as file:
        file.write(
            '{"event_type": "login_failure", "timestamp": "2026-11-04T10:01:00Z"}\n'
        )

    assert len(collector.collect_events()) == 2
    with sqlite3.connect(database_file) as connection:
        state = connection.execute(
            "SELECT offset, file_size FROM collector_state"
        ).fetchone()
    assert state == (log_file.stat().st_size, log_file.stat().st_size)


def test_collector_resets_after_file_truncation(tmp_path):
    log_file = tmp_path / "events.jsonl"
    database_file = tmp_path / "cloudsentinel.db"
    log_file.write_text(
        '{"event_type": "login_failure", "timestamp": "2026-11-04T10:00:00Z"}\n',
        encoding="utf-8"
    )
    collector = SecurityLogCollector(log_file, database_file)
    collector.collect_events()
    log_file.write_text(
        '{"event_type": "login_success"}\n',
        encoding="utf-8"
    )

    events = collector.collect_events()

    assert len(events) == 1
    assert events[0]["event_type"] == "login_success"
