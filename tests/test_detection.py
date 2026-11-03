
from datetime import datetime, timedelta, timezone

from app.detection.rules import SecurityDetector


def create_timestamp(minutes_offset=0):
    """Generate timestamps for controlled security events."""
    event_time = (
        datetime.now(timezone.utc)
        + timedelta(minutes=minutes_offset)
    )
    return event_time.isoformat()


def test_detect_brute_force():
    detector = SecurityDetector()

    events = [
        {
            "event_type": "login_failure",
            "source_ip": "192.168.1.20",
            "timestamp": create_timestamp(0)
        },
        {
            "event_type": "login_failure",
            "source_ip": "192.168.1.20",
            "timestamp": create_timestamp(1)
        },
        {
            "event_type": "login_failure",
            "source_ip": "192.168.1.20",
            "timestamp": create_timestamp(2)
        }
    ]

    alerts = detector.detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "brute_force_attempt"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["source_ip"] == "192.168.1.20"
    assert alerts[0]["failed_attempts"] == 3


def test_no_brute_force_below_threshold():
    detector = SecurityDetector()

    events = [
        {
            "event_type": "login_failure",
            "source_ip": "192.168.1.20",
            "timestamp": create_timestamp(0)
        },
        {
            "event_type": "login_failure",
            "source_ip": "192.168.1.20",
            "timestamp": create_timestamp(1)
        }
    ]

    alerts = detector.detect_brute_force(events)

    assert len(alerts) == 0


def test_detect_port_scan():
    detector = SecurityDetector()

    events = [
        {
            "event_type": "port_connection_attempt",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "destination_port": port,
            "timestamp": create_timestamp(index)
        }
        for index, port in enumerate([22, 80, 443, 3306, 8080])
    ]

    alerts = detector.detect_port_scan(events)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "port_scan_detected"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["destination_ip"] == "192.168.1.1"
    assert alerts[0]["unique_ports"] == 5
    assert alerts[0]["destination_ports"] == [
        22, 80, 443, 3306, 8080
    ]


def test_no_port_scan_below_threshold():
    detector = SecurityDetector()

    events = [
        {
            "event_type": "port_connection_attempt",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "destination_port": port,
            "timestamp": create_timestamp(index)
        }
        for index, port in enumerate([22, 80, 443, 8080])
    ]

    alerts = detector.detect_port_scan(events)

    assert len(alerts) == 0


def test_invalid_timestamps_are_ignored():
    detector = SecurityDetector()

    events = [
        {
            "event_type": "login_failure",
            "source_ip": "192.168.1.20",
            "timestamp": "invalid-timestamp"
        },
        {
            "event_type": "login_failure",
            "source_ip": "192.168.1.20",
            "timestamp": None
        }
    ]

    alerts = detector.detect_brute_force(events)

    assert len(alerts) == 0


def test_invalid_destination_ports_are_ignored():
    detector = SecurityDetector()

    events = [
        {
            "event_type": "port_connection_attempt",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "destination_port": port,
            "timestamp": create_timestamp(index)
        }
        for index, port in enumerate([22, 80, 443, 0, 70000])
    ]

    alerts = detector.detect_port_scan(events)

    assert len(alerts) == 0
