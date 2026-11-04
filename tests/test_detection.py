
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
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["source_ip"] == "192.168.1.20"
    assert alerts[0]["failed_attempts"] == 3
    assert "window_start" in alerts[0]
    assert "window_end" in alerts[0]


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
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["destination_ip"] == "192.168.1.1"
    assert alerts[0]["unique_ports"] == 5
    assert alerts[0]["destination_ports"] == [
        22, 80, 443, 3306, 8080
    ]
    assert "window_start" in alerts[0]
    assert "window_end" in alerts[0]


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


def test_brute_force_at_five_minute_boundary_is_one_burst():
    detector = SecurityDetector()
    start = datetime(2026, 11, 4, tzinfo=timezone.utc)

    events = [
        {
            "event_type": "login_failure",
            "source_ip": "192.168.1.20",
            "timestamp": (start + timedelta(minutes=offset)).isoformat()
        }
        for offset in [0, 2, 5]
    ]

    alerts = detector.detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["window_start"] == start.isoformat()
    assert alerts[0]["window_end"] == (
        start + timedelta(minutes=5)
    ).isoformat()


def test_brute_force_severity_scales_with_attempt_volume():
    detector = SecurityDetector()
    start = datetime.now(timezone.utc)

    for attempts, severity in [
        (3, "medium"),
        (6, "high"),
        (11, "critical")
    ]:
        events = [
            {
                "event_type": "login_failure",
                "source_ip": "192.168.1.20",
                "timestamp": (
                    start + timedelta(seconds=index)
                ).isoformat()
            }
            for index in range(attempts)
        ]

        alerts = detector.detect_brute_force(events)

        assert alerts[0]["severity"] == severity


def test_port_scan_severity_scales_with_unique_port_volume():
    start = datetime.now(timezone.utc)

    for port_count, severity in [(5, "medium"), (9, "medium"), (10, "high")]:
        detector = SecurityDetector()
        events = [
            {
                "event_type": "port_connection_attempt",
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.1",
                "destination_port": port,
                "timestamp": (
                    start + timedelta(seconds=index)
                ).isoformat()
            }
            for index, port in enumerate(range(1, port_count + 1))
        ]

        alerts = detector.detect_port_scan(events)

        assert alerts[0]["severity"] == severity


def test_detector_thresholds_read_from_environment(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_FAILED_LOGIN_THRESHOLD", "4")
    monkeypatch.setenv("CLOUDSENTINEL_TIME_WINDOW_MINUTES", "7")
    monkeypatch.setenv("CLOUDSENTINEL_PORT_SCAN_THRESHOLD", "6")

    detector = SecurityDetector()

    assert detector.failed_login_threshold == 4
    assert detector.time_window == timedelta(minutes=7)
    assert detector.port_scan_threshold == 6
