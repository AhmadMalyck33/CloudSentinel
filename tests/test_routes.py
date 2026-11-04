
import json
import re
import urllib.parse

import pytest

from app import create_app
import app.routes as routes
from app.services.alert_manager import AlertManager
from app.services.detection_service import DetectionService


@pytest.fixture()
def security_files(tmp_path, monkeypatch):
    event_file = tmp_path / "events.jsonl"
    database_file = tmp_path / "cloudsentinel.db"

    event_file.write_text(
        "\n".join([
            '{"event_type": "login_failure", "source_ip": "192.168.1.20", "timestamp": "2026-11-02T16:01:00Z"}',
            '{"event_type": "login_failure", "source_ip": "192.168.1.20", "timestamp": "2026-11-02T16:02:00Z"}',
            '{"event_type": "login_failure", "source_ip": "192.168.1.20", "timestamp": "2026-11-02T16:03:00Z"}',
        ]) + "\n",
        encoding="utf-8"
    )
    monkeypatch.setenv("CLOUDSENTINEL_DB", str(database_file))

    monkeypatch.setattr(routes, "EVENT_FILE", event_file)

    return event_file, database_file


@pytest.fixture()
def client():
    app = create_app({"TESTING": True})

    with app.test_client() as client:
        yield client


@pytest.fixture()
def test_alert(tmp_path, monkeypatch):
    # Create a separate temporary alert file for testing.
    database_file = tmp_path / "cloudsentinel.db"

    manager = AlertManager(database_file)

    manager.save_alerts([
        {
            "alert_type": "test_alert",
            "source_ip": "192.168.1.100",
            "severity": "high"
        }
    ])

    # Redirect the API to the temporary file.
    monkeypatch.setenv("CLOUDSENTINEL_DB", str(database_file))

    return manager.get_alerts()[0]


def test_home(client):
    response = client.get("/")

    assert response.status_code == 200

    data = response.get_json()

    assert data["project"] == "CloudSentinel"
    assert data["status"] == "running"


def test_security_headers(client):
    response = client.get("/health")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Content-Security-Policy"] == (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'"
    )


def test_health(client):
    response = client.get("/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "healthy"
    assert data["service"] == "CloudSentinel API"


def test_api_status_reports_database_and_unknown_exporter(
    client, tmp_path, monkeypatch
):
    database_file = tmp_path / "cloudsentinel.db"
    monkeypatch.setenv("CLOUDSENTINEL_DB", str(database_file))
    monkeypatch.delenv("PROMETHEUS_URL", raising=False)

    AlertManager(database_file).record_detection_run(
        "2026-11-04T10:00:00+00:00"
    )

    response = client.get("/api/status")

    assert response.status_code == 200
    assert response.get_json() == {
        "api": "up",
        "database": "up",
        "last_detection_at": "2026-11-04T10:00:00+00:00",
        "exporter": "unknown"
    }


def test_api_status_reports_database_down(client, tmp_path, monkeypatch):
    database_file = tmp_path / "missing" / "cloudsentinel.db"
    monkeypatch.setenv("CLOUDSENTINEL_DB", str(database_file))
    monkeypatch.delenv("PROMETHEUS_URL", raising=False)

    response = client.get("/api/status")

    assert response.status_code == 200
    assert response.get_json() == {
        "api": "up",
        "database": "down",
        "last_detection_at": None,
        "exporter": "unknown"
    }


def test_api_status_reports_exporter_down(
    client, tmp_path, monkeypatch
):
    database_file = tmp_path / "cloudsentinel.db"
    monkeypatch.setenv("CLOUDSENTINEL_DB", str(database_file))
    monkeypatch.setattr(routes, "_exporter_status", lambda: "down")

    response = client.get("/api/status")

    assert response.status_code == 200
    assert response.get_json()["exporter"] == "down"


def test_dashboard(client):
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"CloudSentinel" in response.data


def test_demo_login_records_success_and_failure(client, tmp_path, monkeypatch):
    event_file = tmp_path / "events.jsonl"
    monkeypatch.setattr(routes, "EVENT_FILE", event_file)

    success = client.post(
        "/demo/login",
        json={"username": "demo", "password": "demo-pass"}
    )
    failure = client.post(
        "/demo/login",
        json={"username": "demo", "password": "wrong"}
    )

    assert success.status_code == 200
    assert failure.status_code == 401
    events = [
        json.loads(line)
        for line in event_file.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["event_type"] for event in events] == [
        "login_success",
        "login_failure"
    ]
    assert all(event["username"] == "demo" for event in events)
    assert all(event["source_ip"] == "127.0.0.1" for event in events)


@pytest.mark.parametrize("payload", [
    {"username": "", "password": "x"},
    {"username": "x" * 65, "password": "x"},
    {"username": "x", "password": ""},
    {"username": "x", "password": "x" * 65}
])
def test_demo_login_rejects_invalid_lengths(
    client, tmp_path, monkeypatch, payload
):
    monkeypatch.setattr(routes, "EVENT_FILE", tmp_path / "events.jsonl")
    response = client.post("/demo/login", json=payload)
    assert response.status_code == 400


def test_demo_login_rate_limit_returns_retry_after(
    client, tmp_path, monkeypatch
):
    monkeypatch.setattr(routes, "EVENT_FILE", tmp_path / "events.jsonl")
    monkeypatch.setenv("CLOUDSENTINEL_LOGIN_RATE_LIMIT", "1")
    with routes.LOGIN_REQUESTS_LOCK:
        routes.LOGIN_REQUESTS.clear()

    client.post("/demo/login", json={"username": "a", "password": "b"})
    response = client.post(
        "/demo/login",
        json={"username": "a", "password": "b"}
    )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"


def test_demo_login_rejects_event_file_over_limit(
    client, tmp_path, monkeypatch
):
    event_file = tmp_path / "events.jsonl"
    event_file.write_text("x", encoding="utf-8")
    monkeypatch.setattr(routes, "EVENT_FILE", event_file)
    monkeypatch.setenv("CLOUDSENTINEL_MAX_EVENT_FILE_MB", "0")

    response = client.post(
        "/demo/login",
        json={"username": "a", "password": "b"}
    )

    assert response.status_code == 503


def test_five_failed_demo_logins_create_brute_force_alert(
    client, tmp_path, monkeypatch
):
    event_file = tmp_path / "events.jsonl"
    database_file = tmp_path / "cloudsentinel.db"
    monkeypatch.setattr(routes, "EVENT_FILE", event_file)
    monkeypatch.setenv("CLOUDSENTINEL_DB", str(database_file))

    for _ in range(5):
        response = client.post(
            "/demo/login",
            json={"username": "demo", "password": "wrong"}
        )
        assert response.status_code == 401

    result = DetectionService(
        event_file=event_file,
        alert_file=database_file
    ).process_events()

    assert result["alerts_saved"] == 1
    alerts = AlertManager(database_file).get_alerts()
    assert alerts[0]["alert_type"] == "brute_force_attempt"
    assert alerts[0]["source_ip"] == "127.0.0.1"


def test_get_alerts(client, security_files):
    response = client.get("/alerts")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "success"
    assert "alerts" in data
    assert "total_alerts" in data


def test_api_summary_returns_status_and_severity_counts(
    client, tmp_path, monkeypatch
):
    database_file = tmp_path / "cloudsentinel.db"
    monkeypatch.setenv("CLOUDSENTINEL_DB", str(database_file))
    manager = AlertManager(database_file)

    manager.save_alerts([
        {"alert_type": "one", "severity": "critical"},
        {"alert_type": "two", "severity": "high"},
        {"alert_type": "three", "severity": "medium"},
        {"alert_type": "four", "severity": "low"}
    ])
    alerts = manager.get_alerts()
    manager.update_alert_status(alerts[1]["alert_id"], "acknowledged")
    manager.update_alert_status(alerts[2]["alert_id"], "resolved")

    response = client.get("/api/summary")

    assert response.status_code == 200
    assert response.get_json() == {
        "total": 4,
        "open": 2,
        "acknowledged": 1,
        "resolved": 1,
        "severity": {
            "low": 1,
            "medium": 1,
            "high": 1,
            "critical": 1
        }
    }


def test_api_trends_returns_hourly_and_top_source_data(
    client, tmp_path, monkeypatch
):
    database_file = tmp_path / "cloudsentinel.db"
    monkeypatch.setenv("CLOUDSENTINEL_DB", str(database_file))
    manager = AlertManager(database_file)
    manager.save_alerts([
        {
            "alert_type": "brute_force_attempt",
            "source_ip": "192.0.2.10",
            "severity": "high"
        },
        {
            "alert_type": "port_scan_detected",
            "source_ip": "192.0.2.10",
            "severity": "medium"
        },
        {
            "alert_type": "service_alert",
            "alert_name": "CloudSentinelApiDown",
            "summary": "API is unavailable",
            "source_ip": "docker-exporter:9323",
            "severity": "medium"
        }
    ])

    response = client.get("/api/trends")

    assert response.status_code == 200
    data = response.get_json()
    assert len(data["alerts_per_hour"]) == 24
    assert data["top_source_ips"] == [
        {"source_ip": "192.0.2.10", "count": 2}
    ]
    assert sum(item["count"] for item in data["alerts_per_hour"]) == 3


def test_api_trends_returns_empty_datasets(client, security_files):
    response = client.get("/api/trends")

    assert response.status_code == 200
    assert response.get_json() == {
        "alerts_per_hour": [],
        "top_source_ips": []
    }


@pytest.mark.parametrize("prometheus_url", ["file:///tmp/prometheus", "not-a-url"])
def test_prometheus_invalid_url_returns_safe_statuses(
    client, monkeypatch, prometheus_url
):
    monkeypatch.setenv("PROMETHEUS_URL", prometheus_url)

    status_response = client.get("/api/status")
    infrastructure_response = client.get("/api/infrastructure")

    assert status_response.get_json()["exporter"] == "unknown"
    assert infrastructure_response.get_json() == {
        "status": "unavailable",
        "containers": []
    }


def test_api_infrastructure_returns_prometheus_metrics(
    client, monkeypatch
):
    monkeypatch.setenv("PROMETHEUS_URL", "http://prometheus:9090")
    responses = {
        "cloudsentinel_container_cpu_usage_percent": [
            {"metric": {"container_name": "api"}, "value": [1, "42.5"]}
        ],
        "cloudsentinel_container_memory_usage_bytes": [
            {"metric": {"container_name": "api"}, "value": [1, "52428800"]}
        ],
        "cloudsentinel_container_memory_limit_bytes": [
            {"metric": {"container_name": "api"}, "value": [1, "104857600"]}
        ]
    }

    class MockResponse:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(self.payload).encode("utf-8")

    def mock_urlopen(url, timeout):
        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(url).query
        )["query"][0]
        return MockResponse({
            "status": "success",
            "data": {"result": responses[query]}
        })

    monkeypatch.setattr(routes.urllib.request, "urlopen", mock_urlopen)

    response = client.get("/api/infrastructure")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "success",
        "containers": [{
            "name": "api",
            "cpu_percent": 42.5,
            "memory_used_mb": 50.0,
            "memory_limit_mb": 100.0,
            "memory_percent": 50.0
        }]
    }


def test_api_infrastructure_returns_unavailable_when_prometheus_is_down(
    client, monkeypatch
):
    monkeypatch.setenv("PROMETHEUS_URL", "http://prometheus:9090")

    def mock_urlopen(url, timeout):
        raise TimeoutError("Prometheus unavailable")

    monkeypatch.setattr(routes.urllib.request, "urlopen", mock_urlopen)

    response = client.get("/api/infrastructure")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "unavailable",
        "containers": []
    }


def test_get_audit_returns_records(client, security_files):
    response = client.get("/audit")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "success",
        "total_records": 0,
        "records": []
    }


def test_alertmanager_webhook_saves_and_deduplicates_firing_alert(
    client, security_files, monkeypatch
):
    monkeypatch.setenv("ALERTMANAGER_WEBHOOK_TOKEN", "webhook-token")
    payload = {
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "fingerprint": "fingerprint-1",
                "labels": {
                    "alertname": "HighContainerCpu",
                    "severity": "warning",
                    "instance": "docker-exporter:9323"
                },
                "annotations": {
                    "summary": "Container CPU usage is high"
                }
            },
            {
                "status": "resolved",
                "fingerprint": "fingerprint-2",
                "labels": {
                    "alertname": "ResolvedAlert",
                    "severity": "critical"
                }
            }
        ]
    }

    headers = {"Authorization": "Bearer webhook-token"}
    response = client.post(
        "/webhooks/alertmanager",
        json=payload,
        headers=headers
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "success",
        "alerts_received": 2,
        "firing_alerts": 1,
        "alerts_saved": 1,
        "duplicates_skipped": 0,
        "alerts_resolved": 0
    }

    duplicate_response = client.post(
        "/webhooks/alertmanager",
        json=payload,
        headers=headers
    )

    assert duplicate_response.status_code == 200
    assert duplicate_response.get_json()["alerts_saved"] == 0
    assert duplicate_response.get_json()["duplicates_skipped"] == 1

    alerts = client.get("/alerts").get_json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "service_alert"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["original_severity"] == "warning"
    assert alerts[0]["fingerprint"] == "fingerprint-1"


def test_alertmanager_webhook_resolves_and_refires_alert(
    client, security_files, monkeypatch
):
    monkeypatch.setenv("ALERTMANAGER_WEBHOOK_TOKEN", "webhook-token")
    headers = {"Authorization": "Bearer webhook-token"}
    alert = {
        "status": "firing",
        "fingerprint": "repeatable",
        "labels": {"alertname": "HighContainerCpu", "severity": "critical"},
        "annotations": {"summary": "CPU high"}
    }

    assert client.post(
        "/webhooks/alertmanager",
        json={"alerts": [alert]},
        headers=headers
    ).get_json()["alerts_saved"] == 1
    assert client.post(
        "/webhooks/alertmanager",
        json={"alerts": [alert]},
        headers=headers
    ).get_json()["duplicates_skipped"] == 1

    resolved = dict(alert)
    resolved["status"] = "resolved"
    response = client.post(
        "/webhooks/alertmanager",
        json={"alerts": [resolved]},
        headers=headers
    )
    assert response.get_json()["alerts_resolved"] == 1

    audit = client.get("/audit").get_json()["records"]
    assert audit[-1]["actor"] == "alertmanager"
    assert audit[-1]["reason"] == "Alert resolved automatically"

    response = client.post(
        "/webhooks/alertmanager",
        json={"alerts": [alert]},
        headers=headers
    )
    assert response.get_json()["alerts_saved"] == 1
    assert len(client.get("/alerts").get_json()["alerts"]) == 2


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("info", "low"), ("unexpected", "medium")]
)
def test_alertmanager_webhook_normalizes_severity(
    client, security_files, monkeypatch, severity, expected
):
    monkeypatch.setenv("ALERTMANAGER_WEBHOOK_TOKEN", "webhook-token")
    response = client.post(
        "/webhooks/alertmanager",
        json={"alerts": [{
            "status": "firing",
            "fingerprint": severity,
            "labels": {"severity": severity},
            "annotations": {}
        }]},
        headers={"Authorization": "Bearer webhook-token"}
    )

    assert response.status_code == 200
    alert = client.get("/alerts").get_json()["alerts"][0]
    assert alert["severity"] == expected
    assert alert["original_severity"] == severity


def test_alertmanager_webhook_rejects_oversize_payload(
    client, monkeypatch
):
    monkeypatch.setenv("ALERTMANAGER_WEBHOOK_TOKEN", "webhook-token")
    response = client.post(
        "/webhooks/alertmanager",
        json={"alerts": [{}] * 101},
        headers={"Authorization": "Bearer webhook-token"}
    )

    assert response.status_code == 413


@pytest.mark.parametrize(
    ("configured_token", "request_token", "expected_status"),
    [(None, "webhook-token", 503), ("webhook-token", None, 401),
     ("webhook-token", "wrong-token", 401)]
)
def test_alertmanager_webhook_rejects_invalid_auth(
    client,
    security_files,
    monkeypatch,
    configured_token,
    request_token,
    expected_status
):
    if configured_token is None:
        monkeypatch.delenv("ALERTMANAGER_WEBHOOK_TOKEN", raising=False)
    else:
        monkeypatch.setenv("ALERTMANAGER_WEBHOOK_TOKEN", configured_token)

    headers = {}
    if request_token is not None:
        headers["Authorization"] = f"Bearer {request_token}"

    response = client.post(
        "/webhooks/alertmanager",
        json={"alerts": []},
        headers=headers
    )

    assert response.status_code == expected_status


def test_process_events(client, security_files, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")
    response = client.post(
        "/process-events",
        headers={"X-API-Key": "test-key-12345678"}
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "success"
    assert "events_processed" in data
    assert "alerts_saved" in data


def test_metrics(client):
    response = client.get("/metrics")

    assert response.status_code == 200
    assert b"cloudsentinel_http_requests_total" in response.data


def test_metrics_include_alert_gauge(client, security_files, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")
    client.post(
        "/process-events",
        headers={"X-API-Key": "test-key-12345678"}
    )

    response = client.get("/metrics")

    assert response.status_code == 200
    assert (
        b'cloudsentinel_alerts{severity="medium",status="open"} 1.0'
        in response.data
    )


def test_metrics_alert_gauge_refreshes_after_resolution(
    client, test_alert, monkeypatch, tmp_path
):
    multiprocess_directory = tmp_path / "prometheus"
    multiprocess_directory.mkdir()
    monkeypatch.setenv(
        "PROMETHEUS_MULTIPROC_DIR",
        str(multiprocess_directory)
    )
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")

    response = client.get("/metrics")
    assert b'cloudsentinel_alerts{severity="high",status="open"} 1.0' in response.data

    response = client.patch(
        f"/alerts/{test_alert['alert_id']}/status",
        headers={"X-API-Key": "test-key-12345678"},
        json={"status": "resolved", "actor": "tester"}
    )
    assert response.status_code == 200

    response = client.get("/metrics")
    assert b'cloudsentinel_alerts{severity="high",status="open"} 0.0' in response.data
    assert b'cloudsentinel_alerts{severity="high",status="resolved"} 1.0' in response.data


def test_metrics_include_detection_counter(
    client, security_files, monkeypatch
):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")
    client.post(
        "/process-events",
        headers={"X-API-Key": "test-key-12345678"}
    )

    first_metrics = client.get("/metrics").data
    client.post(
        "/process-events",
        headers={"X-API-Key": "test-key-12345678"}
    )
    second_metrics = client.get("/metrics").data

    pattern = (
        rb'cloudsentinel_detections_total\{'
        rb'alert_type="brute_force_attempt"\} ([0-9.]+)'
    )
    first_value = re.search(pattern, first_metrics)
    second_value = re.search(pattern, second_metrics)

    assert first_value is not None
    assert second_value is not None
    assert float(first_value.group(1)) >= 1
    assert first_value.group(1) == second_value.group(1)


def test_metrics_track_duration_and_404(client):
    client.get("/route-that-does-not-exist")

    response = client.get("/metrics")

    assert response.status_code == 200
    assert b"cloudsentinel_http_request_duration_seconds" in response.data
    assert (
        b'cloudsentinel_http_requests_total{'
        b'endpoint="unknown",method="GET",status="404"}' in response.data
    )


def test_update_alert_status(client, test_alert, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")
    alert_id = test_alert["alert_id"]

    # First update: open -> acknowledged
    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "acknowledged"},
        headers={"X-API-Key": "test-key-12345678"}
    )

    assert response.status_code == 200

    audit_response = client.get("/audit")
    audit_data = audit_response.get_json()

    assert audit_data["total_records"] == 1
    assert audit_data["records"][0]["alert_id"] == alert_id
    assert audit_data["records"][0]["old_status"] == "open"
    assert audit_data["records"][0]["new_status"] == "acknowledged"
    assert audit_data["records"][0]["actor"] == "api"
    assert "reason" not in audit_data["records"][0]

    # Second update: acknowledged -> resolved
    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={
            "status": "resolved",
            "actor": "operator",
            "reason": "Confirmed investigation complete"
        },
        headers={"X-API-Key": "test-key-12345678"}
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "success"
    assert data["alert"]["status"] == "resolved"
    assert "updated_at" in data["alert"]

    audit_data = client.get("/audit").get_json()
    assert audit_data["total_records"] == 2
    assert audit_data["records"][1]["actor"] == "operator"
    assert audit_data["records"][1]["reason"] == (
        "Confirmed investigation complete"
    )


def test_invalid_alert_status(client, test_alert, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")
    alert_id = test_alert["alert_id"]

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "invalid"},
        headers={"X-API-Key": "test-key-12345678"}
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["status"] == "error"


@pytest.mark.parametrize("payload", [
    {"status": "acknowledged", "actor": ""},
    {"status": "acknowledged", "actor": 123},
    {"status": "acknowledged", "actor": "x" * 51},
    {"status": "acknowledged", "reason": 123},
    {"status": "acknowledged", "reason": "x" * 201}
])
def test_invalid_audit_fields(client, test_alert, monkeypatch, payload):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")

    response = client.patch(
        f"/alerts/{test_alert['alert_id']}/status",
        json=payload,
        headers={"X-API-Key": "test-key-12345678"}
    )

    assert response.status_code == 400


def test_missing_alert(client, security_files, monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")
    response = client.patch(
        "/alerts/nonexistent-alert-id/status",
        json={"status": "resolved"},
        headers={"X-API-Key": "test-key-12345678"}
    )

    assert response.status_code == 404

    data = response.get_json()

    assert data["status"] == "error"
    assert data["message"] == "Alert not found."


@pytest.mark.parametrize("method, path", [
    ("post", "/process-events"),
    ("patch", "/alerts/nonexistent-alert-id/status")
])
def test_write_operation_requires_configured_key(
    client, method, path, monkeypatch
):
    monkeypatch.delenv("CLOUDSENTINEL_API_KEY", raising=False)

    response = getattr(client, method)(
        path,
        json={"status": "resolved"} if method == "patch" else None
    )

    assert response.status_code == 503


def test_write_operation_rejects_short_configured_key(
    client, monkeypatch
):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "short-key")

    response = client.post(
        "/process-events",
        headers={"X-API-Key": "short-key"}
    )

    assert response.status_code == 503
    assert response.get_json()["message"] == (
        "Write operations are not configured."
    )


@pytest.mark.parametrize("method, path", [
    ("post", "/process-events"),
    ("patch", "/alerts/nonexistent-alert-id/status")
])
def test_write_operation_rejects_missing_header(
    client, method, path, monkeypatch
):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")

    response = getattr(client, method)(
        path,
        json={"status": "resolved"} if method == "patch" else None
    )

    assert response.status_code == 401


@pytest.mark.parametrize("method, path", [
    ("post", "/process-events"),
    ("patch", "/alerts/nonexistent-alert-id/status")
])
def test_write_operation_rejects_wrong_key(
    client, method, path, monkeypatch
):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")

    response = getattr(client, method)(
        path,
        headers={"X-API-Key": "wrong-key"},
        json={"status": "resolved"} if method == "patch" else None
    )

    assert response.status_code == 401


@pytest.mark.parametrize("method, path", [
    ("post", "/process-events"),
    ("patch", "/alerts/nonexistent-alert-id/status")
])
def test_write_operation_accepts_correct_key(
    client, security_files, method, path, monkeypatch
):
    monkeypatch.setenv("CLOUDSENTINEL_API_KEY", "test-key-12345678")

    response = getattr(client, method)(
        path,
        headers={"X-API-Key": "test-key-12345678"},
        json={"status": "resolved"} if method == "patch" else None
    )

    assert response.status_code == (
        200 if method == "post" else 404
    )
