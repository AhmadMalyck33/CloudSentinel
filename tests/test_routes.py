
import pytest

from app import create_app
import app.routes as routes
from app.services.alert_manager import AlertManager


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


@pytest.fixture()
def test_alert(tmp_path, monkeypatch):
    # Create a separate temporary alert file for testing.
    alert_file = tmp_path / "alerts.jsonl"

    manager = AlertManager(alert_file)

    manager.save_alerts([
        {
            "alert_type": "test_alert",
            "source_ip": "192.168.1.100",
            "severity": "high"
        }
    ])

    # Redirect the API to the temporary file.
    monkeypatch.setattr(routes, "ALERT_FILE", alert_file)

    return manager.get_alerts()[0]


def test_home(client):
    response = client.get("/")

    assert response.status_code == 200

    data = response.get_json()

    assert data["project"] == "CloudSentinel"
    assert data["status"] == "running"


def test_health(client):
    response = client.get("/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "healthy"
    assert data["service"] == "CloudSentinel API"


def test_dashboard(client):
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"CloudSentinel" in response.data


def test_get_alerts(client):
    response = client.get("/alerts")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "success"
    assert "alerts" in data
    assert "total_alerts" in data


def test_process_events(client):
    response = client.post("/process-events")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "success"
    assert "events_processed" in data
    assert "alerts_saved" in data


def test_metrics(client):
    response = client.get("/metrics")

    assert response.status_code == 200
    assert b"cloudsentinel_http_requests_total" in response.data


def test_update_alert_status(client, test_alert):
    alert_id = test_alert["alert_id"]

    # First update: open -> acknowledged
    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "acknowledged"}
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "success"
    assert data["alert"]["status"] == "acknowledged"
    assert "updated_at" in data["alert"]

    # Second update: acknowledged -> resolved
    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "resolved"}
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["alert"]["status"] == "resolved"


def test_invalid_alert_status(client, test_alert):
    alert_id = test_alert["alert_id"]

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "invalid"}
    )

    assert response.status_code == 400

    data = response.get_json()

    assert data["status"] == "error"


def test_missing_alert(client):
    response = client.patch(
        "/alerts/nonexistent-alert-id/status",
        json={"status": "resolved"}
    )

    assert response.status_code == 404

    data = response.get_json()

    assert data["status"] == "error"
    assert data["message"] == "Alert not found."
