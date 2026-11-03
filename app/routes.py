
from flask import Blueprint, jsonify, Response, render_template, request
from datetime import datetime, timezone
from pathlib import Path

from prometheus_client import (
    Counter,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST
)

from app.services.alert_manager import AlertManager
from app.services.detection_service import DetectionService


main = Blueprint("main", __name__)


# Dashboard frontend route
@main.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


# Prometheus metrics
HTTP_REQUESTS = Counter(
    "cloudsentinel_http_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status"]
)

HTTP_REQUEST_DURATION = Histogram(
    "cloudsentinel_http_request_duration_seconds",
    "HTTP request processing duration in seconds",
    ["endpoint"]
)


# Security event and alert storage locations
PROJECT_ROOT = Path(__file__).resolve().parent.parent

EVENT_FILE = PROJECT_ROOT / "data" / "security" / "events.jsonl"

ALERT_FILE = PROJECT_ROOT / "data" / "security" / "alerts.jsonl"


# Home API route
@main.route("/", methods=["GET"])
def home():
    HTTP_REQUESTS.labels(
        method="GET",
        endpoint="/",
        status="200"
    ).inc()

    return jsonify({
        "project": "CloudSentinel",
        "description": "Infrastructure Monitoring and Security Platform",
        "status": "running",
        "version": "1.0.0"
    })


# Health check API route
@main.route("/health", methods=["GET"])
def health():
    HTTP_REQUESTS.labels(
        method="GET",
        endpoint="/health",
        status="200"
    ).inc()

    return jsonify({
        "status": "healthy",
        "service": "CloudSentinel API",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200


# Retrieve security alerts
@main.route("/alerts", methods=["GET"])
def get_alerts():
    HTTP_REQUESTS.labels(
        method="GET",
        endpoint="/alerts",
        status="200"
    ).inc()

    manager = AlertManager(ALERT_FILE)
    alerts = manager.get_alerts()

    return jsonify({
        "status": "success",
        "total_alerts": len(alerts),
        "alerts": alerts
    }), 200


# Update security alert status
@main.route("/alerts/<alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id):

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or "status" not in data:
        return jsonify({
            "status": "error",
            "message": "Please provide a status in the JSON request."
        }), 400

    new_status = data["status"]

    if not isinstance(new_status, str):
        return jsonify({
            "status": "error",
            "message": "Status must be a string."
        }), 400

    manager = AlertManager(ALERT_FILE)

    try:
        updated_alert = manager.update_alert_status(
            alert_id=alert_id,
            new_status=new_status
        )

    except ValueError as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 400

    if updated_alert is None:
        return jsonify({
            "status": "error",
            "message": "Alert not found."
        }), 404

    HTTP_REQUESTS.labels(
        method="PATCH",
        endpoint="/alerts/status",
        status="200"
    ).inc()

    return jsonify({
        "status": "success",
        "message": "Alert status updated successfully.",
        "alert": updated_alert
    }), 200


# Process security events and generate alerts
@main.route("/process-events", methods=["POST"])
def process_events():

    service = DetectionService(
        event_file=EVENT_FILE,
        alert_file=ALERT_FILE
    )

    result = service.process_events()

    HTTP_REQUESTS.labels(
        method="POST",
        endpoint="/process-events",
        status="200"
    ).inc()

    return jsonify(result), 200


# Prometheus metrics endpoint
@main.route("/metrics", methods=["GET"])
def metrics():
    return Response(
        generate_latest(),
        mimetype=CONTENT_TYPE_LATEST
    )
