
from flask import Blueprint, jsonify, Response
from datetime import datetime, timezone
from pathlib import Path

from prometheus_client import (
    Counter,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST
)

from app.services.alert_manager import AlertManager

main = Blueprint("main", __name__)

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

# Security alert storage location
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERT_FILE = PROJECT_ROOT / "data" / "security" / "alerts.jsonl"


@main.route("/", methods=["GET"])
def home():
    HTTP_REQUESTS.labels(
        method="GET", endpoint="/", status="200"
    ).inc()

    return jsonify({
        "project": "CloudSentinel",
        "description": "Infrastructure Monitoring and Security Platform",
        "status": "running",
        "version": "1.0.0"
    })


@main.route("/health", methods=["GET"])
def health():
    HTTP_REQUESTS.labels(
        method="GET", endpoint="/health", status="200"
    ).inc()

    return jsonify({
        "status": "healthy",
        "service": "CloudSentinel API",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200


@main.route("/alerts", methods=["GET"])
def get_alerts():
    HTTP_REQUESTS.labels(
        method="GET", endpoint="/alerts", status="200"
    ).inc()

    manager = AlertManager(ALERT_FILE)
    alerts = manager.get_alerts()

    return jsonify({
        "status": "success",
        "total_alerts": len(alerts),
        "alerts": alerts
    }), 200


@main.route("/metrics", methods=["GET"])
def metrics():
    return Response(
        generate_latest(),
        mimetype=CONTENT_TYPE_LATEST
    )
