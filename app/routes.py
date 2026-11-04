
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
from collections import Counter as ValueCounter
from collections import defaultdict, deque
import urllib.error
import urllib.parse
import urllib.request

from flask import (
    Blueprint,
    g,
    jsonify,
    Response,
    render_template,
    request
)
from datetime import datetime, timedelta, timezone
from pathlib import Path

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
    multiprocess,
    CONTENT_TYPE_LATEST
)

from app.services.alert_manager import AlertManager
from app.services.audit_manager import AuditManager
from app.services.detection_service import DetectionService
from app.metrics import ALERTS


main = Blueprint("main", __name__)
logger = logging.getLogger(__name__)


def _prometheus_get(path_and_query: str):
    prometheus_url = os.environ.get("PROMETHEUS_URL")
    if not prometheus_url:
        raise ValueError("PROMETHEUS_URL is not configured.")

    parsed_url = urllib.parse.urlparse(prometheus_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("PROMETHEUS_URL must use http or https.")

    url = f"{prometheus_url.rstrip('/')}{path_and_query}"
    with urllib.request.urlopen(url, timeout=2) as response:  # nosec B310 - scheme is validated above
        return json.load(response)


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
    ["method", "endpoint", "status"]
)


# Security event storage location
PROJECT_ROOT = Path(__file__).resolve().parent.parent

EVENT_FILE = PROJECT_ROOT / "data" / "security" / "events.jsonl"
LOGIN_REQUESTS = defaultdict(deque)
LOGIN_REQUESTS_LOCK = threading.Lock()


def get_database_path() -> Path:
    return Path(os.environ.get(
        "CLOUDSENTINEL_DB",
        PROJECT_ROOT / "data" / "security" / "cloudsentinel.db"
    ))


def _login_rate_limit() -> int:
    try:
        return max(int(os.environ.get(
            "CLOUDSENTINEL_LOGIN_RATE_LIMIT",
            "20"
        )), 0)
    except ValueError:
        return 20


def _event_file_max_bytes() -> int:
    try:
        megabytes = float(os.environ.get(
            "CLOUDSENTINEL_MAX_EVENT_FILE_MB",
            "10"
        ))
    except ValueError:
        megabytes = 10
    return max(int(megabytes * 1024 * 1024), 0)


def _login_rate_limited(remote_addr: str) -> bool:
    now = time.monotonic()
    cutoff = now - 60
    limit = _login_rate_limit()
    with LOGIN_REQUESTS_LOCK:
        requests = LOGIN_REQUESTS[remote_addr]
        while requests and requests[0] <= cutoff:
            requests.popleft()
        if len(requests) >= limit:
            return True
        requests.append(now)
    return False


def register_metrics_hooks(app):
    @app.before_request
    def record_request_start():
        g.request_start_time = time.perf_counter()

    @app.after_request
    def record_request_metrics(response):
        endpoint = (
            request.url_rule.rule
            if request.url_rule is not None
            else "unknown"
        )
        duration = time.perf_counter() - g.request_start_time
        method = request.method
        status = str(response.status_code)

        HTTP_REQUESTS.labels(
            method=method,
            endpoint=endpoint,
            status=status
        ).inc()
        HTTP_REQUEST_DURATION.labels(
            method=method,
            endpoint=endpoint,
            status=status
        ).observe(duration)

        return response


def require_api_key():
    configured_key = os.environ.get("CLOUDSENTINEL_API_KEY")

    if not configured_key or len(configured_key) < 16:
        if configured_key:
            logger.warning(
                "CLOUDSENTINEL_API_KEY must be at least 16 characters."
            )
        return jsonify({
            "status": "error",
            "message": "Write operations are not configured."
        }), 503

    provided_key = request.headers.get("X-API-Key", "")

    if not hmac.compare_digest(provided_key, configured_key):
        return jsonify({
            "status": "error",
            "message": "Invalid or missing API key."
        }), 401

    return None


def require_alertmanager_token():
    configured_token = os.environ.get("ALERTMANAGER_WEBHOOK_TOKEN")

    if not configured_token:
        return jsonify({
            "status": "error",
            "message": "Alertmanager webhook is not configured."
        }), 503

    authorization = request.headers.get("Authorization", "")
    scheme, _, provided_token = authorization.partition(" ")

    if (
        scheme.lower() != "bearer"
        or not hmac.compare_digest(provided_token, configured_token)
    ):
        return jsonify({
            "status": "error",
            "message": "Invalid or missing Alertmanager token."
        }), 401

    return None


# Home API route
@main.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "CloudSentinel",
        "description": "Infrastructure Monitoring and Security Platform",
        "status": "running",
        "version": "1.0.0"
    })


# Health check API route
@main.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "CloudSentinel API",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200


def _database_status() -> str:
    try:
        connection = sqlite3.connect(get_database_path())
        connection.execute("SELECT 1").fetchone()
        connection.close()
    except (OSError, sqlite3.Error):
        return "down"

    return "up"


def _exporter_status() -> str:
    query = urllib.parse.urlencode({
        "query": 'up{job="docker-exporter"}'
    })

    try:
        payload = _prometheus_get(f"/api/v1/query?{query}")
    except (OSError, ValueError, urllib.error.URLError):
        return "unknown"

    if not isinstance(payload, dict):
        return "unknown"

    data = payload.get("data")
    if not isinstance(data, dict):
        return "unknown"

    results = data.get("result")
    if not isinstance(results, list):
        return "unknown"
    if not results:
        return "down"

    values = [
        result.get("value", [])
        for result in results
        if isinstance(result, dict)
    ]
    return "up" if any(
        len(value) > 1 and value[1] == "1"
        for value in values
        if isinstance(value, list)
    ) else "down"


@main.route("/api/status", methods=["GET"])
def api_status():
    database_status = _database_status()
    last_detection_at = None

    if database_status == "up":
        try:
            last_detection_at = AlertManager(
                get_database_path()
            ).get_last_detection_at()
        except (OSError, sqlite3.Error):
            database_status = "down"

    return jsonify({
        "api": "up",
        "database": database_status,
        "last_detection_at": last_detection_at,
        "exporter": _exporter_status()
    }), 200


@main.route("/demo/login", methods=["POST"])
def demo_login():
    if _login_rate_limited(request.remote_addr or "unknown"):
        response = jsonify({
            "status": "error",
            "message": "Too many login requests. Try again later."
        })
        response.headers["Retry-After"] = "60"
        return response, 429

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "status": "error",
            "message": "Request must contain a JSON object."
        }), 400

    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({
            "status": "error",
            "message": "Username and password must be strings."
        }), 400
    if not 1 <= len(username) <= 64:
        return jsonify({
            "status": "error",
            "message": "Username must be between 1 and 64 characters."
        }), 400
    if not 1 <= len(password) <= 64:
        return jsonify({
            "status": "error",
            "message": "Password must be between 1 and 64 characters."
        }), 400

    event_type = (
        "login_success"
        if username == "demo" and password == "demo-pass"
        else "login_failure"
    )
    event = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "source_ip": request.remote_addr
    }

    serialized_event = (json.dumps(event) + "\n").encode("utf-8")
    try:
        current_size = EVENT_FILE.stat().st_size if EVENT_FILE.exists() else 0
    except OSError:
        current_size = 0
    if current_size + len(serialized_event) > _event_file_max_bytes():
        return jsonify({
            "status": "error",
            "message": "Security event storage is full."
        }), 503

    EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_FILE.open("ab") as file:
        file.write(serialized_event)

    if event_type == "login_success":
        return jsonify({
            "status": "success",
            "message": "Login successful."
        }), 200

    return jsonify({
        "status": "error",
        "message": "Invalid username or password."
    }), 401


# Retrieve security alerts
@main.route("/alerts", methods=["GET"])
def get_alerts():
    manager = AlertManager(get_database_path())
    alerts = manager.get_alerts()

    return jsonify({
        "status": "success",
        "total_alerts": len(alerts),
        "alerts": alerts
    }), 200


@main.route("/api/summary", methods=["GET"])
def api_summary():
    alerts = AlertManager(get_database_path()).get_alerts()
    status_counts = {
        "open": 0,
        "acknowledged": 0,
        "resolved": 0
    }
    severity_counts = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }

    for alert in alerts:
        status = str(alert.get("status", "open")).lower()
        severity = str(alert.get("severity", "low")).lower()

        if status in status_counts:
            status_counts[status] += 1
        if severity in severity_counts:
            severity_counts[severity] += 1

    return jsonify({
        "total": len(alerts),
        **status_counts,
        "severity": severity_counts
    }), 200


@main.route("/api/trends", methods=["GET"])
def api_trends():
    now = datetime.now(timezone.utc)
    current_hour = now.replace(
        minute=0,
        second=0,
        microsecond=0
    )
    window_start = current_hour - timedelta(hours=23)
    recent_alerts = []

    for alert in AlertManager(get_database_path()).get_alerts():
        generated_at = alert.get("generated_at")
        if not isinstance(generated_at, str):
            continue

        try:
            timestamp = datetime.fromisoformat(
                generated_at.replace("Z", "+00:00")
            )
        except ValueError:
            continue

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        timestamp = timestamp.astimezone(timezone.utc)
        if window_start <= timestamp <= now:
            recent_alerts.append((alert, timestamp))

    if not recent_alerts:
        return jsonify({
            "alerts_per_hour": [],
            "top_source_ips": []
        }), 200

    hourly_counts = ValueCounter(
        timestamp.replace(minute=0, second=0, microsecond=0)
        for _, timestamp in recent_alerts
    )
    alerts_per_hour = [
        {
            "hour": (window_start + timedelta(hours=offset)).isoformat(),
            "count": hourly_counts.get(
                window_start + timedelta(hours=offset),
                0
            )
        }
        for offset in range(24)
    ]
    source_counts = ValueCounter(
        alert.get("source_ip")
        for alert, _ in recent_alerts
        if (
            alert.get("source_ip")
            and alert.get("alert_type") in {
                "brute_force_attempt",
                "port_scan_detected"
            }
        )
    )

    return jsonify({
        "alerts_per_hour": alerts_per_hour,
        "top_source_ips": [
            {"source_ip": source_ip, "count": count}
            for source_ip, count in source_counts.most_common(5)
        ]
    }), 200


INFRASTRUCTURE_QUERIES = (
    "cloudsentinel_container_cpu_usage_percent",
    "cloudsentinel_container_memory_usage_bytes",
    "cloudsentinel_container_memory_limit_bytes"
)


def _query_prometheus_metric(metric: str) -> list:
    query = urllib.parse.urlencode({"query": metric})
    payload = _prometheus_get(f"/api/v1/query?{query}")

    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise ValueError("Invalid Prometheus response.")

    data = payload.get("data")
    results = data.get("result") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise ValueError("Invalid Prometheus result.")

    return results


@main.route("/api/infrastructure", methods=["GET"])
def api_infrastructure():
    try:
        metric_results = {
            metric: _query_prometheus_metric(metric)
            for metric in INFRASTRUCTURE_QUERIES
        }
    except (OSError, ValueError, urllib.error.URLError):
        return jsonify({
            "status": "unavailable",
            "containers": []
        }), 200

    containers = {}
    for metric, results in metric_results.items():
        for result in results:
            if not isinstance(result, dict):
                continue
            labels = result.get("metric", {})
            values = result.get("value", [])
            name = labels.get("container_name") if isinstance(
                labels, dict
            ) else None
            if not name or not isinstance(values, list) or len(values) < 2:
                continue
            try:
                value = float(values[1])
            except (TypeError, ValueError):
                continue
            containers.setdefault(name, {})[metric] = value

    response_containers = []
    for name, metrics in sorted(containers.items()):
        cpu = metrics.get(INFRASTRUCTURE_QUERIES[0], 0)
        memory_used = metrics.get(INFRASTRUCTURE_QUERIES[1], 0)
        memory_limit = metrics.get(INFRASTRUCTURE_QUERIES[2], 0)
        memory_percent = (
            memory_used / memory_limit * 100
            if memory_limit > 0
            else 0
        )
        response_containers.append({
            "name": name,
            "cpu_percent": round(cpu, 2),
            "memory_used_mb": round(memory_used / (1024 * 1024), 2),
            "memory_limit_mb": round(memory_limit / (1024 * 1024), 2),
            "memory_percent": round(memory_percent, 2)
        })

    return jsonify({
        "status": "success",
        "containers": response_containers
    }), 200


# Retrieve alert status audit records
@main.route("/audit", methods=["GET"])
def get_audit_records():
    records = AuditManager(get_database_path()).get_records()

    return jsonify({
        "status": "success",
        "total_records": len(records),
        "records": records
    }), 200


# Update security alert status
@main.route("/alerts/<alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id):

    auth_error = require_api_key()
    if auth_error is not None:
        return auth_error

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

    actor = data.get("actor", "api")
    reason = data.get("reason")

    if not isinstance(actor, str) or not actor:
        return jsonify({
            "status": "error",
            "message": "Actor must be a non-empty string."
        }), 400
    if len(actor) > 50:
        return jsonify({
            "status": "error",
            "message": "Actor must be 50 characters or fewer."
        }), 400

    if reason is not None and not isinstance(reason, str):
        return jsonify({
            "status": "error",
            "message": "Reason must be a string."
        }), 400

    if isinstance(reason, str) and len(reason) > 200:
        return jsonify({
            "status": "error",
            "message": "Reason must be 200 characters or fewer."
        }), 400

    manager = AlertManager(get_database_path())
    try:
        updated_alert = manager.update_alert_status_with_audit(
            alert_id=alert_id,
            new_status=new_status,
            actor=actor,
            reason=reason
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

    return jsonify({
        "status": "success",
        "message": "Alert status updated successfully.",
        "alert": updated_alert
    }), 200


# Process security events and generate alerts
@main.route("/process-events", methods=["POST"])
def process_events():

    auth_error = require_api_key()
    if auth_error is not None:
        return auth_error

    service = DetectionService(
        event_file=EVENT_FILE,
        alert_file=get_database_path()
    )

    result = service.process_events()

    return jsonify(result), 200


@main.route("/webhooks/alertmanager", methods=["POST"])
def alertmanager_webhook():
    auth_error = require_alertmanager_token()
    if auth_error is not None:
        return auth_error

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(
        payload.get("alerts"), list
    ):
        return jsonify({
            "status": "error",
            "message": "Alertmanager payload must contain an alerts list."
        }), 400
    if len(payload["alerts"]) > 100:
        return jsonify({
            "status": "error",
            "message": "Alertmanager payload cannot contain more than 100 alerts."
        }), 413

    firing_alerts = []
    resolved_fingerprints = []
    for alert in payload["alerts"]:
        if not isinstance(alert, dict):
            return jsonify({
                "status": "error",
                "message": "Each Alertmanager alert must be an object."
            }), 400

        alert_status = alert.get("status")
        if alert_status not in {"firing", "resolved"}:
            continue

        fingerprint = alert.get("fingerprint")
        labels = alert.get("labels")
        if not isinstance(fingerprint, str) or not fingerprint:
            return jsonify({
                "status": "error",
                "message": "Firing alerts require a fingerprint."
            }), 400
        if not isinstance(labels, dict):
            return jsonify({
                "status": "error",
                "message": "Alertmanager alerts require labels."
            }), 400
        if alert_status == "resolved":
            resolved_fingerprints.append(fingerprint)
            continue

        annotations = alert.get("annotations", {})
        if not isinstance(annotations, dict):
            return jsonify({
                "status": "error",
                "message": "Alert annotations must be an object."
            }), 400

        original_severity = labels.get("severity", "unknown")
        normalized_severity = {
            "warning": "medium",
            "critical": "critical",
            "info": "low"
        }.get(original_severity, "medium")
        firing_alerts.append({
            "alert_type": "service_alert",
            "severity": normalized_severity,
            "original_severity": original_severity,
            "source_ip": labels.get("instance"),
            "destination_ip": labels.get("job"),
            "alert_name": labels.get("alertname", "unknown"),
            "summary": annotations.get("summary"),
            "fingerprint": fingerprint
        })

    manager = AlertManager(get_database_path())
    existing_fingerprints = {
        alert.get("fingerprint")
        for alert in manager.get_alerts()
        if alert.get("alert_type") == "service_alert"
        and alert.get("status") != "resolved"
    }
    new_alerts = []
    for alert in firing_alerts:
        if alert["fingerprint"] not in existing_fingerprints:
            new_alerts.append(alert)
            existing_fingerprints.add(alert["fingerprint"])

    saved_count = manager.save_alerts(new_alerts)
    alerts_resolved = 0
    for fingerprint in resolved_fingerprints:
        matching_alert = next(
            (
                alert for alert in manager.get_alerts()
                if (
                    alert.get("alert_type") == "service_alert"
                    and alert.get("fingerprint") == fingerprint
                    and alert.get("status") in {"open", "acknowledged"}
                )
            ),
            None
        )
        if matching_alert is None:
            continue

        manager.update_alert_status_with_audit(
            matching_alert["alert_id"],
            "resolved",
            "alertmanager",
            "Alert resolved automatically"
        )
        alerts_resolved += 1

    return jsonify({
        "status": "success",
        "alerts_received": len(payload["alerts"]),
        "firing_alerts": len(firing_alerts),
        "alerts_saved": saved_count,
        "duplicates_skipped": len(firing_alerts) - saved_count,
        "alerts_resolved": alerts_resolved
    }), 200


# Prometheus metrics endpoint
@main.route("/metrics", methods=["GET"])
def metrics():
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        registry.register(ALERTS)
        multiprocess.MultiProcessCollector(registry)
        metrics_output = generate_latest(registry)
    else:
        metrics_output = generate_latest()

    return Response(metrics_output, mimetype=CONTENT_TYPE_LATEST)
