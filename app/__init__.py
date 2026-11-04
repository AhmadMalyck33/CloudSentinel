import logging
import os
import sqlite3
import threading
import time

from flask import Flask


logger = logging.getLogger(__name__)


def _background_detection_enabled(app: Flask) -> bool:
    if app.config.get("TESTING"):
        return False

    disabled = os.environ.get(
        "CLOUDSENTINEL_DISABLE_BACKGROUND_DETECTION",
        ""
    ).lower()
    return disabled not in {"1", "true", "yes", "on"}


def _run_detection_loop(app: Flask) -> None:
    from app.routes import EVENT_FILE, get_database_path
    from app.services.detection_service import DetectionService

    while True:
        try:
            DetectionService(
                event_file=EVENT_FILE,
                alert_file=get_database_path()
            ).process_events()
        except (OSError, ValueError, sqlite3.Error):
            logger.exception("Background detection failed.")

        time.sleep(10)


def _start_background_detection(app: Flask) -> None:
    if not _background_detection_enabled(app):
        return

    thread = threading.Thread(
        target=_run_detection_loop,
        args=(app,),
        name="cloudsentinel-detection",
        daemon=True
    )
    thread.start()


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        PROMETHEUS_PORT=os.environ.get("PROMETHEUS_PORT", "9090"),
        GRAFANA_PORT=os.environ.get("GRAFANA_PORT", "3001")
    )
    if test_config:
        app.config.update(test_config)

    from app.routes import main, register_metrics_hooks

    app.register_blueprint(main)
    register_metrics_hooks(app)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "connect-src 'self'"
        )
        return response

    _start_background_detection(app)

    return app