from flask import Blueprint, jsonify
from datetime import datetime, timezone

main = Blueprint("main", __name__)


@main.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "CloudSentinel",
        "description": "Infrastructure Monitoring and Security Platform",
        "status": "running",
        "version": "1.0.0"
    })


@main.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "CloudSentinel API",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200