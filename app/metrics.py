import os
from pathlib import Path

from prometheus_client import Counter, REGISTRY
from prometheus_client.core import GaugeMetricFamily


class AlertCollector:
    """Collect current alert counts directly from the alert database."""

    STATUSES = ("open", "acknowledged", "resolved")
    SEVERITIES = ("low", "medium", "high", "critical", "other")

    def collect(self):
        from app.services.alert_manager import AlertManager

        database_path = Path(os.environ.get(
            "CLOUDSENTINEL_DB",
            Path(__file__).resolve().parent.parent
            / "data" / "security" / "cloudsentinel.db"
        ))
        counts = {
            (status, severity): 0
            for status in self.STATUSES
            for severity in self.SEVERITIES
        }

        for alert in AlertManager(database_path).get_alerts():
            status = alert.get("status", "open")
            severity = alert.get("severity", "other")
            if status not in self.STATUSES:
                status = "open"
            if severity not in self.SEVERITIES[:-1]:
                severity = "other"
            counts[(status, severity)] += 1

        metric = GaugeMetricFamily(
            "cloudsentinel_alerts",
            "Current security alerts by status and severity",
            labels=["status", "severity"]
        )
        for (status, severity), count in counts.items():
            metric.add_metric([status, severity], count)
        yield metric


ALERTS = AlertCollector()
REGISTRY.register(ALERTS)

DETECTIONS_TOTAL = Counter(
    "cloudsentinel_detections_total",
    "New security alerts saved by alert type",
    ["alert_type"]
)
