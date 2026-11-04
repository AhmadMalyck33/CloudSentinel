
from pathlib import Path
from typing import Any

from app.detection.rules import SecurityDetector
from app.metrics import DETECTIONS_TOTAL
from app.services.log_collector import SecurityLogCollector
from app.services.alert_manager import AlertManager


class DetectionService:
    """Coordinates security event collection, detection and alert storage."""

    def __init__(
        self,
        event_file: str | Path,
        alert_file: str | Path
    ):
        self.collector = SecurityLogCollector(event_file, alert_file)
        self.detector = SecurityDetector()
        self.alert_manager = AlertManager(alert_file)

    def process_events(self) -> dict[str, Any]:
        """Collect events, detect threats and prevent duplicate alerts."""

        events = self.collector.collect_events()

        brute_force_alerts = (
            self.detector.detect_brute_force(events)
        )

        port_scan_alerts = (
            self.detector.detect_port_scan(events)
        )

        all_alerts = brute_force_alerts + port_scan_alerts

        existing_alerts = self.alert_manager.get_alerts()

        existing_keys = {
            (
                alert.get("alert_type"),
                alert.get("source_ip"),
                alert.get("destination_ip"),
                alert.get("window_start")
            )
            for alert in existing_alerts
        }

        new_alerts = []

        for alert in all_alerts:
            alert_key = (
                alert.get("alert_type"),
                alert.get("source_ip"),
                alert.get("destination_ip"),
                alert.get("window_start")
            )

            if alert_key not in existing_keys:
                new_alerts.append(alert)
                existing_keys.add(alert_key)

        saved_count = self.alert_manager.save_alerts(new_alerts)
        self.alert_manager.record_detection_run()

        if saved_count:
            for alert in new_alerts:
                DETECTIONS_TOTAL.labels(
                    alert_type=alert.get("alert_type", "unknown")
                ).inc()

        return {
            "status": "success",
            "events_processed": len(events),
            "brute_force_alerts": len(brute_force_alerts),
            "port_scan_alerts": len(port_scan_alerts),
            "total_alerts_detected": len(all_alerts),
            "new_alerts": len(new_alerts),
            "alerts_saved": saved_count,
            "duplicates_skipped": len(all_alerts) - len(new_alerts)
        }
