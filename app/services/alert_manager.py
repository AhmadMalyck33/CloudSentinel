
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Any


class AlertManager:
    """Stores, retrieves and manages security alerts."""

    VALID_STATUSES = {
        "open",
        "acknowledged",
        "resolved"
    }

    def __init__(self, alert_file: str | Path):
        self.alert_file = Path(alert_file)
        self.alert_file.parent.mkdir(parents=True, exist_ok=True)

    def save_alerts(
        self,
        alerts: list[dict[str, Any]]
    ) -> int:
        """Save new alerts with unique IDs and an initial status."""

        if not alerts:
            return 0

        saved_count = 0

        with self.alert_file.open("a", encoding="utf-8") as file:
            for alert in alerts:
                record = alert.copy()

                record["alert_id"] = str(uuid.uuid4())
                record["status"] = "open"

                record["generated_at"] = (
                    datetime.now(timezone.utc).isoformat()
                )

                file.write(json.dumps(record) + "\n")
                saved_count += 1

        return saved_count

    def get_alerts(self) -> list[dict[str, Any]]:
        """Retrieve alerts and migrate older records when necessary."""

        if not self.alert_file.exists():
            return []

        alerts = []
        migration_needed = False

        with self.alert_file.open("r", encoding="utf-8") as file:
            for line in file:
                try:
                    alert = json.loads(line)

                    if not isinstance(alert, dict):
                        continue

                    if not alert.get("alert_id"):
                        alert["alert_id"] = str(uuid.uuid4())
                        migration_needed = True

                    if not alert.get("status"):
                        alert["status"] = "open"
                        migration_needed = True

                    alerts.append(alert)

                except json.JSONDecodeError:
                    continue

        # Save migrated records without deleting existing alert information.
        if migration_needed:
            self._write_alerts(alerts)

        return alerts

    def _write_alerts(
        self,
        alerts: list[dict[str, Any]]
    ) -> None:
        """Rewrite the alert file with the updated records."""

        with self.alert_file.open("w", encoding="utf-8") as file:
            for alert in alerts:
                file.write(json.dumps(alert) + "\n")

    def update_alert_status(
        self,
        alert_id: str,
        new_status: str
    ) -> dict[str, Any] | None:
        """Update the status of an existing alert."""

        if new_status not in self.VALID_STATUSES:
            raise ValueError(
                f"Invalid status. Choose one of: "
                f"{', '.join(sorted(self.VALID_STATUSES))}"
            )

        alerts = self.get_alerts()

        for alert in alerts:
            if alert.get("alert_id") == alert_id:
                alert["status"] = new_status

                alert["updated_at"] = (
                    datetime.now(timezone.utc).isoformat()
                )

                self._write_alerts(alerts)
                return alert

        return None
