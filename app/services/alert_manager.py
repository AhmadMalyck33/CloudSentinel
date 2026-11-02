
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any


class AlertManager:
    """Stores and retrieves security alerts."""

    def __init__(self, alert_file: str | Path):
        self.alert_file = Path(alert_file)
        self.alert_file.parent.mkdir(parents=True, exist_ok=True)

    def save_alerts(
        self,
        alerts: list[dict[str, Any]]
    ) -> int:
        """Append alerts to the JSONL file."""

        if not alerts:
            return 0

        saved_count = 0

        with self.alert_file.open("a", encoding="utf-8") as file:
            for alert in alerts:
                record = alert.copy()
                record["generated_at"] = (
                    datetime.now(timezone.utc).isoformat()
                )

                file.write(json.dumps(record) + "\n")
                saved_count += 1

        return saved_count

    def get_alerts(self) -> list[dict[str, Any]]:
        """Read previously saved alerts."""

        if not self.alert_file.exists():
            return []

        alerts = []

        with self.alert_file.open("r", encoding="utf-8") as file:
            for line in file:
                try:
                    alert = json.loads(line)

                    if isinstance(alert, dict):
                        alerts.append(alert)

                except json.JSONDecodeError:
                    continue

        return alerts
