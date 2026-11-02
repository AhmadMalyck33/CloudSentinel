
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


class SecurityDetector:
    """Detects suspicious activity in collected security events."""

    def __init__(
        self,
        failed_login_threshold: int = 3,
        time_window_minutes: int = 5
    ):
        self.failed_login_threshold = failed_login_threshold
        self.time_window = timedelta(minutes=time_window_minutes)

    def detect_brute_force(
        self,
        events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        failed_attempts = defaultdict(list)
        alerts = []

        for event in events:
            if event.get("event_type") != "login_failure":
                continue

            source_ip = event.get("source_ip")
            timestamp = event.get("timestamp")

            if not source_ip or not timestamp:
                continue

            try:
                event_time = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )

                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)

            except (ValueError, TypeError):
                continue

            failed_attempts[source_ip].append(event_time)

        for source_ip, timestamps in failed_attempts.items():
            timestamps.sort()

            for current_time in timestamps:
                window_start = current_time - self.time_window

                attempts = [
                    timestamp for timestamp in timestamps
                    if window_start <= timestamp <= current_time
                ]

                if len(attempts) >= self.failed_login_threshold:
                    alerts.append({
                        "alert_type": "brute_force_attempt",
                        "severity": "high",
                        "source_ip": source_ip,
                        "failed_attempts": len(attempts),
                        "time_window_minutes": (
                            self.time_window.total_seconds() / 60
                        ),
                        "description": (
                            f"Possible brute-force activity detected "
                            f"from {source_ip}"
                        )
                    })
                    break

        return alerts
