
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


class SecurityDetector:
    """Detects suspicious activity in collected security events."""

    def __init__(
        self,
        failed_login_threshold: int = 3,
        time_window_minutes: int = 5,
        port_scan_threshold: int = 5
    ):
        self.failed_login_threshold = failed_login_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        self.port_scan_threshold = port_scan_threshold

    def _parse_timestamp(self, timestamp: Any):
        """Parse an ISO 8601 timestamp safely."""

        if not isinstance(timestamp, str):
            return None

        try:
            event_time = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            if event_time.tzinfo is None:
                event_time = event_time.replace(
                    tzinfo=timezone.utc
                )

            return event_time

        except ValueError:
            return None

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
            event_time = self._parse_timestamp(
                event.get("timestamp")
            )

            if not source_ip or event_time is None:
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

    def detect_port_scan(
        self,
        events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Detect one source IP probing multiple destination ports."""

        connection_attempts = defaultdict(list)
        alerts = []

        for event in events:

            if event.get("event_type") != "port_connection_attempt":
                continue

            source_ip = event.get("source_ip")
            destination_ip = event.get("destination_ip")
            destination_port = event.get("destination_port")

            event_time = self._parse_timestamp(
                event.get("timestamp")
            )

            if not source_ip or not destination_ip:
                continue

            if (
                not isinstance(destination_port, int)
                or isinstance(destination_port, bool)
                or not 1 <= destination_port <= 65535
            ):
                continue

            if event_time is None:
                continue

            key = (source_ip, destination_ip)

            connection_attempts[key].append(
                (event_time, destination_port)
            )

        for (source_ip, destination_ip), attempts in (
            connection_attempts.items()
        ):

            attempts.sort(key=lambda item: item[0])

            for current_time, _ in attempts:

                window_start = current_time - self.time_window

                ports = {
                    port
                    for timestamp, port in attempts
                    if window_start <= timestamp <= current_time
                }

                if len(ports) >= self.port_scan_threshold:

                    alerts.append({
                        "alert_type": "port_scan_detected",
                        "severity": "high",
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "unique_ports": len(ports),
                        "destination_ports": sorted(ports),
                        "time_window_minutes": (
                            self.time_window.total_seconds() / 60
                        ),
                        "description": (
                            f"Possible port scanning activity detected "
                            f"from {source_ip} against {destination_ip}"
                        )
                    })

                    break

        return alerts
