
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import os
from typing import Any


def _environment_threshold(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default

    threshold = int(value)
    if threshold < 1:
        raise ValueError(f"{name} must be a positive integer.")

    return threshold


class SecurityDetector:
    """Detects suspicious activity in collected security events."""

    def __init__(
        self,
        failed_login_threshold: int | None = None,
        time_window_minutes: int | None = None,
        port_scan_threshold: int | None = None
    ):
        self.failed_login_threshold = (
            failed_login_threshold
            if failed_login_threshold is not None
            else _environment_threshold(
                "CLOUDSENTINEL_FAILED_LOGIN_THRESHOLD",
                3
            )
        )
        window_minutes = (
            time_window_minutes
            if time_window_minutes is not None
            else _environment_threshold(
                "CLOUDSENTINEL_TIME_WINDOW_MINUTES",
                5
            )
        )
        self.time_window = timedelta(minutes=window_minutes)
        self.port_scan_threshold = (
            port_scan_threshold
            if port_scan_threshold is not None
            else _environment_threshold(
                "CLOUDSENTINEL_PORT_SCAN_THRESHOLD",
                5
            )
        )

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
            search_start = 0

            while search_start < len(timestamps):
                best_attempts = []
                best_end = None

                for index in range(search_start, len(timestamps)):
                    current_time = timestamps[index]
                    window_start = current_time - self.time_window

                    attempts = [
                        timestamp for timestamp in timestamps[search_start:]
                        if window_start <= timestamp <= current_time
                    ]

                    if (
                        len(attempts) >= self.failed_login_threshold
                        and len(attempts) > len(best_attempts)
                    ):
                        best_attempts = attempts
                        best_end = current_time

                if not best_attempts or best_end is None:
                    break

                alerts.append({
                    "alert_type": "brute_force_attempt",
                    "severity": self._brute_force_severity(
                        len(best_attempts)
                    ),
                    "source_ip": source_ip,
                    "failed_attempts": len(best_attempts),
                    "window_start": best_attempts[0].isoformat(),
                    "window_end": best_end.isoformat(),
                    "time_window_minutes": (
                        self.time_window.total_seconds() / 60
                    ),
                    "description": (
                        f"Possible brute-force activity detected "
                        f"from {source_ip}"
                    )
                })
                search_start = next(
                    (
                        next_index
                        for next_index, timestamp in enumerate(timestamps)
                        if timestamp > best_end + self.time_window
                    ),
                    len(timestamps)
                )

        return alerts

    @staticmethod
    def _brute_force_severity(attempts: int) -> str:
        if attempts <= 5:
            return "medium"
        if attempts <= 10:
            return "high"
        return "critical"

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
            search_start = 0

            while search_start < len(attempts):
                best_ports = set()
                best_window = []
                best_end = None

                for index in range(search_start, len(attempts)):
                    current_time, _ = attempts[index]

                    window_start = current_time - self.time_window

                    window = [
                        (timestamp, port)
                        for timestamp, port in attempts[search_start:]
                        if window_start <= timestamp <= current_time
                    ]
                    ports = {port for _, port in window}

                    if (
                        len(ports) >= self.port_scan_threshold
                        and len(ports) > len(best_ports)
                    ):
                        best_ports = ports
                        best_window = window
                        best_end = current_time

                if not best_ports or best_end is None:
                    break

                alerts.append({
                    "alert_type": "port_scan_detected",
                    "severity": (
                        "medium"
                        if len(best_ports) <= 9
                        else "high"
                    ),
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "unique_ports": len(best_ports),
                    "destination_ports": sorted(best_ports),
                    "window_start": min(
                        timestamp for timestamp, _ in best_window
                    ).isoformat(),
                    "window_end": best_end.isoformat(),
                    "time_window_minutes": (
                        self.time_window.total_seconds() / 60
                    ),
                    "description": (
                        f"Possible port scanning activity detected "
                        f"from {source_ip} against {destination_ip}"
                    )
                })
                search_start = next(
                    (
                        next_index
                        for next_index, (timestamp, _) in enumerate(attempts)
                        if timestamp > best_end + self.time_window
                    ),
                    len(attempts)
                )

        return alerts
