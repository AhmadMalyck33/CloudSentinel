
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class SecurityLogCollector:
    """Reads and parses security events from a JSONL file."""

    def __init__(
        self,
        log_file: str | Path,
        state_file: str | Path | None = None
    ):
        self.log_file = Path(log_file)
        self.state_file = Path(state_file) if state_file else None
        if self.state_file:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self._initialize_state()

    def collect_events(self) -> list[dict[str, Any]]:
        """Read new events and return the retained detection history."""

        if not self.log_file.exists():
            return self._load_recent_events() if self.state_file else []

        if not self.state_file:
            return self._read_events(0)[0]

        file_size = self.log_file.stat().st_size
        offset, stored_size, recent_events = self._load_state()
        if file_size < offset or stored_size < offset:
            offset = 0
            recent_events = []

        new_events, new_offset = self._read_events(offset)
        events = recent_events + new_events
        events = self._retain_recent_events(events)
        self._save_state(new_offset, file_size, events)
        return events

    def _initialize_state(self) -> None:
        with sqlite3.connect(self.state_file) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS collector_state (
                    file_path TEXT PRIMARY KEY,
                    offset INTEGER NOT NULL,
                    file_size INTEGER NOT NULL,
                    recent_events TEXT NOT NULL
                )
            """)

    def _load_state(self) -> tuple[int, int, list[dict[str, Any]]]:
        with sqlite3.connect(self.state_file) as connection:
            row = connection.execute(
                """
                SELECT offset, file_size, recent_events
                FROM collector_state
                WHERE file_path = ?
                """,
                (str(self.log_file.resolve()),)
            ).fetchone()

        if row is None:
            return 0, 0, []
        try:
            recent_events = json.loads(row[2])
        except json.JSONDecodeError:
            recent_events = []
        if not isinstance(recent_events, list):
            recent_events = []
        return row[0], row[1], [
            event for event in recent_events
            if isinstance(event, dict)
        ]

    def _save_state(
        self,
        offset: int,
        file_size: int,
        recent_events: list[dict[str, Any]]
    ) -> None:
        with sqlite3.connect(self.state_file) as connection:
            connection.execute(
                """
                INSERT INTO collector_state
                (file_path, offset, file_size, recent_events)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(file_path) DO UPDATE SET
                    offset = excluded.offset,
                    file_size = excluded.file_size,
                    recent_events = excluded.recent_events
                """,
                (
                    str(self.log_file.resolve()),
                    offset,
                    file_size,
                    json.dumps(recent_events)
                )
            )

    def _read_events(
        self,
        offset: int
    ) -> tuple[list[dict[str, Any]], int]:
        events = []
        with self.log_file.open("rb") as file:
            file.seek(offset)
            data = file.read()

        last_newline = data.rfind(b"\n")
        if last_newline < 0:
            return [], offset

        complete_data = data[:last_newline + 1]
        for line_number, raw_line in enumerate(
            complete_data.splitlines(),
            start=1
        ):
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
            except json.JSONDecodeError:
                print(f"Invalid JSON at line {line_number}; skipping.")

        return events, offset + len(complete_data)

    def _load_recent_events(self) -> list[dict[str, Any]]:
        return self._read_events(0)[0]

    def _retain_recent_events(
        self,
        events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        timestamps = []
        for event in events:
            timestamp = event.get("timestamp")
            if not isinstance(timestamp, str):
                continue
            try:
                parsed = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            timestamps.append(parsed)

        if not timestamps:
            return events

        latest = max(timestamps)
        try:
            window_minutes = int(os.environ.get(
                "CLOUDSENTINEL_TIME_WINDOW_MINUTES",
                "5"
            ))
        except ValueError:
            window_minutes = 5
        cutoff = latest - timedelta(minutes=max(window_minutes, 1) * 2)

        retained = []
        for event in events:
            timestamp = event.get("timestamp")
            if not isinstance(timestamp, str):
                continue
            try:
                parsed = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            if parsed >= cutoff:
                retained.append(event)
        return retained
