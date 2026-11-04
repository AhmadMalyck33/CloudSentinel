import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AlertManager:
    """Stores, retrieves and manages security alerts in SQLite."""

    VALID_STATUSES = {
        "open",
        "acknowledged",
        "resolved"
    }

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path or os.environ.get(
            "CLOUDSENTINEL_DB",
            "data/security/cloudsentinel.db"
        ))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()
        self._import_jsonl_if_empty()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    generated_at TEXT,
                    data TEXT NOT NULL
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    old_status TEXT NOT NULL,
                    new_status TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS detection_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detected_at TEXT NOT NULL
                )
            """)

    def _import_jsonl_if_empty(self) -> None:
        with self._connect() as connection:
            alert_count = connection.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]

            if alert_count or self.db_path.name == "alerts.jsonl":
                return

            jsonl_path = self.db_path.parent / "alerts.jsonl"
            if not jsonl_path.exists():
                return

            records = []
            with jsonl_path.open("r", encoding="utf-8") as file:
                for line in file:
                    try:
                        alert = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if not isinstance(alert, dict):
                        continue

                    alert = alert.copy()
                    alert.setdefault("alert_id", str(uuid.uuid4()))
                    alert.setdefault("status", "open")
                    records.append(alert)

            for alert in records:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO alerts
                    (alert_id, status, generated_at, data)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        alert["alert_id"],
                        alert["status"],
                        alert.get("generated_at"),
                        json.dumps(alert)
                    )
                )

    def save_alerts(
        self,
        alerts: list[dict[str, Any]]
    ) -> int:
        """Save new alerts with unique IDs and an initial status."""

        if not alerts:
            return 0

        saved_count = 0
        generated_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as connection:
            for alert in alerts:
                record = alert.copy()
                record["alert_id"] = str(uuid.uuid4())
                record["status"] = "open"
                record["generated_at"] = generated_at

                connection.execute(
                    """
                    INSERT INTO alerts
                    (alert_id, status, generated_at, data)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        record["alert_id"],
                        record["status"],
                        record["generated_at"],
                        json.dumps(record)
                    )
                )
                saved_count += 1

        return saved_count

    def get_alerts(self) -> list[dict[str, Any]]:
        """Retrieve alerts without modifying the database."""

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT data FROM alerts ORDER BY rowid"
            ).fetchall()

        return [json.loads(row["data"]) for row in rows]

    def record_detection_run(
        self,
        detected_at: str | None = None
    ) -> None:
        timestamp = detected_at or datetime.now(timezone.utc).isoformat()

        with self._connect() as connection:
            connection.execute(
                "INSERT INTO detection_runs (detected_at) VALUES (?)",
                (timestamp,)
            )

    def get_last_detection_at(self) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT MAX(detected_at) AS latest
                FROM (
                    SELECT detected_at FROM detection_runs
                    UNION ALL
                    SELECT generated_at AS detected_at
                    FROM alerts
                    WHERE generated_at IS NOT NULL
                )
                """
            ).fetchone()

        return row["latest"] if row and row["latest"] else None

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

        updated_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM alerts WHERE alert_id = ?",
                (alert_id,)
            ).fetchone()

            if row is None:
                return None

            alert = json.loads(row["data"])
            alert["status"] = new_status
            alert["updated_at"] = updated_at

            connection.execute(
                """
                UPDATE alerts
                SET status = ?, data = ?
                WHERE alert_id = ?
                """,
                (new_status, json.dumps(alert), alert_id)
            )

        return alert
