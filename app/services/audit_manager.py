import sqlite3
import os
from pathlib import Path
from typing import Any


class AuditManager:
    """Stores and retrieves alert status audit records in SQLite."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path or os.environ.get(
            "CLOUDSENTINEL_DB",
            "data/security/cloudsentinel.db"
        ))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
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

    def append_record(
        self,
        alert_id: str,
        old_status: str,
        new_status: str,
        actor: str,
        reason: str | None
    ) -> dict[str, Any]:
        from datetime import datetime, timezone

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id,
            "old_status": old_status,
            "new_status": new_status,
            "actor": actor
        }

        if reason is not None:
            record["reason"] = reason

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audit
                (timestamp, alert_id, old_status, new_status, actor, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record["timestamp"],
                    alert_id,
                    old_status,
                    new_status,
                    actor,
                    reason
                )
            )

        return record

    def get_records(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT timestamp, alert_id, old_status, new_status, actor,
                       reason
                FROM audit
                ORDER BY id
                """
            ).fetchall()

        records = []
        for row in rows:
            record = dict(row)
            if record["reason"] is None:
                del record["reason"]
            records.append(record)

        return records
