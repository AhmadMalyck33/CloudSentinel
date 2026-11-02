
import json
from pathlib import Path
from typing import Any


class SecurityLogCollector:
    """Reads and parses security events from a JSONL file."""

    def __init__(self, log_file: str | Path):
        self.log_file = Path(log_file)

    def collect_events(self) -> list[dict[str, Any]]:
        """Read valid JSON events from the log file."""

        events = []

        if not self.log_file.exists():
            return events

        with self.log_file.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)

                    if isinstance(event, dict):
                        events.append(event)

                except json.JSONDecodeError:
                    print(
                        f"Invalid JSON at line {line_number}; skipping."
                    )

        return events
