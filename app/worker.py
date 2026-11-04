import logging
import os
import signal
import time
from pathlib import Path
from threading import Event
from typing import Callable

from app.services.detection_service import DetectionService


logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVENT_FILE = PROJECT_ROOT / "data" / "security" / "events.jsonl"


def _database_path() -> Path:
    return Path(os.environ.get(
        "CLOUDSENTINEL_DB",
        PROJECT_ROOT / "data" / "security" / "cloudsentinel.db"
    ))


def _detection_interval() -> float:
    try:
        interval = float(os.environ.get(
            "CLOUDSENTINEL_DETECTION_INTERVAL",
            "10"
        ))
    except ValueError:
        logger.warning(
            "Invalid CLOUDSENTINEL_DETECTION_INTERVAL; using 10 seconds."
        )
        return 10

    return max(interval, 0)


def _run_loop(
    stop_event: Event,
    sleep: Callable[[float], None] = time.sleep
) -> None:
    interval = _detection_interval()
    while not stop_event.is_set():
        try:
            result = DetectionService(
                event_file=EVENT_FILE,
                alert_file=_database_path()
            ).process_events()
            logger.info("Detection run completed: %s", result)
        except Exception:
            logger.exception("Detection run failed.")

        if not stop_event.is_set():
            sleep(interval)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    stop_event = Event()

    def request_shutdown(signum, _frame) -> None:
        logger.info("Received signal %s; stopping detection worker.", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    _run_loop(stop_event)
    logger.info("Detection worker stopped.")


if __name__ == "__main__":
    main()
