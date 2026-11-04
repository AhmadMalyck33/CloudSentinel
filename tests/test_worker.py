from threading import Event

import app.worker as worker


def test_worker_loop_runs_detection_once_with_mocked_sleep(monkeypatch):
    calls = []

    class FakeDetectionService:
        def __init__(self, event_file, alert_file):
            calls.append(("init", event_file, alert_file))

        def process_events(self):
            calls.append(("process",))
            return {"new_alerts": 1}

    stop_event = Event()

    def stop_after_sleep(interval):
        assert interval == 10
        stop_event.set()

    monkeypatch.delenv("CLOUDSENTINEL_DETECTION_INTERVAL", raising=False)
    monkeypatch.setattr(worker, "DetectionService", FakeDetectionService)

    worker._run_loop(stop_event, sleep=stop_after_sleep)

    assert [call[0] for call in calls] == ["init", "process"]
