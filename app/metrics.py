from prometheus_client import Counter, Gauge


ALERTS = Gauge(
    "cloudsentinel_alerts",
    "Current security alerts by status and severity",
    ["status", "severity"],
    multiprocess_mode="mostrecent"
)

DETECTIONS_TOTAL = Counter(
    "cloudsentinel_detections_total",
    "New security alerts saved by alert type",
    ["alert_type"]
)
