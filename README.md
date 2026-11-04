# CloudSentinel

### One Platform. Four Domains. Smarter Digital Operations.

CloudSentinel is a DevOps and Cybersecurity monitoring platform designed to bring application health, infrastructure monitoring, and security event detection together in one environment.

It collects structured security events, identifies suspicious activity, generates and manages security alerts, exposes application metrics, and provides infrastructure monitoring through Prometheus and Grafana.

## 1. Project Overview

Modern IT environments operate across applications, networks, infrastructure, and security systems. Monitoring these components separately can make it difficult to identify operational problems and suspicious activity.

CloudSentinel addresses this challenge through a unified monitoring platform that combines:

- **Cybersecurity:** Security event analysis and alert management.
- **DevOps:** Docker-based application deployment and CI/CD automation.
- **Monitoring:** Application and container metrics using Prometheus.
- **Visualization:** Monitoring dashboards through Grafana.

## 2. Key Features

### Security Monitoring
- Collects structured security events in JSONL format.
- Detects brute-force login attempts.
- Detects potential port-scanning activity.
- Generates high-severity security alerts.
- Supports alert status management: Open, Acknowledged, and Resolved.
- Prevents duplicate alerts when previously processed events are analyzed again.

### Application Monitoring
- Flask-based REST API.
- Application health endpoint.
- Prometheus metrics endpoint.
- HTTP request metrics.

### Infrastructure Monitoring

- Docker container CPU monitoring.
- Docker container memory monitoring.
- Prometheus scrapes application and Docker Exporter metrics every 15 seconds.
- Grafana dashboards for infrastructure and application visualization.
- Persistent Prometheus and Grafana data using Docker named volumes.

**Prometheus scrape targets:**
- `cloudsentinel-api:5000/metrics`
- `docker-exporter:9323/metrics`

The Docker Exporter exposes container metrics internally through the Docker Compose network.

### DevOps and Automation
- Docker containerization.
- Docker Compose multi-service deployment.
- GitHub Actions CI/CD workflow.
- Automated backend testing.
- Python security scanning.
- Docker image vulnerability scanning using Trivy.

## 3. Technology Stack

| Category | Technologies |
|---|---|---|
| Backend | Python, Flask |
| Security Detection | Python, JSONL |
| Frontend | HTML, CSS, JavaScript |
| Containerization | Docker |
| Orchestration | Docker Compose |
| Metrics Collection | Prometheus |
| Visualization | Grafana |
| CI/CD | GitHub Actions |
| Security Scanning | Bandit, pip-audit, Trivy |
| Testing | Pytest |
| Version Control | Git, GitHub |

## 4. System Architecture

The platform consists of the following major components:

1. **Flask API:** Provides application endpoints and connects the dashboard with backend services.
2. **Security Log Collector:** Reads structured security event records.
3. **Detection Engine:** Analyzes events and identifies suspicious patterns.
4. **Alert Manager:** Creates alerts, prevents duplicates, and manages alert statuses.
5. **Dashboard:** Displays security alerts and application status.
6. **Prometheus:** Collects application and Docker infrastructure metrics.
7. **Docker Exporter:** Exposes Docker container metrics.
8. **Grafana:** Visualizes infrastructure and application monitoring data.
9. **GitHub Actions:** Automates testing, security checks, and Docker image builds.

## 5. Security Detection Rules

CloudSentinel currently implements two detection rules:

| Detection Rule | Detection Condition | Severity |
|---|---|---|
| Brute Force Detection | At least 3 failed login attempts from the same source IP within 5 minutes | Medium (3-5), high (6-10), critical (>10) |
| Port Scan Detection | At least 5 unique destination ports from the same source IP to the same destination IP within 5 minutes | Medium (5-9), high (10+) |

Detection thresholds can be configured with
`CLOUDSENTINEL_FAILED_LOGIN_THRESHOLD`,
`CLOUDSENTINEL_TIME_WINDOW_MINUTES`, and
`CLOUDSENTINEL_PORT_SCAN_THRESHOLD`. They default to `3`, `5`, and `5`.

Repeated processing of previously detected events is handled through alert deduplication.

## 6. Project Structure

```text
CloudSentinel/
│
├── app/
│   ├── detection/
│   │   └── rules.py
│   ├── worker.py              # standalone detection worker
│   ├── services/
│   │   ├── log_collector.py
│   │   ├── alert_manager.py
│   │   └── detection_service.py
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   ├── templates/
│   │   └── dashboard.html
│   └── routes.py
│
├── data/
│   ├── sample/
│   │   └── events.jsonl
│   └── security/              # runtime files, ignored by Git
│
├── monitoring/
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   └── rules.yml
│   ├── alertmanager/
│   ├── grafana/
│   └── docker-exporter/
│       ├── Dockerfile
│       └── exporter.py
│
├── tests/
│   ├── data/
│   │   └── labeled_events.jsonl
│   ├── test_routes.py
│   ├── test_detection.py
│   └── test_evaluation.py
│
├── docs/
│   └── evaluation.md
├── scripts/
│   ├── evaluate_detection.py
│   └── generate_env.py
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── Dockerfile
├── compose.yaml
├── requirements.txt
├── requirements-dev.txt
├── run.py
└── README.md
```

## 7. Getting Started

### Prerequisites

Install the following tools:

- Python 3.12 or compatible Python version.
- Git.
- Docker Desktop.
- Docker Compose.

### Clone the Repository

```bash
git clone https://github.com/AhmadMalyck33/CloudSentinel.git
cd CloudSentinel
```

### Run with Docker Compose

Build and start the services:

```bash
python scripts/generate_env.py
docker compose up -d --build
```

The generator creates `.env` with cryptographically random values for
`GRAFANA_ADMIN_PASSWORD`, `CLOUDSENTINEL_API_KEY`, and
`ALERTMANAGER_WEBHOOK_TOKEN`. It never overwrites an existing `.env`; the file
is ignored and must never be committed. Do not type production secrets into
`.env.example`.

The API connects to Prometheus through the Compose network using
`PROMETHEUS_URL=http://prometheus:9090`. When running the API outside Compose,
set `PROMETHEUS_URL` to the reachable Prometheus URL; an optional example is
included in `.env.example`.

The generated `CLOUDSENTINEL_API_KEY` value is required in the `X-API-Key`
header for write endpoints such as `/process-events` and alert status updates.
In the dashboard, enter this key in the password field in the header area; it
is kept only in the page's in-memory JavaScript variable. GET endpoints remain
open. API keys shorter than 16 characters are rejected.

Demo login requests are limited to 20 requests per minute per source address
by default. Configure this with `CLOUDSENTINEL_LOGIN_RATE_LIMIT`. Event
storage is capped at 10 MB by default; configure the limit with
`CLOUDSENTINEL_MAX_EVENT_FILE_MB`.

Check running containers:

```bash
docker compose ps
```

View service logs:

```bash
docker compose logs
```

Stop the services:

```bash
docker compose down
```

To preserve monitoring data, do not remove the named Docker volumes when stopping the project.

### Linux notes

The API and detector containers run as the non-root UID/GID `1000:1000`.
Before starting Compose on Linux, make the bind-mounted security directory
writable by that user:

```bash
sudo chown -R 1000:1000 data/security
```

Running without root privileges limits the impact of a compromised application
and avoids creating root-owned alert, event, and database files on the host.

## 8. Access the Platform

After successful deployment, access the services using:

| Service | URL |
|---|---|
| CloudSentinel Dashboard | http://localhost:5000/dashboard |
| Flask API | http://localhost:5000 |
| Prometheus | http://127.0.0.1:9090 |
| Grafana | http://localhost:3001 |

Verify that the API can query Prometheus and the exporter metrics with:

```bash
curl http://localhost:5000/api/status
curl http://localhost:5000/api/infrastructure
```

The status response should contain `"exporter": "up"`, and the infrastructure
response should contain a non-empty `containers` array.

Grafana is provisioned automatically with a Prometheus datasource and the
CloudSentinel Overview dashboard. Its credentials depend on the configuration
in the Docker Compose file; no manual datasource or dashboard setup is needed.

## 9. API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Application information |
| GET | `/health` | Application health status |
| GET | `/alerts` | Retrieve security alerts |
| GET | `/audit` | Retrieve alert status audit records |
| PATCH | `/alerts/<alert_id>/status` | Update alert status |
| POST | `/process-events` | Process stored security events |
| GET | `/metrics` | Expose Prometheus metrics |

Write endpoints require the `CLOUDSENTINEL_API_KEY` environment variable and
the same value in the `X-API-Key` request header. They return `503` when the
environment variable is not configured and `401` for a missing or incorrect
header.

Alert and audit data is stored in SQLite at
`CLOUDSENTINEL_DB` (default:
`data/security/cloudsentinel.db`). On first use, existing
`data/security/alerts.jsonl` records are imported when the database is empty.

The container runs Gunicorn with two workers as the non-root `cloudsentinel`
user. Prometheus metrics use multiprocess mode through
`PROMETHEUS_MULTIPROC_DIR`; the Compose bind-mounted `data/security`
directory is used by UID/GID `1000`.

Compose runs detection in the separate `detector` service with the same
application image and data volume. It processes events every
`CLOUDSENTINEL_DETECTION_INTERVAL` seconds (default `10`). The API's
in-process detection thread is disabled in Compose to avoid one detector per
Gunicorn worker. For local development outside Compose, the original thread
remains enabled unless `CLOUDSENTINEL_DISABLE_BACKGROUND_DETECTION` is set.

The Docker exporter accesses the Docker Engine through the
`tecnativa/docker-socket-proxy` service. Only container listing and inspection
operations are enabled (`CONTAINERS=1`); all POST requests are denied
(`POST=0`). The proxy has no published port and is attached only to Compose's
internal `docker-socket` network, while the exporter also joins the monitoring
network so Prometheus can scrape it.

The exporter image runs as a non-root user. Its polling interval is configured
with `EXPORTER_INTERVAL_SECONDS` (default `10`), and its log level with
`LOG_LEVEL` (default `INFO`). Per-container statistics are logged at DEBUG
level.

To verify the exporter can read stats, start the stack and check its metrics:

```bash
docker compose up -d --build
```

The exporter is not published to the host, so run the check from the
Prometheus container or inspect the Prometheus target instead:

```bash
docker compose exec prometheus wget -qO- http://docker-exporter:9323/metrics
```

The proxy should allow container reads but reject container actions. For
example, a read request through the proxy should succeed, while stopping a
container should fail:

```bash
docker compose exec docker-exporter python -c "import docker; print(docker.from_env().containers.list())"
docker compose exec docker-exporter python -c "import docker; docker.from_env().containers.get('cloudsentinel-docker-exporter').stop()"
```

The first command should return container data and exporter metrics should show
`cloudsentinel_docker_exporter_up 1`. The second command should raise a Docker
API permission/error response because POST requests are disabled. Do not use a
production container for this stop test.

Prometheus loads alerting rules from
`monitoring/prometheus/rules.yml` and sends alerts to the internal
Alertmanager service. Alertmanager forwards firing alerts to
`POST /webhooks/alertmanager` using the `ALERTMANAGER_WEBHOOK_TOKEN` bearer
token. The endpoint stores each alert as `service_alert` and deduplicates
repeated notifications using Alertmanager's fingerprint.

To test the webhook directly:

```bash
curl -X POST http://localhost:5000/webhooks/alertmanager ^
  -H "Authorization: Bearer %ALERTMANAGER_WEBHOOK_TOKEN%" ^
  -H "Content-Type: application/json" ^
  --data "{\"alerts\":[{\"status\":\"firing\",\"fingerprint\":\"test-1\",\"labels\":{\"alertname\":\"TestAlert\",\"severity\":\"warning\"},\"annotations\":{\"summary\":\"Test alert\"}}]}"
```

The first request should return `alerts_saved: 1`; repeating it should return
`alerts_saved: 0` and `duplicates_skipped: 1`.

The demo login endpoint writes login events for testing detection:

```text
POST /demo/login
{"username": "demo", "password": "demo-pass"}
```

Only those credentials succeed; every other credential pair records a
`login_failure` event and returns `401`. A background detection thread runs
every 10 seconds in normal application processes. Set
`CLOUDSENTINEL_DISABLE_BACKGROUND_DETECTION=true` to disable it, such as when
running a separate scheduled detection job. The thread is disabled
automatically when the Flask app runs with `TESTING` enabled.

## 10. Testing

Run the backend test suite:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -v
```

On Windows PowerShell, use the same commands from the repository root. The
development requirements include pytest, Bandit, and pip-audit; the production
image installs only `requirements.txt`.

Evaluate the labeled detection dataset:

```bash
python scripts/evaluate_detection.py
```

The project includes tests covering:

- API routes and responses.
- Security detection rules.
- Security log collection and validation.
- Detection precision and recall.

## 11. Running the Demo

With the Flask app running locally or through Docker, submit a successful or
failed demo login:

```powershell
curl.exe -X POST http://localhost:5000/demo/login `
  -H "Content-Type: application/json" `
  --data '{"username":"demo","password":"demo-pass"}'
```

Only `demo` / `demo-pass` succeeds. Other credentials create failed-login
events. The detector service processes events every 10 seconds by default.
View generated alerts at `http://localhost:5000/alerts` or in the dashboard.

## 12. Known limitations

- There is no deployment step yet.
- The JSONL event source is a demo input, not a production log pipeline.
- HTTPS is not configured.
- The API key is shared between users.
- SQLite is intended for a single-node deployment.

## 13. CI/CD Pipeline

Cloud