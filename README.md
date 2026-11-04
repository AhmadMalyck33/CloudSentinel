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
|---|---|
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

| Detection Rule | Detection Condition |
|---|---|
| Brute Force Detection | At least 3 failed login attempts from the same source IP within 5 minutes |
| Port Scan Detection | At least 5 unique destination ports from the same source IP to the same destination IP within 5 minutes |

Both detection rules generate high-severity alerts.

Repeated processing of previously detected events is handled through alert deduplication.

## 6. Project Structure

```text
CloudSentinel/
│
├── app/
│   ├── detection/
│   │   └── rules.py
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
│   └── security/
│       ├── events.jsonl
│       └── alerts.jsonl
│
├── monitoring/
│   ├── prometheus/
│   │   └── prometheus.yml
│   └── docker-exporter/
│
├── tests/
│   ├── test_routes.py
│   ├── test_detection.py
│   └── test_log_collector.py
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── config/
├── docs/
├── screenshots/
├── Dockerfile
├── compose.yaml
├── requirements.txt
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
docker compose up -d --build
```

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

## 8. Access the Platform

After successful deployment, access the services using:

| Service | URL |
|---|---|
| CloudSentinel Dashboard | http://localhost:5000/dashboard |
| Flask API | http://localhost:5000 |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3001 |

Grafana credentials depend on the configuration in the Docker Compose file.

## 9. API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Application information |
| GET | `/health` | Application health status |
| GET | `/alerts` | Retrieve security alerts |
| PATCH | `/alerts/<alert_id>/status` | Update alert status |
| POST | `/process-events` | Process stored security events |
| GET | `/metrics` | Expose Prometheus metrics |

## 10. Testing

Run the backend test suite:

```bash
python -m pytest -v
```

The project currently includes tests covering:

- API routes and responses.
- Security detection rules.
- Security log collection and validation.

**Current test result:** 20 tests passed.

## 11. CI/CD Pipeline

Cloud