import logging
import os
import time

import docker
from prometheus_client import Gauge, start_http_server

log_level = getattr(
    logging,
    os.environ.get("LOG_LEVEL", "INFO").upper(),
    logging.INFO
)
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Prometheus metrics
CONTAINER_CPU_USAGE = Gauge(
    "cloudsentinel_container_cpu_usage_percent",
    "CPU usage percentage for each Docker container",
    ["container_name"]
)

CONTAINER_MEMORY_USAGE = Gauge(
    "cloudsentinel_container_memory_usage_bytes",
    "Memory usage in bytes for each Docker container",
    ["container_name"]
)

CONTAINER_MEMORY_LIMIT = Gauge(
    "cloudsentinel_container_memory_limit_bytes",
    "Memory limit in bytes for each Docker container",
    ["container_name"]
)

EXPORTER_UP = Gauge(
    "cloudsentinel_docker_exporter_up",
    "Whether the Docker exporter can communicate with Docker"
)

METRIC_LABELS = {
    CONTAINER_CPU_USAGE: set(),
    CONTAINER_MEMORY_USAGE: set(),
    CONTAINER_MEMORY_LIMIT: set()
}


def get_cpu_percentage(stats):
    cpu_stats = stats.get("cpu_stats", {})
    previous_cpu_stats = stats.get("precpu_stats", {})

    cpu_usage = cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
    previous_cpu_usage = (
        previous_cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
    )

    system_usage = cpu_stats.get("system_cpu_usage", 0)
    previous_system_usage = previous_cpu_stats.get(
        "system_cpu_usage", 0
    )

    cpu_delta = cpu_usage - previous_cpu_usage
    system_delta = system_usage - previous_system_usage

    online_cpus = cpu_stats.get(
        "online_cpus",
        len(cpu_stats.get("cpu_usage", {}).get("percpu_usage", []))
    )

    if system_delta <= 0 or cpu_delta < 0:
        return 0.0

    return (cpu_delta / system_delta) * online_cpus * 100.0


def get_memory_usage(stats):
    memory_stats = stats.get("memory_stats", {})

    usage = memory_stats.get("usage", 0)
    limit = memory_stats.get("limit", 0)

    cache = memory_stats.get("stats", {}).get(
        "inactive_file",
        memory_stats.get("stats", {}).get("cache", 0)
    )

    memory_used = max(usage - cache, 0)

    return memory_used, limit


def _polling_interval():
    try:
        return max(float(os.environ.get(
            "EXPORTER_INTERVAL_SECONDS",
            "10"
        )), 0)
    except ValueError:
        logging.warning(
            "Invalid EXPORTER_INTERVAL_SECONDS; using 10 seconds."
        )
        return 10


def main():
    logging.info("Connecting to Docker Engine...")

    client = docker.from_env()

    # Verify Docker connectivity
    client.ping()
    logging.info("Successfully connected to Docker Engine.")

    # Start Prometheus metrics endpoint
    start_http_server(9323)
    logging.info("Exporter metrics available on port 9323.")

    while True:
        try:
            containers = client.containers.list()
            observed_names = set()

            for container in containers:
                name = container.name

                try:
                    stats = container.stats(stream=False)

                    cpu_percent = get_cpu_percentage(stats)
                    memory_used, memory_limit = get_memory_usage(stats)

                    CONTAINER_CPU_USAGE.labels(
                        container_name=name
                    ).set(cpu_percent)

                    CONTAINER_MEMORY_USAGE.labels(
                        container_name=name
                    ).set(memory_used)

                    CONTAINER_MEMORY_LIMIT.labels(
                        container_name=name
                    ).set(memory_limit)
                    observed_names.add(name)

                    logging.debug(
                        "%s | CPU: %.2f%% | Memory: %.2f MiB",
                        name,
                        cpu_percent,
                        memory_used / (1024 * 1024)
                    )

                except docker.errors.APIError as error:
                    logging.warning(
                        "Could not retrieve statistics for %s: %s",
                        name,
                        error
                    )

            # Remove metrics for containers that were not updated this loop.
            for metric in (
                CONTAINER_CPU_USAGE,
                CONTAINER_MEMORY_USAGE,
                CONTAINER_MEMORY_LIMIT
            ):
                for name in METRIC_LABELS[metric] - observed_names:
                    metric.remove(name)
                METRIC_LABELS[metric] = set(observed_names)

            EXPORTER_UP.set(1)

        except docker.errors.DockerException as error:
            EXPORTER_UP.set(0)
            logging.error("Docker communication error: %s", error)

        except Exception:
            EXPORTER_UP.set(0)
            logging.exception("Unexpected exporter error")

        time.sleep(_polling_interval())


if __name__ == "__main__":
    main()
