import importlib.util
import sys
import types
from pathlib import Path


docker_stub = types.ModuleType("docker")
docker_stub.errors = types.SimpleNamespace(
    APIError=type("APIError", (Exception,), {}),
    DockerException=type("DockerException", (Exception,), {})
)
sys.modules.setdefault("docker", docker_stub)

EXPORTER_PATH = (
    Path(__file__).resolve().parent.parent
    / "monitoring" / "docker-exporter" / "exporter.py"
)
SPEC = importlib.util.spec_from_file_location("docker_exporter", EXPORTER_PATH)
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


def test_get_cpu_percentage():
    stats = {
        "cpu_stats": {
            "cpu_usage": {"total_usage": 150},
            "system_cpu_usage": 200,
            "online_cpus": 2
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 100},
            "system_cpu_usage": 100
        }
    }

    assert exporter.get_cpu_percentage(stats) == 100.0


def test_get_memory_usage():
    stats = {
        "memory_stats": {
            "usage": 1000,
            "limit": 2000,
            "stats": {"inactive_file": 250}
        }
    }

    assert exporter.get_memory_usage(stats) == (750, 2000)
