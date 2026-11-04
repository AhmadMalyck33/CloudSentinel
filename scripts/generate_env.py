import secrets
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"
ENV_FILE = PROJECT_ROOT / ".env"
SECRET_NAMES = (
    "GRAFANA_ADMIN_PASSWORD",
    "CLOUDSENTINEL_API_KEY",
    "ALERTMANAGER_WEBHOOK_TOKEN"
)


def generate_env() -> bool:
    """Create .env with generated secrets without overwriting an existing file."""

    if ENV_FILE.exists():
        return False

    content = ENV_EXAMPLE.read_text(encoding="utf-8")
    values = {
        name: secrets.token_urlsafe(32)
        for name in SECRET_NAMES
    }
    lines = []
    for line in content.splitlines(keepends=True):
        name, separator, _ = line.partition("=")
        if separator and name in values:
            line_ending = "\n" if line.endswith("\n") else ""
            line = f"{name}={values[name]}{line_ending}"
        lines.append(line)

    ENV_FILE.write_text("".join(lines), encoding="utf-8")
    return True


if __name__ == "__main__":
    if generate_env():
        print(f"Created {ENV_FILE}")
    else:
        print(f"{ENV_FILE} already exists; leaving it unchanged.")
