import importlib


def test_generate_env_creates_random_secrets_without_overwriting(
    tmp_path, monkeypatch
):
    generator = importlib.import_module("scripts.generate_env")
    example = tmp_path / ".env.example"
    env_file = tmp_path / ".env"
    example.write_text(
        "GRAFANA_ADMIN_PASSWORD=\n"
        "CLOUDSENTINEL_API_KEY=\n"
        "ALERTMANAGER_WEBHOOK_TOKEN=\n"
        "OTHER=value\n",
        encoding="utf-8"
    )
    monkeypatch.setattr(generator, "ENV_EXAMPLE", example)
    monkeypatch.setattr(generator, "ENV_FILE", env_file)

    assert generator.generate_env() is True
    generated = env_file.read_text(encoding="utf-8")
    values = dict(
        line.split("=", 1)
        for line in generated.splitlines()
        if "=" in line
    )
    for name in generator.SECRET_NAMES:
        assert len(values[name]) >= 16
    assert values["OTHER"] == "value"

    env_file.write_text("KEEP_ME=true\n", encoding="utf-8")
    assert generator.generate_env() is False
    assert env_file.read_text(encoding="utf-8") == "KEEP_ME=true\n"
