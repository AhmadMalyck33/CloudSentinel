
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus_multiproc

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 1000 cloudsentinel \
    && useradd --uid 1000 --gid cloudsentinel --home-dir /app \
        --no-create-home cloudsentinel \
    && mkdir -p /app/data/security "$PROMETHEUS_MULTIPROC_DIR" \
    && chown -R cloudsentinel:cloudsentinel /app \
        "$PROMETHEUS_MULTIPROC_DIR"

COPY app/ ./app/
COPY run.py .

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)"]

USER cloudsentinel

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "run:app"]