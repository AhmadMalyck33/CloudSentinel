FROM python:3.12-slim

WORKDIR /exporter

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN groupadd --gid 1000 exporter \
    && useradd --uid 1000 --gid exporter --home-dir /exporter \
        --no-create-home exporter \
    && chown -R exporter:exporter /exporter

COPY exporter.py .

EXPOSE 9323

USER exporter

CMD ["python", "exporter.py"]
