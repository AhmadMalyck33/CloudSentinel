
# Use an official Python base image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Prevent Python from creating cache files
ENV PYTHONDONTWRITEBYTECODE=1

# Display Python logs immediately
ENV PYTHONUNBUFFERED=1

# Copy dependency file first
COPY requirements.txt .

# Install project dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app/ ./app/
COPY run.py .

# Expose Flask application port
EXPOSE 5000

# Start CloudSentinel
CMD ["python", "run.py"]
