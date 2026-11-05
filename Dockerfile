# AI App Security & Quality Scanner — Container Image
FROM python:3.10-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies including git for safe cloning
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt reportlab prometheus-client pyjwt passlib

# Copy source code and frontend
COPY scanner/ /app/scanner/
COPY frontend/ /app/frontend/
COPY alembic.ini /app/
COPY pytest.ini /app/

# Create non-root system user for security
RUN groupadd -r scanner && useradd -r -g scanner -d /app -s /sbin/nologin scanner \
    && mkdir -p /app/tmp_scans \
    && chown -R scanner:scanner /app

USER scanner

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "scanner.main:app", "--host", "0.0.0.0", "--port", "8000"]

