FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PREFIX_DB_PATH=/data/prefix_policy.db

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Writable data directory for the SQLite database (mounted as a volume
# in docker-compose.yml so analysis versions survive container restarts).
RUN mkdir -p /data && chown -R nobody:nogroup /data /app
USER nobody

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request; \
        urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT','8080') + '/health', timeout=3)" || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
