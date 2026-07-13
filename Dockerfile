FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (.dockerignore keeps .env, venv, data out)
COPY . .

# Create data directories
RUN mkdir -p /app/data /app/chroma_data

# Run unprivileged; uid 1000 matches the typical host user owning the
# bind-mounted ./data and ./chroma_data volumes
RUN useradd -u 1000 -m sentinel && chown -R sentinel:sentinel /app
USER sentinel

# Set environment variables
ENV PYTHONUNBUFFERED=1

# main.py touches this heartbeat file every scheduler tick (30s)
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import os,sys,time; sys.exit(0 if time.time()-os.stat('/tmp/sentinel-heartbeat').st_mtime < 120 else 1)"

# Run the application
CMD ["python", "main.py"]
