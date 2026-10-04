FROM python:3.11-slim

# Prevent Python from writing bytecode and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create runtime directories and unprivileged user
RUN mkdir -p /app/data /app/logs /app/keys && \
    useradd -u 1001 -m honeyuser && \
    chown -R honeyuser:honeyuser /app

USER honeyuser

# Decoy SSH, Decoy HTTP, and SOC Dashboard
EXPOSE 2222 8080 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/stats || exit 1

ENTRYPOINT ["python", "main.py"]