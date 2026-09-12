# =============================================================================
# Secure API Gateway - Docker Image
# =============================================================================
# Multi-stage build for production-ready image with minimal footprint.
# =============================================================================

# ---- Stage 1: Build Stage ----
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---- Stage 2: Production Stage ----
FROM python:3.12-slim AS production

WORKDIR /app

# Create non-root user
RUN groupadd -r gateway && useradd -r -g gateway -d /home/gateway -m -s /sbin/nologin gateway

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /root/.local /home/gateway/.local

# Copy application code
COPY . .

# Ensure scripts are in PATH and set permissions
ENV PATH=/home/gateway/.local/bin:$PATH
RUN chown -R gateway:gateway /app /home/gateway/.local

# Shared directory for multi-worker Prometheus metrics
RUN mkdir -p /tmp/prometheus_metrics && chown gateway:gateway /tmp/prometheus_metrics
ENV prometheus_multiproc_dir=/tmp/prometheus_metrics

# Switch to non-root user
USER gateway

# Expose application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run database migrations, then start the application.
# --no-server-header removes the default `server: uvicorn` header (see the
# security middleware note in app/middleware/security.py).
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4 --no-server-header"]
