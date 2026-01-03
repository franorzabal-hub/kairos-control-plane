# Kairos Control Plane - Dockerfile for Production
# Multi-stage build optimized for smaller image size and security

# =============================================================================
# Stage 1: Builder - Install dependencies
# =============================================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies required for some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install Python dependencies to a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies with no cache to reduce image size
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Stage 2: Production - Final lightweight image
# =============================================================================
FROM python:3.11-slim

# Labels for metadata (OCI standard)
LABEL org.opencontainers.image.title="Kairos Control Plane"
LABEL org.opencontainers.image.description="Control plane API for Kairos tenant provisioning on GKE"
LABEL org.opencontainers.image.vendor="Kairos"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.source="https://github.com/kairos/control-plane"

WORKDIR /app

# Install runtime dependencies only (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security (best practice for production)
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy application code with correct ownership
COPY --chown=appuser:appgroup src/ ./src/

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PORT=8000 \
    USE_IN_CLUSTER=true

# Expose the application port
EXPOSE 8000

# Switch to non-root user for security
USER appuser

# Health check using the /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl --fail --silent http://localhost:8000/health || exit 1

# Run the application with Uvicorn ASGI server
# - workers: 1 (scale horizontally with container replicas)
# - host: 0.0.0.0 to accept external connections
# - port: 8000 (standard for web services)
# - no-access-log: disabled for production (use structured logging instead)
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
