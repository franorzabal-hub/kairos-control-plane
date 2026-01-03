# Kairos Control Plane - Dockerfile for Cloud Run
# Multi-stage build for smaller image size

FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


FROM python:3.11-slim

# Labels for metadata
LABEL org.opencontainers.image.title="Kairos Control Plane"
LABEL org.opencontainers.image.description="Control plane API for Kairos cluster management"
LABEL org.opencontainers.image.vendor="Kairos"

WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

# Copy installed packages from builder with correct ownership
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local

# Copy application code with correct ownership
COPY --chown=appuser:appuser src/ ./src/

# Make sure scripts in .local are usable
ENV PATH=/home/appuser/.local/bin:$PATH

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8080
ENV USE_IN_CLUSTER=true

# Expose port
EXPOSE 8080

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Run the application
CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
