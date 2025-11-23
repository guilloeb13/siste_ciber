# =============================================================================
# NavajaCyber Backend Dockerfile
# USO AUTORIZADO ÚNICAMENTE
# =============================================================================

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libmagic1 \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r navaja && useradd -r -g navaja navaja

# Set work directory
WORKDIR /app

# Copy requirements first for caching
COPY pyproject.toml ./

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -e .

# Install additional security tools
RUN pip install bandit pip-audit

# Copy application code
COPY backend/ ./backend/
COPY analysis/ ./analysis/
COPY forensic/ ./forensic/
COPY ctf/ ./ctf/
COPY agents/ ./agents/

# Change ownership to app user
RUN chown -R navaja:navaja /app

# Switch to non-root user
USER navaja

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
