# Multi-stage build for smaller image
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir --user -r requirements.txt

# Download the large spaCy model (direct pip install is more reliable than spacy download)
RUN pip install --no-cache-dir --user https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.7.1/en_core_web_lg-3.7.1-py3-none-any.whl

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application
COPY main.py .

# Make sure scripts in .local are usable and Python can find packages
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/root/.local/lib/python3.11/site-packages:$PYTHONPATH

# Cloud Run sets PORT environment variable dynamically
# Default to 8080 if not set
ENV PORT=8080

# Expose the port
EXPOSE 8080

# Run the application using shell form to properly expand PORT variable
# Cloud Run will set PORT automatically, so we read it from environment
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1"]