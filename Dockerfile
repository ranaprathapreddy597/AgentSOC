# Multi-Stage Production Dockerfile for AgentSOC FastAPI Backend
FROM python:3.13-slim as builder

WORKDIR /app

# Install build essential dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
RUN pip install --no-cache-dir uv

# Copy dependency definition
COPY requirements.txt .

# Install dependencies into virtual environment
RUN uv venv /app/.venv && \
    . /app/.venv/bin/activate && \
    uv pip install --no-cache -r requirements.txt

# Final Runtime Image
FROM python:3.13-slim as runner

WORKDIR /app

# Copy virtual environment and application source
COPY --from=builder /app/.venv /app/.venv
COPY src /app/src

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
