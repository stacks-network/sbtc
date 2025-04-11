FROM python:3.13-slim AS emily-sidecar

# Install uv 0.6.5
COPY --from=ghcr.io/astral-sh/uv@sha256:562193a4a9d398f8aedddcb223e583da394ee735de36b5815f8f1d22cb49be15 /uv /uvx /bin/

# Copy the application into the container.
COPY ../../emily_sidecar /app

# Install the application dependencies.
WORKDIR /app
RUN uv sync --frozen --no-cache

# Environment variables
ENV EMILY_API_KEY=testApiKey
ENV EMILY_ENDPOINT=http://emily-server:3031

# Expose the FastAPI port
EXPOSE 20540

# Run the FastAPI app
CMD ["uv", "run", "uvicorn", "--host", "0.0.0.0", "--port", "20540", "--workers", "4", "--timeout-keep-alive", "30", "--log-level", "info", "app.main:app"]
