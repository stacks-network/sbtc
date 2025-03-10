FROM python:3.13-slim AS emily-sidecar

# Install uv.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy the application into the container.
COPY ../../emily_sidecar /app

# Install the application dependencies.
WORKDIR /app
RUN uv sync --frozen --no-cache

# Expose the FastAPI port
EXPOSE 20540
ENV EMILY_API_KEY=testApiKey
ENV EMILY_ENDPOINT=http://emily-server:3031
CMD ["/app/.venv/bin/uvicorn", "--host", "0.0.0.0", "--port", "20540", "--workers", "4", "--timeout-keep-alive", "30", "--log-level" , "info", "app.main:app"]
