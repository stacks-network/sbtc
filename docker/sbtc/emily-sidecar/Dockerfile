FROM python:3.12-slim AS emily-sidecar

WORKDIR /app
COPY ../../emily_sidecar /app
# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt
# Expose the FastAPI port
EXPOSE 20540
ENV EMILY_API_KEY=testApiKey
ENV EMILY_ENDPOINT=http://emily-server:3031
CMD ["uvicorn", "--host", "0.0.0.0", "--port", "20540", "--workers", "4", "--timeout-keep-alive", "30", "--log-level" , "info", "main:app"]
