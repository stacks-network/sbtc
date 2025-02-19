FROM python:3.12-slim AS emily-sidecar
WORKDIR /emily_client
COPY ../../.generated-sources/emily/client/python/private /emily_client
# Install the emily client
RUN pip install --no-cache-dir -e .

WORKDIR /app
COPY ../../emily_sidecar /app
# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt
# Expose the FastAPI port
EXPOSE 20540
ENV EMILY_API_KEY=testApiKey
ENV EMILY_ENDPOINT=http://emily-server:3031
ENV DEPLOYER_ADDRESS=SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS
CMD ["uvicorn", "--host", "0.0.0.0", "--port", "20540", "--workers", "4", "--timeout-keep-alive", "30", "--log-level" , "info", "main:app"]
