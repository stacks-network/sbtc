FROM python:3.13-slim AS emily-cron

# Install uv 0.6.5
COPY --from=ghcr.io/astral-sh/uv@sha256:562193a4a9d398f8aedddcb223e583da394ee735de36b5815f8f1d22cb49be15 /uv /uvx /bin/

# Install cron
RUN apt-get update && apt-get install -y cron && rm -rf /var/lib/apt/lists/*

# Copy the application into the container
COPY ../../emily_cron /app

# Install the application dependencies
WORKDIR /app
RUN uv sync --frozen --no-cache

# Make the script executable
RUN chmod +x /app/main.py

# Create the log file to be able to run tail
RUN touch /var/log/cron.log

# Environment variables
ENV API_KEY=testApiKey
ENV EMILY_ENDPOINT=http://emily-server:3031
ENV PRIVATE_EMILY_ENDPOINT=http://emily-server:3031
ENV MEMPOOL_API_URL=https://mempool.space/api
ENV HIRO_API_URL=https://api.hiro.so/extended
ENV MIN_BLOCK_CONFIRMATIONS=6
ENV MAX_UNCONFIRMED_TIME=86400
ENV DEPLOYER_ADDRESS=SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS

# Set up the cron job to log to the log file only
# Run every 10 minutes
RUN echo "*/10 * * * * cd /app && uv run python /app/main.py >> /var/log/cron.log 2>&1" > /etc/cron.d/emily-cron
RUN chmod 0644 /etc/cron.d/emily-cron
RUN crontab /etc/cron.d/emily-cron

# Start cron and tail the log file to stdout
CMD bash -c "\
    # Write container start timestamp to log
    echo '=== CONTAINER STARTED: $(date) ===' > /var/log/cron.log && \
    # Copy environment variables to /etc/environment so they're available to cron
    # Filter out no_proxy which can cause issues
    printenv | grep -v 'no_proxy' > /etc/environment && \
    # Start the cron daemon in the background
    cron && \
    # Follow the log file to keep container running and stream logs
    tail -f /var/log/cron.log"