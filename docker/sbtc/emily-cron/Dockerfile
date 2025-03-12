FROM python:3.13-slim

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

# Set up the cron job
RUN echo "*/5 * * * * EMILY_API_KEY=${EMILY_API_KEY} EMILY_ENDPOINT=${EMILY_ENDPOINT} /app/main.py >> /var/log/cron.log 2>&1" > /etc/cron.d/emily-cron
RUN chmod 0644 /etc/cron.d/emily-cron
RUN crontab /etc/cron.d/emily-cron

# Create the log file to be able to run tail
RUN touch /var/log/cron.log

# Environment variables
ENV EMILY_API_KEY=testApiKey
ENV EMILY_ENDPOINT=http://emily-server:3031

# Run cron in the foreground
CMD cron && tail -f /var/log/cron.log