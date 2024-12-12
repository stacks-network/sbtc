FROM python:3.12 AS emily-sidecar
WORKDIR /app
COPY ../../emily_sidecar /app
# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt
# Set environment variables
ENV FLASK_APP=app.py
# Expose the Flask port
EXPOSE 20540
ENV EMILY_API_KEY=testApiKey
ENV EMILY_CHAINSTATE_URL=http://emily-server:3031/chainstate
ENV DEPLOYER_ADDRESS=SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS
CMD ["gunicorn", "-c", "gunicorn_config.py", "wsgi:app"]
