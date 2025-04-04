# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Set environment variables for Python best practices
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system dependencies if needed (e.g., build tools, libraries)
# RUN apt-get update && apt-get install -y --no-install-recommends some-package && rm -rf /var/lib/apt/lists/*

# Copy the dependencies file and install them
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container
COPY proxy_app.py .

# Create a non-root user and group for security
RUN addgroup --system app && adduser --system --group app
USER app

# Make internal port available (matches default PORT env var)
# The actual mapping happens during `docker run`
EXPOSE 5002

# Define default environment variables (override at runtime)
# Critical secrets (PROXY_API_KEYS, SERVICENOW_PASSWORD, etc.) MUST be provided securely at runtime
ENV FLASK_DEBUG=False
ENV PORT=5002

# Entrypoint script to check required env vars and start Gunicorn
# Using an entrypoint script allows for pre-start checks
RUN echo "#!/bin/sh" > /app/entrypoint.sh && \
    echo "set -e" >> /app/entrypoint.sh && \
    echo 'echo "Checking required environment variables..."' >> /app/entrypoint.sh && \
    echo 'REQUIRED_VARS="FABRIC_CA_SERVER_URL SERVICENOW_INSTANCE SERVICENOW_TABLE SERVICENOW_USER SERVICENOW_PASSWORD SERVICENOW_APPROVAL_FIELD SERVICENOW_APPROVAL_VALUE PROXY_API_KEYS"' >> /app/entrypoint.sh && \
    echo 'for VAR_NAME in $REQUIRED_VARS; do' >> /app/entrypoint.sh && \
    echo '  eval VALUE=\$$VAR_NAME' >> /app/entrypoint.sh && \
    echo '  if [ -z "$VALUE" ]; then' >> /app/entrypoint.sh && \
    echo '    echo >&2 "Fatal: Required environment variable $VAR_NAME is not set."' >> /app/entrypoint.sh && \
    echo '    exit 1' >> /app/entrypoint.sh && \
    echo '  fi' >> /app/entrypoint.sh && \
    echo 'done' >> /app/entrypoint.sh && \
    echo 'echo "Required variables seem present. Starting Gunicorn..."' >> /app/entrypoint.sh && \
    echo '# Use PORT env var, default to 5002 if not set for binding' >> /app/entrypoint.sh && \
    echo 'BIND_PORT=${PORT:-5002}' >> /app/entrypoint.sh && \
    echo '# Send Gunicorn logs to stdout/stderr for Docker logging' >> /app/entrypoint.sh && \
    echo 'exec gunicorn --workers 4 --bind 0.0.0.0:${BIND_PORT} --access-logfile - --error-logfile - proxy_app:app' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Run the application via the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]
