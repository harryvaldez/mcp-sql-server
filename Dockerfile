FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and ODBC driver
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg2 \
    apt-transport-https \
    unixodbc-dev \
    && curl https://packages.microsoft.com/keys/microsoft.asc | tee /etc/apt/trusted.gpg.d/microsoft.asc \
    && curl https://packages.microsoft.com/config/debian/12/prod.list > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y msodbcsql18 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY README.md .
COPY DEPLOYMENT.md .

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

EXPOSE 8000

ENV MCP_SERVER_HOST=0.0.0.0
ENV MCP_SERVER_PORT=8000

USER appuser

CMD ["python", "server.py"]