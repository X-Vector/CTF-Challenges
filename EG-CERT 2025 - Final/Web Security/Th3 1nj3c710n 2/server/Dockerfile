FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    vim-common \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the challenge directory
COPY challenge/ .

# Create directories and set permissions
RUN mkdir -p static/uploads && \
    mkdir -p /app/data && \
    chown -R nobody:nogroup /app && \
    chmod -R 755 /app && \
    chmod -R 777 /app/data && \
    chmod -R 777 /app/static/uploads

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose port
EXPOSE 8721

# Use the entrypoint
ENTRYPOINT ["/entrypoint.sh"]
