FROM python:3.11-slim

LABEL maintainer="security@example.com"
LABEL description="INetSim-style Honeypot with Telemetry"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Replace the base image's pip first: pip before 26.2.2 always trusts its
# vendored CA bundle, which still includes the distrusted eMudhra emSign root
# (https://discuss.python.org/t/109576). Pinned by URL and hash, so the
# upgrade itself can't be tampered with in transit.
RUN pip install --no-cache-dir \
    "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY core/ ./core/
COPY services/ ./services/
COPY honeypot.py .
COPY analyze_telemetry.py .
COPY backfill_samples.py .
COPY honeypot_config.json .

# Create data directory
RUN mkdir -p /app/honeypot_data

# Create non-root user
RUN useradd -m -u 1000 honeypot && \
    chown -R honeypot:honeypot /app

# Switch to non-root user
USER honeypot

# Expose ports (non-privileged)
EXPOSE 8080/tcp
EXPOSE 8443/tcp
EXPOSE 8444/tcp
EXPOSE 2222/tcp
EXPOSE 2121/tcp
EXPOSE 5353/tcp
EXPOSE 40000-40009/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 8080)); s.close()"

# Volume for persistent data
VOLUME ["/app/honeypot_data"]

# Run honeypot
CMD ["python", "-u", "honeypot.py"]
