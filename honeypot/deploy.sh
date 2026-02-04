#!/bin/bash
# Quick deployment script for honeypot

set -e

echo "========================================"
echo "Honeypot Deployment Script"
echo "========================================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "[ERROR] docker-compose is not installed. Please install docker-compose first."
    exit 1
fi

# Create data directory
echo "[*] Creating data directory..."
mkdir -p honeypot_data

# Generate default config if not exists
if [ ! -f honeypot_config.json ]; then
    echo "[*] Generating default configuration..."
    cat > honeypot_config.json << 'EOF'
{
  "output_dir": "./honeypot_data",
  "services": {
    "http": {
      "enabled": true,
      "port": 8080
    },
    "ssh": {
      "enabled": true,
      "port": 2222
    },
    "ftp": {
      "enabled": true,
      "port": 2121
    },
    "dns": {
      "enabled": true,
      "port": 5353
    }
  },
  "elasticsearch": {
    "enabled": true,
    "hosts": ["elasticsearch:9200"],
    "index_prefix": "honeypot"
  }
}
EOF
    echo "[+] Configuration created: honeypot_config.json"
fi

# Build and start containers
echo "[*] Building Docker images..."
docker-compose build

echo "[*] Starting honeypot services..."
docker-compose up -d

echo ""
echo "========================================"
echo "Deployment Complete!"
echo "========================================"
echo ""
echo "Services running:"
echo "  - HTTP:   Port 80  -> 8080"
echo "  - SSH:    Port 22  -> 2222"
echo "  - FTP:    Port 21  -> 2121"
echo "  - DNS:    Port 53  -> 5353"
echo ""
echo "Optional services:"
echo "  - ElasticSearch: http://localhost:9200"
echo "  - Kibana:        http://localhost:5601"
echo ""
echo "Data directory: ./honeypot_data"
echo ""
echo "Useful commands:"
echo "  View logs:      docker-compose logs -f honeypot"
echo "  Stop honeypot:  docker-compose down"
echo "  Analyze data:   docker-compose exec honeypot python analyze_telemetry.py ./honeypot_data"
echo ""
echo "========================================"
echo ""

# Show initial logs
echo "[*] Showing initial logs (Ctrl+C to exit)..."
sleep 2
docker-compose logs -f honeypot
