# Standalone Ubuntu Server Setup Guide

This guide will help you deploy the complete honeypot stack on a single Ubuntu server.

## Prerequisites

- Ubuntu Server 20.04 LTS or newer
- Minimum 2GB RAM (4GB recommended)
- 20GB free disk space (50GB+ for long-term storage)
- Root or sudo access
- Server exposed to internet (or network you want to monitor)

## Installation Methods

### Method 1: Docker (Recommended - Easiest)

Docker keeps everything isolated and makes management simple.

#### Step 1: Install Docker

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add your user to docker group (optional, to run without sudo)
sudo usermod -aG docker $USER
newgrp docker

# Verify installation
docker --version
docker-compose --version
```

#### Step 2: Deploy Honeypot

```bash
# Extract the honeypot files
cd ~
tar -xzf honeypot.tar.gz
cd honeypot

# Make deploy script executable
chmod +x deploy.sh

# Deploy everything
./deploy.sh
```

That's it! The honeypot is now running with:
- HTTP on port 80
- SSH on port 22
- FTP on port 21
- DNS on port 53
- ElasticSearch on port 9200
- Kibana on port 5601

#### Managing the Docker Deployment

```bash
# View logs
docker-compose logs -f honeypot

# Stop honeypot
docker-compose down

# Start honeypot
docker-compose up -d

# Restart after config changes
docker-compose restart honeypot

# View running containers
docker-compose ps

# Generate report
docker-compose exec honeypot python analyze_telemetry.py ./honeypot_data
```

---

### Method 2: Native Installation (More Control)

If you prefer not to use Docker or want maximum performance.

#### Step 1: Install Python and Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.11+ and tools
sudo apt install -y python3.11 python3-pip python3-venv git curl

# Create application directory
sudo mkdir -p /opt/honeypot
sudo chown $USER:$USER /opt/honeypot
cd /opt/honeypot

# Extract honeypot files (assuming you uploaded honeypot.tar.gz)
tar -xzf ~/honeypot.tar.gz --strip-components=1

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 2: Configure Honeypot

```bash
# Generate default config
python honeypot.py
# This will create honeypot_config.json and exit

# Edit configuration
nano honeypot_config.json
```

**For standalone server, use these settings:**

```json
{
  "output_dir": "/opt/honeypot/honeypot_data",
  "services": {
    "http": {
      "enabled": true,
      "port": 80
    },
    "ssh": {
      "enabled": true,
      "port": 22
    },
    "ftp": {
      "enabled": true,
      "port": 21
    },
    "dns": {
      "enabled": true,
      "port": 53
    }
  },
  "elasticsearch": {
    "enabled": false,
    "hosts": ["localhost:9200"]
  }
}
```

**Note**: Ports below 1024 require root privileges or capabilities.

#### Step 3: Setup Port Permissions

**Option A: Run as root (simpler, less secure)**
```bash
sudo /opt/honeypot/venv/bin/python /opt/honeypot/honeypot.py
```

**Option B: Use setcap (recommended)**
```bash
# Allow Python to bind to privileged ports
sudo setcap 'cap_net_bind_service=+ep' /opt/honeypot/venv/bin/python3.11

# Now run as regular user
python honeypot.py
```

**Option C: Use iptables forwarding (most secure)**
```bash
# Keep honeypot on high ports, forward with iptables
# Edit honeypot_config.json to use ports 8080, 2222, 2121, 5353

# Forward external ports to honeypot ports
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
sudo iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5353

# Save rules
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

#### Step 4: Create Systemd Service

```bash
# Create service file
sudo nano /etc/systemd/system/honeypot.service
```

Add this content:

```ini
[Unit]
Description=INetSim Honeypot
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/opt/honeypot
Environment="PATH=/opt/honeypot/venv/bin"
ExecStart=/opt/honeypot/venv/bin/python /opt/honeypot/honeypot.py
Restart=always
RestartSec=10
StandardOutput=append:/opt/honeypot/honeypot.log
StandardError=append:/opt/honeypot/honeypot.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/honeypot/honeypot_data

[Install]
WantedBy=multi-user.target
```

Replace `YOUR_USERNAME` with your actual username.

If using privileged ports (80, 22, 21, 53):
```ini
# Add this line under [Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

Enable and start:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable honeypot

# Start service
sudo systemctl start honeypot

# Check status
sudo systemctl status honeypot

# View logs
sudo journalctl -u honeypot -f
```

---

## Optional: Install ElasticSearch + Kibana

For enhanced visualization and analysis (requires 4GB+ RAM).

### Quick Install

```bash
# Add Elastic repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Install ElasticSearch
sudo apt update
sudo apt install elasticsearch

# Configure ElasticSearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Add/modify these settings:
```yaml
cluster.name: honeypot-cluster
network.host: localhost
xpack.security.enabled: false  # Disable for local use
```

```bash
# Start ElasticSearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Verify
curl localhost:9200

# Install Kibana
sudo apt install kibana

# Configure Kibana
sudo nano /etc/kibana/kibana.yml
```

Add:
```yaml
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
```

```bash
# Start Kibana
sudo systemctl enable kibana
sudo systemctl start kibana

# Access Kibana at http://YOUR_SERVER_IP:5601
```

### Enable ElasticSearch in Honeypot

```bash
# Edit honeypot config
nano /opt/honeypot/honeypot_config.json
```

Change:
```json
"elasticsearch": {
  "enabled": true,
  "hosts": ["localhost:9200"]
}
```

```bash
# Restart honeypot
sudo systemctl restart honeypot

# Setup ES indices
cd /opt/honeypot
source venv/bin/activate
python setup_elasticsearch.py
```

---

## Network Configuration

### Firewall Setup

**If using Docker deployment:**
```bash
# Docker handles most networking
# Just open Kibana if you want external access
sudo ufw allow 5601/tcp comment 'Kibana'
```

**If using native deployment:**
```bash
# Enable firewall
sudo ufw enable

# Allow honeypot ports (these will receive malicious traffic)
sudo ufw allow 80/tcp comment 'HTTP Honeypot'
sudo ufw allow 22/tcp comment 'SSH Honeypot'
sudo ufw allow 21/tcp comment 'FTP Honeypot'
sudo ufw allow 53 comment 'DNS Honeypot'

# Allow your SSH management port (change 2222 to your actual management port)
# IMPORTANT: Change your real SSH port first!
sudo ufw allow 2222/tcp comment 'Real SSH Management'

# If using ElasticSearch/Kibana
sudo ufw allow 5601/tcp comment 'Kibana'

# Check rules
sudo ufw status
```

### Protecting Your Management SSH

**CRITICAL**: Don't run honeypot SSH on port 22 if that's your management SSH!

```bash
# Change your real SSH to different port
sudo nano /etc/ssh/sshd_config

# Change this line:
Port 2222  # Or any other port

# Restart SSH
sudo systemctl restart sshd

# Test new port works before disconnecting!
ssh -p 2222 user@your_server

# Now you can run SSH honeypot on port 22
```

---

## Monitoring and Maintenance

### View Real-Time Events

```bash
# Watch event log
tail -f /opt/honeypot/honeypot_data/events.jsonl

# Pretty print JSON
tail -f /opt/honeypot/honeypot_data/events.jsonl | jq .

# Filter for attacks
tail -f /opt/honeypot/honeypot_data/events.jsonl | grep attack
```

### Generate Reports

```bash
cd /opt/honeypot
source venv/bin/activate

# Last 24 hours
python analyze_telemetry.py ./honeypot_data

# Last week
python analyze_telemetry.py ./honeypot_data --hours 168

# Save to file
python analyze_telemetry.py ./honeypot_data --output report.txt
```

### Check Resource Usage

```bash
# Service status
sudo systemctl status honeypot

# Resource usage
ps aux | grep honeypot
top -p $(pgrep -f honeypot.py)

# Disk usage
du -sh /opt/honeypot/honeypot_data/*

# Network connections
sudo netstat -tulpn | grep python
```

### Log Rotation

```bash
# Create logrotate config
sudo nano /etc/logrotate.d/honeypot
```

Add:
```
/opt/honeypot/honeypot.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 YOUR_USERNAME YOUR_USERNAME
}

/opt/honeypot/honeypot_data/events.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
}
```

### Automated Analysis

Create daily report:

```bash
# Create script
nano /opt/honeypot/daily_report.sh
```

Add:
```bash
#!/bin/bash
cd /opt/honeypot
source venv/bin/activate
python analyze_telemetry.py ./honeypot_data --hours 24 --output /opt/honeypot/reports/report-$(date +%Y-%m-%d).txt
```

```bash
# Make executable
chmod +x /opt/honeypot/daily_report.sh

# Add to crontab
crontab -e

# Add this line (run at 1 AM daily)
0 1 * * * /opt/honeypot/daily_report.sh
```

---

## Testing Your Deployment

### From the Server Itself

```bash
cd /opt/honeypot
source venv/bin/activate
python test_honeypot.py
```

### From Another Machine

```bash
# Test HTTP
curl http://YOUR_SERVER_IP/

# Test SSH (will log credentials)
ssh root@YOUR_SERVER_IP

# Test FTP
ftp YOUR_SERVER_IP

# Check if being logged
ssh into_your_server
tail /opt/honeypot/honeypot_data/events.jsonl
```

---

## Backup Strategy

### Daily Backup

```bash
# Create backup script
nano /opt/honeypot/backup.sh
```

Add:
```bash
#!/bin/bash
BACKUP_DIR="/backup/honeypot"
DATE=$(date +%Y-%m-%d)

mkdir -p $BACKUP_DIR

# Backup events
tar -czf $BACKUP_DIR/events-$DATE.tar.gz /opt/honeypot/honeypot_data/events.jsonl*

# Backup samples
tar -czf $BACKUP_DIR/samples-$DATE.tar.gz /opt/honeypot/honeypot_data/samples/

# Keep only last 30 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

```bash
chmod +x /opt/honeypot/backup.sh

# Add to crontab (2 AM daily)
0 2 * * * /opt/honeypot/backup.sh
```

---

## Performance Tuning

### For High-Traffic Deployments

```bash
# Increase file descriptor limits
sudo nano /etc/security/limits.conf
```

Add:
```
* soft nofile 65536
* hard nofile 65536
```

```bash
# Increase kernel limits
sudo nano /etc/sysctl.conf
```

Add:
```
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.ip_local_port_range = 1024 65535
```

Apply:
```bash
sudo sysctl -p
```

### Optimize ElasticSearch

```bash
sudo nano /etc/elasticsearch/jvm.options
```

Set heap size (use 50% of available RAM, max 32GB):
```
-Xms2g
-Xmx2g
```

---

## Troubleshooting

### Honeypot Won't Start

```bash
# Check logs
sudo journalctl -u honeypot -n 50

# Check port conflicts
sudo netstat -tulpn | grep -E ':80|:22|:21|:53'

# Test manually
cd /opt/honeypot
source venv/bin/activate
python honeypot.py
# Watch for error messages
```

### No Events Being Logged

```bash
# Check file permissions
ls -la /opt/honeypot/honeypot_data/

# Fix permissions
sudo chown -R $USER:$USER /opt/honeypot/honeypot_data/

# Check if services started
sudo netstat -tulpn | grep python

# Test connectivity
curl http://localhost
```

### High Memory Usage

```bash
# Check memory
free -h

# If ElasticSearch is the culprit, reduce heap
sudo nano /etc/elasticsearch/jvm.options
# Reduce -Xms and -Xmx values

# Restart ElasticSearch
sudo systemctl restart elasticsearch
```

---

## Security Checklist

- [ ] Change default SSH port for management
- [ ] Enable UFW firewall
- [ ] Setup SSH key authentication (disable password)
- [ ] Regular system updates (`apt update && apt upgrade`)
- [ ] Monitor disk space
- [ ] Setup log rotation
- [ ] Backup honeypot data regularly
- [ ] Isolate server (separate VLAN if possible)
- [ ] Monitor for anomalous behavior
- [ ] Keep honeypot code updated

---

## Quick Command Reference

```bash
# View logs
sudo journalctl -u honeypot -f

# Restart honeypot
sudo systemctl restart honeypot

# Generate report
cd /opt/honeypot && source venv/bin/activate && python analyze_telemetry.py ./honeypot_data

# Check status
sudo systemctl status honeypot

# View recent attacks
tail -50 /opt/honeypot/honeypot_data/events.jsonl | grep attack

# Disk usage
du -sh /opt/honeypot/honeypot_data/*

# Top attackers
cd /opt/honeypot && source venv/bin/activate && python -c "
import json
from collections import Counter
ips = Counter()
with open('honeypot_data/events.jsonl') as f:
    for line in f:
        event = json.loads(line)
        ips[event['source_ip']] += 1
for ip, count in ips.most_common(10):
    print(f'{ip}: {count}')
"
```

---

## What's Next?

1. **Let it run for 24 hours** - See what finds you
2. **Review the analysis** - `python analyze_telemetry.py ./honeypot_data`
3. **Setup Kibana dashboards** - Visualize attack patterns
4. **Integrate with your pipeline** - Connect to IDA/Ghidra/YARA
5. **Customize detection** - Add your own attack patterns

The server will now continuously collect telemetry on all connection attempts and attacks!
