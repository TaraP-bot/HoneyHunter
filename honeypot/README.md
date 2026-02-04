# INetSim-Inspired Honeypot Framework

A comprehensive, production-ready honeypot system designed for threat intelligence gathering and malware analysis. Features multi-protocol service emulation, deep telemetry collection, and real-time attack visualization.

## 🎯 Overview

This honeypot framework emulates multiple vulnerable services to attract and analyze malicious traffic. It captures detailed telemetry on all connection attempts, attack patterns, and malware samples for security research and threat intelligence.

### Key Features

- **Multi-Protocol Support**: HTTP, SSH, FTP, DNS honeypot services
- **Deep Telemetry Collection**: Comprehensive logging of all connection attempts and payloads
- **Attack Detection**: Built-in detection for SQL injection, XSS, path traversal, RCE attempts
- **Sample Capture**: Automatic collection of uploaded files and malware
- **Real-Time Analysis**: ElasticSearch + Kibana for live threat visualization
- **Secure Management**: Tailscale VPN for zero-trust remote access
- **Production-Ready**: Docker deployment with systemd integration and auto-restart

## 🏗️ Architecture

```
Internet Traffic
      ↓
[Digital Ocean Firewall]
      ↓
┌─────────────────────────────────────┐
│   Honeypot Droplet (Ubuntu)         │
│                                     │
│   Public Ports (Exposed):          │
│   - HTTP (80)  → Honeypot          │
│   - FTP (21)   → Honeypot          │
│   - SSH (2222) → Honeypot          │
│   - DNS (5353) → Honeypot          │
│                                     │
│   Private/Tailscale Only:          │
│   - SSH (22)   → Real SSH          │
│   - Kibana (5601) → Dashboards     │
│   - ElasticSearch → Internal       │
└─────────────────────────────────────┘
      ↑
   Tailscale VPN (Management)
      ↑
Your Computer
```

## 📊 Data Collection

### Event Types Captured

- **HTTP Requests**: Method, path, headers, query parameters, POST data
- **HTTP Attacks**: SQL injection, XSS, path traversal, command injection, XXE, RCE
- **SSH Attempts**: Login credentials, commands executed, session replay
- **FTP Activity**: Login attempts, file uploads/downloads, directory traversal
- **DNS Queries**: Domain lookups, DGA detection, tunneling attempts, C2 beaconing

### Data Storage Locations

```
/opt/honeypot/honeypot_data/
├── events.jsonl              # All telemetry events (JSON Lines format)
├── samples/                  # Captured files and malware
│   ├── <sha256>.bin         # Binary file content
│   └── <sha256>.json        # File metadata
└── pcap/                     # Packet captures (if enabled)
```

### ElasticSearch Indices

Events are automatically indexed to ElasticSearch:
- **Index Pattern**: `honeypot-YYYY.MM.DD`
- **Retention**: Configurable (default: unlimited)
- **Fields**: All event attributes fully indexed and searchable

## 🚀 Quick Installation

### Prerequisites

- Ubuntu 22.04 LTS server (Digital Ocean recommended)
- 2GB RAM minimum (4GB recommended)
- 20GB disk minimum
- Tailscale account (free)

### Installation Steps

1. **Create Digital Ocean droplet** with Ubuntu 22.04
2. **Configure firewall** (see below)
3. **Install Tailscale** on droplet and local computer
4. **Run installer**: `bash install.sh docker`
5. **Access Kibana**: `http://YOUR_TAILSCALE_IP:5601`

For detailed instructions, see `QUICKSTART.md`

## 📈 Accessing Your Data

### Kibana Dashboard

Access via Tailscale only:
```
http://YOUR_TAILSCALE_IP:5601
```

### JSON Logs

Direct file access:
```bash
tail -f /opt/honeypot/honeypot_data/events.jsonl
cat events.jsonl | jq .
```

### Analysis Tool

Built-in reporting:
```bash
honeypot-report docker
```

## 🔒 Security Model

- **Public Services**: Honeypot ports (80, 21, 2222, 5353) - Fully exposed
- **Management SSH**: Port 22 - Tailscale VPN only
- **Kibana**: Port 5601 - Tailscale VPN only  
- **ElasticSearch**: Port 9200 - Internal Docker network only

## 🛠️ Management

```bash
# View status
honeypot-status

# View logs
honeypot-logs docker

# Generate report
honeypot-report docker

# Control service
sudo systemctl restart honeypot
```

## 📊 Example Queries

```bash
# Top attacking IPs
cat events.jsonl | jq -r .source_ip | sort | uniq -c | sort -rn | head -20

# SSH credentials attempted
cat events.jsonl | jq 'select(.event_type=="ssh_login_attempt") | "\(.decoded_payload.username):\(.decoded_payload.password)"'

# HTTP attack types
cat events.jsonl | jq -r 'select(.event_type=="http_attack") | .decoded_payload.attack_types[]' | sort | uniq -c
```

## 📚 Documentation

- **README.md** - This overview (you are here)
- **QUICKSTART.md** - Step-by-step installation guide
- **DEPLOYMENT_GUIDE.md** - Detailed deployment instructions  
- **PROJECT_STRUCTURE.md** - Architecture and code organization

## 🎯 What You'll Capture

After 24 hours of operation, expect to see:

- **Port Scanners**: Mass scanning bots hitting all ports
- **SSH Brute Force**: Thousands of login attempts with common credentials
- **Web Attacks**: SQL injection, XSS, path traversal attempts
- **Vulnerability Scanners**: Automated tools probing for known CVEs
- **Malware Downloads**: wget/curl attempts to download malicious payloads
- **Botnet Activity**: C2 communication and infection attempts

## ⚠️ Important Notes

- This is a **real honeypot** that will attract **real attackers**
- Monitor disk space regularly - logs and samples accumulate quickly
- Captured files may be **malicious** - handle with appropriate precautions
- Review legal requirements for honeypot deployment in your jurisdiction

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional protocol support (SMTP, Telnet, SMB)
- Enhanced detection patterns
- Machine learning integration
- Visualization templates

---

**Happy Hunting! 🎯**

For detailed setup instructions, see `QUICKSTART.md`
