# Honeypot Deployment Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     INetSim-Style Honeypot                      │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │   HTTP   │  │   SSH    │  │   FTP    │  │   DNS    │      │
│  │  :8080   │  │  :2222   │  │  :2121   │  │  :5353   │      │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘      │
│        │             │              │             │            │
│        └─────────────┴──────────────┴─────────────┘            │
│                           │                                    │
│                 ┌─────────▼─────────┐                         │
│                 │ Telemetry Engine  │                         │
│                 │  - Event Logger   │                         │
│                 │  - ES Indexer     │                         │
│                 │  - File Capture   │                         │
│                 └─────────┬─────────┘                         │
│                           │                                    │
└───────────────────────────┼────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
        ┌───────▼────────┐      ┌──────▼────────┐
        │ ElasticSearch  │      │  File System  │
        │  (Optional)    │      │               │
        └───────┬────────┘      │ events.jsonl  │
                │               │ samples/      │
        ┌───────▼────────┐      │ pcap/         │
        │     Kibana     │      └───────────────┘
        │ Visualization  │
        └────────────────┘
```

## Quick Start (Docker - Recommended)

### 1. Clone/Download Files

```bash
# Ensure you have all files in place
ls -la
# Should see: honeypot.py, docker-compose.yml, Dockerfile, etc.
```

### 2. Deploy with Docker

```bash
# Make deploy script executable
chmod +x deploy.sh

# Deploy everything
./deploy.sh
```

This will:
- Create default configuration
- Build Docker images
- Start all services
- Launch ElasticSearch and Kibana

### 3. Verify Services

```bash
# Check running containers
docker-compose ps

# View logs
docker-compose logs -f honeypot

# Test services
python test_honeypot.py
```

### 4. Access Interfaces

- **Honeypot HTTP**: http://localhost:80
- **ElasticSearch**: http://localhost:9200
- **Kibana**: http://localhost:5601

## Manual Deployment (No Docker)

### 1. Install Dependencies

```bash
# Python 3.11+
python3 --version

# Install packages
pip install -r requirements.txt

# Optional: ElasticSearch
# Download from https://www.elastic.co/downloads/elasticsearch
```

### 2. Configure Honeypot

```bash
# First run creates default config
python honeypot.py

# Edit configuration
nano honeypot_config.json
```

### 3. Run Honeypot

```bash
# Standard run
python honeypot.py

# Background process
nohup python honeypot.py > honeypot.log 2>&1 &
```

### 4. Monitor and Analyze

```bash
# Watch events in real-time
tail -f honeypot_data/events.jsonl

# Generate report
python analyze_telemetry.py ./honeypot_data

# View specific time range
python analyze_telemetry.py ./honeypot_data --hours 168  # 1 week
```

## Production Deployment

### Network Configuration

For production, use standard ports with port forwarding:

```bash
# iptables rules (requires root)
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
sudo iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5353

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### Security Isolation

**CRITICAL**: Always isolate honeypots:

```bash
# Example network setup
# 1. Create isolated VLAN/subnet
# 2. Place honeypot in DMZ
# 3. No access to internal networks
# 4. Out-of-band logging to separate server
```

### Systemd Service

Create `/etc/systemd/system/honeypot.service`:

```ini
[Unit]
Description=INetSim Honeypot
After=network.target

[Service]
Type=simple
User=honeypot
WorkingDirectory=/opt/honeypot
ExecStart=/usr/bin/python3 /opt/honeypot/honeypot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable honeypot
sudo systemctl start honeypot
sudo systemctl status honeypot
```

## ElasticSearch Setup

### 1. Start ElasticSearch

```bash
# With Docker
docker-compose up -d elasticsearch kibana

# Manual install
sudo systemctl start elasticsearch
sudo systemctl start kibana
```

### 2. Configure Honeypot

Edit `honeypot_config.json`:

```json
{
  "elasticsearch": {
    "enabled": true,
    "hosts": ["localhost:9200"],
    "index_prefix": "honeypot"
  }
}
```

### 3. Setup Index Template

```bash
python setup_elasticsearch.py
```

### 4. Create Kibana Dashboards

1. Open Kibana: http://localhost:5601
2. Management → Index Patterns
3. Create pattern: `honeypot-*`
4. Set `timestamp` as time field

Sample visualizations:
- **Line chart**: Events over time
- **Pie chart**: Protocols distribution
- **Table**: Top attacking IPs
- **Bar chart**: Attack types
- **Map**: Geographic distribution (with GeoIP)

## Integration Examples

### With Your Malware Analysis Pipeline

```python
#!/usr/bin/env python3
"""
Integrate honeypot samples with existing pipeline
"""
from pathlib import Path
import shutil
import hashlib

# Monitor honeypot samples
samples_dir = Path('./honeypot_data/samples')
pipeline_queue = Path('/your/malware/pipeline/queue')

# Process new samples
for sample in samples_dir.glob('*.bin'):
    # Check if already processed
    sha256 = sample.stem
    
    if not (pipeline_queue / sample.name).exists():
        # Copy to pipeline
        shutil.copy(sample, pipeline_queue)
        
        # Copy metadata
        meta_file = sample.with_suffix('.json')
        if meta_file.exists():
            shutil.copy(meta_file, pipeline_queue)
        
        print(f"[+] Queued: {sha256}")
```

### With IDA Pro

```python
#!/usr/bin/env python3
"""
Auto-analyze honeypot samples with IDA Pro
"""
import subprocess
from pathlib import Path

samples_dir = Path('./honeypot_data/samples')
ida_script = Path('./ida_analysis.py')

for sample in samples_dir.glob('*.bin'):
    output = sample.with_suffix('.idb')
    
    if not output.exists():
        print(f"[*] Analyzing {sample.name}...")
        subprocess.run([
            'idat64',
            '-A',  # Auto-analysis
            f'-S{ida_script}',
            str(sample)
        ])
```

### With YARA

```python
#!/usr/bin/env python3
"""
Scan honeypot samples with YARA
"""
import yara
from pathlib import Path

rules = yara.compile(filepath='malware_rules.yar')
samples_dir = Path('./honeypot_data/samples')

for sample in samples_dir.glob('*.bin'):
    matches = rules.match(str(sample))
    
    if matches:
        print(f"[ALERT] {sample.name}")
        for match in matches:
            print(f"  - Rule: {match.rule}")
            print(f"  - Tags: {match.tags}")
```

## Monitoring and Maintenance

### Log Rotation

```bash
# Configure logrotate
cat > /etc/logrotate.d/honeypot << EOF
/opt/honeypot/honeypot.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

### Data Archival

```bash
# Archive old samples (30 days)
find honeypot_data/samples -type f -mtime +30 -exec gzip {} \;

# Archive to remote storage
rsync -avz honeypot_data/ backup-server:/honeypot-archive/
```

### Performance Monitoring

```bash
# Container stats
docker stats honeypot

# Resource usage
top -p $(pgrep -f honeypot.py)

# Disk usage
du -sh honeypot_data/
```

## Troubleshooting

### Services Won't Start

```bash
# Check port availability
netstat -tulpn | grep -E '8080|2222|2121|5353'

# Check logs
docker-compose logs honeypot
# or
tail -f honeypot.log

# Check permissions
ls -la honeypot_data/
chmod -R 755 honeypot_data/
```

### No Telemetry Being Captured

1. Verify services started:
   ```bash
   docker-compose ps
   ```

2. Test connectivity:
   ```bash
   python test_honeypot.py
   ```

3. Check events file:
   ```bash
   ls -lh honeypot_data/events.jsonl
   tail honeypot_data/events.jsonl
   ```

### ElasticSearch Issues

```bash
# Check ES status
curl localhost:9200/_cluster/health?pretty

# View indices
curl localhost:9200/_cat/indices?v

# Check honeypot indices
curl localhost:9200/honeypot-*/_count

# Delete old indices (if needed)
curl -X DELETE localhost:9200/honeypot-2024.01.01
```

### High Memory Usage

```bash
# Limit ES memory in docker-compose.yml
environment:
  - "ES_JAVA_OPTS=-Xms512m -Xmx512m"

# Rotate events.jsonl more frequently
mv honeypot_data/events.jsonl honeypot_data/events.jsonl.old
gzip honeypot_data/events.jsonl.old
```

## Customization

### Adding New Services

1. Create service in `services/`:

```python
# services/telnet_service.py
from honeypot_manager import HoneypotService

class TelnetHoneypot(HoneypotService):
    def __init__(self, port: int, telemetry):
        super().__init__("Telnet", port, telemetry)
    
    async def handle_client(self, reader, writer):
        # Implement telnet emulation
        pass
```

2. Register in `honeypot.py`:

```python
from telnet_service import TelnetHoneypot

# In initialize_services():
if config['services']['telnet']['enabled']:
    telnet = TelnetHoneypot(
        port=config['services']['telnet']['port'],
        telemetry=telemetry
    )
    self.manager.register_service(telnet)
```

### Custom Detection Rules

Add to service files:

```python
# In http_service.py
def has_exploit_patterns(self) -> Dict[str, bool]:
    combined = f"{self.path} {self.body}".lower()
    
    patterns = {
        'log4shell': bool(re.search(r'\$\{jndi:', combined)),
        'your_pattern': bool(re.search(r'pattern', combined)),
    }
    
    return {k: v for k, v in patterns.items() if v}
```

## Best Practices

1. **Isolation**: Never connect honeypot to production networks
2. **Monitoring**: Set up alerts for interesting activity
3. **Updates**: Keep honeypot code and Docker images updated
4. **Backup**: Regular backups of telemetry data
5. **Legal**: Ensure compliance with local laws
6. **Documentation**: Log all configuration changes
7. **Testing**: Regularly test services with test_honeypot.py

## Support and Contribution

- Check logs: `honeypot.log`
- Analyze data: `python analyze_telemetry.py`
- Test services: `python test_honeypot.py`
- View README: `README.md`

## References

- INetSim: https://www.inetsim.org/
- ElasticSearch: https://www.elastic.co/
- Docker: https://docs.docker.com/
- Python asyncio: https://docs.python.org/3/library/asyncio.html
