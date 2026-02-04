# INetSim-Style Honeypot with Telemetry

A comprehensive honeypot framework inspired by INetSim, designed for malware analysis and threat intelligence gathering with deep telemetry collection.

## Features

### Multi-Protocol Support
- **HTTP/HTTPS**: Web server emulation with exploit detection
- **SSH**: Credential harvesting and command logging
- **FTP**: File transfer monitoring
- **DNS**: Query logging, DGA detection, C2 beaconing analysis

### Telemetry Collection
- **Event Logging**: JSON-formatted events with full context
- **Session Tracking**: Per-connection session management
- **Sample Collection**: Automatic capture of uploaded/downloaded files
- **ElasticSearch Integration**: Optional real-time indexing
- **PCAP Support**: Network traffic capture (planned)

### Attack Detection
- SQL Injection patterns
- XSS attempts
- Path traversal
- Command injection
- File upload monitoring
- DGA domain detection
- C2 beaconing patterns
- Scanner fingerprinting

## Architecture

```
honeypot/
├── core/
│   └── honeypot_manager.py    # Main orchestration framework
├── services/
│   ├── http_service.py        # HTTP/HTTPS honeypot
│   ├── ssh_service.py         # SSH honeypot
│   ├── ftp_service.py         # FTP honeypot
│   └── dns_service.py         # DNS honeypot
├── honeypot.py                # Main entry point
├── analyze_telemetry.py       # Analysis tool
└── honeypot_config.json       # Configuration
```

## Quick Start

### Installation

```bash
# Clone or download the honeypot
cd honeypot

# Install dependencies
pip install elasticsearch  # Optional, for ES integration

# Run honeypot
python honeypot.py
```

### First Run

On first run, a default configuration will be created:

```json
{
  "output_dir": "./honeypot_data",
  "services": {
    "http": {"enabled": true, "port": 8080},
    "ssh": {"enabled": true, "port": 2222},
    "ftp": {"enabled": true, "port": 2121},
    "dns": {"enabled": true, "port": 5353}
  },
  "elasticsearch": {
    "enabled": false,
    "hosts": ["localhost:9200"]
  }
}
```

**Note**: Ports 8080, 2222, 2121, 5353 are used by default to avoid requiring root. For production deployment on standard ports, use Docker or iptables port forwarding.

### Running Services

```bash
# Standard execution
python honeypot.py

# View logs
tail -f honeypot.log

# Analyze data
python analyze_telemetry.py ./honeypot_data --hours 24
```

## Configuration

### Service Configuration

Each service can be enabled/disabled and configured independently:

```json
"services": {
  "http": {
    "enabled": true,
    "port": 8080
  },
  "ssh": {
    "enabled": true,
    "port": 2222
  }
}
```

### ElasticSearch Integration

Enable for real-time indexing and Kibana visualization:

```json
"elasticsearch": {
  "enabled": true,
  "hosts": ["localhost:9200"],
  "index_prefix": "honeypot"
}
```

Indices are created daily: `honeypot-2024.01.15`

## Telemetry Schema

### Event Structure

All events follow this base schema:

```json
{
  "timestamp": "2024-01-15T10:30:45.123456",
  "event_type": "http_request",
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "dest_port": 8080,
  "protocol": "http",
  "service": "HTTP",
  "session_id": "abc123def456",
  "payload": "GET / HTTP/1.1...",
  "payload_size": 1024,
  "decoded_payload": {
    "method": "GET",
    "path": "/admin/login.php",
    "headers": {...}
  }
}
```

### Event Types

- `http_request` - HTTP request received
- `http_attack` - Detected attack pattern
- `ssh_connection` - SSH connection attempt
- `ssh_login_attempt` - Credential submission
- `ssh_command` - Command executed in shell
- `ftp_login_attempt` - FTP authentication
- `ftp_upload` - File uploaded
- `dns_query` - DNS query received
- `dns_suspicious` - Suspicious DNS pattern

## Analysis

### Generate Reports

```bash
# Analyze last 24 hours
python analyze_telemetry.py ./honeypot_data

# Custom time range
python analyze_telemetry.py ./honeypot_data --hours 168  # 1 week

# Save report to file
python analyze_telemetry.py ./honeypot_data --output report.txt
```

### Report Contents

- **Summary Statistics**: Total events, sessions, unique IPs
- **Protocol Breakdown**: Events per protocol
- **Attack Analysis**: Attack types and frequencies
- **Top Attackers**: Most active source IPs
- **Login Attempts**: Captured credentials
- **Scanner Detection**: Port scanning behavior
- **DNS Analysis**: Query patterns, suspicious domains
- **Malware Samples**: Captured file information

### Sample Output

```
======================================================================
HONEYPOT TELEMETRY ANALYSIS REPORT
======================================================================
Generated: 2024-01-15T10:30:00.000000
Data Directory: ./honeypot_data

SUMMARY
----------------------------------------------------------------------
Total Events:      15,432
Unique Sessions:   3,821
Unique Source IPs: 1,247
Samples Captured:  23

TOP ATTACKERS
----------------------------------------------------------------------
 1. 203.0.113.45   - Events: 1,247, Attacks: 89, Logins: 156
 2. 198.51.100.22  - Events:   834, Attacks: 45, Logins: 201
```

## Integration with Your Workflow

### ElasticSearch + Kibana

1. Start ElasticSearch and Kibana
2. Enable ES in config
3. Create Kibana dashboards for:
   - Attack timeline
   - Geographic IP distribution
   - Attack type breakdown
   - Top targeted services

### YARA Scanning

Integrate with your existing YARA workflow:

```python
import yara
from pathlib import Path

rules = yara.compile(filepath='malware_rules.yar')

samples_dir = Path('./honeypot_data/samples')
for sample in samples_dir.glob('*.bin'):
    matches = rules.match(str(sample))
    if matches:
        print(f"[ALERT] {sample.name}: {matches}")
```

### IDA Pro / Ghidra Automation

Auto-analyze captured samples:

```python
import subprocess

samples_dir = Path('./honeypot_data/samples')
for sample in samples_dir.glob('*.bin'):
    # IDA Pro headless analysis
    subprocess.run([
        'idat64',
        '-A',
        '-S/path/to/analysis_script.py',
        str(sample)
    ])
```

### Malware Feed Integration

Forward captured samples to your existing pipeline:

```python
from pathlib import Path
import shutil

# Copy new samples to your analysis queue
samples_dir = Path('./honeypot_data/samples')
analysis_queue = Path('/your/malware/pipeline/queue')

for sample in samples_dir.glob('*.bin'):
    if not (analysis_queue / sample.name).exists():
        shutil.copy(sample, analysis_queue)
```

## Security Considerations

### Isolation

**CRITICAL**: Always run honeypots in isolated environments:

- Dedicated VM or container
- Separate network segment (VLAN)
- Strict firewall rules
- No access to internal networks

### Network Segmentation

```
Internet → Firewall → [Honeypot Network] → Honeypot
                               ↓
                        Logging Server (out-of-band)
```

### Port Forwarding (Production)

To use standard ports without root:

```bash
# iptables forwarding
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
```

### Log Management

Honeypots generate large volumes of data:

```bash
# Rotate logs
logrotate /etc/logrotate.d/honeypot

# Compress old events
gzip honeypot_data/events.jsonl.old

# Archive samples older than 30 days
find honeypot_data/samples -mtime +30 -exec gzip {} \;
```

## Extending the Honeypot

### Adding New Services

1. Create new service class inheriting from `HoneypotService`
2. Implement `handle_client()` method
3. Register in `honeypot.py`

Example SMTP honeypot skeleton:

```python
class SMTPHoneypot(HoneypotService):
    def __init__(self, port: int, telemetry):
        super().__init__("SMTP", port, telemetry)
    
    async def handle_client(self, reader, writer):
        # Send banner
        writer.write(b"220 mail.example.com ESMTP\r\n")
        await writer.drain()
        
        # Process SMTP commands
        while True:
            data = await reader.readline()
            command = data.decode().strip()
            # ... handle HELO, MAIL FROM, RCPT TO, DATA, etc.
```

### Custom Detection Rules

Add to `http_service.py`:

```python
def has_exploit_patterns(self) -> Dict[str, bool]:
    combined = f"{self.path} {self.body}".lower()
    patterns = {
        'log4shell': bool(re.search(r'\$\{jndi:', combined)),
        'shellshock': bool(re.search(r'\(\)\s*\{', combined)),
        # Add your custom patterns
    }
    return {k: v for k, v in patterns.items() if v}
```

## Troubleshooting

### Services Won't Start

```bash
# Check if ports are in use
netstat -tulpn | grep -E '8080|2222|2121|5353'

# Check permissions
ls -la honeypot_data/

# Check logs
tail -f honeypot.log
```

### ElasticSearch Connection Failed

```bash
# Verify ES is running
curl localhost:9200

# Check ES logs
tail -f /var/log/elasticsearch/elasticsearch.log

# Install ES Python client
pip install elasticsearch
```

### No Events Being Logged

1. Check file permissions on `honeypot_data/`
2. Verify services started successfully in logs
3. Test connectivity: `telnet localhost 8080`
4. Check firewall rules

## Performance

### Resource Usage

Typical resource consumption:
- **Memory**: 50-200 MB (depending on traffic)
- **CPU**: <5% (idle), up to 30% under heavy attack
- **Disk**: ~100 MB/day (varies with traffic)

### Scaling

For high-traffic environments:

1. **Increase connection limits**:
   ```python
   server = await asyncio.start_server(
       self.handle_client,
       '0.0.0.0',
       self.port,
       backlog=1000  # Increase from default 100
   )
   ```

2. **Implement rate limiting**:
   ```python
   # Track connections per IP
   self.rate_limits[source_ip] = time.time()
   ```

3. **Use multiple instances** behind load balancer

## Future Enhancements

- [ ] SMTP honeypot
- [ ] Telnet honeypot
- [ ] SMB/CIFS honeypot
- [ ] PCAP capture integration
- [ ] GeoIP enrichment
- [ ] Automated threat intel sharing (MISP, STIX)
- [ ] Machine learning for anomaly detection
- [ ] Grafana dashboard templates
- [ ] Docker Compose deployment
- [ ] Kubernetes manifests

## Contributing

This is a framework designed for customization. Common additions:

- Additional service emulations
- New exploit detection patterns
- Custom telemetry enrichment
- Integration with your toolchain

## License

Designed for security research and education. Use responsibly in controlled environments only.

## References

- INetSim: https://www.inetsim.org/
- Cowrie SSH Honeypot: https://github.com/cowrie/cowrie
- Modern Honey Network: https://github.com/pwnlandia/mhn
- T-Pot: https://github.com/telekom-security/tpotce

## Support

For issues or questions, refer to:
- Honeypot logs: `honeypot.log`
- Event data: `honeypot_data/events.jsonl`
- Sample analysis: `analyze_telemetry.py`
