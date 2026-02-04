# Honeypot Project Structure

```
honeypot/
│
├── README.md                    # Main documentation
├── DEPLOYMENT_GUIDE.md          # Deployment instructions
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Container build file
├── docker-compose.yml           # Multi-container orchestration
├── deploy.sh                    # Quick deployment script
│
├── honeypot.py                  # Main entry point
├── analyze_telemetry.py         # Telemetry analysis tool
├── test_honeypot.py             # Service testing script
├── setup_elasticsearch.py       # ES configuration tool
│
├── core/                        # Core framework
│   ├── __init__.py
│   └── honeypot_manager.py      # Service orchestration
│                                # Telemetry collection
│                                # Session management
│
├── services/                    # Protocol implementations
│   ├── __init__.py
│   ├── http_service.py          # HTTP/HTTPS honeypot
│   ├── ssh_service.py           # SSH honeypot
│   ├── ftp_service.py           # FTP honeypot
│   └── dns_service.py           # DNS honeypot
│
└── honeypot_data/               # Runtime data (created on first run)
    ├── events.jsonl             # Event log
    ├── samples/                 # Captured files
    │   ├── <sha256>.bin         # Sample binary
    │   └── <sha256>.json        # Sample metadata
    └── pcap/                    # Packet captures (future)
```

## File Descriptions

### Configuration & Deployment

- **honeypot_config.json**: Main configuration file (auto-generated)
  - Service enable/disable flags
  - Port configurations
  - ElasticSearch settings
  - Detection rules

- **docker-compose.yml**: Docker orchestration
  - Honeypot container
  - ElasticSearch container (optional)
  - Kibana container (optional)
  - Network configuration
  - Volume mounts

- **Dockerfile**: Container image definition
  - Python 3.11 base
  - System dependencies
  - Security hardening
  - Non-root user

### Core Framework

- **core/honeypot_manager.py**: Main orchestration
  - `HoneypotManager`: Service lifecycle management
  - `TelemetryCollector`: Event logging and storage
  - `HoneypotService`: Base class for all services
  - Session tracking
  - Sample collection

### Service Implementations

- **services/http_service.py**: Web server emulation
  - `HTTPHoneypot`: Main service class
  - `HTTPRequest`: Request parser
  - Attack pattern detection:
    - SQL injection
    - XSS
    - Path traversal
    - Command injection
  - Response generation
  - File upload capture

- **services/ssh_service.py**: SSH emulation
  - `SSHHoneypot`: Main service class
  - Credential capture
  - Shell simulation
  - Command logging
  - Download attempt detection

- **services/ftp_service.py**: FTP server emulation
  - `FTPHoneypot`: Main service class
  - Authentication logging
  - File transfer monitoring
  - Directory listing emulation

- **services/dns_service.py**: DNS server
  - `DNSHoneypot`: Main service class
  - `DNSQuery`: Query parser
  - DGA detection
  - C2 beaconing detection
  - Subdomain tunneling detection

### Analysis Tools

- **analyze_telemetry.py**: Data analysis
  - `TelemetryAnalyzer`: Main analyzer class
  - Summary statistics
  - Attack pattern analysis
  - Credential extraction
  - Scanner detection
  - Report generation

- **test_honeypot.py**: Service testing
  - `HoneypotTester`: Test harness
  - HTTP testing
  - SSH testing
  - FTP testing
  - DNS testing

- **setup_elasticsearch.py**: ES configuration
  - Index template creation
  - Sample queries
  - Kibana setup guide

### Scripts

- **deploy.sh**: Quick deployment
  - Docker image build
  - Service startup
  - Health checks
  - Log tailing

- **honeypot.py**: Main entry
  - Service initialization
  - Signal handling
  - Status display
  - Configuration management

## Data Flow

```
Internet Traffic
       ↓
[Service Handlers]
       ↓
[Protocol Parsing]
       ↓
[Attack Detection]
       ↓
[Telemetry Collection]
       ↓
  ┌────┴────┐
  ↓         ↓
[JSON Log] [ElasticSearch]
  ↓         ↓
[Analysis] [Kibana]
```

## Event Schema

Each event captured contains:

```json
{
  "timestamp": "ISO-8601 datetime",
  "event_type": "service_event_type",
  "source_ip": "attacker IP",
  "source_port": "attacker port",
  "dest_port": "service port",
  "protocol": "http|ssh|ftp|dns",
  "service": "Service Name",
  "session_id": "unique session ID",
  "payload": "raw data (truncated)",
  "payload_size": "bytes",
  "decoded_payload": {
    // Protocol-specific parsed data
  },
  "headers": {
    // HTTP headers, etc.
  }
}
```

## Extension Points

### Adding New Services

1. Create `services/yourservice_service.py`
2. Implement `YourServiceHoneypot(HoneypotService)`
3. Define `handle_client()` method
4. Add to `honeypot.py` initialization
5. Add config section to `honeypot_config.json`

### Custom Detection

1. Add patterns to service files
2. Update `has_exploit_patterns()` or equivalent
3. Create new event types as needed
4. Update telemetry schema

### Telemetry Enrichment

1. Extend `TelemetryCollector` class
2. Add enrichment in `log_event()` method
3. Update ElasticSearch mappings
4. Modify Kibana visualizations

## Dependencies

### Required
- Python 3.11+
- asyncio (built-in)
- pathlib (built-in)
- json (built-in)

### Optional
- elasticsearch >= 8.0.0 (for ES integration)
- pandas >= 2.0.0 (for advanced analysis)
- matplotlib >= 3.7.0 (for visualization)
- geoip2 >= 4.7.0 (for geolocation)
- yara-python >= 4.3.0 (for malware scanning)

### Docker
- Docker Engine 20.10+
- Docker Compose 2.0+

## Port Mapping

Default configuration:

| Service | Internal | External | Protocol |
|---------|----------|----------|----------|
| HTTP    | 8080     | 80       | TCP      |
| SSH     | 2222     | 22       | TCP      |
| FTP     | 2121     | 21       | TCP      |
| DNS     | 5353     | 53       | TCP/UDP  |

## Storage Requirements

Typical daily storage (moderate traffic):

- events.jsonl: ~50-100 MB
- samples/: ~10-50 MB
- logs: ~10 MB

Recommendations:
- 10 GB minimum for honeypot_data/
- 50 GB for 30 days retention
- ElasticSearch: 100 GB+ for long-term storage

## Performance

Expected performance on modest hardware:

| Metric | Value |
|--------|-------|
| Concurrent connections | 100+ |
| Events/second | 50+ |
| Memory usage | 50-200 MB |
| CPU usage (idle) | <5% |
| CPU usage (load) | 10-30% |

Scalability:
- Single instance: ~1000 req/sec
- Multiple instances: Linear scaling
- ElasticSearch: Shard-based scaling

## Security Notes

1. **Isolation**: Run in isolated network segment
2. **Monitoring**: Alert on anomalous behavior
3. **Updates**: Regular security updates
4. **Access**: Restrict management access
5. **Logging**: Out-of-band log collection
6. **Backup**: Regular data backups
7. **Legal**: Ensure legal compliance

## Development

### Testing

```bash
# Run tests
python test_honeypot.py

# Check code style
black .

# Type checking
mypy .
```

### Debugging

```bash
# Enable debug logging
# Edit honeypot_manager.py:
logging.basicConfig(level=logging.DEBUG)

# Monitor events
tail -f honeypot_data/events.jsonl | jq .

# Check ElasticSearch
curl localhost:9200/honeypot-*/_search?pretty
```

### Contributing

Common improvements:
- Additional service implementations
- Enhanced detection patterns
- Performance optimizations
- Documentation updates
- Test coverage

## Version History

- v1.0: Initial release
  - HTTP, SSH, FTP, DNS services
  - Basic telemetry collection
  - ElasticSearch integration
  - Docker deployment

## License

Designed for security research and education.
Use only in authorized, isolated environments.

## Credits

Inspired by:
- INetSim (simulation framework)
- Cowrie (SSH/Telnet honeypot)
- T-Pot (multi-honeypot platform)
- Modern Honey Network (management platform)
