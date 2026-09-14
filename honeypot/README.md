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

### Lossless TCP traffic capture

`tcp_data` events capture the exact bytes returned by application reads and passed
into writes for HTTP (including binary traffic on 8080), FTP, TCP DNS, and the
simplified SSH fallback. `payload_base64` is the authoritative byte representation;
`payload_size` counts those bytes. Existing protocol `payload` fields remain text
previews and must not be used for byte-level analysis. Historical lossy payloads
cannot be repaired by this change.

Each capture includes `session_id`, `direction` (`inbound` / `outbound`),
`source_ip`, `source_port`, `dest_ip`, `dest_port`, and `stream_offset` (separate
zero-based byte offsets in each direction). An incoming connection might be
`192.0.2.2:49804 -> 192.0.2.1:8080`; its response goes
`192.0.2.1:8080 -> 192.0.2.2:49804`. These fields are directional for `tcp_data`;
older protocol events retain their existing conventions. Ports come from the
socket, so NAT/container port translation may hide the original external port.

Outbound `capture_status` is `drained`, `drain_failed`, or `write_buffered`.
Drained means the asyncio drain completed, not that the peer acknowledged or
processed the bytes. Capture does not include TCP headers, ACKs, retransmissions,
or original packet boundaries. AsyncSSH mode uses its own encrypted transport
and is not covered; UDP is not implemented by this DNS service. Use separate
packet capture if those details are required.

The HTTP listener now treats non-HTTP input as a passive binary stream, retaining
subsequent reads until peer EOF, a 30-second idle timeout, or a 1 MiB connection
limit. It sends no speculative binary handshake. HTTP handles one request per connection, with a 10-second initial read timeout.
`tcp_connection_closed` records the HTTP/binary handler's local closure reason.
Silent binary
peers may continue reconnecting because passive capture does not implement their
protocol.

To investigate possible four-byte big-endian length framing, select `tcp_data`
events for one session and direction, sort by `stream_offset`, verify contiguous
offsets, base64-decode and concatenate. Only then examine length prefixes: a TCP
read can split a prefix or contain multiple frames. A stream of 114 bytes could
contain `4 + 23 + 4 + 83`, but that interpretation must match the actual bytes.
Framing, varying entropy, and reconnect timing alone do not prove C2, encryption,
or ephemeral key exchange; no such classification is assigned automatically.

The Elasticsearch template includes the new fields (`payload_base64` as binary).
Apply the updated template as part of your normal deployment before new daily
indices are created; it does not change mappings of existing indices. Capture is
also written to `events.jsonl`. Full capture increases log volume, so account for
it in existing retention and storage settings.

Offline regression checks (no listening sockets or external services):

```sh
python3 -m unittest discover -s honeypot/tests -v
```


### HTTP submissions and script uploads

The listener now reassembles headers and bodies across TCP reads and accepts
`Content-Length`, chunked transfer encoding (including trailers), and
`Expect: 100-continue`. It saves submissions independently of attack detection,
file extension, and content type:

- Full HTTP request evidence and a separate body sample for POST, PUT, PATCH,
  and other methods that carry a body.
- Multipart files of any extension, including `.php`, `.jsp`, `.aspx`, shell
  scripts, archives, and executables, plus multipart text fields and empty files.
- Percent-decoded URL-encoded form values, including duplicate fields.
- Raw JSON, XML, text, binary, and content-encoded bodies. Compressed bodies are
  retained as received, not decompressed; JSON string values are not separately
  interpreted or executed.

Samples continue to use `samples/<sha256>.bin` regardless of original extension:
**a PHP upload is stored as a .bin file containing the PHP bytes**. The companion
JSON records metadata. `http_artifact` events in `events.jsonl` link each sample
hash to the session, source port, request path, capture status, artifact kind,
and original multipart filename/form field where provided. Repeated identical
content shares a sample; its sidecar describes the latest save, while events
retain the individual occurrences. Client filenames are metadata only and never
used as local filesystem paths. A request to `/shell.php` by itself does not
supply the server-side PHP source; only content actually submitted is captured.

Collection is bounded to 64 KiB headers, 10 MiB body, 12 MiB wire data, a
10-second idle read timeout, and 60 seconds total after HTTP classification.
Incomplete, oversized, malformed, and timed-out requests retain collected request
evidence and any assembled body, with a non-`complete` capture status. They are
not treated as complete uploads. Extraction is limited to 256 top-level parts or
form fields; the full captured body remains available beyond that limit. Nested
multipart content is retained in the body but not recursively extracted.
Ambiguous Content-Length/Transfer-Encoding combinations are retained as evidence
without trying to choose an interpretation. Unframed bytes already received are
saved, but HTTP bodies without length or chunked framing are not read to EOF.

These changes require rebuilding the honeypot image from the updated source;
the existing Dockerfile already copies the entire `services/` directory. No
Compose changes or additional Python packages are needed.

### Searchable sample contents: `honeypot-samples`

When Elasticsearch is enabled, saving a sample now also indexes a searchable
text derivative in the separate `honeypot-samples` index. One document is created
per SHA-256 (`_id` equals the hash); repeated captures do not overwrite that
sample document. Its metadata describes the first successful indexing, while
`http_artifact` events continue to describe individual HTTP occurrences. A
backfilled sample uses the available sidecar metadata, which may reflect a later
occurrence. The original `.bin` and JSON files are still saved locally first.

Search `content_text` for PHP source, commands, URLs, or other text. Valid UTF-8
without binary control characters is indexed as text; other data contributes
printable ASCII strings of at least four characters. Only the first 1 MiB of a
sample is examined for text. `extraction_method`, `bytes_examined`, and
`text_truncated` describe this derivative; the SHA-256 and `size` always describe
the full sample. Files are not executed, unpacked, or decompiled. UTF-16 and
compressed/encrypted contents are not decoded. Text searches use Elasticsearch's
standard analyzer, not exact byte or arbitrary substring matching.

The index includes searchable `filename`, `content_type`, `artifact_kind`, and
`capture_status` fields when available, plus the complete supplied `metadata` in
_source (not dynamically indexed). An exact-name template with priority 500
separates its mappings from the older broad `honeypot-*` event template. Setup is
automatic on the first sample write or backfill and requires Elasticsearch
permissions to manage templates/mappings, create the index, and index documents.
If indexing fails, local capture continues; the failure is logged and backfill
can retry it. There is no automatic retry queue. Existing hash documents are
skipped, so backfill does not refresh extraction or metadata for them.

After copying the updated source to `/opt/honeypot`, rebuild there:

```sh
cd /opt/honeypot
docker compose up -d --build honeypot
```

To index existing samples or retry files missed during an Elasticsearch outage:

```sh
docker compose exec honeypot python backfill_samples.py
```

The backfill script is included in the rebuilt image. It uses the configured
Elasticsearch hosts and output directory; optional arguments are `--config`,
`--samples-dir`, and `--host`. It streams files to verify their SHA-256 filenames,
keeps only the text extraction prefix in memory, reports indexed/existing/failed
counts, and exits nonzero on failures. Missing sidecars are allowed; malformed
sidecars or hash mismatches are reported as failures. Backfill does not modify
local files or start the honeypot.

In Kibana, create a separate data view named `honeypot-samples`, using
`indexed_at` as its time field (or no time filter to see all samples). For event
views use `honeypot-20*`; the old `honeypot-*` pattern also matches the new samples
index and would mix samples with connection events.

Example in Kibana Dev Tools:

```json
GET honeypot-samples/_search
{
  "query": {"match": {"content_text": "base64_decode"}},
  "_source": ["sha256", "filename", "content_text", "extraction_method", "text_truncated", "metadata"]
}
```

An Elasticsearch result's `sha256` identifies the original
`honeypot_data/samples/<sha256>.bin` file. Sample-index retention is independent of
daily event-index retention; no deletion/expiry policy is installed by this code.
