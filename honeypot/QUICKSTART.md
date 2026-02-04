# Quick Start Installation Guide

## One-Command Install

### Option 1: Docker Installation (Recommended)

```bash
# Download honeypot.tar.gz to your server, then:
sudo bash install.sh docker
```

### Option 2: Native Python Installation

```bash
# Download honeypot.tar.gz to your server, then:
sudo bash install.sh native
```

## What the Installer Does

The automated installer will:

1. ✅ Check system compatibility
2. ✅ Install required dependencies
3. ✅ Detect SSH port conflicts and offer to fix
4. ✅ Setup honeypot services
5. ✅ Configure firewall (UFW)
6. ✅ Create systemd service (auto-start on boot)
7. ✅ Setup log rotation
8. ✅ Create helper commands
9. ✅ Start the honeypot
10. ✅ Run basic tests

## Installation Steps

### 1. Prepare Your Server

```bash
# SSH into your Ubuntu server
ssh user@your-server-ip

# Update system (recommended)
sudo apt update && sudo apt upgrade -y
```

### 2. Upload Honeypot Files

**Method A: SCP (from your local machine)**
```bash
scp honeypot.tar.gz user@your-server-ip:/tmp/
```

**Method B: wget (if hosted somewhere)**
```bash
cd /tmp
wget https://your-hosting/honeypot.tar.gz
```

**Method C: Direct from local directory**
```bash
# If you already have the files on the server
cp honeypot.tar.gz /tmp/
```

### 3. Run Installer

```bash
# SSH into your server
ssh user@your-server-ip

# Make installer executable
chmod +x install.sh

# Run installer
sudo bash install.sh docker  # or 'native'
```

### 4. Follow Prompts

The installer will ask you:

**SSH Port Conflict:**
```
Would you like to change your SSH port to 2222 now? (y/n)
```
- Choose `y` to automatically move SSH to port 2222
- Choose `n` to configure manually later

**Kibana Access:**
```
Allow external access to Kibana (port 5601)? (y/n)
```
- Choose `y` if you want to access dashboards from outside
- Choose `n` for local-only access

### 5. Verify Installation

The installer will automatically run tests. You should see:

```
======================================
Test Summary
======================================
HTTP      : 5/5 tests passed
SSH       : 2/2 tests passed
FTP       : 1/1 tests passed
DNS       : 1/1 tests passed
======================================
```

## Post-Installation

### Management Commands

The installer creates convenient commands:

```bash
# View status and recent events
honeypot-status

# Generate analysis report
honeypot-report docker  # or 'native'

# View live logs
honeypot-logs docker    # or 'native'
```

### Systemd Service

```bash
# Start honeypot
sudo systemctl start honeypot

# Stop honeypot
sudo systemctl stop honeypot

# Restart honeypot
sudo systemctl restart honeypot

# View status
sudo systemctl status honeypot

# Disable auto-start
sudo systemctl disable honeypot
```

### View Events

```bash
# Watch events in real-time
tail -f /opt/honeypot/honeypot_data/events.jsonl

# Pretty print with jq
tail -f /opt/honeypot/honeypot_data/events.jsonl | jq .

# Count events by type
cat /opt/honeypot/honeypot_data/events.jsonl | jq -r .event_type | sort | uniq -c
```

### Access Interfaces

**Kibana Dashboard** (if installed):
```
http://YOUR_SERVER_IP:5601
```

1. Go to Management → Stack Management → Index Patterns
2. Create pattern: `honeypot-*`
3. Set time field: `timestamp`
4. Go to Discover to see events

**ElasticSearch** (Docker only):
```
http://YOUR_SERVER_IP:9200
```

## Customization

### Edit Configuration

```bash
# Docker deployment
sudo nano /opt/honeypot/honeypot_config.json
sudo systemctl restart honeypot

# Native deployment
sudo nano /opt/honeypot/honeypot_config.json
sudo systemctl restart honeypot
```

### Change Ports

Edit `/opt/honeypot/honeypot_config.json`:

```json
{
  "services": {
    "http": {
      "enabled": true,
      "port": 8080
    }
  }
}
```

Then restart:
```bash
sudo systemctl restart honeypot
```

### Enable/Disable Services

Edit configuration and set `"enabled": false`:

```json
{
  "services": {
    "ssh": {
      "enabled": false,
      "port": 22
    }
  }
}
```

## Troubleshooting

### Installer Fails

```bash
# Check installer output
sudo bash install.sh docker 2>&1 | tee install.log

# Common issues:
# - honeypot.tar.gz not found → Place in /tmp or current directory
# - Port conflicts → Change SSH port or run on different ports
# - Permission issues → Run with sudo
```

### Honeypot Won't Start

```bash
# Check logs
sudo journalctl -u honeypot -n 50

# For Docker
cd /opt/honeypot
sudo docker-compose logs honeypot

# Check port conflicts
sudo netstat -tulpn | grep -E ':80|:22|:21|:53'
```

### No Events Logging

```bash
# Check file permissions
ls -la /opt/honeypot/honeypot_data/

# Check if services are listening
sudo netstat -tulpn | grep python
# or
sudo docker ps

# Test connectivity
curl http://localhost
```

### Docker Issues

```bash
# Check Docker status
sudo systemctl status docker

# View all containers
sudo docker ps -a

# Restart Docker
sudo systemctl restart docker
sudo systemctl restart honeypot
```

### Firewall Issues

```bash
# Check firewall status
sudo ufw status verbose

# Allow specific port
sudo ufw allow 80/tcp

# Disable temporarily (DANGEROUS)
sudo ufw disable

# Re-enable
sudo ufw enable
```

## Uninstallation

### Docker Deployment

```bash
# Stop services
sudo systemctl stop honeypot
sudo systemctl disable honeypot

# Remove containers
cd /opt/honeypot
sudo docker-compose down -v

# Remove files
sudo rm -rf /opt/honeypot
sudo rm /etc/systemd/system/honeypot.service
sudo rm /usr/local/bin/honeypot-*

# Reload systemd
sudo systemctl daemon-reload
```

### Native Deployment

```bash
# Stop service
sudo systemctl stop honeypot
sudo systemctl disable honeypot

# Remove files
sudo rm -rf /opt/honeypot
sudo rm /etc/systemd/system/honeypot.service
sudo rm /usr/local/bin/honeypot-*

# Remove user
sudo userdel -r honeypot

# Reload systemd
sudo systemctl daemon-reload
```

## Security Checklist

After installation, ensure:

- [ ] SSH moved to non-standard port (e.g., 2222)
- [ ] SSH key authentication enabled
- [ ] Password authentication disabled (SSH)
- [ ] Firewall (UFW) enabled
- [ ] Only necessary ports open
- [ ] Regular backups configured
- [ ] Log rotation enabled
- [ ] System updates scheduled

## Monitoring

### Daily Checks

```bash
# Generate report
honeypot-report docker

# Check disk usage
df -h
du -sh /opt/honeypot/honeypot_data/*

# Review top attackers
cat /opt/honeypot/honeypot_data/events.jsonl | \
  jq -r .source_ip | sort | uniq -c | sort -rn | head -10
```

### Weekly Tasks

```bash
# Archive old events
cd /opt/honeypot/honeypot_data
gzip events.jsonl.1 events.jsonl.2

# Backup samples
tar -czf samples-backup-$(date +%Y%m%d).tar.gz samples/

# Review and clean old data
find samples/ -type f -mtime +30 -ls
```

## Performance Tuning

### Increase File Descriptors

```bash
sudo nano /etc/security/limits.conf
```

Add:
```
* soft nofile 65536
* hard nofile 65536
```

### Optimize ElasticSearch (Docker)

Edit `/opt/honeypot/docker-compose.yml`:

```yaml
elasticsearch:
  environment:
    - "ES_JAVA_OPTS=-Xms2g -Xmx2g"  # Adjust based on RAM
```

## Getting Help

### Log Locations

- **Honeypot logs**: `/opt/honeypot/honeypot.log`
- **Event data**: `/opt/honeypot/honeypot_data/events.jsonl`
- **Systemd logs**: `journalctl -u honeypot`
- **Docker logs**: `docker-compose logs honeypot`

### Diagnostic Information

```bash
# System info
uname -a
lsb_release -a

# Honeypot status
honeypot-status

# Service status
sudo systemctl status honeypot

# Network status
sudo netstat -tulpn

# Disk space
df -h
```

## Support

- Check documentation: README.md, DEPLOYMENT_GUIDE.md
- Review logs: `honeypot-logs docker`
- Generate report: `honeypot-report docker`
- Test services: `python test_honeypot.py`

## What's Next?

1. **Monitor for 24 hours** - Let it collect data
2. **Generate your first report** - `honeypot-report docker`
3. **Setup Kibana dashboards** - Visualize the data
4. **Integrate with your tools** - YARA, IDA, Ghidra
5. **Customize detection rules** - Add your own patterns

Happy hunting! 🎯
