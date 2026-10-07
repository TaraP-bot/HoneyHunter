#!/usr/bin/env python3
"""
Honeypot Telemetry Analysis
Analyze captured telemetry for patterns, IoCs, and threat intelligence
"""

import json
import logging
import os
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Any, Set
import hashlib


# Captured content smaller than this is too generic for hash blocking:
# the same few bytes easily occur in legitimate data
SMALL_SAMPLE = 64


class TelemetryAnalyzer:
    """Analyze honeypot telemetry data"""
    
    def __init__(self, data_dir: Path, exclude_ips=()):
        self.data_dir = Path(data_dir)
        # The sensor's own address (tests run from it) plus anything passed in
        self.exclude_ips = {ip for ip in (os.environ.get('PUBLIC_IP'), *exclude_ips) if ip}
        self.events_file = self.data_dir / "events.jsonl"
        self.samples_dir = self.data_dir / "samples"
        
        self.events: List[Dict[str, Any]] = []
        self.sessions: Dict[str, List[Dict]] = defaultdict(list)
        
    def load_events(self, hours: int = 24):
        """Load events from the last N hours"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        if not self.events_file.exists():
            logging.warning(f"No events file found: {self.events_file}")
            return
        
        with open(self.events_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('source_ip') in self.exclude_ips:
                        continue
                    event_time = datetime.fromisoformat(event['timestamp'])
                    
                    if event_time >= cutoff:
                        self.events.append(event)
                        self.sessions[event['session_id']].append(event)
                except Exception as e:
                    logging.error(f"Error parsing event: {e}")
        
        logging.info(f"Loaded {len(self.events)} events from {len(self.sessions)} sessions")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get overall summary statistics"""
        if not self.events:
            return {}
        
        # Count by event type
        event_types = Counter(e['event_type'] for e in self.events)
        
        # Count by protocol
        protocols = Counter(e['protocol'] for e in self.events)
        
        # Unique source IPs
        source_ips = set(e['source_ip'] for e in self.events)
        
        # Attack events
        attack_events = [e for e in self.events if 'attack' in e['event_type']]
        
        # Login attempts
        login_events = [e for e in self.events if 'login' in e['event_type']]
        successful_logins = [e for e in login_events 
                            if (e.get('decoded_payload') or {}).get('success', False)]
        
        # Downloads/uploads
        download_events = [e for e in self.events if 'download' in e['event_type']]
        upload_events = [e for e in self.events if 'upload' in e['event_type']]
        
        # Captured samples
        sample_count = len(list(self.samples_dir.glob("*.bin"))) if self.samples_dir.exists() else 0
        
        return {
            'total_events': len(self.events),
            'unique_sessions': len(self.sessions),
            'unique_ips': len(source_ips),
            'event_types': dict(event_types),
            'protocols': dict(protocols),
            'attacks': {
                'total': len(attack_events),
                'by_type': self._count_attack_types(attack_events)
            },
            'logins': {
                'attempts': len(login_events),
                'successful': len(successful_logins),
                'credentials': self._extract_credentials(login_events)
            },
            'downloads': len(download_events),
            'uploads': len(upload_events),
            'samples_captured': sample_count
        }
    
    def _count_attack_types(self, attack_events: List[Dict]) -> Dict[str, int]:
        """Count different attack types"""
        types = Counter()
        
        for event in attack_events:
            payload = (event.get('decoded_payload') or {})
            if 'attack_types' in payload:
                for attack_type in payload['attack_types']:
                    types[attack_type] += 1
        
        return dict(types)
    
    def _extract_credentials(self, login_events: List[Dict]) -> Dict[str, int]:
        """Extract and count credential pairs"""
        creds = Counter()
        
        for event in login_events:
            payload = (event.get('decoded_payload') or {})
            username = payload.get('username', 'unknown')
            password = payload.get('password', 'unknown')
            creds[f"{username}:{password}"] += 1
        
        # Return top 20
        return dict(creds.most_common(20))
    
    def get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most active attacker IPs"""
        ip_stats = defaultdict(lambda: {
            'total_events': 0,
            'attacks': 0,
            'logins': 0,
            'downloads': 0,
            'protocols': set()
        })
        
        for event in self.events:
            ip = event['source_ip']
            stats = ip_stats[ip]
            
            stats['total_events'] += 1
            stats['protocols'].add(event['protocol'])
            
            if 'attack' in event['event_type']:
                stats['attacks'] += 1
            if 'login' in event['event_type']:
                stats['logins'] += 1
            if 'download' in event['event_type']:
                stats['downloads'] += 1
        
        # Convert to list and sort
        result = []
        for ip, stats in ip_stats.items():
            result.append({
                'ip': ip,
                'total_events': stats['total_events'],
                'attacks': stats['attacks'],
                'logins': stats['logins'],
                'downloads': stats['downloads'],
                'protocols': list(stats['protocols'])
            })
        
        result.sort(key=lambda x: x['total_events'], reverse=True)
        return result[:limit]
    
    def detect_scanning_behavior(self) -> List[Dict[str, Any]]:
        """Detect port scanning behavior"""
        ip_ports = defaultdict(set)
        
        for event in self.events:
            ip = event['source_ip']
            port = event['dest_port']
            ip_ports[ip].add(port)
        
        # IPs hitting 3+ different ports = scanner
        scanners = []
        for ip, ports in ip_ports.items():
            if len(ports) >= 3:
                # Get user agents if available
                user_agents = set()
                for event in self.events:
                    if event['source_ip'] == ip:
                        headers = (event.get('headers') or {})
                        if 'User-Agent' in headers:
                            user_agents.add(headers['User-Agent'])
                
                scanners.append({
                    'ip': ip,
                    'ports_scanned': list(ports),
                    'port_count': len(ports),
                    'user_agents': list(user_agents)
                })
        
        scanners.sort(key=lambda x: x['port_count'], reverse=True)
        return scanners
    
    def get_malware_samples(self) -> List[Dict[str, Any]]:
        """Get information about captured malware samples"""
        if not self.samples_dir.exists():
            return []
        
        samples = []
        for sample_file in self.samples_dir.glob("*.bin"):
            meta_file = sample_file.with_suffix('.json')
            
            if meta_file.exists():
                with open(meta_file) as f:
                    metadata = json.load(f)
                if metadata.get('source_ip') in self.exclude_ips:
                    continue
                samples.append(metadata)
        
        samples.sort(key=lambda m: m.get('timestamp', ''), reverse=True)
        return samples
    
    @staticmethod
    def sample_name(sample: Dict[str, Any]) -> str:
        """Human-readable name: the uploaded file name when there is one,
        otherwise where in the request the bytes came from"""
        request = f"{sample.get('method', '?')} {sample.get('path', '?')}"
        if sample.get('filename'):
            return f"file '{sample['filename']}' ({request})"
        if sample.get('field_name'):
            return f"form field '{sample['field_name']}' ({request})"
        kind = {'http_request': 'whole request', 'http_body': 'request body'}.get(
            sample.get('artifact_kind'), sample.get('artifact_kind', 'data'))
        return f"{kind} of {request}"
    
    def get_dns_analysis(self) -> Dict[str, Any]:
        """Analyze DNS queries for C2 patterns"""
        dns_events = [e for e in self.events if e['protocol'] == 'dns']
        
        if not dns_events:
            return {}
        
        # Top queried domains
        domains = Counter()
        suspicious_domains = []
        
        for event in dns_events:
            payload = (event.get('decoded_payload') or {})
            domain = payload.get('domain', '')
            
            if domain:
                domains[domain] += 1
            
            # Collect suspicious DNS events
            if event['event_type'] == 'dns_suspicious':
                suspicious_domains.append({
                    'domain': domain,
                    'ip': event['source_ip'],
                    'indicators': payload.get('indicators', []),
                    'timestamp': event['timestamp']
                })
        
        return {
            'total_queries': len(dns_events),
            'unique_domains': len(domains),
            'top_domains': dict(domains.most_common(20)),
            'suspicious': suspicious_domains
        }
    
    def get_http_attack_analysis(self) -> Dict[str, Any]:
        """Analyze HTTP attacks"""
        http_attacks = [e for e in self.events if e['event_type'] == 'http_attack']
        
        if not http_attacks:
            return {}
        
        # Attack types
        attack_types = Counter()
        paths_attacked = Counter()
        scanners = Counter()
        
        for event in http_attacks:
            payload = (event.get('decoded_payload') or {})
            
            # Count attack types
            for attack_type in payload.get('attack_types', []):
                attack_types[attack_type] += 1
            
            # Track paths
            path = payload.get('path', '')
            if path:
                paths_attacked[path] += 1
            
            # Track scanners
            if payload.get('is_scanner', False):
                ua = payload.get('user_agent', 'Unknown')
                scanners[ua] += 1
        
        return {
            'total_attacks': len(http_attacks),
            'attack_types': dict(attack_types),
            'top_targeted_paths': dict(paths_attacked.most_common(10)),
            'scanners': dict(scanners.most_common(10))
        }
    
    def generate_report(self, output_file: Path = None) -> str:
        """Generate comprehensive report"""
        report = []
        
        report.append("="*70)
        report.append("HONEYPOT TELEMETRY ANALYSIS REPORT")
        report.append("="*70)
        report.append(f"Generated: {datetime.utcnow().isoformat()}")
        report.append(f"Data Directory: {self.data_dir}")
        report.append("")
        
        # Summary
        summary = self.get_summary()
        report.append("SUMMARY")
        report.append("-"*70)
        report.append(f"Total Events:      {summary.get('total_events', 0)}")
        report.append(f"Unique Sessions:   {summary.get('unique_sessions', 0)}")
        report.append(f"Unique Source IPs: {summary.get('unique_ips', 0)}")
        report.append(f"Samples Captured:  {summary.get('samples_captured', 0)}")
        report.append("")
        
        # Protocols
        report.append("PROTOCOLS")
        report.append("-"*70)
        for protocol, count in summary.get('protocols', {}).items():
            report.append(f"  {protocol:10s}: {count:5d}")
        report.append("")
        
        # Attacks
        attacks = summary.get('attacks', {})
        report.append("ATTACKS")
        report.append("-"*70)
        report.append(f"Total Attacks: {attacks.get('total', 0)}")
        for attack_type, count in attacks.get('by_type', {}).items():
            report.append(f"  {attack_type:20s}: {count:5d}")
        report.append("")
        
        # Top Attackers
        report.append("TOP ATTACKERS")
        report.append("-"*70)
        for i, attacker in enumerate(self.get_top_attackers(10), 1):
            report.append(f"{i:2d}. {attacker['ip']:15s} - " +
                         f"Events: {attacker['total_events']:4d}, " +
                         f"Attacks: {attacker['attacks']:3d}, " +
                         f"Logins: {attacker['logins']:3d}")
        report.append("")
        
        # Credentials
        logins = summary.get('logins', {})
        report.append("LOGIN ATTEMPTS")
        report.append("-"*70)
        report.append(f"Total Attempts: {logins.get('attempts', 0)}")
        report.append(f"Successful:     {logins.get('successful', 0)}")
        report.append("\nTop Credentials:")
        for cred, count in list(logins.get('credentials', {}).items())[:10]:
            report.append(f"  {cred:30s}: {count:4d}")
        report.append("")
        
        # Scanners
        scanners = self.detect_scanning_behavior()
        if scanners:
            report.append("PORT SCANNERS DETECTED")
            report.append("-"*70)
            for scanner in scanners[:5]:
                report.append(f"  {scanner['ip']:15s} - {scanner['port_count']} ports")
                report.append(f"    Ports: {scanner['ports_scanned']}")
        report.append("")
        
        # DNS Analysis
        dns = self.get_dns_analysis()
        if dns:
            report.append("DNS ANALYSIS")
            report.append("-"*70)
            report.append(f"Total Queries:    {dns.get('total_queries', 0)}")
            report.append(f"Unique Domains:   {dns.get('unique_domains', 0)}")
            report.append(f"Suspicious:       {len(dns.get('suspicious', []))}")
        report.append("")
        
        # HTTP Attacks
        http_attacks = self.get_http_attack_analysis()
        if http_attacks:
            report.append("HTTP ATTACK ANALYSIS")
            report.append("-"*70)
            report.append(f"Total HTTP Attacks: {http_attacks.get('total_attacks', 0)}")
            report.append("\nAttack Types:")
            for attack_type, count in http_attacks.get('attack_types', {}).items():
                report.append(f"  {attack_type:20s}: {count:4d}")
        report.append("")
        
        # Malware Samples
        samples = self.get_malware_samples()
        if samples:
            report.append("CAPTURED SAMPLES")
            report.append("-"*70)
            report.append(f"{len(samples)} captured, newest first. Hashes of content under "
                          f"{SMALL_SAMPLE} bytes are too generic to block safely.")
            report.append("")
            for sample in samples:
                size = sample.get('size', 0)
                report.append(f"  SHA256:  {sample.get('sha256', 'unknown')}")
                report.append(f"  Name:    {self.sample_name(sample)}")
                details = [sample.get('artifact_kind', '?'), f"{size} bytes"]
                if sample.get('content_type'):
                    details.append(sample['content_type'])
                if sample.get('capture_status') not in (None, 'complete'):
                    details.append(f"capture {sample['capture_status']}")
                report.append(f"  Kind:    {', '.join(details)}")
                report.append(f"  Source:  {sample.get('source_ip', 'unknown')} at "
                              f"{sample.get('timestamp', '?')[:19]} via {sample.get('protocol', '?')}")
                if sample.get('user_agent'):
                    report.append(f"  Agent:   {sample['user_agent'][:90]}")
                if size < SMALL_SAMPLE:
                    report.append("  Note:    generic tiny content - do not block by this hash")
                report.append("")
        
        report.append("="*70)
        
        # Join and optionally save
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            logging.info(f"Report saved to: {output_file}")
        
        return report_text


def main():
    """Generate analysis report"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze honeypot telemetry")
    parser.add_argument('data_dir', type=Path, help='Honeypot data directory')
    parser.add_argument('--hours', type=int, default=24, 
                       help='Hours of data to analyze (default: 24)')
    parser.add_argument('--output', type=Path, help='Output report file')
    parser.add_argument('--exclude', action='append', default=[], metavar='IP',
                       help='Ignore events from this source IP (repeatable); '
                            'the PUBLIC_IP environment variable is always excluded')
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    analyzer = TelemetryAnalyzer(args.data_dir, args.exclude)
    analyzer.load_events(hours=args.hours)
    
    report = analyzer.generate_report(output_file=args.output)
    print(report)


if __name__ == "__main__":
    main()
