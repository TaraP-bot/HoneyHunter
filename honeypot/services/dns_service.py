#!/usr/bin/env python3
"""
DNS Honeypot Service
Logs DNS queries, detects C2 beaconing, DGA domains, exfiltration attempts
"""

import asyncio
import logging
import struct
from datetime import datetime
from typing import List, Tuple, Dict, Any

from honeypot_manager import HoneypotService, ProtocolEvent


async def _read_exact(reader, n: int):
    """Read exactly n bytes, or return None if the peer closes first"""
    data = b''
    while len(data) < n:
        chunk = await reader.read(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


class DNSQuery:
    """Parse DNS query packet"""
    
    def __init__(self, data: bytes):
        self.data = data
        self.transaction_id = 0
        self.questions: List[Tuple[str, int, int]] = []
        self._parse()
    
    def _parse(self):
        """Parse DNS query"""
        try:
            # Parse header (12 bytes)
            if len(self.data) < 12:
                return
            
            self.transaction_id = struct.unpack('!H', self.data[0:2])[0]
            flags = struct.unpack('!H', self.data[2:4])[0]
            qdcount = struct.unpack('!H', self.data[4:6])[0]
            
            # Parse questions
            offset = 12
            for _ in range(qdcount):
                qname, offset = self._parse_domain_name(offset)
                if offset + 4 <= len(self.data):
                    qtype = struct.unpack('!H', self.data[offset:offset+2])[0]
                    qclass = struct.unpack('!H', self.data[offset+2:offset+4])[0]
                    offset += 4
                    self.questions.append((qname, qtype, qclass))
                    
        except Exception as e:
            logging.error(f"DNS parsing error: {e}")
    
    def _parse_domain_name(self, offset: int) -> Tuple[str, int]:
        """Parse domain name from DNS packet"""
        parts = []
        
        while offset < len(self.data):
            length = self.data[offset]
            
            if length == 0:
                offset += 1
                break
            elif length & 0xC0 == 0xC0:  # Pointer
                if offset + 1 < len(self.data):
                    pointer = struct.unpack('!H', self.data[offset:offset+2])[0] & 0x3FFF
                    pointed_name, _ = self._parse_domain_name(pointer)
                    parts.append(pointed_name)
                offset += 2
                break
            else:
                offset += 1
                if offset + length <= len(self.data):
                    parts.append(self.data[offset:offset+length].decode('utf-8', errors='ignore'))
                    offset += length
        
        return '.'.join(parts), offset
    
    def get_query_name(self) -> str:
        """Get first query name"""
        if self.questions:
            return self.questions[0][0]
        return ""
    
    def get_query_type(self) -> str:
        """Get query type as string"""
        if not self.questions:
            return "UNKNOWN"
        
        qtype = self.questions[0][1]
        types = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            6: 'SOA',
            12: 'PTR',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA',
            33: 'SRV',
            255: 'ANY'
        }
        return types.get(qtype, f'TYPE{qtype}')


class DNSHoneypot(HoneypotService):
    """DNS honeypot - logs queries and detects malicious patterns"""
    
    def __init__(self, port: int, telemetry):
        super().__init__("DNS", port, telemetry)
        
        # Default response IP
        self.default_ip = "127.0.0.1"
        
        # Track queries per IP for beaconing detection
        self.query_history: Dict[str, List[str]] = {}
        
        # Known malicious/suspicious patterns
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', 
                               '.top', '.work', '.click', '.cc']
        
    async def handle_client(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """Handle DNS query"""
        source_ip, source_port = self.get_peer_info(writer)
        session_id = self.telemetry.generate_session_id(
            source_ip, source_port, self.port
        )
        reader, writer = self.capture_streams(reader, writer, session_id)
        
        try:
            # DNS over TCP prefixes every message with a 2-byte length
            # (RFC 1035 4.2.2). Reading raw bytes as a query misparsed every
            # request; non-DNS probes on port 53 are still captured as
            # tcp_data by the stream capture, just not logged as queries.
            prefix = await asyncio.wait_for(_read_exact(reader, 2), timeout=5.0)
            if prefix is None:
                return
            length = struct.unpack('!H', prefix)[0]
            if length < 12:  # shorter than a DNS header
                return
            data = await asyncio.wait_for(_read_exact(reader, length), timeout=5.0)
            if data is None:
                return
            
            # Parse query
            query = DNSQuery(data)
            domain = query.get_query_name()
            qtype = query.get_query_type()
            
            # Log query
            await self._log_query(query, source_ip, source_port, session_id)
            
            # Track for beaconing detection
            self._track_query(source_ip, domain)
            
            # Detect suspicious patterns
            await self._detect_malicious_patterns(query, source_ip, session_id)
            
            # Send response
            response = self._build_response(query)
            writer.write(struct.pack('!H', len(response)) + response)
            await writer.drain()
            
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logging.error(f"Error handling DNS query: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def _log_query(self, query: DNSQuery, source_ip: str, 
                        source_port: int, session_id: str):
        """Log DNS query"""
        domain = query.get_query_name()
        qtype = query.get_query_type()
        
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='dns_query',
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.port,
            protocol='dns',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'domain': domain,
                'query_type': qtype,
                'transaction_id': query.transaction_id
            }
        )
        
        await self.telemetry.log_event(event)
        logging.info(f"DNS query: {domain} ({qtype}) from {source_ip}")
    
    def _track_query(self, source_ip: str, domain: str):
        """Track queries for beaconing detection"""
        if source_ip not in self.query_history:
            self.query_history[source_ip] = []
        
        self.query_history[source_ip].append(domain)
        
        # Keep only last 100 queries per IP
        if len(self.query_history[source_ip]) > 100:
            self.query_history[source_ip] = self.query_history[source_ip][-100:]
    
    async def _detect_malicious_patterns(self, query: DNSQuery, 
                                         source_ip: str, session_id: str):
        """Detect malicious DNS patterns"""
        domain = query.get_query_name()
        
        indicators = {}
        
        # DGA detection (long random-looking domains)
        if len(domain) > 20 and self._looks_random(domain):
            indicators['dga_domain'] = True
        
        # Suspicious TLD
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            indicators['suspicious_tld'] = True
        
        # Subdomain tunneling (too many subdomains)
        if domain.count('.') > 5:
            indicators['subdomain_tunneling'] = True
        
        # Long subdomain (possible exfiltration)
        parts = domain.split('.')
        if any(len(part) > 50 for part in parts):
            indicators['long_subdomain'] = True
        
        # Beaconing detection (repetitive queries)
        if source_ip in self.query_history:
            recent_queries = self.query_history[source_ip][-10:]
            if recent_queries.count(domain) > 3:
                indicators['beaconing'] = True
        
        # Base64-like patterns in subdomain
        if self._has_base64_pattern(domain):
            indicators['base64_encoding'] = True
        
        if indicators:
            await self._log_suspicious_activity(domain, indicators, 
                                                source_ip, session_id)
    
    def _looks_random(self, domain: str) -> bool:
        """Detect if domain looks randomly generated"""
        # Remove TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        name = parts[0]
        
        # Check for low vowel ratio
        vowels = sum(1 for c in name.lower() if c in 'aeiou')
        consonants = sum(1 for c in name.lower() if c.isalpha() and c not in 'aeiou')
        
        if consonants > 0:
            ratio = vowels / consonants
            if ratio < 0.2 or ratio > 2.0:
                return True
        
        # Check for digit patterns
        if sum(1 for c in name if c.isdigit()) > len(name) * 0.3:
            return True
        
        return False
    
    def _has_base64_pattern(self, domain: str) -> bool:
        """Detect base64-like encoding in domain"""
        import re
        # Look for long sequences of alphanumeric with possible + or /
        pattern = r'[A-Za-z0-9+/]{20,}'
        return bool(re.search(pattern, domain))
    
    async def _log_suspicious_activity(self, domain: str, 
                                       indicators: Dict[str, bool],
                                       source_ip: str, session_id: str):
        """Log suspicious DNS activity"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='dns_suspicious',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='dns',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'domain': domain,
                'indicators': list(indicators.keys())
            }
        )
        
        await self.telemetry.log_event(event)
        logging.warning(f"Suspicious DNS from {source_ip}: {domain} - {indicators}")
    
    def _build_response(self, query: DNSQuery) -> bytes:
        """Build DNS response"""
        try:
            response = bytearray()
            
            # Transaction ID
            response.extend(struct.pack('!H', query.transaction_id))
            
            # Flags: response, authoritative, no error
            flags = 0x8400
            response.extend(struct.pack('!H', flags))
            
            # Question count, Answer count, Authority, Additional
            response.extend(struct.pack('!HHHH', len(query.questions), 1, 0, 0))
            
            # Echo question section
            question_data = query.data[12:]  # Skip header
            response.extend(question_data)
            
            # Add answer (A record pointing to default IP)
            # Name pointer to question
            response.extend(b'\xc0\x0c')
            
            # Type (A), Class (IN)
            response.extend(struct.pack('!HH', 1, 1))
            
            # TTL (300 seconds)
            response.extend(struct.pack('!I', 300))
            
            # Data length (4 for IPv4)
            response.extend(struct.pack('!H', 4))
            
            # IP address
            ip_parts = self.default_ip.split('.')
            response.extend(bytes([int(p) for p in ip_parts]))
            
            return bytes(response)
            
        except Exception as e:
            logging.error(f"Error building DNS response: {e}")
            # Return minimal error response
            return query.data[:2] + b'\x81\x82' + query.data[4:]


if __name__ == "__main__":
    from honeypot_manager import TelemetryCollector
    from pathlib import Path
    
    async def main():
        telemetry = TelemetryCollector(Path("./honeypot_data"))
        
        # Note: DNS typically uses UDP, but this example uses TCP for simplicity
        # For production, you'd want to handle UDP as well
        dns = DNSHoneypot(5353, telemetry)
        await dns.start()
        
        print("DNS honeypot running on port 5353 (TCP)...")
        await asyncio.Event().wait()
    
    asyncio.run(main())
