#!/usr/bin/env python3
"""
HTTP/HTTPS Honeypot Service
Emulates web server and captures all requests, headers, payloads
"""

import asyncio
import logging
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional
from pathlib import Path

from honeypot_manager import HoneypotService, ProtocolEvent
from http_capture import collect_request, extract_parts


class HTTPRequest:
    """Parse and represent HTTP request"""
    
    def __init__(self, raw_data: str):
        self.raw = raw_data
        self.method = ""
        self.path = ""
        self.version = ""
        self.headers: Dict[str, str] = {}
        self.body = ""
        self.parsed_query: Dict[str, list] = {}
        
        self._parse()
    
    def _parse(self):
        """Parse raw HTTP request"""
        try:
            lines = self.raw.split('\r\n')
            
            # Request line
            if lines:
                parts = lines[0].split(' ')
                if len(parts) >= 3:
                    self.method = parts[0]
                    self.path = parts[1]
                    self.version = parts[2]
                    
                    # Parse query parameters
                    parsed = urlparse(self.path)
                    self.parsed_query = parse_qs(parsed.query)
            
            # Headers
            body_start = -1
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    self.headers[key.strip()] = value.strip()
            
            # Body
            if body_start > 0:
                self.body = '\r\n'.join(lines[body_start:])
                
        except Exception as e:
            logging.error(f"Error parsing HTTP request: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging"""
        return {
            'method': self.method,
            'path': self.path,
            'version': self.version,
            'headers': self.headers,
            'query_params': self.parsed_query,
            'body': self.body[:1000] if self.body else "",  # Truncate body
            'body_size': len(self.body)
        }
    
    def get_user_agent(self) -> str:
        """Extract User-Agent"""
        return self.headers.get('User-Agent', 'Unknown')
    
    def is_scanner(self) -> bool:
        """Detect common scanners"""
        ua = self.get_user_agent().lower()
        scanners = ['nmap', 'masscan', 'nikto', 'sqlmap', 'burp', 
                   'metasploit', 'acunetix', 'nessus', 'openvas',
                   'scanner', 'bot', 'crawler', 'python-requests']
        return any(s in ua for s in scanners)
    
    def has_exploit_patterns(self) -> Dict[str, bool]:
        """Detect common exploit patterns"""
        combined = f"{self.path} {self.body}".lower()
        
        patterns = {
            'sql_injection': bool(re.search(r'(\bunion\b.*\bselect\b|\'.*or.*=|sleep\(|benchmark\()', combined)),
            'xss': bool(re.search(r'(<script|javascript:|onerror=|onload=)', combined)),
            'path_traversal': bool(re.search(r'(\.\./|\.\.\\|/etc/passwd|c:\\windows)', combined)),
            'command_injection': bool(re.search(r'(;.*ls|;.*cat|;.*whoami|\|.*ping|\$\()', combined)),
            'xxe': bool(re.search(r'(<!entity|<!doctype.*system)', combined)),
            'file_upload': 'multipart/form-data' in self.headers.get('Content-Type', '').lower(),
            'rce_attempt': bool(re.search(r'(eval\(|exec\(|system\(|passthru\()', combined)),
        }
        
        return {k: v for k, v in patterns.items() if v}


class HTTPHoneypot(HoneypotService):
    """HTTP/HTTPS honeypot service"""
    
    def __init__(self, port: int, telemetry, ssl_cert: Optional[Path] = None):
        super().__init__("HTTP", port, telemetry)
        self.ssl_cert = ssl_cert
        
        # Response templates
        self.response_templates = {
            'default': self._generate_default_response,
            'admin': self._generate_admin_panel,
            'api': self._generate_api_response,
            '404': self._generate_404,
        }
        
    async def handle_client(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """Handle HTTP client connection"""
        source_ip, source_port = self.get_peer_info(writer)
        session_id = self.telemetry.generate_session_id(
            source_ip, source_port, self.port
        )
        reader, writer = self.capture_streams(reader, writer, session_id)
        
        close_reason = "handler_complete"
        try:
            # Read request (with timeout)
            raw_request = await asyncio.wait_for(
                reader.read(65536),  # 64KB max
                timeout=10.0
            )
            
            if not raw_request:
                return
            
            # An HTTP method token can span reads. Classify only after its space,
            # or once bytes cannot be a bounded uppercase method token.
            while b' ' not in raw_request and len(raw_request) < 32 and all(
                65 <= byte <= 90 or byte == 45 for byte in raw_request
            ):
                more = await asyncio.wait_for(reader.read(65536), timeout=10.0)
                if not more:
                    break
                raw_request += more
            method = raw_request.split(b' ', 1)[0]
            is_http = b' ' in raw_request and 0 < len(method) <= 32 and all(
                65 <= byte <= 90 or byte == 45 for byte in method
            )
            if not is_http:
                # Passive capture: no invented handshake or HTTP response.
                total = len(raw_request)
                while total < 1024 * 1024:
                    data = await asyncio.wait_for(
                        reader.read(min(65536, 1024 * 1024 - total)), timeout=30.0
                    )
                    if not data:
                        close_reason = 'peer_eof'
                        return
                    total += len(data)
                close_reason = 'binary_capture_limit'
                return

            raw_request, body, capture_headers, capture_status = await collect_request(
                raw_request, reader, writer
            )
            request_str = raw_request.decode('utf-8', errors='replace')
            request = HTTPRequest(request_str)
            
            # Log connection event
            await self._log_request(request, source_ip, source_port, session_id, raw_request)
            
            # Detect and log attacks
            exploits = request.has_exploit_patterns()
            if exploits:
                await self._log_attack(request, exploits, source_ip, session_id)
            
            await self._capture_submission(
                raw_request, body, capture_headers, capture_status,
                request, source_ip, source_port, session_id
            )
            
            # Generate response
            response = self._select_response(request)
            writer.write(response.encode())
            await writer.drain()
            
        except asyncio.TimeoutError:
            close_reason = 'idle_timeout'
            logging.debug(f"Timeout from {source_ip}")
        except Exception as e:
            close_reason = 'handler_error'
            logging.error(f"Error handling HTTP client: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            await self.telemetry.log_event(ProtocolEvent(
                timestamp=datetime.utcnow().isoformat(), event_type='tcp_connection_closed',
                source_ip=source_ip, source_port=source_port,
                dest_port=writer.get_extra_info('sockname')[1],
                dest_ip=writer.get_extra_info('sockname')[0],
                protocol='tcp', service=self.name, session_id=session_id,
                decoded_payload={'reason': close_reason},
            ))
    
    async def _log_request(self, request: HTTPRequest, source_ip: str, 
                          source_port: int, session_id: str, raw_request: bytes):
        """Log HTTP request event"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='http_request',
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.port,
            protocol='http',
            service=self.name,
            session_id=session_id,
            payload=request.raw[:2000],  # Truncate
            payload_size=len(raw_request),
            decoded_payload=request.to_dict(),
            headers=request.headers
        )
        
        await self.telemetry.log_event(event)
    
    async def _log_attack(self, request: HTTPRequest, exploits: Dict[str, bool],
                         source_ip: str, session_id: str):
        """Log detected attack patterns"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='http_attack',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='http',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'attack_types': list(exploits.keys()),
                'path': request.path,
                'method': request.method,
                'user_agent': request.get_user_agent(),
                'is_scanner': request.is_scanner()
            }
        )
        
        await self.telemetry.log_event(event)
        logging.warning(f"Attack detected from {source_ip}: {', '.join(exploits.keys())}")
    
    async def _capture_submission(self, raw, body, headers, status, request,
                                  source_ip, source_port, session_id):
        """Save complete submission evidence regardless of extension or MIME type."""
        if not body and request.method not in ('POST', 'PUT', 'PATCH') and status == 'complete':
            return
        metadata = {
            'session_id': session_id, 'source_port': source_port, 'dest_port': self.port,
            'method': request.method, 'path': request.path,
            'content_type': headers.get('content-type', ''),
            'content_encoding': headers.get('content-encoding', ''),
            'capture_status': status, 'user_agent': request.get_user_agent(),
        }
        async def save(data, details):
            info = {**metadata, **details}
            digest = await self.telemetry.save_sample(data, source_ip, 'http_upload', info)
            await self.telemetry.log_event(ProtocolEvent(
                timestamp=datetime.utcnow().isoformat(), event_type='http_artifact',
                source_ip=source_ip, source_port=source_port, dest_port=self.port,
                protocol='http', service=self.name, session_id=session_id,
                payload_size=len(data), decoded_payload={**info, 'sha256': digest},
            ))

        await save(raw, {'artifact_kind': 'http_request'})
        await save(body, {'artifact_kind': 'http_body'})
        if status == 'complete' and not headers.get('content-encoding'):
            try:
                for index, (data, details) in enumerate(extract_parts(body, headers.get('content-type', ''))):
                    if index >= 256:
                        await self.telemetry.log_event(ProtocolEvent(
                            timestamp=datetime.utcnow().isoformat(), event_type='http_extraction_limit',
                            source_ip=source_ip, source_port=source_port, dest_port=self.port,
                            protocol='http', service=self.name, session_id=session_id,
                            decoded_payload={'part_limit': 256, 'raw_body_preserved': True},
                        ))
                        break
                    await save(data, {**details, 'part_index': index})
            except (ValueError, UnicodeError) as exc:
                logging.warning('Upload extraction failed; raw body preserved: %s', exc)

    def _select_response(self, request: HTTPRequest) -> str:
        """Select appropriate response based on request"""
        path = request.path.lower()
        
        # Admin panels
        if any(x in path for x in ['/admin', '/login', '/phpmyadmin', '/wp-admin']):
            return self.response_templates['admin']()
        
        # API endpoints
        elif any(x in path for x in ['/api/', '.json', '/v1/', '/v2/']):
            return self.response_templates['api']()
        
        # Default
        else:
            return self.response_templates['default']()
    
    def _generate_default_response(self) -> str:
        """Generate default web page response"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome to our server</h1>
    <p>This is a test page.</p>
</body>
</html>"""
        
        return self._build_response(200, 'OK', html, 'text/html')
    
    def _generate_admin_panel(self) -> str:
        """Generate fake admin login page"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <style>
        body { font-family: Arial; margin: 50px; }
        .login { max-width: 300px; padding: 20px; border: 1px solid #ccc; }
        input { width: 100%; margin: 10px 0; padding: 8px; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; }
    </style>
</head>
<body>
    <div class="login">
        <h2>Administrator Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""
        
        return self._build_response(200, 'OK', html, 'text/html')
    
    def _generate_api_response(self) -> str:
        """Generate fake API response"""
        json_response = '{"status": "ok", "message": "API endpoint", "version": "1.0"}'
        return self._build_response(200, 'OK', json_response, 'application/json')
    
    def _generate_404(self) -> str:
        """Generate 404 response"""
        html = "<html><body><h1>404 Not Found</h1></body></html>"
        return self._build_response(404, 'Not Found', html, 'text/html')
    
    def _build_response(self, status_code: int, status_text: str, 
                       body: str, content_type: str) -> str:
        """Build HTTP response"""
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        response += f"Content-Type: {content_type}\r\n"
        response += f"Content-Length: {len(body)}\r\n"
        response += "Server: Apache/2.4.41 (Ubuntu)\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += body
        
        return response


# Example usage
if __name__ == "__main__":
    from honeypot_manager import TelemetryCollector
    from pathlib import Path
    
    async def main():
        telemetry = TelemetryCollector(Path("./honeypot_data"))
        
        http = HTTPHoneypot(8080, telemetry)
        await http.start()
        
        print("HTTP honeypot running on port 8080...")
        await asyncio.Event().wait()
    
    asyncio.run(main())
