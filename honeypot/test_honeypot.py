#!/usr/bin/env python3
"""
Honeypot Test Script
Test various services and generate sample telemetry
"""

import asyncio
import socket
import urllib.request
import urllib.error
from pathlib import Path


class HoneypotTester:
    """Test honeypot services"""
    
    def __init__(self, host='localhost'):
        self.host = host
        self.results = []
    
    def test_http(self, port=8080):
        """Test HTTP service"""
        print(f"[*] Testing HTTP on port {port}...")
        
        tests = [
            ('GET', '/', 'Basic request'),
            ('GET', '/admin/login.php', 'Admin panel'),
            ('GET', '/?id=1\' OR \'1\'=\'1', 'SQL injection attempt'),
            ('GET', '/?q=<script>alert(1)</script>', 'XSS attempt'),
            ('GET', '/../../etc/passwd', 'Path traversal'),
        ]
        
        for method, path, description in tests:
            try:
                url = f'http://{self.host}:{port}{path}'
                req = urllib.request.Request(url, method=method)
                req.add_header('User-Agent', 'Mozilla/5.0 (Test Scanner)')
                
                with urllib.request.urlopen(req, timeout=5) as response:
                    print(f"  [+] {description}: {response.status}")
                    self.results.append(('HTTP', True, description))
            except urllib.error.HTTPError as e:
                print(f"  [+] {description}: {e.code}")
                self.results.append(('HTTP', True, description))
            except Exception as e:
                print(f"  [-] {description}: {e}")
                self.results.append(('HTTP', False, description))
    
    def test_ssh(self, port=2222):
        """Test SSH service"""
        print(f"\n[*] Testing SSH on port {port}...")
        
        credentials = [
            ('root', 'root'),
            ('admin', 'admin'),
            ('user', 'password'),
        ]
        
        for username, password in credentials:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.host, port))
                
                # Read SSH banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                print(f"  [+] SSH banner: {banner.strip()}")
                
                # Send username
                sock.send(f"{username}\n".encode())
                sock.recv(1024)  # Prompt
                
                # Send password
                sock.send(f"{password}\n".encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                print(f"  [+] Login attempt: {username}:{password}")
                self.results.append(('SSH', True, f"Login: {username}"))
                
                sock.close()
                
            except Exception as e:
                print(f"  [-] Login {username}:{password}: {e}")
                self.results.append(('SSH', False, f"Login: {username}"))
    
    def test_ftp(self, port=2121):
        """Test FTP service"""
        print(f"\n[*] Testing FTP on port {port}...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, port))
            
            # Read banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"  [+] FTP banner: {banner.strip()}")
            
            # USER command
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"  [+] USER: {response.strip()}")
            
            # PASS command
            sock.send(b"PASS test@test.com\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"  [+] PASS: {response.strip()}")
            
            # LIST command
            sock.send(b"LIST\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            print(f"  [+] LIST: {response.strip()}")
            
            sock.close()
            self.results.append(('FTP', True, 'Connection test'))
            
        except Exception as e:
            print(f"  [-] FTP test failed: {e}")
            self.results.append(('FTP', False, 'Connection test'))
    
    def test_dns(self, port=5353):
        """Test DNS service"""
        print(f"\n[*] Testing DNS on port {port}...")
        
        # Simple DNS query for A record (very basic, not proper DNS)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, port))
            
            # Send minimal DNS-like query
            query = b'\x00\x01'  # Transaction ID
            query += b'\x01\x00'  # Flags
            query += b'\x00\x01'  # Questions
            query += b'\x00\x00\x00\x00\x00\x00'  # Answers, Authority, Additional
            
            # Domain name: example.com (length-prefixed labels)
            query += b'\x07example\x03com\x00'
            query += b'\x00\x01'  # Type A
            query += b'\x00\x01'  # Class IN
            
            sock.send(query)
            response = sock.recv(1024)
            
            print(f"  [+] DNS query sent, received {len(response)} bytes")
            self.results.append(('DNS', True, 'Query test'))
            
            sock.close()
            
        except Exception as e:
            print(f"  [-] DNS test failed: {e}")
            self.results.append(('DNS', False, 'Query test'))
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*60)
        print("Test Summary")
        print("="*60)
        
        by_service = {}
        for service, success, description in self.results:
            if service not in by_service:
                by_service[service] = {'passed': 0, 'failed': 0}
            
            if success:
                by_service[service]['passed'] += 1
            else:
                by_service[service]['failed'] += 1
        
        for service, counts in by_service.items():
            total = counts['passed'] + counts['failed']
            print(f"{service:10s}: {counts['passed']}/{total} tests passed")
        
        print("="*60)
        print("\nCheck honeypot_data/events.jsonl for captured telemetry")


def main():
    """Run all tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test honeypot services")
    parser.add_argument('--host', default='localhost', help='Honeypot host')
    parser.add_argument('--http-port', type=int, default=8080, help='HTTP port')
    parser.add_argument('--ssh-port', type=int, default=2222, help='SSH port')
    parser.add_argument('--ftp-port', type=int, default=2121, help='FTP port')
    parser.add_argument('--dns-port', type=int, default=5353, help='DNS port')
    
    args = parser.parse_args()
    
    print("="*60)
    print("Honeypot Service Tester")
    print("="*60)
    print(f"Target: {args.host}")
    print("="*60)
    
    tester = HoneypotTester(args.host)
    
    # Run tests
    tester.test_http(args.http_port)
    tester.test_ssh(args.ssh_port)
    tester.test_ftp(args.ftp_port)
    tester.test_dns(args.dns_port)
    
    # Summary
    tester.print_summary()


if __name__ == "__main__":
    main()
