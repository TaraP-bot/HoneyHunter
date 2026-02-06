#!/usr/bin/env python3
"""
Test script to verify file upload capture is working correctly
"""

import socket
import hashlib
import sys


def test_http_upload(host='localhost', port=8080):
    """Test HTTP multipart file upload"""
    print(f"[*] Testing HTTP file upload on {host}:{port}")
    
    # Create test file content
    test_content = b"This is a test malware sample!\nLine 2\nLine 3"
    expected_hash = hashlib.sha256(test_content).hexdigest()
    
    print(f"[*] Test file SHA256: {expected_hash}")
    print(f"[*] Test file size: {len(test_content)} bytes")
    
    # Build multipart form data
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    
    # Construct multipart body
    body = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="file"; filename="malware.bin"\r\n'
    body += b"Content-Type: application/octet-stream\r\n"
    body += b"\r\n"
    body += test_content
    body += b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    
    # Build HTTP request
    request = b"POST /api/upload HTTP/1.1\r\n"
    request += f"Host: {host}:{port}\r\n".encode()
    request += b"User-Agent: curl/8.7.1\r\n"
    request += f"Content-Type: multipart/form-data; boundary={boundary}\r\n".encode()
    request += f"Content-Length: {len(body)}\r\n".encode()
    request += b"Connection: close\r\n"
    request += b"\r\n"
    request += body
    
    try:
        # Send request
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        print(f"[*] Sending {len(request)} bytes...")
        sock.sendall(request)
        
        # Receive response
        response = sock.recv(4096)
        print(f"[*] Response received: {len(response)} bytes")
        print(f"[*] Response:\n{response.decode('utf-8', errors='ignore')}")
        
        sock.close()
        
        print("\n[+] Upload completed successfully!")
        print(f"[*] Check honeypot_data/samples/{expected_hash}.bin for the captured file")
        print(f"[*] Check honeypot_data/samples/{expected_hash}.json for metadata")
        
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ftp_upload(host='localhost', port=21):
    """Test FTP file upload (STOR command)"""
    print(f"\n[*] Testing FTP file upload on {host}:{port}")
    
    test_content = b"FTP test file content\nMalicious payload here"
    expected_hash = hashlib.sha256(test_content).hexdigest()
    
    print(f"[*] Test file SHA256: {expected_hash}")
    print(f"[*] Test file size: {len(test_content)} bytes")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Read banner
        banner = sock.recv(1024)
        print(f"[*] Banner: {banner.decode('utf-8', errors='ignore').strip()}")
        
        # Login
        sock.send(b"USER anonymous\r\n")
        resp = sock.recv(1024)
        print(f"[*] USER: {resp.decode('utf-8', errors='ignore').strip()}")
        
        sock.send(b"PASS test@test.com\r\n")
        resp = sock.recv(1024)
        print(f"[*] PASS: {resp.decode('utf-8', errors='ignore').strip()}")
        
        # Set binary mode
        sock.send(b"TYPE I\r\n")
        resp = sock.recv(1024)
        print(f"[*] TYPE: {resp.decode('utf-8', errors='ignore').strip()}")
        
        # Upload file
        sock.send(b"STOR malware.bin\r\n")
        resp = sock.recv(1024)
        print(f"[*] STOR: {resp.decode('utf-8', errors='ignore').strip()}")
        
        # Send file data (in simplified honeypot, this goes over control connection)
        sock.send(test_content)
        
        # Wait for completion
        import time
        time.sleep(1)
        
        resp = sock.recv(1024)
        print(f"[*] Transfer response: {resp.decode('utf-8', errors='ignore').strip()}")
        
        sock.send(b"QUIT\r\n")
        sock.close()
        
        print(f"\n[+] FTP upload test completed!")
        print(f"[*] Check honeypot_data/samples/{expected_hash}.bin for the captured file")
        
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_samples_dir(samples_dir="./honeypot_data/samples"):
    """Check what's in the samples directory"""
    from pathlib import Path
    
    print(f"\n[*] Checking samples directory: {samples_dir}")
    
    samples_path = Path(samples_dir)
    if not samples_path.exists():
        print(f"[-] Directory does not exist: {samples_dir}")
        return
    
    files = list(samples_path.iterdir())
    if not files:
        print("[-] No files found in samples directory")
        return
    
    print(f"[*] Found {len(files)} files:")
    
    bin_files = [f for f in files if f.suffix == '.bin']
    json_files = [f for f in files if f.suffix == '.json']
    
    print(f"    - {len(bin_files)} .bin files (actual samples)")
    print(f"    - {len(json_files)} .json files (metadata)")
    
    # Show recent files
    recent = sorted(files, key=lambda f: f.stat().st_mtime, reverse=True)[:5]
    print(f"\n[*] Most recent files:")
    for f in recent:
        size = f.stat().st_size
        print(f"    - {f.name} ({size} bytes)")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test honeypot file upload capture")
    parser.add_argument('--host', default='localhost', help='Honeypot host')
    parser.add_argument('--http-port', type=int, default=8080, help='HTTP port')
    parser.add_argument('--ftp-port', type=int, default=2121, help='FTP port')
    parser.add_argument('--verify-only', action='store_true', help='Only verify samples directory')
    
    args = parser.parse_args()
    
    print("="*70)
    print("Honeypot File Upload Test")
    print("="*70)
    
    if args.verify_only:
        verify_samples_dir()
    else:
        # Run tests
        http_ok = test_http_upload(args.host, args.http_port)
        ftp_ok = test_ftp_upload(args.host, args.ftp_port)
        
        # Verify
        verify_samples_dir()
        
        print("\n" + "="*70)
        print("Test Results:")
        print(f"  HTTP Upload: {'PASS' if http_ok else 'FAIL'}")
        print(f"  FTP Upload:  {'PASS' if ftp_ok else 'FAIL'}")
        print("="*70)
