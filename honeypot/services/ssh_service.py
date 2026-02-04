#!/usr/bin/env python3
"""
SSH Honeypot Service
Captures login attempts, credentials, and commands
"""

import asyncio
import logging
import base64
from datetime import datetime
from typing import Dict, Any, List

from honeypot_manager import HoneypotService, ProtocolEvent


class SSHHoneypot(HoneypotService):
    """SSH honeypot - captures credentials and commands"""
    
    def __init__(self, port: int, telemetry):
        super().__init__("SSH", port, telemetry)
        
        # Common credential pairs to "accept"
        self.fake_credentials = {
            'root': ['root', 'password', 'toor', '123456', 'admin'],
            'admin': ['admin', 'password', '123456'],
            'user': ['user', 'password'],
            'pi': ['raspberry', 'pi'],
            'ubuntu': ['ubuntu'],
        }
        
        # SSH version string
        self.ssh_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        
        # Fake shell environment
        self.shell_responses = {
            'uname': 'Linux ubuntu 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux',
            'whoami': 'root',
            'pwd': '/root',
            'id': 'uid=0(root) gid=0(root) groups=0(root)',
            'ls': 'Desktop  Documents  Downloads  Pictures  Videos',
            'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash',
        }
    
    async def handle_client(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """Handle SSH client connection"""
        source_ip, source_port = self.get_peer_info(writer)
        session_id = self.telemetry.generate_session_id(
            source_ip, source_port, self.port
        )
        
        try:
            # Send SSH version
            writer.write(f"{self.ssh_version}\r\n".encode())
            await writer.drain()
            
            # Log connection
            await self._log_connection(source_ip, source_port, session_id)
            
            # Read client version
            client_version = await asyncio.wait_for(reader.readline(), timeout=10.0)
            client_version = client_version.decode('utf-8', errors='ignore').strip()
            
            await self._log_client_version(client_version, source_ip, session_id)
            
            # Try to capture credentials (simplified - real SSH is complex)
            # This is a basic interaction, not full SSH protocol
            credentials = await self._attempt_credential_capture(
                reader, writer, source_ip, session_id
            )
            
            if credentials:
                # Simulate shell if credentials accepted
                await self._simulate_shell(reader, writer, source_ip, session_id)
        
        except asyncio.TimeoutError:
            logging.debug(f"SSH timeout from {source_ip}")
        except Exception as e:
            logging.error(f"Error handling SSH client: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def _log_connection(self, source_ip: str, source_port: int, 
                             session_id: str):
        """Log SSH connection attempt"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ssh_connection',
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.port,
            protocol='ssh',
            service=self.name,
            session_id=session_id
        )
        
        await self.telemetry.log_event(event)
    
    async def _log_client_version(self, version: str, source_ip: str, 
                                  session_id: str):
        """Log SSH client version"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ssh_client_version',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ssh',
            service=self.name,
            session_id=session_id,
            payload=version,
            decoded_payload={'client_version': version}
        )
        
        await self.telemetry.log_event(event)
    
    async def _attempt_credential_capture(self, reader: asyncio.StreamReader,
                                         writer: asyncio.StreamWriter,
                                         source_ip: str, session_id: str) -> bool:
        """Attempt to capture login credentials (simplified)"""
        # This is a VERY simplified version - real SSH uses key exchange
        # For a production honeypot, use libraries like asyncssh or paramiko
        
        try:
            # Send fake prompt
            writer.write(b"login: ")
            await writer.drain()
            
            username = await asyncio.wait_for(reader.readline(), timeout=30.0)
            username = username.decode('utf-8', errors='ignore').strip()
            
            writer.write(b"Password: ")
            await writer.drain()
            
            password = await asyncio.wait_for(reader.readline(), timeout=30.0)
            password = password.decode('utf-8', errors='ignore').strip()
            
            # Log credentials
            await self._log_credentials(username, password, source_ip, session_id)
            
            # Check if we should "accept" these credentials
            if username in self.fake_credentials:
                if password in self.fake_credentials[username]:
                    writer.write(b"\r\nWelcome to Ubuntu 20.04 LTS\r\n")
                    await writer.drain()
                    return True
            
            writer.write(b"\r\nAccess denied\r\n")
            await writer.drain()
            return False
            
        except Exception as e:
            logging.debug(f"Credential capture error: {e}")
            return False
    
    async def _log_credentials(self, username: str, password: str, 
                               source_ip: str, session_id: str):
        """Log captured credentials"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ssh_login_attempt',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ssh',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'username': username,
                'password': password,
                'success': username in self.fake_credentials and 
                          password in self.fake_credentials.get(username, [])
            }
        )
        
        await self.telemetry.log_event(event)
        logging.warning(f"SSH login attempt: {username}:{password} from {source_ip}")
    
    async def _simulate_shell(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter,
                             source_ip: str, session_id: str):
        """Simulate interactive shell session"""
        try:
            prompt = "root@ubuntu:~# "
            
            while True:
                writer.write(prompt.encode())
                await writer.drain()
                
                command = await asyncio.wait_for(reader.readline(), timeout=300.0)
                command = command.decode('utf-8', errors='ignore').strip()
                
                if not command:
                    continue
                
                # Log command
                await self._log_command(command, source_ip, session_id)
                
                # Exit commands
                if command.lower() in ['exit', 'logout', 'quit']:
                    writer.write(b"logout\r\n")
                    await writer.drain()
                    break
                
                # Download detection
                if any(x in command.lower() for x in ['wget', 'curl', 'fetch']):
                    await self._log_download_attempt(command, source_ip, session_id)
                
                # Execute command (fake responses)
                response = self._execute_fake_command(command)
                writer.write(f"{response}\r\n".encode())
                await writer.drain()
                
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logging.error(f"Shell simulation error: {e}")
    
    async def _log_command(self, command: str, source_ip: str, session_id: str):
        """Log executed command"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ssh_command',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ssh',
            service=self.name,
            session_id=session_id,
            payload=command,
            decoded_payload={
                'command': command,
                'is_download': any(x in command.lower() for x in ['wget', 'curl', 'fetch']),
                'is_malicious': any(x in command.lower() for x in ['rm -rf', '/dev/null', 'iptables', 'nc -'])
            }
        )
        
        await self.telemetry.log_event(event)
    
    async def _log_download_attempt(self, command: str, source_ip: str, 
                                    session_id: str):
        """Log malware download attempts"""
        # Extract URL
        import re
        url_match = re.search(r'(https?://[^\s]+)', command)
        url = url_match.group(1) if url_match else "unknown"
        
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ssh_download_attempt',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ssh',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'command': command,
                'url': url,
                'tool': 'wget' if 'wget' in command.lower() else 'curl'
            }
        )
        
        await self.telemetry.log_event(event)
        logging.warning(f"Download attempt from {source_ip}: {url}")
    
    def _execute_fake_command(self, command: str) -> str:
        """Execute fake command and return response"""
        # Exact matches
        if command in self.shell_responses:
            return self.shell_responses[command]
        
        # Pattern matching
        if command.startswith('ls'):
            return self.shell_responses['ls']
        elif command.startswith('cd'):
            return ""
        elif command.startswith('cat'):
            return "cat: file not found"
        elif command.startswith('wget') or command.startswith('curl'):
            return "Connecting... done.\nSaved to disk"
        elif command.startswith('chmod'):
            return ""
        elif command.startswith('./'):
            return f"{command}: Permission denied"
        else:
            return f"{command}: command not found"


if __name__ == "__main__":
    from honeypot_manager import TelemetryCollector
    from pathlib import Path
    
    async def main():
        telemetry = TelemetryCollector(Path("./honeypot_data"))
        
        ssh = SSHHoneypot(2222, telemetry)
        await ssh.start()
        
        print("SSH honeypot running on port 2222...")
        await asyncio.Event().wait()
    
    asyncio.run(main())
