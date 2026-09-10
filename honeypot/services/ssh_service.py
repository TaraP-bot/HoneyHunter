#!/usr/bin/env python3
"""
SSH Honeypot Service
Captures login attempts, credentials, and commands using asyncssh
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    ASYNCSSH_AVAILABLE = False
    logging.warning("asyncssh not available - SSH honeypot will use simplified mode")

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.honeypot_manager import HoneypotService, ProtocolEvent


class SSHHoneypot(HoneypotService):
    """SSH honeypot - captures credentials and commands"""
    
    def __init__(self, port: int, telemetry):
        super().__init__("SSH", port, telemetry)
        
        # Common credential pairs to "accept"
        self.fake_credentials = {
            'root': ['root', 'password', 'toor', '123456', 'admin', ''],
            'admin': ['admin', 'password', '123456', ''],
            'user': ['user', 'password', ''],
            'pi': ['raspberry', 'pi', ''],
            'ubuntu': ['ubuntu', ''],
            'test': ['test', ''],
        }
        
        # SSH version string
        self.ssh_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        
    async def start(self):
        """Start SSH honeypot server"""
        if ASYNCSSH_AVAILABLE:
            await self._start_asyncssh()
        else:
            await super().start()
    
    async def _start_asyncssh(self):
        """Start SSH server using asyncssh"""
        logging.info(f"Starting {self.name} honeypot on port {self.port} (asyncssh mode)")
        
        try:
            # Generate host key if needed
            if not os.path.exists('/tmp/ssh_host_key'):
                key = asyncssh.generate_private_key('ssh-rsa')
                key.write_private_key('/tmp/ssh_host_key')
            
            # Start SSH server
            await asyncssh.create_server(
                lambda: SSHServerProtocol(self),
                '',
                self.port,
                server_host_keys=['/tmp/ssh_host_key'],
                server_version=self.ssh_version,
            )
            
            logging.info(f"{self.name} honeypot listening on port {self.port}")
            
            # Keep server running
            await asyncio.Event().wait()
            
        except Exception as e:
            logging.error(f"Failed to start SSH honeypot: {e}")
            # Fall back to simple mode
            await super().start()
    
    async def handle_client(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """Handle SSH client connection (fallback mode)"""
        source_ip, source_port = self.get_peer_info(writer)
        session_id = self.telemetry.generate_session_id(
            source_ip, source_port, self.port
        )
        reader, writer = self.capture_streams(reader, writer, session_id)
        
        try:
            # Send SSH version
            writer.write(f"{self.ssh_version}\r\n".encode())
            await writer.drain()
            
            # Log connection
            await self._log_connection(source_ip, source_port, session_id)
            
            # Read some data (won't parse properly without asyncssh)
            data = await asyncio.wait_for(reader.read(4096), timeout=10.0)
            
            await self._log_raw_data(data, source_ip, source_port, session_id)
        
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
    
    async def _log_raw_data(self, data: bytes, source_ip: str, source_port: int,
                           session_id: str):
        """Log raw SSH data (fallback mode)"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ssh_data',
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.port,
            protocol='ssh',
            service=self.name,
            session_id=session_id,
            payload=data[:500].hex(),  # Store as hex
            payload_size=len(data),
            decoded_payload={'note': 'Raw SSH protocol data - install asyncssh for proper parsing'}
        )
        
        await self.telemetry.log_event(event)
    
    async def log_login_attempt(self, username: str, password: str, 
                               source_ip: str, session_id: str):
        """Log captured credentials"""
        success = username in self.fake_credentials and password in self.fake_credentials.get(username, [])
        
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
                'success': success
            }
        )
        
        await self.telemetry.log_event(event)
        logging.warning(f"SSH login attempt: {username}:{password} from {source_ip}")
        
        return success
    
    async def log_command(self, command: str, source_ip: str, session_id: str):
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
            decoded_payload={
                'command': command
            }
        )
        
        await self.telemetry.log_event(event)
        logging.info(f"SSH command from {source_ip}: {command}")


class SSHServerProtocol(asyncssh.SSHServer):
    """asyncssh server protocol handler"""
    
    def __init__(self, honeypot: SSHHoneypot):
        self.honeypot = honeypot
        self.source_ip = None
        self.session_id = None
    
    def connection_made(self, conn):
        """Handle new connection"""
        self.conn = conn
        peername = conn.get_extra_info('peername')
        if peername:
            self.source_ip = peername[0]
            self.session_id = self.honeypot.telemetry.generate_session_id(
                self.source_ip, peername[1], self.honeypot.port
            )
            
            asyncio.create_task(self.honeypot._log_connection(
                self.source_ip, peername[1], self.session_id
            ))
    
    def password_auth_supported(self):
        """Enable password authentication"""
        return True
    
    def validate_password(self, username, password):
        """Validate credentials and log attempt"""
        if not self.source_ip:
            return False
        
        # Log the attempt
        asyncio.create_task(self.honeypot.log_login_attempt(
            username, password, self.source_ip, self.session_id
        ))
        
        # Check if credentials should be accepted
        if username in self.honeypot.fake_credentials:
            if password in self.honeypot.fake_credentials[username]:
                return True
        
        return False
    
    def session_requested(self):
        """Create session after successful authentication"""
        return SSHSessionHandler(self.honeypot, self.source_ip, self.session_id)


class SSHSessionHandler(asyncssh.SSHServerSession):
    """Handle SSH session after authentication"""
    
    def __init__(self, honeypot: SSHHoneypot, source_ip: str, session_id: str):
        self.honeypot = honeypot
        self.source_ip = source_ip
        self.session_id = session_id
        self._input = ''
    
    def connection_made(self, chan):
        """Session started"""
        self._chan = chan
    
    def shell_requested(self):
        """Shell requested"""
        return True
    
    def session_started(self):
        """Send welcome message and prompt"""
        self._chan.write('\r\nWelcome to Ubuntu 20.04.3 LTS\r\n')
        self._chan.write('root@ubuntu:~# ')
    
    def data_received(self, data, datatype):
        """Handle received data"""
        self._input += data
        
        # Echo back for interactive feel
        self._chan.write(data)
        
        # Check for newline
        if '\n' in self._input or '\r' in self._input:
            command = self._input.strip()
            self._input = ''
            
            if command:
                # Log command
                asyncio.create_task(self.honeypot.log_command(
                    command, self.source_ip, self.session_id
                ))
                
                # Send fake response
                response = self._get_command_response(command)
                if response:
                    self._chan.write(f'\r\n{response}\r\n')
                else:
                    self._chan.write('\r\n')
            
            # Send new prompt
            self._chan.write('root@ubuntu:~# ')
    
    def _get_command_response(self, command: str) -> str:
        """Get fake response for command"""
        responses = {
            'whoami': 'root',
            'pwd': '/root',
            'id': 'uid=0(root) gid=0(root) groups=0(root)',
            'uname -a': 'Linux ubuntu 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux',
            'ls': 'Desktop  Documents  Downloads',
            'ls -la': 'total 32\ndrwxr-xr-x 5 root root 4096 Jan 15 10:30 .\ndrwxr-xr-x 3 root root 4096 Jan 15 10:28 ..',
        }
        
        # Exact match
        if command in responses:
            return responses[command]
        
        # Partial match
        for cmd_pattern, response in responses.items():
            if command.startswith(cmd_pattern):
                return response
        
        # Default
        if command.startswith('cat '):
            return 'cat: permission denied'
        elif command.startswith('cd '):
            return ''
        else:
            return f'{command}: command not found'
    
    def eof_received(self):
        """Handle EOF"""
        self._chan.exit(0)
    
    def break_received(self, msec):
        """Handle break signal"""
        return True
