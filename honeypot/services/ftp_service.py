#!/usr/bin/env python3
"""
FTP Honeypot Service
Captures login attempts and file uploads/downloads
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from honeypot_manager import HoneypotService, ProtocolEvent


class FTPHoneypot(HoneypotService):
    """FTP honeypot - captures credentials and file operations"""
    
    def __init__(self, port: int, telemetry, banner: Optional[str] = None):
        super().__init__("FTP", port, telemetry)
        self.banner = banner or "(vsFTPd 3.0.3)"

        # Valid credentials for honeypot
        self.valid_users = {
            'anonymous': '',
            'ftp': 'ftp',
            'admin': 'admin',
            'user': 'user'
        }
        
        # Fake filesystem
        self.fake_files = [
            'readme.txt',
            'backup.zip',
            'config.cfg',
            'database.sql',
            'passwords.txt'
        ]
        
        self.current_user: Optional[str] = None
        self.authenticated = False
    
    async def handle_client(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """Handle FTP client connection"""
        source_ip, source_port = self.get_peer_info(writer)
        session_id = self.telemetry.generate_session_id(
            source_ip, source_port, self.port
        )
        reader, writer = self.capture_streams(reader, writer, session_id)
        
        self.current_user = None
        self.authenticated = False
        
        try:
            # Send welcome banner
            await self._send_response(writer, 220, self.banner)
            
            # Log connection
            await self._log_connection(source_ip, source_port, session_id)
            
            # Process commands
            while True:
                data = await asyncio.wait_for(reader.readline(), timeout=300.0)
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                if not command:
                    continue
                
                # Log command
                await self._log_command(command, source_ip, session_id)
                
                # Process command
                await self._process_command(command, reader, writer, 
                                           source_ip, session_id)
                
        except asyncio.TimeoutError:
            logging.debug(f"FTP timeout from {source_ip}")
        except Exception as e:
            logging.error(f"Error handling FTP client: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def _send_response(self, writer: asyncio.StreamWriter, 
                            code: int, message: str):
        """Send FTP response"""
        response = f"{code} {message}\r\n"
        writer.write(response.encode())
        await writer.drain()
    
    async def _log_connection(self, source_ip: str, source_port: int, 
                             session_id: str):
        """Log FTP connection"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_connection',
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.port,
            protocol='ftp',
            service=self.name,
            session_id=session_id
        )
        
        await self.telemetry.log_event(event)
    
    async def _log_command(self, command: str, source_ip: str, session_id: str):
        """Log FTP command"""
        # Parse command and arguments
        parts = command.split(None, 1)
        cmd = parts[0].upper() if parts else ''
        arg = parts[1] if len(parts) > 1 else ''
        
        # Redact password from logging
        display_arg = arg
        if cmd == 'PASS':
            display_arg = '***REDACTED***'
        
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_command',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ftp',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'command': cmd,
                'argument': arg if cmd != 'PASS' else '***REDACTED***',
                'full_command': f"{cmd} {display_arg}" if display_arg else cmd
            }
        )
        
        await self.telemetry.log_event(event)
    
    async def _process_command(self, command: str, 
                              reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter,
                              source_ip: str, session_id: str):
        """Process FTP command"""
        parts = command.split(None, 1)
        cmd = parts[0].upper() if parts else ''
        arg = parts[1] if len(parts) > 1 else ''
        
        if cmd == 'USER':
            self.current_user = arg
            await self._send_response(writer, 331, "Please specify the password.")
            
        elif cmd == 'PASS':
            await self._handle_password(arg, writer, source_ip, session_id)
            
        elif cmd == 'SYST':
            await self._send_response(writer, 215, "UNIX Type: L8")
            
        elif cmd == 'PWD':
            # vsftpd sends just the quoted path; anonymous users are chrooted
            if self.current_user in ('anonymous', 'ftp'):
                await self._send_response(writer, 257, '"/"')
            else:
                await self._send_response(writer, 257, f'"/home/{self.current_user}"')
            
        elif cmd == 'LIST' or cmd == 'NLST':
            await self._handle_list(writer, source_ip, session_id)
            
        elif cmd == 'RETR':
            await self._handle_download(arg, writer, source_ip, session_id)
            
        elif cmd == 'STOR':
            await self._handle_upload(arg, reader, writer, source_ip, session_id)
            
        elif cmd == 'TYPE':
            if arg.upper().startswith('I'):
                await self._send_response(writer, 200, "Switching to Binary mode.")
            elif arg.upper().startswith('A'):
                await self._send_response(writer, 200, "Switching to ASCII mode.")
            else:
                await self._send_response(writer, 500, "Unrecognised TYPE command.")
            
        elif cmd == 'PASV':
            # Passive mode (simplified - won't actually work)
            await self._send_response(writer, 227, "Entering Passive Mode (127,0,0,1,195,149).")
            
        elif cmd == 'PORT':
            await self._send_response(writer, 200, "PORT command successful. Consider using PASV.")
            
        elif cmd == 'QUIT':
            await self._send_response(writer, 221, "Goodbye.")

        else:
            await self._send_response(writer, 500, "Unknown command.")
    
    async def _handle_password(self, password: str, 
                               writer: asyncio.StreamWriter,
                               source_ip: str, session_id: str):
        """Handle password authentication"""
        # Log login attempt
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_login_attempt',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ftp',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'username': self.current_user,
                'password': password,
                'success': False
            }
        )
        
        # Check credentials
        if self.current_user in self.valid_users:
            if self.valid_users[self.current_user] == password or \
               self.current_user == 'anonymous':
                self.authenticated = True
                event.decoded_payload['success'] = True
                await self._send_response(writer, 230, "Login successful.")
                logging.warning(f"FTP login: {self.current_user}:{password} from {source_ip}")
            else:
                await self._send_response(writer, 530, "Login incorrect.")
        else:
            await self._send_response(writer, 530, "Login incorrect.")
        
        await self.telemetry.log_event(event)
    
    async def _handle_list(self, writer: asyncio.StreamWriter,
                          source_ip: str, session_id: str):
        """Handle LIST command"""
        if not self.authenticated:
            await self._send_response(writer, 530, "Please login with USER and PASS.")
            return
        
        # Send fake file listing
        await self._send_response(writer, 150, "Here comes the directory listing.")
        
        listing = []
        for filename in self.fake_files:
            listing.append(f"-rw-r--r-- 1 ftp ftp 1024 Jan 01 12:00 {filename}")
        
        # In real FTP, this would go over data connection
        # For honeypot, we'll just send it on control connection
        for line in listing:
            writer.write(f"{line}\r\n".encode())
        await writer.drain()

        await self._send_response(writer, 226, "Directory send OK.")
        
        # Log listing request
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_list',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ftp',
            service=self.name,
            session_id=session_id,
            decoded_payload={'files': self.fake_files}
        )
        
        await self.telemetry.log_event(event)
    
    async def _handle_download(self, filename: str, 
                               writer: asyncio.StreamWriter,
                               source_ip: str, session_id: str):
        """Handle RETR (download) command"""
        if not self.authenticated:
            await self._send_response(writer, 530, "Please login with USER and PASS.")
            return
        
        # Log download attempt
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_download',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ftp',
            service=self.name,
            session_id=session_id,
            decoded_payload={'filename': filename}
        )
        
        await self.telemetry.log_event(event)
        
        if filename in self.fake_files:
            # Size matches the 1024 bytes shown in the LIST output
            await self._send_response(
                writer, 150,
                f"Opening BINARY mode data connection for {filename} (1024 bytes).")
            # Fake file transfer
            await asyncio.sleep(0.1)
            await self._send_response(writer, 226, "Transfer complete.")
        else:
            await self._send_response(writer, 550, "Failed to open file.")
    
    async def _handle_upload(self, filename: str,
                            reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter,
                            source_ip: str, session_id: str):
        """Handle STOR (upload) command"""
        if not self.authenticated:
            await self._send_response(writer, 530, "Please login with USER and PASS.")
            return
        
        await self._send_response(writer, 150, "Ok to send data.")

        # Try to capture uploaded data (simplified)
        try:
            # In real FTP, this comes over data connection
            # For honeypot demo, we'll attempt to read some data
            data = await asyncio.wait_for(reader.read(1024*1024), timeout=30.0)  # 1MB max
            
            if data:
                # Save uploaded file
                metadata = {
                    'filename': filename,
                    'username': self.current_user
                }
                await self.telemetry.save_sample(data, source_ip, 'ftp_upload', metadata)
        except asyncio.TimeoutError:
            pass

        await self._send_response(writer, 226, "Transfer complete.")
        
        # Log upload
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_upload',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ftp',
            service=self.name,
            session_id=session_id,
            decoded_payload={'filename': filename}
        )
        
        await self.telemetry.log_event(event)
        logging.warning(f"FTP upload: {filename} from {source_ip}")


if __name__ == "__main__":
    from honeypot_manager import TelemetryCollector
    from pathlib import Path
    
    async def main():
        telemetry = TelemetryCollector(Path("./honeypot_data"))
        
        ftp = FTPHoneypot(2121, telemetry)
        await ftp.start()
        
        print("FTP honeypot running on port 2121...")
        await asyncio.Event().wait()
    
    asyncio.run(main())
