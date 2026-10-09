#!/usr/bin/env python3
"""
FTP Honeypot Service
Captures login attempts and file uploads/downloads
"""

import asyncio
import logging
import os
import random
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from honeypot_manager import HoneypotService, ProtocolEvent


# vsftpd 3.0.3's replies with its default Ubuntu build (no TLS)
FEAT_LINES = ['EPRT', 'EPSV', 'MDTM', 'PASV', 'REST STREAM', 'SIZE', 'TVFS']
HELP_LINES = [
    'ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD',
    'MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR',
    'RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD',
    'XPWD XRMD',
]
FILE_MTIME = '20260101120000'  # matches "Jan 01  2026" in the LIST output
FILE_SIZE = 1024                # matches the LIST output
DATA_TIMEOUT = 60.0             # vsftpd's accept_timeout
MAX_UPLOAD = 10 * 1024 * 1024   # stop reading an upload past this


def pasv_ports() -> list:
    """Passive data ports, e.g. FTP_PASV_PORTS=40000-40009; must be published"""
    first, _, last = os.environ.get('FTP_PASV_PORTS', '40000-40009').partition('-')
    return list(range(int(first), int(last or first) + 1))


class PassiveListener:
    """One-shot passive-mode listener that accepts only the control client's IP,
    as vsftpd does with pasv_promiscuous=NO"""

    def __init__(self, client_ip: str):
        self.client_ip = client_ip
        self.server = None
        self.port = None
        self.conn = asyncio.get_running_loop().create_future()

    async def open(self, ports: list) -> bool:
        for port in random.sample(ports, len(ports)):
            try:
                self.server = await asyncio.start_server(self._accept, '0.0.0.0', port)
            except OSError:
                continue  # in use by another session
            self.port = self.server.sockets[0].getsockname()[1]
            return True
        return False

    async def _accept(self, reader, writer):
        peer = (writer.get_extra_info('peername') or ('',))[0]
        if peer != self.client_ip or self.conn.done():
            writer.close()
            return
        self.conn.set_result((reader, writer))

    async def wait(self, timeout: float):
        try:
            return await asyncio.wait_for(asyncio.shield(self.conn), timeout)
        except asyncio.TimeoutError:
            return None

    def close(self):
        if self.server:
            self.server.close()
        if not self.conn.done():
            self.conn.cancel()


def fake_content(filename: str) -> bytes:
    """Stable FILE_SIZE bytes per file name"""
    return random.Random(filename).randbytes(FILE_SIZE)


@dataclass
class FTPSession:
    """Per-connection state; the service object is shared by all clients"""
    source_ip: str
    user: Optional[str] = None
    authenticated: bool = False
    binary: bool = False
    pasv: Optional[PassiveListener] = None
    active: bool = False  # PORT/EPRT accepted; never connected to


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
        
        # Address advertised in PASV replies; never the container's own IP
        self.public_ip = os.environ.get('PUBLIC_IP') or '127.0.0.1'
        self.version = self.banner.strip('()')
        self.pasv_ports = pasv_ports()
    
    async def handle_client(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """Handle FTP client connection"""
        source_ip, source_port = self.get_peer_info(writer)
        session_id = self.telemetry.generate_session_id(
            source_ip, source_port, self.port
        )
        reader, writer = self.capture_streams(reader, writer, session_id)
        sess = FTPSession(source_ip)

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
                
                # Process command; False means the client sent QUIT
                if not await self._process_command(command, reader, writer,
                                                   sess, session_id):
                    break
                
        except asyncio.TimeoutError:
            logging.debug(f"FTP timeout from {source_ip}")
        except Exception as e:
            logging.error(f"Error handling FTP client: {e}")
        finally:
            if sess.pasv:
                sess.pasv.close()
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

    async def _send_multiline(self, writer: asyncio.StreamWriter, code: int,
                              first: str, lines: list, last: str):
        """Send a multi-line reply: "211-first", indented lines, "211 last" """
        body = [f"{code}-{first}"] + lines + [f"{code} {last}"]
        writer.write(''.join(f"{line}\r\n" for line in body).encode())
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
    
    def _home(self, sess: FTPSession) -> str:
        # Anonymous users are chrooted to /; others land in their home
        return '/' if sess.user in ('anonymous', 'ftp') else f'/home/{sess.user}'

    async def _process_command(self, command: str,
                              reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter,
                              sess: FTPSession, session_id: str) -> bool:
        """Process one FTP command; returns False once the session should end"""
        parts = command.split(None, 1)
        cmd = parts[0].upper() if parts else ''
        arg = parts[1] if len(parts) > 1 else ''

        if cmd == 'QUIT':
            await self._send_response(writer, 221, "Goodbye.")
            return False

        # Commands vsftpd answers before login
        if cmd == 'USER':
            if sess.authenticated:
                await self._send_response(writer, 530, "Can't change to another user.")
            else:
                sess.user = arg
                await self._send_response(writer, 331, "Please specify the password.")
        elif cmd == 'PASS':
            if sess.authenticated:
                await self._send_response(writer, 230, "Already logged in.")
            elif sess.user is None:
                await self._send_response(writer, 503, "Login with USER first.")
            else:
                await self._handle_password(arg, writer, sess, session_id)
        elif cmd == 'FEAT':
            await self._send_multiline(writer, 211, "Features:",
                                       [f" {f}" for f in FEAT_LINES], "End")
        elif cmd == 'OPTS':
            if arg.upper() == 'UTF8 ON':
                await self._send_response(writer, 200, "Always in UTF8 mode.")
            else:
                await self._send_response(writer, 501, "Option not understood.")

        elif not sess.authenticated:
            await self._send_response(writer, 530, "Please login with USER and PASS.")

        elif cmd == 'SYST':
            await self._send_response(writer, 215, "UNIX Type: L8")
        elif cmd == 'HELP':
            await self._send_multiline(writer, 214, "The following commands are recognized.",
                                       [f" {line}" for line in HELP_LINES], "Help OK.")
        elif cmd == 'NOOP':
            await self._send_response(writer, 200, "NOOP ok.")
        elif cmd == 'STAT' and not arg:
            await self._send_multiline(writer, 211, "FTP server status:", [
                f"     Connected to {sess.source_ip}",
                f"     Logged in as {'ftp' if sess.user == 'anonymous' else sess.user}",
                f"     TYPE: {'BINARY' if sess.binary else 'ASCII'}",
                "     No session bandwidth limit",
                "     Session timeout in seconds is 300",
                "     Control connection is plain text",
                "     Data connections will be plain text",
                "     At session startup, client count was 1",
                f"     {self.version} - secure, fast, open source",
            ], "End of status")
        elif cmd in ('PWD', 'XPWD'):
            # vsftpd sends just the quoted path
            await self._send_response(writer, 257, f'"{self._home(sess)}"')
        elif cmd in ('CWD', 'XCWD'):
            if arg.rstrip('/') in ('', '.', '..', '~') or arg in ('/', self._home(sess)):
                await self._send_response(writer, 250, "Directory successfully changed.")
            else:
                await self._send_response(writer, 550, "Failed to change directory.")
        elif cmd in ('CDUP', 'XCUP'):
            await self._send_response(writer, 250, "Directory successfully changed.")
        elif cmd == 'STAT':
            # STAT <path> lists over the control connection
            await self._send_multiline(writer, 213, "Status follows:",
                                       self._listing(), "End of status")
        elif cmd in ('LIST', 'NLST'):
            await self._handle_list(writer, sess, session_id, names_only=cmd == 'NLST')
        elif cmd == 'SIZE':
            if arg.lstrip('/') in self.fake_files:
                await self._send_response(writer, 213, str(FILE_SIZE))
            else:
                await self._send_response(writer, 550, "Could not get file size.")
        elif cmd == 'MDTM':
            if arg.lstrip('/') in self.fake_files:
                await self._send_response(writer, 213, FILE_MTIME)
            else:
                await self._send_response(writer, 550, "Could not get file modification time.")
        elif cmd == 'RETR':
            await self._handle_download(arg, writer, sess, session_id)
        elif cmd == 'STOR':
            await self._handle_upload(arg, reader, writer, sess, session_id)
        elif cmd in ('MKD', 'XMKD', 'RMD', 'XRMD', 'DELE', 'RNFR', 'RNTO', 'APPE', 'STOU'):
            await self._send_response(writer, 550, "Permission denied.")
        elif cmd == 'SITE':
            await self._send_response(writer, 500, "Unknown SITE command.")
        elif cmd == 'TYPE':
            if arg.upper().startswith(('I', 'L')):
                sess.binary = True
                await self._send_response(writer, 200, "Switching to Binary mode.")
            elif arg.upper().startswith('A'):
                sess.binary = False
                await self._send_response(writer, 200, "Switching to ASCII mode.")
            else:
                await self._send_response(writer, 500, "Unrecognised TYPE command.")
        elif cmd == 'MODE':
            if arg.upper() == 'S':
                await self._send_response(writer, 200, "Mode set to S.")
            else:
                await self._send_response(writer, 504, "Bad MODE command.")
        elif cmd == 'STRU':
            if arg.upper() == 'F':
                await self._send_response(writer, 200, "Structure set to F.")
            else:
                await self._send_response(writer, 504, "Bad STRU command.")
        elif cmd == 'REST':
            await self._send_response(writer, 350, f"Restart position accepted ({arg or 0}).")
        elif cmd == 'ABOR':
            await self._send_response(writer, 225, "No transfer to ABOR.")
        elif cmd == 'ALLO':
            await self._send_response(writer, 202, "ALLO command ignored.")
        elif cmd in ('PASV', 'EPSV'):
            port = await self._passive(sess)
            if port is None:
                await self._send_response(writer, 425, "Could not listen for passive connection.")
            elif cmd == 'PASV':
                address = ','.join(self.public_ip.split('.'))
                await self._send_response(
                    writer, 227, f"Entering Passive Mode ({address},{port >> 8},{port & 255}).")
            else:
                await self._send_response(writer, 229, f"Entering Extended Passive Mode (|||{port}|)")
        elif cmd in ('PORT', 'EPRT'):
            # Only the client's own address is accepted (vsftpd port_promiscuous=NO),
            # and the sensor never connects out, so it can't be used to bounce
            if self._active_ip(cmd, arg) != sess.source_ip:
                await self._send_response(writer, 500, f"Illegal {cmd} command.")
            else:
                if sess.pasv:
                    sess.pasv.close()
                    sess.pasv = None
                sess.active = True
                alt = 'PASV' if cmd == 'PORT' else 'EPSV'
                await self._send_response(writer, 200, f"{cmd} command successful. Consider using {alt}.")
        else:
            await self._send_response(writer, 500, "Unknown command.")
        return True

    async def _handle_password(self, password: str,
                               writer: asyncio.StreamWriter,
                               sess: FTPSession, session_id: str):
        """Handle password authentication"""
        # Log login attempt
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_login_attempt',
            source_ip=sess.source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ftp',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'username': sess.user,
                'password': password,
                'success': False
            }
        )
        
        # Check credentials
        if sess.user in self.valid_users:
            if self.valid_users[sess.user] == password or \
               sess.user == 'anonymous':
                sess.authenticated = True
                event.decoded_payload['success'] = True
                await self._send_response(writer, 230, "Login successful.")
                logging.warning(f"FTP login: {sess.user}:{password} from {sess.source_ip}")
            else:
                await self._send_response(writer, 530, "Login incorrect.")
        else:
            await self._send_response(writer, 530, "Login incorrect.")
        
        await self.telemetry.log_event(event)
    
    async def _passive(self, sess: FTPSession) -> Optional[int]:
        """Open a passive listener, replacing any earlier one"""
        if sess.pasv:
            sess.pasv.close()
        sess.active = False
        sess.pasv = PassiveListener(sess.source_ip)
        if await sess.pasv.open(self.pasv_ports):
            return sess.pasv.port
        sess.pasv = None
        return None

    @staticmethod
    def _active_ip(cmd: str, arg: str) -> Optional[str]:
        """Address from "PORT h1,h2,h3,h4,p1,p2" or "EPRT |1|h|p|" """
        if cmd == 'PORT':
            parts = arg.split(',')
            return '.'.join(parts[:4]) if len(parts) == 6 else None
        parts = arg.split(arg[:1]) if arg else []
        return parts[2] if len(parts) == 5 and parts[1] == '1' else None

    async def _data_connection(self, writer: asyncio.StreamWriter,
                               sess: FTPSession, session_id: str):
        """The client's data connection, or None after replying 425. Like
        vsftpd, each PASV/PORT covers one transfer."""
        listener, sess.pasv = sess.pasv, None
        if listener is None:
            if sess.active:
                sess.active = False
                await self._send_response(writer, 425, "Failed to establish connection.")
            else:
                await self._send_response(writer, 425, "Use PORT or PASV first.")
            return None
        try:
            conn = await listener.wait(DATA_TIMEOUT)
        finally:
            listener.close()
        if conn is None:
            await self._send_response(writer, 425, "Failed to establish connection.")
            return None
        return self.capture_streams(*conn, session_id)

    @staticmethod
    async def _close_data(data_writer):
        try:
            data_writer.close()
            await data_writer.wait_closed()
        except Exception:
            pass

    def _listing(self) -> list:
        # vsftpd's layout: numeric IDs (text_userdb_names=NO), and the year
        # instead of the time for files over six months old
        return [f"-rw-r--r--    1 0        0        {FILE_SIZE:>8} Jan 01  2026 {name}"
                for name in self.fake_files]

    async def _handle_list(self, writer: asyncio.StreamWriter,
                          sess: FTPSession, session_id: str, names_only: bool = False):
        """Handle LIST/NLST: the listing goes over the data connection"""
        data = await self._data_connection(writer, sess, session_id)
        if data is None:
            return
        _, data_writer = data
        await self._send_response(writer, 150, "Here comes the directory listing.")
        lines = self.fake_files if names_only else self._listing()
        data_writer.write(''.join(f"{line}\r\n" for line in lines).encode())
        await data_writer.drain()
        await self._close_data(data_writer)
        await self._send_response(writer, 226, "Directory send OK.")

        # Log listing request
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_list',
            source_ip=sess.source_ip,
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
                               sess: FTPSession, session_id: str):
        """Handle RETR (download) command"""
        # Log download attempt
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_download',
            source_ip=sess.source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ftp',
            service=self.name,
            session_id=session_id,
            decoded_payload={'filename': filename}
        )

        await self.telemetry.log_event(event)

        # vsftpd checks the file before touching the data connection
        name = filename.lstrip('/')
        if name not in self.fake_files:
            await self._send_response(writer, 550, "Failed to open file.")
            return
        data = await self._data_connection(writer, sess, session_id)
        if data is None:
            return
        _, data_writer = data
        mode = 'BINARY' if sess.binary else 'ASCII'
        await self._send_response(
            writer, 150, f"Opening {mode} mode data connection for {name} ({FILE_SIZE} bytes).")
        data_writer.write(fake_content(name))
        await data_writer.drain()
        await self._close_data(data_writer)
        await self._send_response(writer, 226, "Transfer complete.")

    async def _handle_upload(self, filename: str,
                            reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter,
                            sess: FTPSession, session_id: str):
        """Handle STOR (upload): the file arrives on the data connection"""
        conn = await self._data_connection(writer, sess, session_id)
        if conn is None:
            return
        data_reader, data_writer = conn
        await self._send_response(writer, 150, "Ok to send data.")

        data = bytearray()
        truncated = False
        try:
            while True:
                chunk = await asyncio.wait_for(data_reader.read(65536), timeout=DATA_TIMEOUT)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) >= MAX_UPLOAD:
                    del data[MAX_UPLOAD:]
                    truncated = True
                    break
        except (asyncio.TimeoutError, ConnectionError):
            pass
        await self._close_data(data_writer)

        if data:
            metadata = {
                'filename': filename,
                'username': sess.user,
                'truncated': truncated
            }
            await self.telemetry.save_sample(bytes(data), sess.source_ip, 'ftp_upload', metadata)

        await self._send_response(writer, 226, "Transfer complete.")

        # Log upload
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ftp_upload',
            source_ip=sess.source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ftp',
            service=self.name,
            session_id=session_id,
            decoded_payload={'filename': filename, 'size': len(data), 'truncated': truncated}
        )

        await self.telemetry.log_event(event)
        logging.warning(f"FTP upload: {filename} ({len(data)} bytes) from {sess.source_ip}")


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
