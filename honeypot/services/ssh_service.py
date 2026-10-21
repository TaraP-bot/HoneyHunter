#!/usr/bin/env python3
"""
SSH Honeypot Service
Captures login attempts, credentials, and commands using asyncssh
"""

import asyncio
import logging
import shlex
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


# Fake host identity. Keep these consistent with each other and with the
# ssh_version banner (OpenSSH 8.2p1-4ubuntu0.5, published 2022-04-02):
# a focal box patched in July 2022 runs kernel 5.4.0-122.138 and still
# reports 20.04.4, as 20.04.5 was released 2022-09-02.
FAKE_HOSTNAME = "ubuntu"
FAKE_OS_VERSION = "20.04.4"
FAKE_KERNEL_RELEASE = "5.4.0-122-generic"
FAKE_KERNEL_VERSION = "#138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022"

FAKE_MOTD = (
    f"Welcome to Ubuntu {FAKE_OS_VERSION} LTS "
    f"(GNU/Linux {FAKE_KERNEL_RELEASE} x86_64)\n"
    "\n"
    " * Documentation:  https://help.ubuntu.com\n"
    " * Management:     https://landscape.canonical.com\n"
    " * Support:        https://ubuntu.com/advantage\n"
)

FAKE_FILES = {
    '/etc/os-release': (
        'NAME="Ubuntu"\n'
        f'VERSION="{FAKE_OS_VERSION} LTS (Focal Fossa)"\n'
        'ID=ubuntu\n'
        'ID_LIKE=debian\n'
        f'PRETTY_NAME="Ubuntu {FAKE_OS_VERSION} LTS"\n'
        'VERSION_ID="20.04"\n'
        'HOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        'VERSION_CODENAME=focal\n'
        'UBUNTU_CODENAME=focal'
    ),
    '/etc/issue': f'Ubuntu {FAKE_OS_VERSION} LTS \\n \\l\n',
    '/etc/hostname': FAKE_HOSTNAME,
}
# lib/os-release is what /etc/os-release symlinks to
FAKE_FILES['/usr/lib/os-release'] = FAKE_FILES['/etc/os-release']


# Stop keeping an scp upload past this (matches the FTP service's cap);
# the rest is still read and acknowledged so the client sees success
MAX_SCP_UPLOAD = 10 * 1024 * 1024


def scp_sink_target(command: str) -> Optional[str]:
    """Return the target path if command is an scp receive ("scp -t PATH"),
    which is what the client runs remotely for an upload; else None"""
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts or os.path.basename(parts[0]) != 'scp':
        return None
    flags = ''.join(p[1:] for p in parts[1:] if p.startswith('-') and p != '-')
    paths = [p for p in parts[1:] if not p.startswith('-') or p == '-']
    if 't' not in flags or 'f' in flags or len(paths) != 1:
        return None
    return paths[0]


class ScpSink:
    """Receiving side of the scp (rcp) protocol, as run by "scp -t".

    The sink sends a zero byte when ready and after each accepted message.
    The client sends control lines: "C<mode> <size> <name>" followed by the
    file bytes and a zero byte, "D<mode> 0 <name>" / "E" to enter and leave
    a directory (-r), "T<mtime> 0 <atime> 0" for times (-p), or a
    1 (warning) / 2 (fatal) byte followed by a message.
    """

    def __init__(self, on_file, limit: int = MAX_SCP_UPLOAD):
        self.on_file = on_file  # called with (data, name, mode, size, complete)
        self.limit = limit
        self.buf = bytearray()
        self.dirs = []
        self.file = None   # (name, mode, size) while receiving file bytes
        self.data = bytearray()
        self.remaining = 0
        self.done = False

    def feed(self, chunk: bytes) -> bytes:
        """Consume client bytes; return what the sink sends back"""
        self.buf.extend(chunk)
        out = bytearray()
        while not self.done:
            if self.file:
                if self.remaining:
                    take = min(self.remaining, len(self.buf))
                    if not take:
                        break
                    room = self.limit - len(self.data)
                    self.data.extend(self.buf[:min(take, max(room, 0))])
                    del self.buf[:take]
                    self.remaining -= take
                    continue
                if not self.buf:
                    break
                # The client follows the file bytes with a status byte
                del self.buf[:1]
                self._finish_file(complete=True)
                out += b'\0'
                continue
            end = self.buf.find(b'\n')
            if end < 0:
                break
            line = bytes(self.buf[:end]).decode('utf-8', 'replace')
            del self.buf[:end + 1]
            out += self._control(line)
        return bytes(out)

    def _control(self, line: str) -> bytes:
        kind, rest = line[:1], line[1:]
        if kind in ('C', 'D'):
            try:
                mode, size, name = rest.split(' ', 2)
                int(mode, 8)
                size = int(size)
                if size < 0 or not name or '/' in name or name in ('.', '..'):
                    raise ValueError
            except ValueError:
                return self._fail('scp: protocol error: bad mode\n')
            if kind == 'D':
                self.dirs.append(name)
            else:
                self.file = ('/'.join(self.dirs + [name]), mode, size)
                self.remaining = size
                self.data = bytearray()
            return b'\0'
        if kind == 'E':
            if self.dirs:
                self.dirs.pop()
            return b'\0'
        if kind == 'T':
            return b'\0'
        if kind in ('\x01', '\x02'):
            # Client-side warning or fatal error; nothing to acknowledge
            if kind == '\x02':
                self.done = True
            return b''
        return self._fail('scp: protocol error: expected control record\n')

    def _fail(self, message: str) -> bytes:
        self.done = True
        return b'\x02' + message.encode()

    def _finish_file(self, complete: bool):
        name, mode, size = self.file
        self.file = None
        self.on_file(bytes(self.data), name, mode, size, complete)
        self.data = bytearray()

    def close(self):
        """Connection ended; keep whatever arrived of an unfinished file"""
        if self.file and self.data:
            self._finish_file(complete=False)
        self.done = True


def fake_uname(args: list) -> str:
    """Mimic GNU coreutils uname for the fake host"""
    fields = [
        ('s', 'Linux'),
        ('n', FAKE_HOSTNAME),
        ('r', FAKE_KERNEL_RELEASE),
        ('v', FAKE_KERNEL_VERSION),
        ('m', 'x86_64'),
        ('p', 'x86_64'),
        ('i', 'x86_64'),
        ('o', 'GNU/Linux'),
    ]
    long_opts = {
        '--all': 'a', '--kernel-name': 's', '--nodename': 'n',
        '--kernel-release': 'r', '--kernel-version': 'v', '--machine': 'm',
        '--processor': 'p', '--hardware-platform': 'i',
        '--operating-system': 'o',
    }
    wanted = set()
    for arg in args:
        if arg in long_opts:
            wanted.add(long_opts[arg])
        elif arg.startswith('-') and not arg.startswith('--'):
            for flag in arg[1:]:
                if flag not in 'asnrvmpio':
                    return (f"uname: invalid option -- '{flag}'\n"
                            "Try 'uname --help' for more information.")
                wanted.add(flag)
        else:
            return (f"uname: extra operand '{arg}'\n"
                    "Try 'uname --help' for more information.")
    if 'a' in wanted:
        wanted = set('snrvmpio')
    if not wanted:
        wanted = {'s'}
    return ' '.join(value for flag, value in fields if flag in wanted)


class SSHHoneypot(HoneypotService):
    """SSH honeypot - captures credentials and commands"""
    
    def __init__(self, port: int, telemetry, ssh_version: Optional[str] = None):
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
        
        # SSH software version (asyncssh adds the "SSH-2.0-" prefix itself,
        # so drop one if the config includes it)
        ssh_version = ssh_version or "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        self.ssh_version = ssh_version.removeprefix("SSH-2.0-")
        
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
            # Generate host key if needed. Keep it in the persistent data dir:
            # a key that changes on every restart is a honeypot tell for
            # scanners that track host keys over time
            host_key = str(self.telemetry.output_dir / 'ssh_host_key')
            if not os.path.exists(host_key):
                key = asyncssh.generate_private_key('ssh-rsa')
                key.write_private_key(host_key)
                os.chmod(host_key, 0o600)

            # Start SSH server
            await asyncssh.create_server(
                lambda: SSHServerProtocol(self),
                '',
                self.port,
                server_host_keys=[host_key],
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
            writer.write(f"SSH-2.0-{self.ssh_version}\r\n".encode())
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

    async def log_request(self, request: str, value: str, source_ip: str,
                          session_id: str, accepted: bool = False):
        """Log an SSH request (exec, subsystem, direct-tcpip) so what the
        client tried is recorded; most are rejected and not served"""
        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ssh_request',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ssh',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'request': request,
                'value': value,
                'accepted': accepted
            }
        )

        await self.telemetry.log_event(event)
        logging.info(f"SSH {request} request from {source_ip}: {value}")

    async def save_scp_upload(self, data: bytes, name: str, mode: str,
                              size: int, complete: bool, target: str,
                              command: str, source_ip: str, session_id: str):
        """Keep a file received over scp as a sample and log the upload"""
        truncated = not complete or len(data) < size
        sha256 = None
        if data:
            metadata = {
                'filename': name,
                'target': target,
                'mode': mode,
                'declared_size': size,
                'command': command,
                'session_id': session_id,
                'artifact_kind': 'scp_upload',
                'truncated': truncated,
            }
            sha256 = await self.telemetry.save_sample(
                data, source_ip, 'scp_upload', metadata)

        event = ProtocolEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type='ssh_upload',
            source_ip=source_ip,
            source_port=0,
            dest_port=self.port,
            protocol='ssh',
            service=self.name,
            session_id=session_id,
            decoded_payload={
                'filename': name,
                'target': target,
                'mode': mode,
                'size': size,
                'captured': len(data),
                'truncated': truncated,
                'sha256': sha256,
            }
        )

        await self.telemetry.log_event(event)
        logging.warning(f"SCP upload: {name} ({len(data)} of {size} bytes) "
                        f"to {target} from {source_ip}")


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
    
    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        """Log port-forwarding attempts (ssh -L / proxying); still rejected"""
        asyncio.create_task(self.honeypot.log_request(
            'direct-tcpip', f'{dest_host}:{dest_port}',
            self.source_ip, self.session_id
        ))
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
        self._scp = None
    
    def connection_made(self, chan):
        """Session started"""
        self._chan = chan
    
    def exec_requested(self, command):
        """Log a command sent without a shell (ssh host 'cmd'). Only an scp
        upload is served, so the file can be captured; the rest are rejected"""
        target = scp_sink_target(command)
        asyncio.create_task(self.honeypot.log_request(
            'exec', command, self.source_ip, self.session_id,
            accepted=target is not None
        ))
        if target is None:
            return False

        def on_file(data, name, mode, size, complete):
            asyncio.create_task(self.honeypot.save_scp_upload(
                data, name, mode, size, complete, target, command,
                self.source_ip, self.session_id
            ))

        # File contents are binary; shell sessions keep the UTF-8 default
        self._chan.set_encoding(None)
        self._scp = ScpSink(on_file)
        return True

    def subsystem_requested(self, subsystem):
        """Log subsystem requests such as sftp; still rejected"""
        asyncio.create_task(self.honeypot.log_request(
            'subsystem', subsystem, self.source_ip, self.session_id
        ))
        return False

    def shell_requested(self):
        """Shell requested"""
        return True
    
    def session_started(self):
        """Send welcome message and prompt"""
        if self._scp:
            # scp -t signals it is ready to receive with a zero byte
            self._chan.write(b'\0')
            return
        self._chan.write(FAKE_MOTD.replace('\n', '\r\n') + '\r\n')
        self._prompt()

    def _prompt(self):
        """Show a prompt, as interactive bash does; without a PTY bash is
        non-interactive and prints none"""
        if self._chan.get_terminal_type() is not None:
            self._chan.write(f'root@{FAKE_HOSTNAME}:~# ')
    
    def data_received(self, data, datatype):
        """Handle received data"""
        if self._scp:
            reply = self._scp.feed(data)
            if reply:
                self._chan.write(reply)
            if self._scp.done:
                self._chan.exit(1)
            return

        # No manual echo: with a PTY, asyncssh's line editor already echoes
        # input and ends the line; without one, real sshd doesn't echo.
        # Echoing again showed every command twice, an obvious tell.
        self._input += data

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
                    # Terminals need CRLF; bare LF staircases the output
                    response = response.replace('\n', '\r\n')
                    self._chan.write(f'{response}\r\n')

            # Send new prompt
            self._prompt()
    
    def _get_command_response(self, command: str) -> str:
        """Get fake response for command"""
        parts = command.split()
        name, args = parts[0], parts[1:]

        # Host identity commands: bots run these first to fingerprint
        if name == 'uname':
            return fake_uname(args)
        if name == 'hostname' and not args:
            return FAKE_HOSTNAME
        if name == 'lsb_release':
            lsb = {
                'i': 'Distributor ID:\tUbuntu',
                'd': f'Description:\tUbuntu {FAKE_OS_VERSION} LTS',
                'r': 'Release:\t20.04',
                'c': 'Codename:\tfocal',
            }
            flags = set(''.join(a.lstrip('-') for a in args)) or {'v'}
            if 'a' in flags:
                flags = set('idrc')
            lines = ['No LSB modules are available.']
            lines += [line for flag, line in lsb.items() if flag in flags]
            return '\n'.join(lines)
        if name == 'cat':
            out = []
            for path in args:
                if path in FAKE_FILES:
                    out.append(FAKE_FILES[path].rstrip('\n'))
                else:
                    out.append(f'cat: {path}: No such file or directory')
            return '\n'.join(out)

        responses = {
            'whoami': 'root',
            'pwd': '/root',
            'id': 'uid=0(root) gid=0(root) groups=0(root)',
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
        if command.startswith('cd '):
            return ''
        else:
            return f'{name}: command not found'
    
    def eof_received(self):
        """Handle EOF"""
        if self._scp:
            self._scp.close()
        self._chan.exit(0)

    def connection_lost(self, exc):
        """Keep a partial scp upload if the client went away mid-file"""
        if self._scp:
            self._scp.close()
    
    def break_received(self, msec):
        """Handle break signal"""
        return True
