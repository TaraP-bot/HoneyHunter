#!/usr/bin/env python3
"""
Complete INetSim-style Honeypot
Main startup script that integrates all services
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path

# Import core framework
sys.path.insert(0, str(Path(__file__).parent / 'core'))
from honeypot_manager import HoneypotManager, TelemetryCollector

# Import services
sys.path.insert(0, str(Path(__file__).parent / 'services'))
from http_service import HTTPHoneypot
from ssh_service import SSHHoneypot
from ftp_service import FTPHoneypot
from dns_service import DNSHoneypot


class INetSimHoneypot:
    """
    INetSim-inspired honeypot with comprehensive telemetry
    
    Services:
    - HTTP/HTTPS: Web server emulation, attack detection
    - SSH: Credential capture, command logging
    - FTP: File transfer monitoring
    - DNS: Query logging, C2 detection
    """
    
    def __init__(self, config_file: Path = None):
        self.manager = HoneypotManager(config_file)
        self.services = []
        self.shutdown_event = asyncio.Event()
        
        # Setup signal handlers
        self._setup_signals()
        
    def _setup_signals(self):
        """Setup graceful shutdown handlers"""
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(
                    sig,
                    lambda: asyncio.create_task(self.shutdown())
                )
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
    
    def initialize_services(self):
        """Initialize all honeypot services"""
        config = self.manager.config
        telemetry = self.manager.telemetry
        
        # HTTP
        if config['services']['http']['enabled']:
            http = HTTPHoneypot(
                port=config['services']['http']['port'],
                telemetry=telemetry
            )
            self.manager.register_service(http)
        
        # HTTPS (if configured)
        if config['services'].get('https', {}).get('enabled', False):
            https = HTTPHoneypot(
                port=config['services']['https']['port'],
                telemetry=telemetry,
                ssl_cert=Path(config['services']['https'].get('cert', ''))
            )
            self.manager.register_service(https)
        
        # SSH
        if config['services']['ssh']['enabled']:
            ssh = SSHHoneypot(
                port=config['services']['ssh']['port'],
                telemetry=telemetry
            )
            self.manager.register_service(ssh)
        
        # FTP
        if config['services']['ftp']['enabled']:
            ftp = FTPHoneypot(
                port=config['services']['ftp']['port'],
                telemetry=telemetry
            )
            self.manager.register_service(ftp)
        
        # DNS
        if config['services']['dns']['enabled']:
            dns = DNSHoneypot(
                port=config['services']['dns']['port'],
                telemetry=telemetry
            )
            self.manager.register_service(dns)
        
        logging.info(f"Initialized {len(self.manager.services)} services")
    
    async def start(self):
        """Start honeypot"""
        logging.info("Starting INetSim-style Honeypot...")
        
        # Initialize services
        self.initialize_services()
        
        # Start all services
        await self.manager.start_all()
        
        # Print status
        self._print_status()
        
        # Wait for shutdown signal
        await self.shutdown_event.wait()
    
    async def shutdown(self):
        """Graceful shutdown"""
        logging.info("Shutting down honeypot...")
        await self.manager.stop_all()
        self.shutdown_event.set()
    
    def _print_status(self):
        """Print honeypot status"""
        print("\n" + "="*60)
        print("INetSim-Style Honeypot Active")
        print("="*60)
        print(f"Output Directory: {self.manager.config['output_dir']}")
        print(f"ElasticSearch: {'Enabled' if self.manager.config['elasticsearch']['enabled'] else 'Disabled'}")
        print("\nActive Services:")
        for name, service in self.manager.services.items():
            print(f"  - {name:10s} on port {service.port}")
        print("\nTelemetry Collection:")
        print(f"  - Event Log: {self.manager.telemetry.event_log}")
        print(f"  - Samples:   {self.manager.telemetry.samples_dir}")
        print(f"  - PCAP:      {self.manager.telemetry.pcap_dir}")
        print("\nPress Ctrl+C to stop")
        print("="*60 + "\n")


def create_default_config(path: Path):
    """Create default configuration file"""
    import json
    
    config = {
        "output_dir": "./honeypot_data",
        "services": {
            "http": {
                "enabled": True,
                "port": 8080
            },
            "https": {
                "enabled": False,
                "port": 8443,
                "cert": "./certs/honeypot.pem"
            },
            "ssh": {
                "enabled": True,
                "port": 2222
            },
            "ftp": {
                "enabled": True,
                "port": 2121
            },
            "dns": {
                "enabled": True,
                "port": 5353
            },
            "smtp": {
                "enabled": False,
                "port": 2525
            },
            "telnet": {
                "enabled": False,
                "port": 2323
            },
            "smb": {
                "enabled": False,
                "port": 4445
            }
        },
        "elasticsearch": {
            "enabled": False,
            "hosts": ["localhost:9200"],
            "index_prefix": "honeypot"
        },
        "response_templates": {
            "http_server": "Apache/2.4.41 (Ubuntu)",
            "ssh_version": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "ftp_banner": "FTP Server Ready"
        },
        "detection": {
            "log_all_connections": True,
            "detect_scanners": True,
            "detect_exploits": True,
            "auto_block": False
        }
    }
    
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"Created default configuration: {path}")


def main():
    """Main entry point"""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('honeypot.log'),
            logging.StreamHandler()
        ]
    )
    
    # Check for config file
    config_path = Path('honeypot_config.json')
    if not config_path.exists():
        print("No configuration found. Creating default config...")
        create_default_config(config_path)
        print(f"\nPlease review and edit {config_path}, then restart.")
        return
    
    # Create and run honeypot
    honeypot = INetSimHoneypot(config_path)
    
    try:
        asyncio.run(honeypot.start())
    except KeyboardInterrupt:
        logging.info("Shutdown requested")
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
    finally:
        logging.info("Honeypot stopped")


if __name__ == "__main__":
    main()
