#!/usr/bin/env python3
"""
INetSim-inspired Honeypot Framework
Comprehensive service emulation with deep telemetry collection
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib

@dataclass
class ConnectionEvent:
    """Base telemetry event for all connections"""
    timestamp: str
    event_type: str
    source_ip: str
    source_port: int
    dest_port: int
    protocol: str
    service: str
    session_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ProtocolEvent(ConnectionEvent):
    """Extended event with protocol-specific data"""
    payload: Optional[str] = None
    payload_size: int = 0
    decoded_payload: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    

class TelemetryCollector:
    """Central telemetry collection and forwarding"""
    
    def __init__(self, output_dir: Path, es_enabled: bool = False, es_hosts: list = None):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Session tracking
        self.sessions: Dict[str, Dict[str, Any]] = {}
        
        # File collection
        self.samples_dir = output_dir / "samples"
        self.samples_dir.mkdir(exist_ok=True)
        
        # PCAP directory
        self.pcap_dir = output_dir / "pcap"
        self.pcap_dir.mkdir(exist_ok=True)
        
        # JSON event log
        self.event_log = output_dir / "events.jsonl"
        
        # ElasticSearch (optional)
        self.es_enabled = es_enabled
        if es_enabled:
            try:
                from elasticsearch import AsyncElasticsearch
                # Use provided hosts or default to localhost
                hosts = es_hosts if es_hosts else ['http://localhost:9200']
                self.es_client = AsyncElasticsearch(hosts)
                logging.info(f"ElasticSearch client initialized with hosts: {hosts}")
            except ImportError:
                logging.warning("elasticsearch-py not installed, disabling ES")
                self.es_enabled = False
        
        logging.info(f"Telemetry collector initialized: {output_dir}")
    
    def generate_session_id(self, source_ip: str, source_port: int, 
                           dest_port: int) -> str:
        """Generate unique session identifier"""
        data = f"{source_ip}:{source_port}:{dest_port}:{datetime.utcnow().isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    async def log_event(self, event: ConnectionEvent):
        """Log event to multiple backends"""
        event_dict = event.to_dict()
        
        # Update session tracking
        if event.session_id not in self.sessions:
            self.sessions[event.session_id] = {
                'start_time': event.timestamp,
                'source_ip': event.source_ip,
                'events': [],
                'total_bytes': 0
            }
        
        session = self.sessions[event.session_id]
        session['events'].append(event_dict)
        session['last_seen'] = event.timestamp
        
        # Write to JSON log
        with open(self.event_log, 'a') as f:
            f.write(json.dumps(event_dict) + '\n')
        
        # Send to ElasticSearch
        if self.es_enabled:
            try:
                await self.es_client.index(
                    index=f"honeypot-{datetime.utcnow().strftime('%Y.%m.%d')}",
                    document=event_dict
                )
            except Exception as e:
                logging.error(f"ES indexing error: {e}")
        
        logging.info(f"[{event.service}] {event.event_type} from {event.source_ip}:{event.source_port}")
    
    async def save_sample(self, data: bytes, source_ip: str, 
                         protocol: str, metadata: Dict[str, Any]) -> str:
        """Save captured file/malware sample"""
        file_hash = hashlib.sha256(data).hexdigest()
        
        # Save sample
        sample_path = self.samples_dir / f"{file_hash}.bin"
        with open(sample_path, 'wb') as f:
            f.write(data)
        
        # Save metadata
        meta_path = self.samples_dir / f"{file_hash}.json"
        metadata.update({
            'sha256': file_hash,
            'size': len(data),
            'source_ip': source_ip,
            'protocol': protocol,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        with open(meta_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logging.info(f"Saved sample: {file_hash} ({len(data)} bytes) from {source_ip}")
        return file_hash
    
    async def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get summary of session activity"""
        return self.sessions.get(session_id)
    
    async def close(self):
        """Cleanup and close connections"""
        if self.es_enabled:
            await self.es_client.close()


class HoneypotService:
    """Base class for honeypot services"""
    
    def __init__(self, name: str, port: int, telemetry: TelemetryCollector):
        self.name = name
        self.port = port
        self.telemetry = telemetry
        self.server = None
        
    async def start(self):
        """Start the service"""
        self.server = await asyncio.start_server(
            self.handle_client,
            '0.0.0.0',
            self.port
        )
        logging.info(f"[{self.name}] Started on port {self.port}")
        
    async def stop(self):
        """Stop the service"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logging.info(f"[{self.name}] Stopped")
    
    async def handle_client(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """Override this in subclasses"""
        raise NotImplementedError
    
    def get_peer_info(self, writer: asyncio.StreamWriter) -> tuple:
        """Extract peer address information"""
        peername = writer.get_extra_info('peername')
        if peername:
            return peername[0], peername[1]
        return "unknown", 0


class HoneypotManager:
    """Main honeypot orchestrator"""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config = self._load_config(config_path)
        
        # Extract ElasticSearch config
        es_config = self.config.get('elasticsearch', {})
        es_enabled = es_config.get('enabled', False)
        es_hosts = es_config.get('hosts', ['http://localhost:9200'])
        
        self.telemetry = TelemetryCollector(
            Path(self.config['output_dir']),
            es_enabled=es_enabled,
            es_hosts=es_hosts
        )
        self.services: Dict[str, HoneypotService] = {}
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _load_config(self, config_path: Optional[Path]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'output_dir': './honeypot_data',
            'services': {
                'http': {'enabled': True, 'port': 80},
                'https': {'enabled': True, 'port': 443},
                'ftp': {'enabled': True, 'port': 21},
                'ssh': {'enabled': True, 'port': 22},
                'smtp': {'enabled': True, 'port': 25},
                'dns': {'enabled': True, 'port': 53},
                'telnet': {'enabled': True, 'port': 23},
                'smb': {'enabled': True, 'port': 445},
            },
            'elasticsearch': {
                'enabled': False,
                'hosts': ['localhost:9200']
            }
        }
        
        if config_path and config_path.exists():
            with open(config_path) as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def register_service(self, service: HoneypotService):
        """Register a service with the manager"""
        self.services[service.name] = service
        logging.info(f"Registered service: {service.name}")
    
    async def start_all(self):
        """Start all registered services"""
        tasks = []
        for service in self.services.values():
            tasks.append(service.start())
        
        await asyncio.gather(*tasks)
        logging.info(f"Started {len(self.services)} services")
    
    async def stop_all(self):
        """Stop all services"""
        tasks = []
        for service in self.services.values():
            tasks.append(service.stop())
        
        await asyncio.gather(*tasks)
        await self.telemetry.close()
        logging.info("All services stopped")
    
    async def run_forever(self):
        """Run until interrupted"""
        await self.start_all()
        
        try:
            # Keep running
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            logging.info("Shutdown requested")
        finally:
            await self.stop_all()


if __name__ == "__main__":
    manager = HoneypotManager()
    asyncio.run(manager.run_forever())
