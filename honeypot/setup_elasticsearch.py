#!/usr/bin/env python3
"""
ElasticSearch Setup for Honeypot
Creates index templates and initial dashboards
"""

import json
import os
import requests
from datetime import datetime


class ElasticSearchSetup:
    """Setup ElasticSearch for honeypot telemetry"""
    
    def __init__(self, es_host='http://localhost:9200'):
        self.es_host = es_host
        self.index_prefix = 'honeypot'
        # Credentials come from the environment, never the command line
        self.auth = None
        if os.environ.get('ES_USERNAME'):
            self.auth = (os.environ['ES_USERNAME'], os.environ.get('ES_PASSWORD', ''))
    
    def create_index_template(self):
        """Create index template for honeypot events"""
        
        template = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "index.refresh_interval": "5s"
                },
                "mappings": {
                    "properties": {
                        "timestamp": {
                            "type": "date"
                        },
                        "event_type": {
                            "type": "keyword"
                        },
                        "source_ip": {
                            "type": "ip"
                        },
                        "source_port": {
                            "type": "integer"
                        },
                        "dest_port": {
                            "type": "integer"
                        },
                        "protocol": {
                            "type": "keyword"
                        },
                        "service": {
                            "type": "keyword"
                        },
                        "session_id": {
                            "type": "keyword"
                        },
                        "payload": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        },
                        "payload_base64": {"type": "binary"},
                        "direction": {"type": "keyword"},
                        "dest_ip": {"type": "ip"},
                        "stream_offset": {"type": "long"},
                        "capture_status": {"type": "keyword"},
                        "payload_size": {
                            "type": "integer"
                        },
                        "decoded_payload": {
                            "type": "object",
                            "enabled": True
                        },
                        "headers": {
                            "type": "object",
                            "enabled": True
                        }
                    }
                }
            }
        }
        
        url = f"{self.es_host}/_index_template/{self.index_prefix}_template"
        
        try:
            response = requests.put(url, json=template, auth=self.auth)
            response.raise_for_status()
            print(f"[+] Index template created: {self.index_prefix}_template")
            return True
        except Exception as e:
            print(f"[-] Failed to create template: {e}")
            return False
    
    def create_sample_queries(self):
        """Generate sample queries for common investigations"""
        
        queries = {
            "top_attackers": {
                "description": "Top 10 attacking IPs",
                "query": {
                    "size": 0,
                    "query": {
                        "match_all": {}
                    },
                    "aggs": {
                        "top_ips": {
                            "terms": {
                                "field": "source_ip",
                                "size": 10
                            }
                        }
                    }
                }
            },
            "attack_timeline": {
                "description": "Attack events over time",
                "query": {
                    "size": 0,
                    "query": {
                        "wildcard": {
                            "event_type": "*attack*"
                        }
                    },
                    "aggs": {
                        "attacks_over_time": {
                            "date_histogram": {
                                "field": "timestamp",
                                "calendar_interval": "1h"
                            }
                        }
                    }
                }
            },
            "protocol_breakdown": {
                "description": "Events by protocol",
                "query": {
                    "size": 0,
                    "query": {
                        "match_all": {}
                    },
                    "aggs": {
                        "by_protocol": {
                            "terms": {
                                "field": "protocol"
                            }
                        }
                    }
                }
            },
            "login_attempts": {
                "description": "All login attempts with credentials",
                "query": {
                    "query": {
                        "wildcard": {
                            "event_type": "*login*"
                        }
                    },
                    "sort": [
                        {"timestamp": "desc"}
                    ]
                }
            },
            "sql_injection_attempts": {
                "description": "Detected SQL injection attempts",
                "query": {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"event_type": "http_attack"}},
                                {"term": {"decoded_payload.attack_types": "sql_injection"}}
                            ]
                        }
                    }
                }
            }
        }
        
        return queries
    
    def print_kibana_queries(self):
        """Print queries for use in Kibana"""
        queries = self.create_sample_queries()
        
        print("\n" + "="*70)
        print("Sample Kibana Queries")
        print("="*70)
        
        for name, data in queries.items():
            print(f"\n{name.upper()}")
            print("-" * 70)
            print(f"Description: {data['description']}")
            print("\nQuery (paste in Kibana Dev Tools):")
            print(f"GET /{self.index_prefix}-*/_search")
            print(json.dumps(data['query'], indent=2))
            print()
    
    def test_connection(self):
        """Test ElasticSearch connection"""
        try:
            response = requests.get(self.es_host, auth=self.auth)
            response.raise_for_status()
            info = response.json()
            print(f"[+] Connected to ElasticSearch")
            print(f"    Version: {info.get('version', {}).get('number', 'unknown')}")
            print(f"    Cluster: {info.get('cluster_name', 'unknown')}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def setup_all(self):
        """Run complete setup"""
        print("="*70)
        print("ElasticSearch Honeypot Setup")
        print("="*70)
        
        # Test connection
        if not self.test_connection():
            print("\n[!] Cannot connect to ElasticSearch")
            print("    Make sure ElasticSearch is running on", self.es_host)
            return False
        
        # Create template
        print("\n[*] Creating index template...")
        if not self.create_index_template():
            return False
        
        # Print sample queries
        self.print_kibana_queries()
        
        print("\n" + "="*70)
        print("Setup Complete!")
        print("="*70)
        print("\nNext steps:")
        print("1. Start the honeypot with ElasticSearch enabled")
        print("2. Access Kibana at http://localhost:5601")
        print("3. Create index pattern: honeypot-*")
        print("4. Use the sample queries above in Dev Tools")
        print("="*70)
        
        return True


def main():
    """Main setup function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Setup ElasticSearch for honeypot")
    parser.add_argument('--host', default='http://localhost:9200',
                       help='ElasticSearch host (default: http://localhost:9200)')
    
    args = parser.parse_args()
    
    setup = ElasticSearchSetup(args.host)
    setup.setup_all()


if __name__ == "__main__":
    main()
