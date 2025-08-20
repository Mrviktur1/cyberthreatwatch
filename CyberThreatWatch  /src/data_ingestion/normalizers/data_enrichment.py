from typing import Dict, Any, List
from datetime import datetime
import socket
import geoip2.database
import requests

class DataEnricher:
    def __init__(self, maxmind_db_path: str = None):
        self.maxmind_db_path = maxmind_db_path
        self.geoip_reader = None
        
        if maxmind_db_path:
            try:
                self.geoip_reader = geoip2.database.Reader(maxmind_db_path)
            except Exception as e:
                print(f"Failed to load MaxMind database: {e}")
    
    def enrich_with_geoip(self, ip_address: str) -> Dict[str, Any]:
        """Enrich data with GeoIP information"""
        if not self.geoip_reader or not ip_address:
            return {}
        
        try:
            response = self.geoip_reader.city(ip_address)
            
            return {
                'geoip_country': response.country.name,
                'geoip_country_code': response.country.iso_code,
                'geoip_city': response.city.name,
                'geoip_latitude': response.location.latitude,
                'geoip_longitude': response.location.longitude,
                'geoip_timezone': response.location.time_zone
            }
        except Exception as e:
            return {'geoip_error': str(e)}
    
    def enrich_with_reverse_dns(self, ip_address: str) -> Dict[str, Any]:
        """Enrich with reverse DNS lookup"""
        if not ip_address:
            return {}
        
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return {'reverse_dns': hostname}
        except socket.herror:
            return {'reverse_dns': 'not found'}
        except Exception as e:
            return {'reverse_dns_error': str(e)}
    
    def enrich_with_whois(self, ip_address: str) -> Dict[str, Any]:
        """Enrich with WHOIS information"""
        # This would typically call an external WHOIS service
        # Placeholder implementation
        return {'whois_info': 'not_implemented'}
    
    def enrich_with_threat_intel(self, indicators: Dict[str, List[str]]) -> Dict[str, Any]:
        """Enrich with threat intelligence data"""
        # Placeholder for threat intelligence enrichment
        results = {}
        
        for ioc_type, values in indicators.items():
            if ioc_type == 'ipv4' and values:
                results['threat_score'] = 0  # Placeholder
                results['threat_tags'] = []  # Placeholder
        
        return results
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich an event with all available data"""
        enriched = event.copy()
        
        # Extract IP addresses for enrichment
        ip_addresses = []
        for field in ['source_ip', 'dest_ip', 'client_ip', 'server_ip']:
            if field in event and event[field]:
                ip_addresses.append(event[field])
        
        # Also look for IPs in message field
        if 'message' in event:
            import re
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', event['message'])
            ip_addresses.extend(ip_matches)
        
        # Enrich with first found IP
        if ip_addresses:
            primary_ip = ip_addresses[0]
            
            # GeoIP enrichment
            if self.geoip_reader:
                geoip_data = self.enrich_with_geoip(primary_ip)
                enriched.update(geoip_data)
            
            # Reverse DNS
            reverse_dns = self.enrich_with_reverse_dns(primary_ip)
            enriched.update(reverse_dns)
            
            # WHOIS
            whois_data = self.enrich_with_whois(primary_ip)
            enriched.update(whois_data)
        
        # Threat intelligence enrichment
        indicators = {}
        for ioc_type in ['ipv4', 'hash_md5', 'hash_sha1', 'hash_sha256', 'domain']:
            if ioc_type in event:
                indicators[ioc_type] = event[ioc_type] if isinstance(event[ioc_type], list) else [event[ioc_type]]
        
        threat_data = self.enrich_with_threat_intel(indicators)
        enriched.update(threat_data)
        
        # Add enrichment metadata
        enriched['enriched_at'] = datetime.now().isoformat()
        enriched['enrichment_version'] = '1.0'
        
        return enriched

class ContextEnricher:
    def __init__(self):
        self.context_data = {}
    
    def add_context(self, key: str, value: Any):
        """Add context data for enrichment"""
        self.context_data[key] = value
    
    def enrich_with_context(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with context data"""
        enriched = event.copy()
        
        for context_key, context_value in self.context_data.items():
            if context_key not in enriched:
                enriched[context_key] = context_value
        
        return enriched