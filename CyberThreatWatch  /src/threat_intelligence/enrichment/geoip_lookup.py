import geoip2.database
import geoip2.errors
from typing import Dict, Any, Optional
import socket
import requests

class GeoIPLookup:
    def __init__(self, maxmind_db_path: str = None):
        self.maxmind_db_path = maxmind_db_path
        self.reader = None
        self.cache = {}
        
        if maxmind_db_path:
            self._initialize_reader()
    
    def _initialize_reader(self):
        """Initialize the GeoIP2 reader"""
        try:
            self.reader = geoip2.database.Reader(self.maxmind_db_path)
        except Exception as e:
            print(f"Failed to initialize GeoIP2 reader: {e}")
            self.reader = None
    
    def lookup_ip(self, ip_address: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Lookup IP address information"""
        if not ip_address or ip_address in ['127.0.0.1', 'localhost', '0.0.0.0']:
            return None
        
        # Check cache first
        if use_cache and ip_address in self.cache:
            return self.cache[ip_address]
        
        # Try MaxMind database first
        if self.reader:
            try:
                response = self.reader.city(ip_address)
                
                result = {
                    'ip': ip_address,
                    'country': response.country.name,
                    'country_code': response.country.iso_code,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'timezone': response.location.time_zone,
                    'accuracy_radius': response.location.accuracy_radius,
                    'source': 'maxmind'
                }
                
                # Cache the result
                self.cache[ip_address] = result
                return result
                
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                print(f"GeoIP lookup error for {ip_address}: {e}")
        
        # Fallback to external API
        return self._fallback_lookup(ip_address)
    
    def _fallback_lookup(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Fallback to external GeoIP service"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                if data['status'] == 'success':
                    result = {
                        'ip': ip_address,
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('region'),
                        'region_name': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'source': 'ip-api'
                    }
                    
                    # Cache the result
                    self.cache[ip_address] = result
                    return result
                    
        except Exception as e:
            print(f"Fallback GeoIP lookup failed for {ip_address}: {e}")
        
        return None
    
    def bulk_lookup(self, ip_addresses: list) -> Dict[str, Any]:
        """Lookup multiple IP addresses"""
        results = {}
        
        for ip in ip_addresses:
            lookup_result = self.lookup_ip(ip)
            if lookup_result:
                results[ip] = lookup_result
        
        return results
    
    def get_country_stats(self, ip_addresses: list) -> Dict[str, Any]:
        """Get statistics by country"""
        country_stats = {}
        
        for ip in ip_addresses:
            lookup_result = self.lookup_ip(ip)
            if lookup_result and 'country' in lookup_result:
                country = lookup_result['country']
                if country not in country_stats:
                    country_stats[country] = 0
                country_stats[country] += 1
        
        return country_stats
    
    def is_internal_ip(self, ip_address: str) -> bool:
        """Check if IP address is internal/private"""
        try:
            ip = ip_address.strip()
            
            # Check for localhost
            if ip in ['127.0.0.1', 'localhost', '::1']:
                return True
            
            # Check for private network ranges
            if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.16.'):
                return True
            
            # Check for link-local
            if ip.startswith('169.254.'):
                return True
            
            return False
            
        except Exception:
            return False

class ReverseDNSLookup:
    def __init__(self):
        self.cache = {}
    
    def lookup(self, ip_address: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        if not ip_address or ip_address in self.cache:
            return self.cache.get(ip_address)
        
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            self.cache[ip_address] = hostname
            return hostname
        except socket.herror:
            self.cache[ip_address] = None
            return None
        except Exception as e:
            print(f"Reverse DNS lookup failed for {ip_address}: {e}")
            return None
    
    def bulk_lookup(self, ip_addresses: list) -> Dict[str, str]:
        """Perform reverse DNS lookup for multiple IPs"""
        results = {}
        
        for ip in ip_addresses:
            hostname = self.lookup(ip)
            if hostname:
                results[ip] = hostname
        
        return results

class GeoIPEnricher:
    def __init__(self, geoip_lookup: GeoIPLookup, reverse_dns: ReverseDNSLookup = None):
        self.geoip_lookup = geoip_lookup
        self.reverse_dns = reverse_dns or ReverseDNSLookup()
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with GeoIP information"""
        enriched = event.copy()
        
        # Check for IP fields to enrich
        ip_fields = ['source_ip', 'src_ip', 'dest_ip', 'dst_ip', 'client_ip', 'server_ip']
        ips_to_enrich = set()
        
        for field in ip_fields:
            if field in event and event[field]:
                ips_to_enrich.add(event[field])
        
        # Also extract IPs from message field
        if 'message' in event:
            import re
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', event['message'])
            ips_to_enrich.update(ip_matches)
        
        # Enrich each IP
        for ip in ips_to_enrich:
            if self.geoip_lookup.is_internal_ip(ip):
                enriched[f'{ip}_type'] = 'internal'
                continue
            
            # GeoIP lookup
            geoip_data = self.geoip_lookup.lookup_ip(ip)
            if geoip_data:
                for key, value in geoip_data.items():
                    if key != 'ip':
                        enriched[f'{ip}_{key}'] = value
            
            # Reverse DNS
            hostname = self.reverse_dns.lookup(ip)
            if hostname:
                enriched[f'{ip}_reverse_dns'] = hostname
        
        return enriched