import whois
from typing import Dict, Any, Optional
import requests
from datetime import datetime
import time

class WHOISLookup:
    def __init__(self, rate_limit_delay: float = 1.0):
        self.rate_limit_delay = rate_limit_delay
        self.cache = {}
        self.last_lookup_time = 0
    
    def lookup_domain(self, domain: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Perform WHOIS lookup for a domain"""
        if not domain:
            return None
        
        # Check cache first
        if use_cache and domain in self.cache:
            return self.cache[domain]
        
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_lookup_time < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - (current_time - self.last_lookup_time))
        
        try:
            # Use python-whois library
            whois_data = whois.whois(domain)
            self.last_lookup_time = time.time()
            
            result = self._parse_whois_data(whois_data)
            result['domain'] = domain
            
            # Cache the result
            self.cache[domain] = result
            return result
            
        except Exception as e:
            print(f"WHOIS lookup failed for {domain}: {e}")
            return None
    
    def lookup_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Perform WHOIS lookup for an IP address"""
        # This typically requires different services than domain WHOIS
        try:
            # Use RIPE, ARIN, or other RIR APIs
            response = requests.get(f"https://stat.ripe.net/data/whois/data.json?resource={ip_address}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return self._parse_ripe_data(data, ip_address)
        except Exception as e:
            print(f"IP WHOIS lookup failed for {ip_address}: {e}")
        
        return None
    
    def _parse_whois_data(self, whois_data: Any) -> Dict[str, Any]:
        """Parse WHOIS data into structured format"""
        result = {}
        
        # Extract common fields
        fields_to_extract = [
            'domain_name', 'registrar', 'whois_server', 'referral_url',
            'updated_date', 'creation_date', 'expiration_date',
            'name_servers', 'status', 'emails', 'dnssec', 'name',
            'org', 'address', 'city', 'state', 'zipcode', 'country'
        ]
        
        for field in fields_to_extract:
            if hasattr(whois_data, field):
                value = getattr(whois_data, field)
                if value:
                    result[field] = value
        
        # Handle date fields
        date_fields = ['updated_date', 'creation_date', 'expiration_date']
        for field in date_fields:
            if field in result:
                if isinstance(result[field], list):
                    result[field] = result[field][0] if result[field] else None
                if isinstance(result[field], datetime):
                    result[field] = result[field].isoformat()
        
        return result
    
    def _parse_ripe_data(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Parse RIPE WHOIS data"""
        result = {
            'ip': ip_address,
            'source': 'ripe'
        }
        
        if 'data' in data and 'records' in data['data']:
            for record in data['data']['records']:
                for attribute in record.get('attributes', []):
                    key = attribute.get('key', '').lower()
                    value = attribute.get('value', '')
                    
                    if key in ['inetnum', 'netname', 'descr', 'country', 'admin-c', 
                              'tech-c', 'status', 'remarks', 'notify', 'mnt-by', 'created', 'last-modified']:
                        result[key] = value
        
        return result
    
    def bulk_lookup(self, domains: list) -> Dict[str, Any]:
        """Perform WHOIS lookup for multiple domains"""
        results = {}
        
        for domain in domains:
            whois_info = self.lookup_domain(domain)
            if whois_info:
                results[domain] = whois_info
        
        return results
    
    def get_domain_age(self, domain: str) -> Optional[int]:
        """Get domain age in days"""
        whois_info = self.lookup_domain(domain)
        if whois_info and 'creation_date' in whois_info:
            try:
                if isinstance(whois_info['creation_date'], str):
                    creation_date = datetime.fromisoformat(whois_info['creation_date'].replace('Z', '+00:00'))
                else:
                    creation_date = whois_info['creation_date']
                
                age_days = (datetime.now() - creation_date).days
                return age_days
            except:
                pass
        
        return None
    
    def is_suspicious_domain(self, domain: str) -> Dict[str, Any]:
        """Check if domain has suspicious characteristics"""
        whois_info = self.lookup_domain(domain)
        if not whois_info:
            return {'suspicious': False, 'reason': 'no_whois_data'}
        
        suspicious_reasons = []
        
        # Check domain age
        domain_age = self.get_domain_age(domain)
        if domain_age and domain_age < 30:  # Less than 30 days old
            suspicious_reasons.append(f'domain_age_{domain_age}_days')
        
        # Check registrar
        registrar = whois_info.get('registrar', '').lower()
        suspicious_registrars = ['nicenic', 'namecheap', 'porkbun']  # Example list
        if any(susp in registrar for susp in suspicious_registrars):
            suspicious_reasons.append('suspicious_registrar')
        
        # Check name servers
        name_servers = whois_info.get('name_servers', [])
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        
        suspicious_ns = ['cloudflare', 'amazonaws']  # Often used by malicious actors
        for ns in name_servers:
            if any(susp in ns.lower() for susp in suspicious_ns):
                suspicious_reasons.append('suspicious_name_server')
                break
        
        return {
            'suspicious': len(suspicious_reasons) > 0,
            'reasons': suspicious_reasons,
            'domain_age_days': domain_age,
            'whois_data': whois_info
        }

class WHOISEnricher:
    def __init__(self, whois_lookup: WHOISLookup):
        self.whois_lookup = whois_lookup
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with WHOIS information"""
        enriched = event.copy()
        
        # Extract domains from event
        domains = set()
        
        # Check URL fields
        url_fields = ['url', 'referrer', 'hostname']
        for field in url_fields:
            if field in event and event[field]:
                import re
                domain_matches = re.findall(r'https?://([^/]+)', event[field])
                domains.update(domain_matches)
        
        # Check message field
        if 'message' in event:
            import re
            domain_matches = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', event['message'])
            domains.update(domain_matches)
        
        # Enrich each domain
        for domain in domains:
            whois_data = self.whois_lookup.lookup_domain(domain)
            if whois_data:
                for key, value in whois_data.items():
                    if key != 'domain':
                        enriched[f'{domain}_{key}'] = value
                
                # Add suspiciousness check
                suspicious_info = self.whois_lookup.is_suspicious_domain(domain)
                enriched[f'{domain}_suspicious'] = suspicious_info
        
        return enriched