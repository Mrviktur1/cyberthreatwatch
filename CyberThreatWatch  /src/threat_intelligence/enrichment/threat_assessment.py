from typing import Dict, Any, List
from datetime import datetime
import requests

class ThreatAssessment:
    def __init__(self):
        self.threat_intel_sources = [
            {
                'name': 'VirusTotal',
                'url': 'https://www.virustotal.com/api/v3/',
                'api_key_required': True
            },
            {
                'name': 'AbuseIPDB',
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'api_key_required': True
            },
            {
                'name': 'AlienVault OTX',
                'url': 'https://otx.alienvault.com/api/v1/indicators/',
                'api_key_required': False
            }
        ]
        self.cache = {}
    
    def assess_ip(self, ip_address: str) -> Dict[str, Any]:
        """Assess threat level of an IP address"""
        if not ip_address:
            return {'threat_level': 'unknown', 'reason': 'no_ip'}
        
        # Check cache
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        assessment = {
            'ip': ip_address,
            'assessed_at': datetime.now().isoformat(),
            'threat_level': 'unknown',
            'confidence': 0,
            'sources_checked': 0,
            'details': {}
        }
        
        # Check with various sources (placeholder implementations)
        abuseipdb_result = self._check_abuseipdb(ip_address)
        if abuseipdb_result:
            assessment['sources_checked'] += 1
            assessment['details']['abuseipdb'] = abuseipdb_result
            
            if abuseipdb_result.get('abuseConfidenceScore', 0) > 50:
                assessment['threat_level'] = 'high'
                assessment['confidence'] = max(assessment['confidence'], abuseipdb_result['abuseConfidenceScore'])
        
        otx_result = self._check_otx(ip_address)
        if otx_result:
            assessment['sources_checked'] += 1
            assessment['details']['otx'] = otx_result
            
            if otx_result.get('pulse_count', 0) > 0:
                assessment['threat_level'] = 'medium'
                assessment['confidence'] = max(assessment['confidence'], 50)
        
        # Determine final threat level
        if assessment['threat_level'] == 'unknown' and assessment['sources_checked'] > 0:
            assessment['threat_level'] = 'low'
        
        # Cache the result
        self.cache[ip_address] = assessment
        return assessment
    
    def assess_domain(self, domain: str) -> Dict[str, Any]:
        """Assess threat level of a domain"""
        # Similar to IP assessment but for domains
        return {
            'domain': domain,
            'assessed_at': datetime.now().isoformat(),
            'threat_level': 'unknown',
            'details': {}
        }
    
    def assess_file_hash(self, file_hash: str, hash_type: str = 'sha256') -> Dict[str, Any]:
        """Assess threat level of a file hash"""
        # Similar to IP assessment but for file hashes
        return {
            'hash': file_hash,
            'hash_type': hash_type,
            'assessed_at': datetime.now().isoformat(),
            'threat_level': 'unknown',
            'details': {}
        }
    
    def _check_abuseipdb(self, ip_address: str) -> Dict[str, Any]:
        """Check IP with AbuseIPDB (placeholder)"""
        # This would require an API key
        return {
            'abuseConfidenceScore': 0,
            'totalReports': 0,
            'lastReportedAt': None
        }
    
    def _check_otx(self, ip_address: str) -> Dict[str, Any]:
        """Check IP with AlienVault OTX (placeholder)"""
        try:
            response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'reputation': data.get('reputation', 0)
                }
        except:
            pass
        
        return {}
    
    def bulk_assess(self, indicators: List[Dict[str, str]]) -> Dict[str, Any]:
        """Assess multiple indicators"""
        results = {
            'total_indicators': len(indicators),
            'assessments': {},
            'summary': {
                'high': 0,
                'medium': 0,
                'low': 0,
                'unknown': 0
            }
        }
        
        for indicator in indicators:
            ioc_type = indicator.get('type')
            ioc_value = indicator.get('value')
            
            if ioc_type == 'ip':
                assessment = self.assess_ip(ioc_value)
            elif ioc_type == 'domain':
                assessment = self.assess_domain(ioc_value)
            elif ioc_type in ['md5', 'sha1', 'sha256']:
                assessment = self.assess_file_hash(ioc_value, ioc_type)
            else:
                continue
            
            results['assessments'][ioc_value] = assessment
            results['summary'][assessment['threat_level']] += 1
        
        return results

class ThreatAssessmentEnricher:
    def __init__(self, threat_assessment: ThreatAssessment):
        self.threat_assessment = threat_assessment
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with threat assessment"""
        enriched = event.copy()
        
        # Extract IOCs from event
        iocs = self._extract_iocs(event)
        
        # Assess each IOC
        threat_assessments = {}
        for ioc_type, ioc_values in iocs.items():
            for ioc_value in ioc_values:
                if ioc_type == 'ip':
                    assessment = self.threat_assessment.assess_ip(ioc_value)
                elif ioc_type == 'domain':
                    assessment = self.threat_assessment.assess_domain(ioc_value)
                elif ioc_type in ['md5', 'sha1', 'sha256']:
                    assessment = self.threat_assessment.assess_file_hash(ioc_value, ioc_type)
                else:
                    continue
                
                threat_assessments[f'{ioc_type}_{ioc_value}'] = assessment
        
        if threat_assessments:
            enriched['threat_assessments'] = threat_assessments
            
            # Determine overall threat level
            max_threat_level = 'unknown'
            for assessment in threat_assessments.values():
                if assessment['threat_level'] == 'high':
                    max_threat_level = 'high'
                    break
                elif assessment['threat_level'] == 'medium' and max_threat_level != 'high':
                    max_threat_level = 'medium'
                elif assessment['threat_level'] == 'low' and max_threat_level not in ['high', 'medium']:
                    max_threat_level = 'low'
            
            enriched['overall_threat_level'] = max_threat_level
        
        return enriched
    
    def _extract_iocs(self, event: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from event"""
        iocs = {
            'ip': [],
            'domain': [],
            'md5': [],
            'sha1': [],
            'sha256': []
        }
        
        # Check specific fields
        for field in ['source_ip', 'dest_ip', 'src_ip', 'dst_ip']:
            if field in event and event[field]:
                iocs['ip'].append(event[field])
        
        for field in ['domain', 'hostname', 'url']:
            if field in event and event[field]:
                # Extract domain from URL
                if field == 'url' and '://' in event[field]:
                    import re
                    domain_match = re.search(r'https?://([^/]+)', event[field])
                    if domain_match:
                        iocs['domain'].append(domain_match.group(1))
                else:
                    iocs['domain'].append(event[field])
        
        for field in ['hash', 'file_hash', 'md5', 'sha1', 'sha256']:
            if field in event and event[field]:
                hash_value = event[field]
                if len(hash_value) == 32:
                    iocs['md5'].append(hash_value)
                elif len(hash_value) == 40:
                    iocs['sha1'].append(hash_value)
                elif len(hash_value) == 64:
                    iocs['sha256'].append(hash_value)
        
        # Also check message field
        if 'message' in event:
            import re
            # Extract IPs
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', event['message'])
            iocs['ip'].extend(ip_matches)
            
            # Extract domains
            domain_matches = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', event['message'])
            iocs['domain'].extend(domain_matches)
            
            # Extract hashes
            hash_matches = re.findall(r'\b[a-fA-F0-9]{32,64}\b', event['message'])
            for hash_val in hash_matches:
                if len(hash_val) == 32:
                    iocs['md5'].append(hash_val)
                elif len(hash_val) == 40:
                    iocs['sha1'].append(hash_val)
                elif len(hash_val) == 64:
                    iocs['sha256'].append(hash_val)
        
        # Remove duplicates
        for ioc_type in iocs:
            iocs[ioc_type] = list(set(iocs[ioc_type]))
        
        return iocs