import requests
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
import time

class CVEFeed:
    def __init__(self, sources: List[str] = None):
        self.sources = sources or [
            "https://cve.circl.lu/api/last",
            "https://services.nvd.nist.gov/rest/json/cves/1.0"
        ]
        self.last_update = None
        self.cve_cache = {}
    
    def fetch_recent_cves(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Fetch recent CVEs from available feeds"""
        all_cves = []
        
        for source in self.sources:
            try:
                if "circl.lu" in source:
                    cves = self._fetch_from_circl(source)
                elif "nist.gov" in source:
                    cves = self._fetch_from_nvd(source, hours)
                else:
                    cves = []
                
                all_cves.extend(cves)
                
            except Exception as e:
                print(f"Error fetching from {source}: {e}")
        
        # Remove duplicates
        unique_cves = {}
        for cve in all_cves:
            if cve['id'] not in unique_cves:
                unique_cves[cve['id']] = cve
        
        self.last_update = datetime.now()
        return list(unique_cves.values())
    
    def _fetch_from_circl(self, url: str) -> List[Dict[str, Any]]:
        """Fetch CVEs from CIRCL feed"""
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        cves = response.json()
        formatted_cves = []
        
        for cve in cves:
            formatted_cves.append({
                'id': cve.get('id'),
                'summary': cve.get('summary', ''),
                'published': cve.get('Published', ''),
                'modified': cve.get('Modified', ''),
                'cvss': cve.get('cvss', 0.0),
                'references': cve.get('references', []),
                'source': 'circl.lu'
            })
        
        return formatted_cves
    
    def _fetch_from_nvd(self, url: str, hours: int) -> List[Dict[str, Any]]:
        """Fetch CVEs from NVD feed"""
        # Calculate time range
        start_time = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')
        
        # NVD API has rate limits, so we need to be careful
        params = {
            'modStartDate': start_time,
            'resultsPerPage': 50
        }
        
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        formatted_cves = []
        
        for item in data.get('result', {}).get('CVE_Items', []):
            cve_data = item['cve']
            metrics = item.get('impact', {}).get('baseMetricV2', {})
            
            formatted_cves.append({
                'id': cve_data['CVE_data_meta']['ID'],
                'summary': cve_data['description']['description_data'][0]['value'],
                'published': item.get('publishedDate', ''),
                'modified': item.get('lastModifiedDate', ''),
                'cvss': metrics.get('cvssV2', {}).get('baseScore', 0.0),
                'references': [ref['url'] for ref in cve_data['references']['reference_data']],
                'source': 'nvd.nist.gov'
            })
        
        return formatted_cves
    
    def monitor_cves(self, callback: callable, interval: int = 3600):
        """Continuously monitor for new CVEs"""
        while True:
            new_cves = self.fetch_recent_cves(24)
            if new_cves:
                callback({
                    'timestamp': datetime.now(),
                    'cves': new_cves,
                    'count': len(new_cves)
                })
            
            time.sleep(interval)
    
    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific CVE"""
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        # Try to fetch from CIRCL
        try:
            response = requests.get(f"https://cve.circl.lu/api/cve/{cve_id}", timeout=30)
            if response.status_code == 200:
                details = response.json()
                self.cve_cache[cve_id] = details
                return details
        except:
            pass
        
        return {'error': 'CVE not found', 'id': cve_id}

class CVEEnricher:
    def __init__(self, cve_feed: CVEFeed):
        self.cve_feed = cve_feed
    
    def enrich_with_cves(self, software_info: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich software information with relevant CVEs"""
        # This is a simplified implementation
        # In reality, you'd need to match software versions with CVE data
        
        enriched = software_info.copy()
        relevant_cves = []
        
        # Placeholder logic - would need actual vulnerability matching
        if 'software' in software_info and 'version' in software_info:
            # Simulate finding relevant CVEs
            all_cves = self.cve_feed.fetch_recent_cves(720)  # Last 30 days
            
            for cve in all_cves:
                if (software_info['software'] in cve['summary'] and 
                    self._is_version_affected(software_info['version'], cve['summary'])):
                    relevant_cves.append(cve)
        
        enriched['related_cves'] = relevant_cves
        enriched['cve_count'] = len(relevant_cves)
        
        return enriched
    
    def _is_version_affected(self, version: str, cve_summary: str) -> bool:
        """Check if version is affected by CVE (simplified)"""
        # This is very simplified - real implementation would need proper version parsing
        # and comparison with affected version ranges from CVE data
        return True  # Placeholder