import requests
import json
from datetime import datetime
from typing import List, Dict, Any
import csv
from io import StringIO

class IOCFeed:
    def __init__(self):
        self.ioc_sources = [
            {
                'name': 'Abuse.ch SSL Blacklist',
                'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv',
                'type': 'csv'
            },
            {
                'name': 'Abuse.ch URL Haus',
                'url': 'https://urlhaus.abuse.ch/downloads/csv/',
                'type': 'csv'
            },
            {
                'name': 'OpenPhish',
                'url': 'https://openphish.com/feed.txt',
                'type': 'text'
            }
        ]
        self.ioc_cache = {}
    
    def fetch_iocs(self, feed_name: str = None) -> List[Dict[str, Any]]:
        """Fetch IOCs from specified feed or all feeds"""
        all_iocs = []
        
        for source in self.ioc_sources:
            if feed_name and source['name'] != feed_name:
                continue
            
            try:
                if source['type'] == 'csv':
                    iocs = self._fetch_csv_iocs(source['url'])
                elif source['type'] == 'text':
                    iocs = self._fetch_text_iocs(source['url'])
                else:
                    iocs = []
                
                # Add source information
                for ioc in iocs:
                    ioc['source'] = source['name']
                    ioc['feed_url'] = source['url']
                    ioc['collected'] = datetime.now().isoformat()
                
                all_iocs.extend(iocs)
                
            except Exception as e:
                print(f"Error fetching from {source['name']}: {e}")
        
        return all_iocs
    
    def _fetch_csv_iocs(self, url: str) -> List[Dict[str, Any]]:
        """Fetch and parse CSV-based IOC feeds"""
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Parse CSV
        csv_data = StringIO(response.text)
        reader = csv.DictReader(csv_data)
        
        iocs = []
        for row in reader:
            # Standardize field names
            standardized_row = {}
            for key, value in row.items():
                standardized_key = key.lower().replace(' ', '_').replace('#', '')
                standardized_row[standardized_key] = value
            
            iocs.append(standardized_row)
        
        return iocs
    
    def _fetch_text_iocs(self, url: str) -> List[Dict[str, Any]]:
        """Fetch and parse text-based IOC feeds"""
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        iocs = []
        for line in response.text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                iocs.append({'ioc': line, 'type': self._detect_ioc_type(line)})
        
        return iocs
    
    def _detect_ioc_type(self, ioc: str) -> str:
        """Detect the type of IOC"""
        if '.' in ioc and '/' not in ioc:  # Simple domain check
            return 'domain'
        elif ioc.startswith('http'):
            return 'url'
        elif len(ioc) == 32 and all(c in '0123456789abcdefABCDEF' for c in ioc):
            return 'md5'
        elif len(ioc) == 40 and all(c in '0123456789abcdefABCDEF' for c in ioc):
            return 'sha1'
        elif len(ioc) == 64 and all(c in '0123456789abcdefABCDEF' for c in ioc):
            return 'sha256'
        else:
            return 'unknown'
    
    def check_ioc(self, value: str) -> List[Dict[str, Any]]:
        """Check if a value appears in any IOC feed"""
        results = []
        
        for source in self.ioc_sources:
            try:
                iocs = self.fetch_iocs(source['name'])
                for ioc in iocs:
                    if value in str(ioc.values()):
                        results.append({
                            'match': value,
                            'source': source['name'],
                            'ioc_data': ioc,
                            'found_at': datetime.now().isoformat()
                        })
            except Exception as e:
                print(f"Error checking IOC in {source['name']}: {e}")
        
        return results
    
    def monitor_feeds(self, callback: callable, interval: int = 3600):
        """Continuously monitor IOC feeds for new entries"""
        previous_iocs = set()
        
        while True:
            try:
                current_iocs = self.fetch_iocs()
                current_ioc_set = set(str(ioc) for ioc in current_iocs)
                
                new_iocs = current_ioc_set - previous_iocs
                if new_iocs:
                    callback({
                        'timestamp': datetime.now(),
                        'new_iocs_count': len(new_iocs),
                        'new_iocs': list(new_iocs),
                        'total_iocs': len(current_ioc_set)
                    })
                
                previous_iocs = current_ioc_set
                
            except Exception as e:
                print(f"Error monitoring IOC feeds: {e}")
            
            time.sleep(interval)

class IOCEnricher:
    def __init__(self, ioc_feed: IOCFeed):
        self.ioc_feed = ioc_feed
    
    def enrich_event_with_ioc(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with IOC information"""
        enriched = event.copy()
        ioc_matches = []
        
        # Check various fields for IOCs
        check_fields = ['source_ip', 'dest_ip', 'url', 'domain', 'hash', 'file_hash']
        
        for field in check_fields:
            if field in event and event[field]:
                matches = self.ioc_feed.check_ioc(event[field])
                if matches:
                    ioc_matches.extend(matches)
        
        # Also check message field for potential IOCs
        if 'message' in event:
            # Simple regex to find potential IOCs in message
            import re
            potential_iocs = re.findall(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b|'
                r'\bhttps?://[^\s]+\b|\b[a-fA-F0-9]{32,64}\b',
                event['message']
            )
            
            for ioc in potential_iocs:
                matches = self.ioc_feed.check_ioc(ioc)
                if matches:
                    ioc_matches.extend(matches)
        
        if ioc_matches:
            enriched['ioc_matches'] = ioc_matches
            enriched['ioc_match_count'] = len(ioc_matches)
            enriched['threat_level'] = 'high' if ioc_matches else 'low'
        
        return enriched