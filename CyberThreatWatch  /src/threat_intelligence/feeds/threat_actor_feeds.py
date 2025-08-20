import requests
import json
from datetime import datetime
from typing import List, Dict, Any

class ThreatActorFeed:
    def __init__(self):
        self.threat_actor_sources = [
            {
                'name': 'MITRE ATT&CK Groups',
                'url': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
                'type': 'mitre'
            },
            {
                'name': 'AlienVault OTX Pulse Groups',
                'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
                'type': 'otx',
                'api_key_required': True
            }
        ]
        self.threat_actor_cache = {}
    
    def fetch_threat_actors(self, source_name: str = None) -> List[Dict[str, Any]]:
        """Fetch threat actor information from feeds"""
        all_actors = []
        
        for source in self.threat_actor_sources:
            if source_name and source['name'] != source_name:
                continue
            
            try:
                if source['type'] == 'mitre':
                    actors = self._fetch_mitre_actors(source['url'])
                elif source['type'] == 'otx' and not source.get('api_key_required', False):
                    actors = self._fetch_otx_actors(source['url'])
                else:
                    actors = []
                
                # Add source information
                for actor in actors:
                    actor['source'] = source['name']
                    actor['collected'] = datetime.now().isoformat()
                
                all_actors.extend(actors)
                
            except Exception as e:
                print(f"Error fetching from {source['name']}: {e}")
        
        return all_actors
    
    def _fetch_mitre_actors(self, url: str) -> List[Dict[str, Any]]:
        """Fetch threat actors from MITRE ATT&CK"""
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        actors = []
        
        for obj in data['objects']:
            if obj['type'] == 'intrusion-set':
                actor = {
                    'id': obj['id'],
                    'name': obj['name'],
                    'description': obj.get('description', ''),
                    'aliases': obj.get('aliases', []),
                    'techniques': [],
                    'references': []
                }
                
                # Get techniques used by this actor
                for ref in data['objects']:
                    if (ref['type'] == 'relationship' and 
                        ref['relationship_type'] == 'uses' and 
                        ref['source_ref'] == obj['id']):
                        technique_id = ref['target_ref']
                        for tech in data['objects']:
                            if tech['id'] == technique_id and tech['type'] == 'attack-pattern':
                                actor['techniques'].append({
                                    'id': technique_id,
                                    'name': tech['name'],
                                    'description': tech.get('description', '')
                                })
                
                actors.append(actor)
        
        return actors
    
    def _fetch_otx_actors(self, url: str) -> List[Dict[str, Any]]:
        """Fetch threat actors from AlienVault OTX"""
        # This is a placeholder - would need API key for real implementation
        return []
    
    def identify_threat_actor(self, techniques: List[str], iocs: List[str]) -> List[Dict[str, Any]]:
        """Identify potential threat actors based on techniques and IOCs"""
        potential_actors = []
        all_actors = self.fetch_threat_actors()
        
        for actor in all_actors:
            match_score = 0
            
            # Check technique matches
            actor_techniques = [tech['id'] for tech in actor.get('techniques', [])]
            technique_matches = set(techniques) & set(actor_techniques)
            if technique_matches:
                match_score += len(technique_matches) * 10
            
            # Check IOC matches (would need more sophisticated matching)
            # Placeholder logic
            
            if match_score > 0:
                actor['match_score'] = match_score
                actor['technique_matches'] = list(technique_matches)
                potential_actors.append(actor)
        
        # Sort by match score
        potential_actors.sort(key=lambda x: x['match_score'], reverse=True)
        
        return potential_actors
    
    def monitor_new_actors(self, callback: callable, interval: int = 86400):
        """Monitor for new threat actors"""
        previous_actors = set()
        
        while True:
            try:
                current_actors = self.fetch_threat_actors()
                current_actor_set = set(actor['id'] for actor in current_actors)
                
                new_actors = current_actor_set - previous_actors
                if new_actors:
                    new_actor_details = [
                        actor for actor in current_actors 
                        if actor['id'] in new_actors
                    ]
                    
                    callback({
                        'timestamp': datetime.now(),
                        'new_actors_count': len(new_actors),
                        'new_actors': new_actor_details
                    })
                
                previous_actors = current_actor_set
                
            except Exception as e:
                print(f"Error monitoring threat actor feeds: {e}")
            
            time.sleep(interval)

class ThreatActorEnricher:
    def __init__(self, threat_actor_feed: ThreatActorFeed):
        self.threat_actor_feed = threat_actor_feed
    
    def enrich_event_with_threat_actor(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with threat actor information"""
        enriched = event.copy()
        
        # Extract techniques from event (simplified)
        techniques = event.get('mitre_techniques', [])
        if not techniques and 'message' in event:
            # Try to extract techniques from message
            techniques = self._extract_techniques_from_message(event['message'])
        
        # Check for threat actor matches
        if techniques:
            potential_actors = self.threat_actor_feed.identify_threat_actor(techniques, [])
            if potential_actors:
                enriched['potential_threat_actors'] = potential_actors
                enriched['primary_threat_actor'] = potential_actors[0]['name']
        
        return enriched
    
    def _extract_techniques_from_message(self, message: str) -> List[str]:
        """Extract MITRE techniques from message text"""
        # This is very simplified - real implementation would need more sophisticated
        # pattern matching and technique identification
        
        technique_patterns = {
            'T1059': ['command line', 'cmd.exe', 'powershell', 'script'],
            'T1071': ['http request', 'web traffic', 'port 80', 'port 443'],
            'T1082': ['system information', 'system info', 'whoami'],
            'T1105': ['file download', 'wget', 'curl', 'file transfer']
        }
        
        found_techniques = []
        message_lower = message.lower()
        
        for technique_id, patterns in technique_patterns.items():
            for pattern in patterns:
                if pattern in message_lower:
                    found_techniques.append(technique_id)
                    break
        
        return found_techniques