import re
from typing import List, Dict, Any
from datetime import datetime

class PatternMatcher:
    def __init__(self):
        self.patterns = self._load_default_patterns()
    
    def _load_default_patterns(self) -> List[Dict[str, Any]]:
        """Load default detection patterns"""
        return [
            {
                'id': 'sql_injection',
                'name': 'SQL Injection Attempt',
                'pattern': r'(\bunion\b.*\bselect\b|\binsert\b.*\binto\b|\bdrop\b.*\btable\b|\bexec\b\(|\bxp_|/\*.*\*/|--|\bwaitfor\b.*\bdelay\b)',
                'description': 'Detect common SQL injection patterns',
                'severity': 'high'
            },
            {
                'id': 'xss_attempt',
                'name': 'Cross-Site Scripting Attempt',
                'pattern': r'(<script|javascript:|onerror=|onload=|onmouseover=|alert\(|document\.cookie|window\.location)',
                'description': 'Detect common XSS patterns',
                'severity': 'high'
            },
            {
                'id': 'rce_attempt',
                'name': 'Remote Code Execution Attempt',
                'pattern': r'(\bphp\b.*\bexec\b|\bsystem\b\(|\bpopen\b\(|\bshell_exec\b\(|\bpassthru\b\(|`.*`|\$\{.*\})',
                'description': 'Detect common RCE patterns',
                'severity': 'critical'
            },
            {
                'id': 'lfi_attempt',
                'name': 'Local File Inclusion Attempt',
                'pattern': r'(\.\./|\.\.\\|\.\.%2f|\.\.%5c|/etc/passwd|/etc/shadow|/proc/self|C:\\windows\\)',
                'description': 'Detect common LFI patterns',
                'severity': 'high'
            },
            {
                'id': 'password_spraying',
                'name': 'Password Spraying Attempt',
                'pattern': r'(password|pwd|pass).*invalid|failed.*login|authentication.*failed',
                'description': 'Detect password spraying patterns',
                'severity': 'medium'
            }
        ]
    
    def add_pattern(self, pattern: Dict[str, Any]):
        """Add a new detection pattern"""
        self.patterns.append(pattern)
    
    def match_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Match text against all patterns"""
        matches = []
        
        for pattern in self.patterns:
            pattern_matches = re.findall(pattern['pattern'], text, re.IGNORECASE)
            if pattern_matches:
                matches.append({
                    'pattern_id': pattern['id'],
                    'pattern_name': pattern['name'],
                    'matches': pattern_matches,
                    'severity': pattern['severity'],
                    'match_count': len(pattern_matches)
                })
        
        return matches
    
    def scan_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan an event for pattern matches"""
        matches = []
        
        # Check message field
        if 'message' in event and event['message']:
            message_matches = self.match_patterns(event['message'])
            if message_matches:
                matches.extend(message_matches)
        
        # Check other text fields
        text_fields = ['request', 'response', 'user_agent', 'url', 'filename']
        for field in text_fields:
            if field in event and event[field]:
                field_matches = self.match_patterns(str(event[field]))
                if field_matches:
                    for match in field_matches:
                        match['field'] = field
                    matches.extend(field_matches)
        
        return matches
    
    def batch_scan(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan multiple events"""
        results = {
            'total_events': len(events),
            'events_with_matches': 0,
            'total_matches': 0,
            'matches_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'events': []
        }
        
        for event in events:
            event_matches = self.scan_event(event)
            if event_matches:
                results['events_with_matches'] += 1
                results['total_matches'] += len(event_matches)
                
                for match in event_matches:
                    results['matches_by_severity'][match['severity']] += 1
                
                results['events'].append({
                    'event': event,
                    'matches': event_matches
                })
        
        return results

class BehavioralPatternMatcher:
    def __init__(self):
        self.behavioral_patterns = []
        self._load_behavioral_patterns()
    
    def _load_behavioral_patterns(self):
        """Load behavioral patterns"""
        self.behavioral_patterns = [
            {
                'id': 'after_hours_activity',
                'name': 'After Hours Activity',
                'description': 'Activity outside normal business hours',
                'condition': self._check_after_hours,
                'severity': 'medium'
            },
            {
                'id': 'multiple_geographies',
                'name': 'Multiple Geographic Locations',
                'description': 'User activity from multiple geographic locations in short time',
                'condition': self._check_multiple_geographies,
                'severity': 'high'
            }
        ]
    
    def _check_after_hours(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for activity outside business hours (9 AM - 5 PM)"""
        alerts = []
        
        for event in events:
            if 'timestamp' in event:
                event_time = datetime.fromisoformat(event['timestamp'])
                hour = event_time.hour
                
                # Check if outside business hours (9 AM - 5 PM)
                if hour < 9 or hour > 17:
                    alerts.append({
                        'pattern_id': 'after_hours_activity',
                        'message': f'Activity detected outside business hours: {event_time}',
                        'event_time': event_time.isoformat(),
                        'user': event.get('user', 'unknown'),
                        'source_ip': event.get('source_ip', 'unknown')
                    })
        
        return alerts
    
    def _check_multiple_geographies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for activity from multiple geographic locations"""
        alerts = []
        user_locations = {}
        
        for event in events:
            if 'user' in event and 'geoip_country' in event:
                user = event['user']
                country = event['geoip_country']
                
                if user not in user_locations:
                    user_locations[user] = set()
                
                user_locations[user].add(country)
                
                if len(user_locations[user]) > 1:
                    alerts.append({
                        'pattern_id': 'multiple_geographies',
                        'message': f'User {user} activity from multiple countries: {user_locations[user]}',
                        'user': user,
                        'countries': list(user_locations[user]),
                        'event_count': len([e for e in events if e.get('user') == user])
                    })
        
        return alerts
    
    def analyze_behavior(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze events for behavioral patterns"""
        alerts = []
        
        for pattern in self.behavioral_patterns:
            pattern_alerts = pattern['condition'](events)
            for alert in pattern_alerts:
                alert['pattern_name'] = pattern['name']
                alert['severity'] = pattern['severity']
            alerts.extend(pattern_alerts)
        
        return alerts