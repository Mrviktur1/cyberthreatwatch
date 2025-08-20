from typing import List, Dict, Any, Callable
from datetime import datetime, timedelta
import re

class RuleEngine:
    def __init__(self):
        self.rules = []
        self.events_buffer = []
        self.max_buffer_size = 10000
        self.load_default_rules()
    
    def load_default_rules(self):
        """Load default correlation rules"""
        self.rules = [
            {
                'id': 'multiple_failed_logins',
                'name': 'Multiple Failed Login Attempts',
                'description': 'Detect multiple failed login attempts from same source',
                'condition': self._check_multiple_failed_logins,
                'severity': 'high',
                'enabled': True
            },
            {
                'id': 'port_scan',
                'name': 'Port Scan Detection',
                'description': 'Detect potential port scanning activity',
                'condition': self._check_port_scan,
                'severity': 'medium',
                'enabled': True
            },
            {
                'id': 'data_exfiltration',
                'name': 'Data Exfiltration',
                'description': 'Detect large outbound data transfers',
                'condition': self._check_data_exfiltration,
                'severity': 'high',
                'enabled': True
            }
        ]
    
    def add_rule(self, rule: Dict[str, Any]):
        """Add a new correlation rule"""
        rule['id'] = f"custom_rule_{len(self.rules) + 1}"
        self.rules.append(rule)
    
    def remove_rule(self, rule_id: str):
        """Remove a correlation rule"""
        self.rules = [rule for rule in self.rules if rule['id'] != rule_id]
    
    def enable_rule(self, rule_id: str, enabled: bool = True):
        """Enable or disable a rule"""
        for rule in self.rules:
            if rule['id'] == rule_id:
                rule['enabled'] = enabled
                break
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an event through all rules"""
        alerts = []
        
        # Add event to buffer
        self.events_buffer.append(event)
        
        # Keep buffer size manageable
        if len(self.events_buffer) > self.max_buffer_size:
            self.events_buffer = self.events_buffer[-self.max_buffer_size:]
        
        # Check all enabled rules
        for rule in self.rules:
            if rule['enabled']:
                try:
                    rule_alerts = rule['condition'](event, self.events_buffer)
                    for alert in rule_alerts:
                        alert['rule_id'] = rule['id']
                        alert['rule_name'] = rule['name']
                        alert['severity'] = rule['severity']
                        alerts.append(alert)
                except Exception as e:
                    print(f"Error executing rule {rule['id']}: {e}")
        
        return alerts
    
    def _check_multiple_failed_logins(self, event: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for multiple failed login attempts"""
        if 'login' not in event.get('message', '').lower() or 'fail' not in event.get('message', '').lower():
            return []
        
        source_ip = event.get('source_ip') or event.get('src_ip') or 'unknown'
        
        # Count failed logins from same source in last 5 minutes
        time_threshold = datetime.now() - timedelta(minutes=5)
        failed_logins = [
            e for e in events
            if e.get('source_ip') == source_ip and
            'login' in e.get('message', '').lower() and
            'fail' in e.get('message', '').lower() and
            datetime.fromisoformat(e.get('timestamp')) > time_threshold
        ]
        
        if len(failed_logins) >= 5:
            return [{
                'message': f'Multiple failed login attempts from {source_ip}',
                'source_ip': source_ip,
                'attempt_count': len(failed_logins),
                'time_window': '5 minutes'
            }]
        
        return []
    
    def _check_port_scan(self, event: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for port scanning activity"""
        if 'port' not in event.get('message', '').lower() or 'scan' not in event.get('message', '').lower():
            return []
        
        source_ip = event.get('source_ip') or event.get('src_ip') or 'unknown'
        dest_ip = event.get('dest_ip') or event.get('dst_ip') or 'unknown'
        
        # Count port-related events from same source to same destination in last minute
        time_threshold = datetime.now() - timedelta(minutes=1)
        port_events = [
            e for e in events
            if e.get('source_ip') == source_ip and
            e.get('dest_ip') == dest_ip and
            'port' in e.get('message', '').lower() and
            datetime.fromisoformat(e.get('timestamp')) > time_threshold
        ]
        
        if len(port_events) >= 10:  # Threshold for port scan
            return [{
                'message': f'Possible port scan from {source_ip} to {dest_ip}',
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'event_count': len(port_events),
                'time_window': '1 minute'
            }]
        
        return []
    
    def _check_data_exfiltration(self, event: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for data exfiltration patterns"""
        if 'bytes' not in event or int(event.get('bytes', 0)) < 1000000:  # 1MB threshold
            return []
        
        source_ip = event.get('source_ip') or event.get('src_ip') or 'unknown'
        
        # Check for large outbound transfers in last hour
        time_threshold = datetime.now() - timedelta(hours=1)
        large_transfers = [
            e for e in events
            if e.get('source_ip') == source_ip and
            int(e.get('bytes', 0)) >= 1000000 and
            datetime.fromisoformat(e.get('timestamp')) > time_threshold
        ]
        
        if len(large_transfers) >= 3:  # Multiple large transfers
            total_bytes = sum(int(e.get('bytes', 0)) for e in large_transfers)
            return [{
                'message': f'Possible data exfiltration from {source_ip}',
                'source_ip': source_ip,
                'transfer_count': len(large_transfers),
                'total_bytes': total_bytes,
                'time_window': '1 hour'
            }]
        
        return []

class CorrelationEngine:
    def __init__(self, rule_engine: RuleEngine):
        self.rule_engine = rule_engine
        self.alert_callbacks = []
    
    def add_alert_callback(self, callback: Callable):
        """Add a callback function for alerts"""
        self.alert_callbacks.append(callback)
    
    def process_events(self, events: List[Dict[str, Any]]):
        """Process multiple events"""
        all_alerts = []
        
        for event in events:
            alerts = self.rule_engine.process_event(event)
            if alerts:
                all_alerts.extend(alerts)
                
                # Notify callbacks
                for callback in self.alert_callbacks:
                    try:
                        callback(alerts)
                    except Exception as e:
                        print(f"Error in alert callback: {e}")
        
        return all_alerts
    
    def load_rules_from_file(self, file_path: str):
        """Load rules from JSON or YAML file"""
        # Placeholder implementation
        pass
    
    def save_rules_to_file(self, file_path: str):
        """Save rules to JSON or YAML file"""
        # Placeholder implementation
        pass