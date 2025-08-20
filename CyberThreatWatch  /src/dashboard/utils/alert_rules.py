from datetime import datetime, timedelta

class AlertRuleEngine:
    def __init__(self):
        self.rules = []
        self.load_default_rules()
    
    def load_default_rules(self):
        """Load default alert rules"""
        self.rules = [
            {
                'id': 1,
                'name': 'Multiple Failed Logins',
                'condition': self.multiple_failed_logins,
                'severity': 'High',
                'enabled': True
            },
            {
                'id': 2,
                'name': 'Unusual Activity',
                'condition': self.unusual_activity,
                'severity': 'Medium',
                'enabled': True
            }
        ]
    
    def multiple_failed_logins(self, events):
        """Detect multiple failed login attempts from same source"""
        failed_logins = [e for e in events if 'failed' in e.get('message', '').lower() 
                        and 'login' in e.get('message', '').lower()]
        
        source_count = {}
        for event in failed_logins:
            source = event.get('source', 'unknown')
            source_count[source] = source_count.get(source, 0) + 1
        
        alerts = []
        for source, count in source_count.items():
            if count >= 5:  # Threshold for alert
                alerts.append({
                    'rule_id': 1,
                    'message': f'Multiple failed login attempts from {source}',
                    'severity': 'High',
                    'source': source,
                    'count': count
                })
        
        return alerts
    
    def unusual_activity(self, events):
        """Detect unusual activity patterns"""
        # Simple implementation - in real scenario, use ML or statistical analysis
        recent_events = [e for e in events 
                        if datetime.now() - e.get('timestamp', datetime.now()) < timedelta(minutes=30)]
        
        if len(recent_events) > 100:  # Threshold for unusual activity
            return [{
                'rule_id': 2,
                'message': 'Unusually high activity detected',
                'severity': 'Medium',
                'event_count': len(recent_events)
            }]
        
        return []
    
    def evaluate_rules(self, events):
        """Evaluate all rules against events"""
        alerts = []
        for rule in self.rules:
            if rule['enabled']:
                rule_alerts = rule['condition'](events)
                alerts.extend(rule_alerts)
        
        return alerts
    
    def add_rule(self, rule):
        """Add a new rule"""
        rule['id'] = len(self.rules) + 1
        self.rules.append(rule)
    
    def toggle_rule(self, rule_id, enabled):
        """Enable/disable a rule"""
        for rule in self.rules:
            if rule['id'] == rule_id:
                rule['enabled'] = enabled
                break