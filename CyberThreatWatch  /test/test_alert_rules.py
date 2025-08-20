import unittest
import sys
import os
from datetime import datetime, timedelta

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.utils.alert_rules import AlertRuleEngine

class TestAlertRuleEngine(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.rule_engine = AlertRuleEngine()
        
        # Sample test events
        self.sample_events = [
            {
                'id': 1,
                'timestamp': datetime(2023, 8, 19, 10, 30, 45),
                'source_ip': '192.168.1.15',
                'message': 'Failed login attempt for user1',
                'event_type': 'authentication',
                'status': 'failed'
            },
            {
                'id': 2,
                'timestamp': datetime(2023, 8, 19, 10, 31, 22),
                'source_ip': '192.168.1.15',
                'message': 'Failed login attempt for user1',
                'event_type': 'authentication',
                'status': 'failed'
            },
            {
                'id': 3,
                'timestamp': datetime(2023, 8, 19, 10, 32, 18),
                'source_ip': '192.168.1.15',
                'message': 'Failed login attempt for user1',
                'event_type': 'authentication',
                'status': 'failed'
            },
            {
                'id': 4,
                'timestamp': datetime(2023, 8, 19, 10, 33, 45),
                'source_ip': '192.168.1.15',
                'message': 'Failed login attempt for user1',
                'event_type': 'authentication',
                'status': 'failed'
            },
            {
                'id': 5,
                'timestamp': datetime(2023, 8, 19, 10, 34, 30),
                'source_ip': '192.168.1.15',
                'message': 'Failed login attempt for user1',
                'event_type': 'authentication',
                'status': 'failed'
            },
            {
                'id': 6,
                'timestamp': datetime(2023, 8, 19, 10, 35, 15),
                'source_ip': '192.168.1.10',
                'message': 'User admin logged in successfully',
                'event_type': 'authentication',
                'status': 'success'
            },
            {
                'id': 7,
                'timestamp': datetime(2023, 8, 19, 10, 36, 0),
                'source_ip': '192.168.1.20',
                'message': 'Network scan detected',
                'event_type': 'network',
                'port_count': 25
            }
        ]
    
    def test_multiple_failed_logins_rule(self):
        """Test multiple failed login attempts rule"""
        # Test with threshold exceeded
        alerts = self.rule_engine.rules[0]['condition'](self.sample_events)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['rule_id'], 1)
        self.assertEqual(alerts[0]['severity'], 'High')
        self.assertIn('192.168.1.15', alerts[0]['message'])
        self.assertEqual(alerts[0]['count'], 5)
    
    def test_multiple_failed_logins_below_threshold(self):
        """Test multiple failed login attempts below threshold"""
        # Use only 3 failed login events (below threshold of 5)
        few_events = [e for e in self.sample_events if e['id'] in [1, 2, 3, 6]]
        
        alerts = self.rule_engine.rules[0]['condition'](few_events)
        self.assertEqual(len(alerts), 0)
    
    def test_unusual_activity_rule(self):
        """Test unusual activity detection rule"""
        # Create events with high activity
        high_activity_events = []
        for i in range(150):  # Exceed threshold of 100
            event = {
                'id': i,
                'timestamp': datetime.now() - timedelta(minutes=i),
                'source_ip': f'192.168.1.{i % 10}',
                'message': f'Event {i}',
                'event_type': 'network'
            }
            high_activity_events.append(event)
        
        alerts = self.rule_engine.rules[1]['condition'](high_activity_events)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['rule_id'], 2)
        self.assertEqual(alerts[0]['severity'], 'Medium')
        self.assertIn('high activity', alerts[0]['message'].lower())
    
    def test_unusual_activity_below_threshold(self):
        """Test unusual activity below threshold"""
        # Create events with normal activity
        normal_activity_events = []
        for i in range(50):  # Below threshold of 100
            event = {
                'id': i,
                'timestamp': datetime.now() - timedelta(minutes=i),
                'source_ip': f'192.168.1.{i % 10}',
                'message': f'Event {i}',
                'event_type': 'network'
            }
            normal_activity_events.append(event)
        
        alerts = self.rule_engine.rules[1]['condition'](normal_activity_events)
        self.assertEqual(len(alerts), 0)
    
    def test_evaluate_all_rules(self):
        """Test evaluation of all rules"""
        alerts = self.rule_engine.evaluate_rules(self.sample_events)
        
        # Should trigger multiple failed logins rule
        self.assertTrue(len(alerts) >= 1)
        
        # Check alert structure
        for alert in alerts:
            self.assertIn('rule_id', alert)
            self.assertIn('message', alert)
            self.assertIn('severity', alert)
    
    def test_add_rule(self):
        """Test adding a custom rule"""
        initial_rule_count = len(self.rule_engine.rules)
        
        new_rule = {
            'name': 'Test Custom Rule',
            'condition': lambda events: [{'test': 'alert'}],
            'severity': 'Low',
            'enabled': True
        }
        
        self.rule_engine.add_rule(new_rule)
        
        self.assertEqual(len(self.rule_engine.rules), initial_rule_count + 1)
        self.assertEqual(self.rule_engine.rules[-1]['name'], 'Test Custom Rule')
        self.assertEqual(self.rule_engine.rules[-1]['id'], initial_rule_count + 1)
    
    def test_toggle_rule(self):
        """Test enabling/disabling rules"""
        rule_id = 1
        
        # Disable the rule
        self.rule_engine.toggle_rule(rule_id, False)
        disabled_rule = next(r for r in self.rule_engine.rules if r['id'] == rule_id)
        self.assertFalse(disabled_rule['enabled'])
        
        # Re-enable the rule
        self.rule_engine.toggle_rule(rule_id, True)
        enabled_rule = next(r for r in self.rule_engine.rules if r['id'] == rule_id)
        self.assertTrue(enabled_rule['enabled'])
    
    def test_evaluate_disabled_rule(self):
        """Test that disabled rules don't generate alerts"""
        rule_id = 1
        
        # Disable the rule
        self.rule_engine.toggle_rule(rule_id, False)
        
        # Evaluate rules
        alerts = self.rule_engine.evaluate_rules(self.sample_events)
        
        # Should not have alerts from disabled rule
        rule_alerts = [a for a in alerts if a.get('rule_id') == rule_id]
        self.assertEqual(len(rule_alerts), 0)
    
    def test_rule_engine_with_empty_events(self):
        """Test rule engine with empty events list"""
        alerts = self.rule_engine.evaluate_rules([])
        self.assertEqual(len(alerts), 0)
    
    def test_rule_engine_with_none_events(self):
        """Test rule engine with None events"""
        alerts = self.rule_engine.evaluate_rules(None)
        self.assertEqual(len(alerts), 0)
    
    def test_custom_rule_condition(self):
        """Test custom rule condition function"""
        def custom_condition(events):
            alerts = []
            for event in events:
                if event.get('event_type') == 'network' and event.get('port_count', 0) > 20:
                    alerts.append({
                        'rule_id': 999,
                        'message': f'Network scan detected from {event.get("source_ip")}',
                        'severity': 'High',
                        'source_ip': event.get('source_ip')
                    })
            return alerts
        
        # Add custom rule
        custom_rule = {
            'name': 'Network Scan Detection',
            'condition': custom_condition,
            'severity': 'High',
            'enabled': True
        }
        
        self.rule_engine.add_rule(custom_rule)
        
        # Evaluate rules
        alerts = self.rule_engine.evaluate_rules(self.sample_events)
        
        # Should find the network scan event
        scan_alerts = [a for a in alerts if a.get('rule_id') == 999]
        self.assertEqual(len(scan_alerts), 1)
        self.assertEqual(scan_alerts[0]['source_ip'], '192.168.1.20')

if __name__ == '__main__':
    unittest.main()