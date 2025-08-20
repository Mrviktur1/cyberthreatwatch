import unittest
import pandas as pd
from datetime import datetime, timedelta
import sys
import os

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.utils.data_processing import DataProcessor

class TestDataProcessor(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.processor = DataProcessor()
        
        # Sample test data
        self.sample_data = [
            {
                'timestamp': '2023-08-19 10:30:45',
                'source_ip': '192.168.1.10',
                'event_type': 'login',
                'status': 'success',
                'user': 'admin'
            },
            {
                'timestamp': '2023-08-19 10:31:22',
                'source_ip': '192.168.1.15',
                'event_type': 'login',
                'status': 'failed',
                'user': 'user1'
            },
            {
                'timestamp': '2023-08-19 10:32:18',
                'source_ip': '192.168.1.15',
                'event_type': 'login',
                'status': 'failed',
                'user': 'user1'
            }
        ]
    
    def test_parse_timestamp_valid(self):
        """Test parsing valid timestamp strings"""
        test_cases = [
            ('2023-08-19 10:30:45', '%Y-%m-%d %H:%M:%S'),
            ('2023-08-19T10:30:45', '%Y-%m-%dT%H:%M:%S'),
            ('19/Aug/2023:10:30:45', '%d/%b/%Y:%H:%M:%S')
        ]
        
        for timestamp_str, expected_format in test_cases:
            with self.subTest(timestamp_str=timestamp_str):
                result = self.processor.parse_timestamp(timestamp_str)
                self.assertIsInstance(result, datetime)
    
    def test_parse_timestamp_invalid(self):
        """Test parsing invalid timestamp strings"""
        invalid_timestamps = ['invalid_date', '123', '']
        
        for timestamp_str in invalid_timestamps:
            with self.subTest(timestamp_str=timestamp_str):
                result = self.processor.parse_timestamp(timestamp_str)
                self.assertIsInstance(result, datetime)  # Should return current time
    
    def test_normalize_data(self):
        """Test data normalization with field mapping"""
        test_data = {
            'src_ip': '192.168.1.10',
            'dst_ip': '10.0.0.1',
            'msg': 'Connection established'
        }
        
        field_mapping = {
            'source_ip': 'src_ip',
            'dest_ip': 'dst_ip',
            'message': 'msg'
        }
        
        result = self.processor.normalize_data(test_data, field_mapping)
        
        self.assertEqual(result['source_ip'], '192.168.1.10')
        self.assertEqual(result['dest_ip'], '10.0.0.1')
        self.assertEqual(result['message'], 'Connection established')
        self.assertNotIn('src_ip', result)
    
    def test_filter_by_time_range(self):
        """Test filtering data by time range"""
        # Create test data with timestamps
        test_data = [
            {'timestamp': datetime(2023, 8, 19, 10, 0, 0), 'event': 'A'},
            {'timestamp': datetime(2023, 8, 19, 11, 0, 0), 'event': 'B'},
            {'timestamp': datetime(2023, 8, 19, 12, 0, 0), 'event': 'C'}
        ]
        
        start_time = datetime(2023, 8, 19, 10, 30, 0)
        end_time = datetime(2023, 8, 19, 11, 30, 0)
        
        result = self.processor.filter_by_time_range(
            test_data, 'timestamp', start_time, end_time
        )
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['event'], 'B')
    
    def test_aggregate_events(self):
        """Test event aggregation by time interval"""
        # Create test data with timestamps
        test_data = [
            {'timestamp': datetime(2023, 8, 19, 10, 0, 0), 'value': 1},
            {'timestamp': datetime(2023, 8, 19, 10, 15, 0), 'value': 2},
            {'timestamp': datetime(2023, 8, 19, 10, 30, 0), 'value': 3},
            {'timestamp': datetime(2023, 8, 19, 10, 45, 0), 'value': 4}
        ]
        
        result = self.processor.aggregate_events(test_data, '30min')
        
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)
    
    def test_aggregate_events_empty(self):
        """Test event aggregation with empty data"""
        result = self.processor.aggregate_events([], '1H')
        self.assertEqual(result, [])
    
    def test_calculate_statistics(self):
        """Test statistics calculation"""
        test_data = [
            {
                'timestamp': datetime(2023, 8, 19, 10, 0, 0),
                'source': '192.168.1.10',
                'value': 100
            },
            {
                'timestamp': datetime(2023, 8, 19, 11, 0, 0),
                'source': '192.168.1.15',
                'value': 200
            },
            {
                'timestamp': datetime(2023, 8, 19, 12, 0, 0),
                'source': '192.168.1.10',
                'value': 150
            }
        ]
        
        stats = self.processor.calculate_statistics(test_data)
        
        self.assertEqual(stats['total_events'], 3)
        self.assertEqual(stats['unique_sources'], 2)
        self.assertIn('start_time', stats)
        self.assertIn('end_time', stats)
    
    def test_calculate_statistics_empty(self):
        """Test statistics calculation with empty data"""
        stats = self.processor.calculate_statistics([])
        self.assertEqual(stats, {})
    
    def test_calculate_statistics_no_source(self):
        """Test statistics calculation without source field"""
        test_data = [
            {'timestamp': datetime(2023, 8, 19, 10, 0, 0), 'value': 100},
            {'timestamp': datetime(2023, 8, 19, 11, 0, 0), 'value': 200}
        ]
        
        stats = self.processor.calculate_statistics(test_data)
        self.assertEqual(stats['unique_sources'], 0)

if __name__ == '__main__':
    unittest.main()