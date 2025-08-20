import unittest
import sys
import os
from datetime import datetime, timedelta

# Add the parent directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.utils.search_engine import SearchEngine

class TestSearchEngine(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.search_engine = SearchEngine()
        
        # Sample test data
        self.sample_data = [
            {
                'id': 1,
                'timestamp': '2023-08-19 10:30:45',
                'source_ip': '192.168.1.10',
                'message': 'User admin logged in successfully',
                'event_type': 'authentication',
                'status': 'success'
            },
            {
                'id': 2,
                'timestamp': '2023-08-19 10:31:22',
                'source_ip': '192.168.1.15',
                'message': 'Failed login attempt for user1',
                'event_type': 'authentication',
                'status': 'failed'
            },
            {
                'id': 3,
                'timestamp': '2023-08-19 10:32:18',
                'source_ip': '192.168.1.15',
                'message': 'Failed login attempt for user1',
                'event_type': 'authentication',
                'status': 'failed'
            },
            {
                'id': 4,
                'timestamp': '2023-08-19 10:33:45',
                'source_ip': '192.168.1.20',
                'message': 'Network connection to 8.8.8.8:53',
                'event_type': 'network',
                'protocol': 'udp',
                'dest_port': 53
            }
        ]
        
        # Index the data
        self.search_engine.index_data(self.sample_data, ['source_ip', 'message', 'event_type'])
    
    def test_basic_search(self):
        """Test basic text search"""
        results = self.search_engine.search('failed', self.sample_data)
        
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIn('failed', result['message'].lower())
    
    def test_case_insensitive_search(self):
        """Test case-insensitive search"""
        results = self.search_engine.search('FAILED', self.sample_data)
        self.assertEqual(len(results), 2)
    
    def test_search_specific_fields(self):
        """Test search limited to specific fields"""
        results = self.search_engine.search(
            '192.168.1.15', 
            self.sample_data, 
            ['source_ip']
        )
        
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertEqual(result['source_ip'], '192.168.1.15')
    
    def test_search_no_results(self):
        """Test search with no matching results"""
        results = self.search_engine.search('nonexistentterm', self.sample_data)
        self.assertEqual(len(results), 0)
    
    def test_advanced_search_field_queries(self):
        """Test advanced search with field-specific queries"""
        query = "source_ip:192.168.1.15 message:failed"
        results = self.search_engine.advanced_search(query, self.sample_data)
        
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertEqual(result['source_ip'], '192.168.1.15')
            self.assertIn('failed', result['message'].lower())
    
    def test_advanced_search_partial_matches(self):
        """Test advanced search with partial matches"""
        query = "source_ip:192.168 message:login"
        results = self.search_engine.advanced_search(query, self.sample_data)
        
        self.assertEqual(len(results), 3)  # All login events from 192.168.x.x
    
    def test_advanced_search_invalid_field(self):
        """Test advanced search with non-existent field"""
        query = "nonexistent_field:value"
        results = self.search_engine.advanced_search(query, self.sample_data)
        self.assertEqual(len(results), 0)
    
    def test_search_by_time_range(self):
        """Test search within time range"""
        # Convert sample data to use datetime objects
        data_with_datetime = []
        for event in self.sample_data:
            event_copy = event.copy()
            event_copy['timestamp'] = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
            data_with_datetime.append(event_copy)
        
        start_time = datetime(2023, 8, 19, 10, 31, 0)
        end_time = datetime(2023, 8, 19, 10, 33, 0)
        
        results = self.search_engine.search_by_time_range(
            data_with_datetime, start_time, end_time
        )
        
        # Should find events from 10:31:22 and 10:32:18
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertTrue(start_time <= result['timestamp'] <= end_time)
    
    def test_index_data(self):
        """Test data indexing functionality"""
        # Create new search engine instance
        se = SearchEngine()
        test_data = [{'id': 1, 'field1': 'value1', 'field2': 'value2'}]
        
        se.index_data(test_data, ['field1', 'field2'])
        
        # Check if values are indexed
        self.assertIn('value1', se.index)
        self.assertIn('value2', se.index)
    
    def test_remove_duplicates(self):
        """Test duplicate removal in search results"""
        # Create data with duplicates
        duplicate_data = self.sample_data + [self.sample_data[0]]  # Add duplicate
        
        results = self.search_engine.search('login', duplicate_data)
        
        # Should have unique results only
        seen_ids = set()
        for result in results:
            self.assertNotIn(result['id'], seen_ids)
            seen_ids.add(result['id'])
    
    def test_empty_search_query(self):
        """Test search with empty query"""
        results = self.search_engine.search('', self.sample_data)
        self.assertEqual(len(results), 0)
    
    def test_none_search_query(self):
        """Test search with None query"""
        results = self.search_engine.search(None, self.sample_data)
        self.assertEqual(len(results), 0)

if __name__ == '__main__':
    unittest.main()