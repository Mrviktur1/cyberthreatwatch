import re
from datetime import datetime, timedelta

class SearchEngine:
    def __init__(self):
        self.index = {}
    
    def index_data(self, data, fields_to_index):
        """Index data for faster searching"""
        for item in data:
            for field in fields_to_index:
                if field in item and item[field]:
                    value = str(item[field]).lower()
                    if value not in self.index:
                        self.index[value] = []
                    self.index[value].append(item)
    
    def search(self, query, data, search_fields=None):
        """Search through data with query"""
        if not search_fields:
            search_fields = ['message', 'source', 'event_type']
        
        results = []
        query = query.lower()
        
        # Simple text search
        for item in data:
            for field in search_fields:
                if field in item and item[field] and query in str(item[field]).lower():
                    results.append(item)
                    break
        
        # Remove duplicates
        unique_results = []
        seen_ids = set()
        for item in results:
            if item.get('id') not in seen_ids:
                unique_results.append(item)
                seen_ids.add(item.get('id'))
        
        return unique_results
    
    def advanced_search(self, query, data):
        """Advanced search with field-specific queries"""
        # Parse field-specific queries (e.g., "source:192.168.1.1 message:failed")
        field_queries = {}
        for part in query.split():
            if ':' in part:
                field, value = part.split(':', 1)
                field_queries[field] = value.lower()
        
        results = data
        
        # Apply field filters
        for field, value in field_queries.items():
            results = [item for item in results 
                      if field in item and item[field] and value in str(item[field]).lower()]
        
        return results
    
    def search_by_time_range(self, data, start_time, end_time, time_field='timestamp'):
        """Search data within time range"""
        return [item for item in data 
                if start_time <= item.get(time_field, datetime.min) <= end_time]