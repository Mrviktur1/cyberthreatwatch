import threading
import time
from typing import Dict, Any, Optional
from collections import OrderedDict
import json

class LRUCache:
    def __init__(self, capacity: int = 1000, default_ttl: int = 300):
        self.capacity = capacity
        self.default_ttl = default_ttl
        self.cache = OrderedDict()
        self.lock = threading.Lock()
        self.expiry_times = {}
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        with self.lock:
            if key not in self.cache:
                return None
            
            # Check if expired
            if key in self.expiry_times and time.time() > self.expiry_times[key]:
                del self.cache[key]
                del self.expiry_times[key]
                return None
            
            # Move to end (most recently used)
            self.cache.move_to_end(key)
            return self.cache[key]
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set item in cache"""
        with self.lock:
            if key in self.cache:
                # Remove existing to update order
                del self.cache[key]
            
            self.cache[key] = value
            
            # Set expiry time
            expiry_ttl = ttl if ttl is not None else self.default_ttl
            self.expiry_times[key] = time.time() + expiry_ttl
            
            # Evict if over capacity
            if len(self.cache) > self.capacity:
                self._evict()
    
    def _evict(self):
        """Evict least recently used item"""
        if self.cache:
            key, _ = self.cache.popitem(last=False)
            if key in self.expiry_times:
                del self.expiry_times[key]
    
    def delete(self, key: str):
        """Delete item from cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
            if key in self.expiry_times:
                del self.expiry_times[key]
    
    def clear(self):
        """Clear all items from cache"""
        with self.lock:
            self.cache.clear()
            self.expiry_times.clear()
    
    def cleanup_expired(self):
        """Clean up expired items"""
        with self.lock:
            current_time = time.time()
            expired_keys = [
                key for key, expiry in self.expiry_times.items()
                if expiry < current_time
            ]
            
            for key in expired_keys:
                if key in self.cache:
                    del self.cache[key]
                del self.expiry_times[key]
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            return {
                'size': len(self.cache),
                'capacity': self.capacity,
                'default_ttl': self.default_ttl,
                'expired_items': len([k for k, v in self.expiry_times.items() 
                                    if v < time.time()])
            }

class CacheManager:
    def __init__(self):
        self.caches = {}
        self.default_capacities = {
            'query_results': 1000,
            'ioc_lookups': 5000,
            'geoip_data': 2000,
            'whois_data': 1000,
            'threat_assessments': 1000
        }
        self.default_ttls = {
            'query_results': 300,  # 5 minutes
            'ioc_lookups': 3600,   # 1 hour
            'geoip_data': 86400,   # 24 hours
            'whois_data': 86400,   # 24 hours
            'threat_assessments': 3600  # 1 hour
        }
    
    def get_cache(self, cache_name: str) -> LRUCache:
        """Get or create a named cache"""
        if cache_name not in self.caches:
            capacity = self.default_capacities.get(cache_name, 1000)
            default_ttl = self.default_ttls.get(cache_name, 300)
            self.caches[cache_name] = LRUCache(capacity, default_ttl)
        
        return self.caches[cache_name]
    
    def cache_query_result(self, cache_name: str, query: str, 
                         params: tuple, result: Any, ttl: Optional[int] = None):
        """Cache a database query result"""
        cache = self.get_cache(cache_name)
        cache_key = self._generate_query_key(query, params)
        cache.set(cache_key, result, ttl)
    
    def get_cached_query(self, cache_name: str, query: str, 
                       params: tuple) -> Optional[Any]:
        """Get cached query result"""
        cache = self.get_cache(cache_name)
        cache_key = self._generate_query_key(query, params)
        return cache.get(cache_key)
    
    def _generate_query_key(self, query: str, params: tuple) -> str:
        """Generate a unique key for a query"""
        if params:
            return f"{query}:{hash(params)}"
        return query
    
    def cache_ioc(self, ioc_type: str, ioc_value: str, data: Any):
        """Cache IOC lookup result"""
        cache = self.get_cache('ioc_lookups')
        cache_key = f"{ioc_type}:{ioc_value}"
        cache.set(cache_key, data)
    
    def get_cached_ioc(self, ioc_type: str, ioc_value: str) -> Optional[Any]:
        """Get cached IOC lookup result"""
        cache = self.get_cache('ioc_lookups')
        cache_key = f"{ioc_type}:{ioc_value}"
        return cache.get(cache_key)
    
    def clear_cache(self, cache_name: str = None):
        """Clear specific cache or all caches"""
        if cache_name:
            if cache_name in self.caches:
                self.caches[cache_name].clear()
        else:
            for cache in self.caches.values():
                cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all caches"""
        stats = {}
        for name, cache in self.caches.items():
            stats[name] = cache.stats()
        return stats
    
    def cleanup_all(self):
        """Clean up expired items in all caches"""
        for cache in self.caches.values():
            cache.cleanup_expired()

class CacheMiddleware:
    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
    
    def with_cache(self, cache_name: str, key_generator: callable, 
                 ttl: Optional[int] = None):
        """Decorator for caching function results"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = key_generator(*args, **kwargs)
                
                # Try to get from cache
                cache = self.cache_manager.get_cache(cache_name)
                cached_result = cache.get(cache_key)
                
                if cached_result is not None:
                    return cached_result
                
                # Call function if not in cache
                result = func(*args, **kwargs)
                
                # Cache the result
                if result is not None:
                    cache.set(cache_key, result, ttl)
                
                return result
            return wrapper
        return decorator