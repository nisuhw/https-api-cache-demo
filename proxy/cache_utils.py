"""Caching utilities for the proxy server."""

import hashlib
import time
import json
import threading
from typing import Optional, Tuple, Dict, Any
from collections import OrderedDict


class RequestCache:
    """Thread-safe in-memory cache for HTTP requests with TTL and improved locking."""

    def __init__(self, ttl_seconds: int = 5, max_size: int = 10000):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        # Use OrderedDict for LRU-like behavior
        self.cache: OrderedDict[str, Tuple[float, Dict[str, Any]]] = OrderedDict()
        
        # Separate locks for different operations
        self._read_lock = threading.RLock()  # For concurrent reads
        self._write_lock = threading.RLock()  # For writes and cache modifications
        self._stats_lock = threading.RLock()  # For statistics operations
        
        # Cache hit/miss counters
        self._hits = 0
        self._misses = 0
        
        # Background cleanup thread
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        """Start background thread for cleaning expired entries."""
        def cleanup_worker():
            while not self._stop_cleanup.wait(30):  # Check every 30 seconds
                try:
                    self._cleanup_expired_entries()
                except Exception as e:
                    # Log error but don't stop the thread
                    print(f"Cache cleanup error: {e}")
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()

    def _cleanup_expired_entries(self):
        """Remove expired entries from cache (internal method)."""
        current_time = time.time()
        expired_keys = []
        
        # Quick scan for expired entries
        with self._read_lock:
            for key, (timestamp, _) in self.cache.items():
                if current_time - timestamp >= self.ttl_seconds:
                    expired_keys.append(key)
        
        # Remove expired entries
        if expired_keys:
            with self._write_lock:
                for key in expired_keys:
                    self.cache.pop(key, None)

    def _generate_cache_key(
        self, method: str, url: str, headers: dict, body: bytes = b""
    ) -> str:
        """Generate a unique cache key based on request attributes."""
        # Create a hashable representation of the request
        cache_data = {
            "method": method.upper(),
            "url": url,
            "headers": {
                k.lower(): v
                for k, v in sorted(headers.items())
                if k.lower()
                not in ["cookie", "authorization", "date", "age", "expires"]
            },
            "body_hash": hashlib.sha256(body).hexdigest() if body else "",
        }

        # Convert to JSON for consistent ordering
        cache_str = json.dumps(cache_data, sort_keys=True)

        # Generate SHA256 hash
        return hashlib.sha256(cache_str.encode()).hexdigest()

    def get(
        self, method: str, url: str, headers: dict, body: bytes = b""
    ) -> Optional[Dict[str, Any]]:
        """Get cached response if available and not expired (thread-safe)."""
        # Generate cache key outside of lock for better performance
        cache_key = self._generate_cache_key(method, url, headers, body)
        current_time = time.time()
        
        # Use read lock for concurrent access
        with self._read_lock:
            if cache_key in self.cache:
                timestamp, response_data = self.cache[cache_key]
                
                # Check if cache entry is still valid
                if current_time - timestamp < self.ttl_seconds:
                    # Move to end for LRU behavior
                    self.cache.move_to_end(cache_key)
                    # Increment hit counter
                    with self._stats_lock:
                        self._hits += 1
                    return response_data
                else:
                    # Remove expired entry (requires write lock)
                    with self._write_lock:
                        self.cache.pop(cache_key, None)
        
        # Increment miss counter
        with self._stats_lock:
            self._misses += 1
        return None

    def set(
        self,
        method: str,
        url: str,
        headers: dict,
        body: bytes,
        response_data: Dict[str, Any],
    ) -> None:
        """Store response in cache (thread-safe)."""
        # Generate cache key outside of lock for better performance
        cache_key = self._generate_cache_key(method, url, headers, body)
        current_time = time.time()
        
        with self._write_lock:
            # Check if we need to evict entries due to size limit
            if len(self.cache) >= self.max_size:
                # Remove oldest entries (LRU)
                while len(self.cache) >= self.max_size * 0.9:  # Keep 90% of max size
                    self.cache.popitem(last=False)
            
            # Store with current timestamp
            self.cache[cache_key] = (current_time, response_data)
            # Move to end for LRU behavior
            self.cache.move_to_end(cache_key)

    def clear_expired(self) -> None:
        """Remove all expired entries from cache (thread-safe)."""
        self._cleanup_expired_entries()

    def clear(self) -> None:
        """Clear all cache entries (thread-safe)."""
        with self._write_lock:
            self.cache.clear()

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics (thread-safe)."""
        current_time = time.time()
        
        with self._stats_lock:
            valid_entries = 0
            total_entries = len(self.cache)
            
            # Count valid entries
            for timestamp, _ in self.cache.values():
                if current_time - timestamp < self.ttl_seconds:
                    valid_entries += 1

            total_requests = self._hits + self._misses
            hit_rate = round((self._hits / total_requests) * 100, 2) if total_requests > 0 else 0
            miss_rate = round((self._misses / total_requests) * 100, 2) if total_requests > 0 else 0
            
            return {
                "total_entries": total_entries,
                "valid_entries": valid_entries,
                "expired_entries": total_entries - valid_entries,
                "max_size": self.max_size,
                "cache_utilization": round((total_entries / self.max_size) * 100, 2) if self.max_size > 0 else 0,
                "cache_hits": self._hits,
                "cache_misses": self._misses,
                "total_requests": total_requests,
                "hit_rate_percent": hit_rate,
                "miss_rate_percent": miss_rate,
            }

    def __del__(self):
        """Cleanup when cache is destroyed."""
        if hasattr(self, '_stop_cleanup'):
            self._stop_cleanup.set()
            if self._cleanup_thread and self._cleanup_thread.is_alive():
                self._cleanup_thread.join(timeout=1)
