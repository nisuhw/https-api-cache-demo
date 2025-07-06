"""Caching utilities for the proxy server."""

import hashlib
import time
import json
from typing import Optional, Tuple, Dict, Any


class RequestCache:
    """Simple in-memory cache for HTTP requests with TTL."""

    def __init__(self, ttl_seconds: int = 5):
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

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
        """Get cached response if available and not expired."""
        cache_key = self._generate_cache_key(method, url, headers, body)

        if cache_key in self.cache:
            timestamp, response_data = self.cache[cache_key]

            # Check if cache entry is still valid
            if time.time() - timestamp < self.ttl_seconds:
                print(f"Cache HIT for {method} {url}")
                return response_data
            else:
                # Remove expired entry
                del self.cache[cache_key]
                print(f"Cache EXPIRED for {method} {url}")

        print(f"Cache MISS for {method} {url}")
        return None

    def set(
        self,
        method: str,
        url: str,
        headers: dict,
        body: bytes,
        response_data: Dict[str, Any],
    ) -> None:
        """Store response in cache."""
        cache_key = self._generate_cache_key(method, url, headers, body)

        # Store with current timestamp
        self.cache[cache_key] = (time.time(), response_data)
        print(f"Cached response for {method} {url}")

    def clear_expired(self) -> None:
        """Remove all expired entries from cache."""
        current_time = time.time()
        expired_keys = [
            key
            for key, (timestamp, _) in self.cache.items()
            if current_time - timestamp >= self.ttl_seconds
        ]

        for key in expired_keys:
            del self.cache[key]

    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()

    def stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        current_time = time.time()
        valid_entries = sum(
            1
            for timestamp, _ in self.cache.values()
            if current_time - timestamp < self.ttl_seconds
        )

        return {
            "total_entries": len(self.cache),
            "valid_entries": valid_entries,
            "expired_entries": len(self.cache) - valid_entries,
        }
