import time
from typing import Optional, Dict, Any, Tuple


class ThreatCache:
    """
    Simple in-memory cache with TTL (Time To Live) for threat intelligence data.

    Cache structure: {ip_address: (data, timestamp)}
    """

    def __init__(self, ttl: int = 300):
        """
        Initialize cache with TTL.

        Args:
            ttl: Time to live in seconds (default: 300 = 5 minutes)
        """
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._ttl = ttl

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve data from cache if exists and not expired.

        Args:
            key: Cache key (IP address)

        Returns:
            Cached data if valid, None otherwise
        """
        if key not in self._cache:
            return None

        data, timestamp = self._cache[key]
        current_time = time.time()

        # Check if cache entry has expired
        if current_time - timestamp > self._ttl:
            # Remove expired entry
            del self._cache[key]
            return None

        return data

    def set(self, key: str, value: Any) -> None:
        """
        Store data in cache with current timestamp.

        Args:
            key: Cache key (IP address)
            value: Data to cache
        """
        self._cache[key] = (value, time.time())

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()

    def remove(self, key: str) -> bool:
        """
        Remove specific entry from cache.

        Args:
            key: Cache key to remove

        Returns:
            True if key was found and removed, False otherwise
        """
        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries from cache.

        Returns:
            Number of entries removed
        """
        current_time = time.time()
        expired_keys = [
            key for key, (_, timestamp) in self._cache.items()
            if current_time - timestamp > self._ttl
        ]

        for key in expired_keys:
            del self._cache[key]

        return len(expired_keys)