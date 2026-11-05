import socket
import time
from urllib.parse import urlparse
from typing import Any
import redis
from scanner.core.config import settings


def is_service_port_open(host: str, port: int, timeout: float = 0.2) -> bool:
    """Quick non-blocking probe to verify if a daemon is listening on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError, TimeoutError):
        return False


class RedisClient:
    """Manages Redis connection, rate limiting, and caching with seamless in-memory fallback.
    
    Includes full parameter configurability and telemetry for performance benchmarking.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        enabled: bool | None = None,
        ttl: int | None = None,
        key_prefix: str | None = None,
        timeout: float | None = None,
        max_connections: int | None = None,
        invalidation_strategy: str | None = None,
    ):
        self.redis_url = redis_url or settings.redis_url
        self.enabled = settings.redis_enabled if enabled is None else enabled
        self.default_ttl = ttl or settings.redis_scan_cache_ttl
        self.key_prefix = settings.redis_key_prefix if key_prefix is None else key_prefix
        self.timeout = timeout or settings.redis_timeout_sec
        self.max_connections = max_connections or settings.redis_max_connections
        self.invalidation_strategy = invalidation_strategy or settings.redis_invalidation_strategy

        self._client: redis.Redis | None = None
        self._is_connected: bool | None = None

        # In-memory fallbacks when Redis is offline or disabled
        self._memory_cache: dict[str, tuple[str, float]] = {}  # key -> (value, expire_at)
        self._memory_rate_limits: dict[str, list[float]] = {}  # key -> timestamps

        # Telemetry metrics
        self.hits: int = 0
        self.misses: int = 0
        self.sets: int = 0
        self.invalidations: int = 0

    def _prefixed_key(self, key: str) -> str:
        if key.startswith(self.key_prefix):
            return key
        return f"{self.key_prefix}{key}"

    @property
    def client(self) -> redis.Redis | None:
        if not self.enabled:
            return None
        if self._is_connected is False:
            return None
        if self._client is None:
            parsed = urlparse(self.redis_url)
            host = parsed.hostname or settings.redis_host
            port = parsed.port or settings.redis_port

            if not is_service_port_open(host, port, timeout=0.1):
                self._is_connected = False
                return None

            try:
                pool = redis.ConnectionPool.from_url(
                    self.redis_url,
                    max_connections=self.max_connections,
                    socket_connect_timeout=self.timeout,
                    decode_responses=True,
                )
                self._client = redis.Redis(connection_pool=pool)
                self._client.ping()
                self._is_connected = True
            except Exception:
                self._is_connected = False
                self._client = None
        return self._client

    def is_healthy(self) -> bool:
        """Check if Redis connection is live."""
        if not self.enabled:
            return False
        try:
            c = self.client
            return c.ping() if c else False
        except Exception:
            return False

    # --- Cache Operations ---

    def get(self, key: str) -> str | None:
        if not self.enabled:
            self.misses += 1
            return None

        p_key = self._prefixed_key(key)
        c = self.client
        if c:
            try:
                val = c.get(p_key)
                if val is not None:
                    self.hits += 1
                    return val
                self.misses += 1
                return None
            except Exception:
                pass

        # Fallback to in-memory store
        if p_key in self._memory_cache:
            val, expire_at = self._memory_cache[p_key]
            if time.time() < expire_at:
                self.hits += 1
                return val
            del self._memory_cache[p_key]

        self.misses += 1
        return None

    def set(self, key: str, value: str, ttl_seconds: int | None = None) -> bool:
        if not self.enabled:
            return False

        p_key = self._prefixed_key(key)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        self.sets += 1

        c = self.client
        if c:
            try:
                c.set(p_key, value, ex=ttl)
                return True
            except Exception:
                pass

        self._memory_cache[p_key] = (value, time.time() + ttl)
        return True

    def delete(self, key: str) -> bool:
        p_key = self._prefixed_key(key)
        self.invalidations += 1

        c = self.client
        if c:
            try:
                c.delete(p_key)
            except Exception:
                pass

        self._memory_cache.pop(p_key, None)
        return True

    def invalidate_scan(self, scan_id: str) -> int:
        """Invalidate all cached items related to a specific scan_id."""
        keys = [
            f"scan:{scan_id}:status",
            f"scan:{scan_id}:report",
            f"scan:{scan_id}:findings",
        ]
        count = 0
        for k in keys:
            self.delete(k)
            count += 1
        return count

    def get_stats(self) -> dict[str, Any]:
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100.0) if total > 0 else 0.0
        return {
            "enabled": self.enabled,
            "connected": self._is_connected is True,
            "hits": self.hits,
            "misses": self.misses,
            "sets": self.sets,
            "invalidations": self.invalidations,
            "hit_rate_pct": round(hit_rate, 2),
            "miss_rate_pct": round(100.0 - hit_rate, 2) if total > 0 else 0.0,
        }

    def reset_stats(self) -> None:
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.invalidations = 0

    # --- Rate Limiting (Sliding Window) ---

    def check_rate_limit(
        self,
        identifier: str,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> tuple[bool, int]:
        """Check if request within sliding window is allowed.
        
        Returns (is_allowed, remaining_requests).
        """
        key = self._prefixed_key(f"rate_limit:{identifier}")
        now = time.time()
        c = self.client

        if c:
            try:
                pipe = c.pipeline()
                pipe.zremrangebyscore(key, 0, now - window_seconds)
                pipe.zadd(key, {str(now): now})
                pipe.zcard(key)
                pipe.expire(key, window_seconds)
                _, _, current_count, _ = pipe.execute()
                is_allowed = current_count <= max_requests
                remaining = max(0, max_requests - current_count)
                return is_allowed, remaining
            except Exception:
                pass

        # In-memory sliding window fallback
        timestamps = self._memory_rate_limits.setdefault(key, [])
        cutoff = now - window_seconds
        self._memory_rate_limits[key] = [t for t in timestamps if t > cutoff]
        self._memory_rate_limits[key].append(now)

        current_count = len(self._memory_rate_limits[key])
        is_allowed = current_count <= max_requests
        remaining = max(0, max_requests - current_count)
        return is_allowed, remaining


redis_client = RedisClient()
