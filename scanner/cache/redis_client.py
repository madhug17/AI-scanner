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
    """Manages Redis connection, rate limiting, and caching with seamless in-memory fallback."""

    def __init__(self, redis_url: str | None = None):
        self.redis_url = redis_url or settings.redis_url
        self._client: redis.Redis | None = None
        self._is_connected: bool | None = None
        # In-memory fallbacks when Redis is offline
        self._memory_cache: dict[str, tuple[str, float]] = {}  # key -> (value, expire_at)
        self._memory_rate_limits: dict[str, list[float]] = {}  # key -> timestamps

    @property
    def client(self) -> redis.Redis | None:
        if self._is_connected is False:
            return None
        if self._client is None:
            parsed = urlparse(self.redis_url)
            host = parsed.hostname or "localhost"
            port = parsed.port or 6379

            if not is_service_port_open(host, port, timeout=0.1):
                self._is_connected = False
                return None

            try:
                self._client = redis.from_url(
                    self.redis_url,
                    socket_connect_timeout=0.5,
                    decode_responses=True,
                )
                self._client.ping()
                self._is_connected = True
            except Exception:
                self._is_connected = False
                self._client = None
        return self._client

    def is_healthy(self) -> bool:
        """Check if Redis connection is live."""
        try:
            c = self.client
            return c.ping() if c else False
        except Exception:
            return False

    # --- Cache Operations ---

    def get(self, key: str) -> str | None:
        c = self.client
        if c:
            try:
                return c.get(key)
            except Exception:
                pass
        # Fallback to memory
        if key in self._memory_cache:
            val, expire_at = self._memory_cache[key]
            if time.time() < expire_at:
                return val
            del self._memory_cache[key]
        return None

    def set(self, key: str, value: str, ttl_seconds: int = 3600) -> bool:
        c = self.client
        if c:
            try:
                c.set(key, value, ex=ttl_seconds)
                return True
            except Exception:
                pass
        self._memory_cache[key] = (value, time.time() + ttl_seconds)
        return True

    def delete(self, key: str) -> bool:
        c = self.client
        if c:
            try:
                c.delete(key)
            except Exception:
                pass
        self._memory_cache.pop(key, None)
        return True

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
        key = f"rate_limit:{identifier}"
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
