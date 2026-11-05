import time
import pytest
from scanner.cache.redis_client import RedisClient


def test_redis_in_memory_cache_fallback():
    client = RedisClient(redis_url="redis://localhost:9999/0")  # offline port

    # Test set and get
    client.set("test_key", "hello_world", ttl_seconds=10)
    assert client.get("test_key") == "hello_world"

    # Test delete
    client.delete("test_key")
    assert client.get("test_key") is None


def test_rate_limiter_sliding_window():
    client = RedisClient(redis_url="redis://localhost:9999/0")
    user_id = "test_client_1"

    # Allow up to 3 requests per 2-second window
    allowed1, remaining1 = client.check_rate_limit(user_id, max_requests=3, window_seconds=2)
    assert allowed1 is True
    assert remaining1 == 2

    allowed2, remaining2 = client.check_rate_limit(user_id, max_requests=3, window_seconds=2)
    assert allowed2 is True
    assert remaining2 == 1

    allowed3, remaining3 = client.check_rate_limit(user_id, max_requests=3, window_seconds=2)
    assert allowed3 is True
    assert remaining3 == 0

    # 4th request must be rejected
    allowed4, remaining4 = client.check_rate_limit(user_id, max_requests=3, window_seconds=2)
    assert allowed4 is False
    assert remaining4 == 0

