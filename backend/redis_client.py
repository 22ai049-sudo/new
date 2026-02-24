from __future__ import annotations

import json
import os
from typing import Any, Optional

import redis
from redis.exceptions import RedisError


class RedisClient:
    """Redis wrapper for queue/pubsub/state with safe degradation if Redis is unavailable."""

    def __init__(self, url: Optional[str] = None) -> None:
        redis_url = url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)

    def publish(self, channel: str, payload: dict[str, Any]) -> int:
        try:
            return self._client.publish(channel, json.dumps(payload))
        except RedisError:
            return 0

    def push_queue(self, queue: str, payload: dict[str, Any]) -> int:
        try:
            return self._client.lpush(queue, json.dumps(payload))
        except RedisError:
            return 0

    def pop_queue(self, queue: str, timeout: int = 1) -> Optional[dict[str, Any]]:
        try:
            item = self._client.brpop(queue, timeout=timeout)
        except RedisError:
            return None
        if item is None:
            return None
        _, raw = item
        return json.loads(raw)

    def set_json(self, key: str, payload: dict[str, Any], ttl_seconds: int = 900) -> None:
        try:
            self._client.setex(key, ttl_seconds, json.dumps(payload))
        except RedisError:
            return

    def get_json(self, key: str) -> Optional[dict[str, Any]]:
        try:
            raw = self._client.get(key)
        except RedisError:
            return None
        return json.loads(raw) if raw else None
