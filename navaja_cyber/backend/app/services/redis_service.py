"""Redis service for caching and pubsub."""

import json
from typing import Any, AsyncIterator

import redis.asyncio as redis


class RedisService:
    """Redis service for caching and real-time messaging."""

    def __init__(self, url: str):
        self.url = url
        self.client: redis.Redis | None = None
        self.pubsub: redis.client.PubSub | None = None

    async def connect(self):
        """Connect to Redis."""
        self.client = redis.from_url(self.url, decode_responses=True)
        self.pubsub = self.client.pubsub()

    async def disconnect(self):
        """Disconnect from Redis."""
        if self.pubsub:
            await self.pubsub.close()
        if self.client:
            await self.client.close()

    async def ping(self) -> bool:
        """Check Redis connection."""
        try:
            if self.client:
                return await self.client.ping()
            return False
        except Exception:
            return False

    async def get(self, key: str) -> Any:
        """Get value from cache."""
        if not self.client:
            return None
        value = await self.client.get(key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return None

    async def set(self, key: str, value: Any, ttl: int | None = None):
        """Set value in cache."""
        if not self.client:
            return
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        if ttl:
            await self.client.setex(key, ttl, value)
        else:
            await self.client.set(key, value)

    async def delete(self, key: str):
        """Delete key from cache."""
        if self.client:
            await self.client.delete(key)

    async def publish(self, channel: str, message: dict):
        """Publish message to channel."""
        if self.client:
            await self.client.publish(channel, json.dumps(message))

    async def subscribe(self, channel: str) -> AsyncIterator[dict]:
        """Subscribe to channel and yield messages."""
        if not self.pubsub:
            return

        await self.pubsub.subscribe(channel)

        async for message in self.pubsub.listen():
            if message["type"] == "message":
                try:
                    yield json.loads(message["data"])
                except json.JSONDecodeError:
                    yield {"raw": message["data"]}
