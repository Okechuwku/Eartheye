from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Deque

from fastapi import Request


class SlidingWindowRateLimiter:
    """Simple in-memory sliding-window limiter for API protection.

    Note: For multi-instance production deployments, replace with a shared
    backend (Redis) so limits are enforced consistently across replicas.
    """

    def __init__(self) -> None:
        self._events: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_seconds

        async with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= limit:
                retry_after = max(1, int(window_seconds - (now - bucket[0])))
                return False, retry_after

            bucket.append(now)
            return True, 0


rate_limiter = SlidingWindowRateLimiter()


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        first_hop = forwarded_for.split(",", 1)[0].strip()
        if first_hop:
            return first_hop

    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip

    return request.client.host if request.client else "unknown"


def build_rate_limit_key(request: Request, bucket: str) -> str:
    ip_address = get_client_ip(request)
    auth_header = request.headers.get("authorization", "")
    token_hint = "anon"
    if auth_header.lower().startswith("bearer "):
        token_hint = auth_header[7:19] or "token"
    return f"{bucket}:{ip_address}:{token_hint}"
