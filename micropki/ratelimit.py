"""Thread-safe token-bucket rate limiter."""

from __future__ import annotations

import threading
import time


class TokenBucketRateLimiter:
    def __init__(self, rate_per_second: float = 0, burst: int = 10):
        self.rate = float(rate_per_second or 0)
        self.burst = max(1, int(burst or 1))
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.rate > 0

    def allow(self, client_id: str) -> tuple[bool, int]:
        if not self.enabled:
            return True, 0
        now = time.monotonic()
        with self._lock:
            tokens, updated = self._state.get(client_id, (float(self.burst), now))
            elapsed = max(0.0, now - updated)
            tokens = min(float(self.burst), tokens + elapsed * self.rate)
            if tokens >= 1.0:
                tokens -= 1.0
                self._state[client_id] = (tokens, now)
                return True, 0
            retry = max(1, int((1.0 - tokens) / self.rate + 0.999))
            self._state[client_id] = (tokens, now)
            return False, retry
