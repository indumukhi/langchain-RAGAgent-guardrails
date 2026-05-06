"""
Security Guardrails — rate limiting, circuit breaker, and request utilities.

Components:
  - RateLimitConfig       : configurable limits (burst, per-minute, per-hour)
  - InMemoryRateLimiter   : sliding-window rate limiter (no external dependency)
  - CircuitBreaker        : open/half-open/closed pattern for LLM service calls
  - get_client_id         : derives a stable client identifier from IP + User-Agent
  - sanitize_for_logging  : strips newlines and truncates for safe log output
"""

import time
import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ── Rate limiter ──────────────────────────────────────────────────────────────

@dataclass
class RateLimitConfig:
    requests_per_minute: int = 20
    requests_per_hour: int = 200
    burst_limit: int = 5          # max requests within a 10-second window
    burst_window_seconds: int = 10


class InMemoryRateLimiter:
    """
    Sliding-window rate limiter backed by an in-process list of timestamps.
    Thread-safe enough for a single-process FastAPI server.
    For multi-process / multi-instance deployments, replace with Redis.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None) -> None:
        self.config = config or RateLimitConfig()
        self._requests: dict[str, list[float]] = defaultdict(list)

    def _prune(self, client_id: str, window_seconds: float) -> None:
        cutoff = time.time() - window_seconds
        self._requests[client_id] = [ts for ts in self._requests[client_id] if ts >= cutoff]

    def check_rate_limit(self, client_id: str) -> tuple[bool, str]:
        """
        Returns (allowed, reason).
        allowed=False means the request should be rejected with 429.
        """
        now = time.time()

        # Burst window check
        burst_hits = [ts for ts in self._requests[client_id] if now - ts < self.config.burst_window_seconds]
        if len(burst_hits) >= self.config.burst_limit:
            return False, (
                f"Too many requests. Maximum {self.config.burst_limit} requests "
                f"per {self.config.burst_window_seconds} seconds."
            )

        # Per-minute check
        self._prune(client_id, 60)
        if len(self._requests[client_id]) >= self.config.requests_per_minute:
            return False, f"Rate limit exceeded. Maximum {self.config.requests_per_minute} requests per minute."

        # Per-hour check (check raw list without pruning to 60s)
        hour_hits = [ts for ts in self._requests[client_id] if now - ts < 3600]
        if len(hour_hits) >= self.config.requests_per_hour:
            return False, f"Hourly limit exceeded. Maximum {self.config.requests_per_hour} requests per hour."

        self._requests[client_id].append(now)
        return True, "OK"

    def get_stats(self, client_id: str) -> dict:
        now = time.time()
        minute_count = len([ts for ts in self._requests[client_id] if now - ts < 60])
        hour_count = len([ts for ts in self._requests[client_id] if now - ts < 3600])
        return {
            "client_id": client_id,
            "requests_last_minute": minute_count,
            "requests_last_hour": hour_count,
            "limit_per_minute": self.config.requests_per_minute,
            "limit_per_hour": self.config.requests_per_hour,
        }


# ── Circuit breaker ───────────────────────────────────────────────────────────

class CircuitBreaker:
    """
    Classic three-state circuit breaker: CLOSED → OPEN → HALF_OPEN → CLOSED.

    CLOSED  : normal operation, failures are counted
    OPEN    : service calls are rejected immediately
    HALF_OPEN: one probe call is allowed; success closes, failure re-opens
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._state = self.CLOSED

    @property
    def state(self) -> str:
        return self._state

    def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        if self._state == self.OPEN:
            elapsed = time.time() - (self._last_failure_time or 0)
            if elapsed > self.recovery_timeout:
                self._state = self.HALF_OPEN
                logger.info("Circuit breaker → HALF_OPEN, allowing probe request.")
            else:
                raise RuntimeError(
                    f"Circuit breaker is OPEN — service temporarily unavailable. "
                    f"Retry in {int(self.recovery_timeout - elapsed)}s."
                )

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        if self._state != self.CLOSED:
            logger.info(f"Circuit breaker → CLOSED after successful call.")
        self._failure_count = 0
        self._state = self.CLOSED

    def _on_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self.failure_threshold:
            self._state = self.OPEN
            logger.error(
                f"Circuit breaker → OPEN after {self._failure_count} consecutive failures."
            )

    def get_status(self) -> dict:
        return {
            "state": self._state,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout_seconds": self.recovery_timeout,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client_id(ip: str, user_agent: str = "") -> str:
    """Derive a short, stable identifier from IP and User-Agent header."""
    raw = f"{ip}:{user_agent}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:16]


def sanitize_for_logging(text: str, max_length: int = 120) -> str:
    """Truncate and strip control characters for safe log output."""
    safe = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    if len(safe) > max_length:
        safe = safe[:max_length] + "…"
    return safe