"""
Structured logging for Ab0t Auth.

Observability at key decision points following functional principles.
Uses structlog for structured, contextual logging.
"""

from __future__ import annotations

import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import structlog


# =============================================================================
# Context Variables for Request Tracking
# =============================================================================

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("user_id", default=None)


# =============================================================================
# Log Event Types
# =============================================================================


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """Structured auth event for logging."""

    event: str
    success: bool
    duration_ms: float | None = None
    user_id: str | None = None
    org_id: str | None = None
    permission: str | None = None
    error: str | None = None
    metadata: dict[str, Any] | None = None


# =============================================================================
# Logger Configuration
# =============================================================================


def configure_logging(
    *,
    level: str = "INFO",
    json_format: bool = True,
    include_timestamp: bool = True,
) -> None:
    """
    Configure structured logging.

    Call once at application startup.
    """
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if include_timestamp:
        processors.append(structlog.processors.TimeStamper(fmt="iso"))

    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(structlog, level.upper(), structlog.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "ab0t_auth") -> structlog.BoundLogger:
    """
    Get configured logger instance.

    Factory function for logger creation.
    """
    return structlog.get_logger(name)


# =============================================================================
# Logging Functions (Pure-ish - side effect is logging)
# =============================================================================


def log_auth_attempt(
    logger: structlog.BoundLogger,
    *,
    method: str,
    success: bool,
    user_id: str | None = None,
    duration_ms: float | None = None,
    error: str | None = None,
    **extra: Any,
) -> None:
    """
    Log authentication attempt.

    Logs at INFO level for success, WARNING for failure.
    """
    event_data = {
        "event_type": "auth_attempt",
        "method": method,
        "success": success,
    }
    if user_id:
        event_data["user_id"] = user_id
    if duration_ms is not None:
        event_data["duration_ms"] = round(duration_ms, 2)
    if error:
        event_data["error"] = error
    event_data.update(extra)

    if success:
        logger.info("Authentication successful", **event_data)
    else:
        logger.warning("Authentication failed", **event_data)


def log_permission_check(
    logger: structlog.BoundLogger,
    *,
    permission: str,
    allowed: bool,
    user_id: str,
    method: str = "local",
    duration_ms: float | None = None,
    **extra: Any,
) -> None:
    """
    Log permission check result.

    Logs at DEBUG level for allowed, INFO for denied.
    """
    event_data = {
        "event_type": "permission_check",
        "permission": permission,
        "allowed": allowed,
        "user_id": user_id,
        "method": method,
    }
    if duration_ms is not None:
        event_data["duration_ms"] = round(duration_ms, 2)
    event_data.update(extra)

    if allowed:
        logger.debug("Permission granted", **event_data)
    else:
        logger.info("Permission denied", **event_data)


def log_token_validation(
    logger: structlog.BoundLogger,
    *,
    valid: bool,
    method: str = "jwt",
    user_id: str | None = None,
    duration_ms: float | None = None,
    error: str | None = None,
    cached: bool = False,
    **extra: Any,
) -> None:
    """
    Log token validation result.

    Logs at DEBUG level for valid tokens, WARNING for invalid.
    """
    event_data = {
        "event_type": "token_validation",
        "valid": valid,
        "method": method,
        "cached": cached,
    }
    if user_id:
        event_data["user_id"] = user_id
    if duration_ms is not None:
        event_data["duration_ms"] = round(duration_ms, 2)
    if error:
        event_data["error"] = error
    event_data.update(extra)

    if valid:
        logger.debug("Token validated", **event_data)
    else:
        logger.warning("Token validation failed", **event_data)


def log_cache_operation(
    logger: structlog.BoundLogger,
    *,
    operation: str,
    cache_type: str,
    hit: bool | None = None,
    key: str | None = None,
    **extra: Any,
) -> None:
    """
    Log cache operation.

    Logs at DEBUG level.
    """
    event_data = {
        "event_type": "cache_operation",
        "operation": operation,
        "cache_type": cache_type,
    }
    if hit is not None:
        event_data["hit"] = hit
    if key:
        event_data["key"] = key[:16] + "..." if len(key) > 16 else key
    event_data.update(extra)

    logger.debug("Cache operation", **event_data)


def log_error(
    logger: structlog.BoundLogger,
    error: Exception,
    *,
    context: str | None = None,
    **extra: Any,
) -> None:
    """
    Log error with context.

    Logs at ERROR level with exception info.
    """
    event_data = {
        "event_type": "error",
        "error_type": type(error).__name__,
        "error_message": str(error),
    }
    if context:
        event_data["context"] = context
    event_data.update(extra)

    logger.error("Error occurred", exc_info=error, **event_data)


# =============================================================================
# Timing Utilities
# =============================================================================


class Timer:
    """
    Simple timer for measuring operation duration.

    Infrastructure class for observability.
    """

    def __init__(self) -> None:
        self._start: float | None = None
        self._end: float | None = None

    def start(self) -> "Timer":
        """Start the timer."""
        self._start = time.perf_counter()
        return self

    def stop(self) -> "Timer":
        """Stop the timer."""
        self._end = time.perf_counter()
        return self

    @property
    def elapsed_ms(self) -> float:
        """Get elapsed time in milliseconds."""
        if self._start is None:
            return 0.0
        end = self._end if self._end is not None else time.perf_counter()
        return (end - self._start) * 1000

    def __enter__(self) -> "Timer":
        return self.start()

    def __exit__(self, *args: Any) -> None:
        self.stop()


def timed(logger: structlog.BoundLogger, event: str) -> Timer:
    """
    Create timer that logs on completion.

    Factory function for timed operations.
    """
    return Timer()


# =============================================================================
# Metrics (Counters)
# =============================================================================


@dataclass
class AuthMetrics:
    """
    Simple in-memory metrics for auth operations.

    Infrastructure class for observability.
    """

    auth_attempts: int = 0
    auth_successes: int = 0
    auth_failures: int = 0
    permission_checks: int = 0
    permission_grants: int = 0
    permission_denials: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    token_validations: int = 0

    def record_auth_attempt(self, success: bool) -> None:
        """Record authentication attempt."""
        self.auth_attempts += 1
        if success:
            self.auth_successes += 1
        else:
            self.auth_failures += 1

    def record_permission_check(self, allowed: bool) -> None:
        """Record permission check."""
        self.permission_checks += 1
        if allowed:
            self.permission_grants += 1
        else:
            self.permission_denials += 1

    def record_cache_access(self, hit: bool) -> None:
        """Record cache access."""
        if hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

    def record_token_validation(self) -> None:
        """Record token validation."""
        self.token_validations += 1

    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0

    @property
    def auth_success_rate(self) -> float:
        """Calculate auth success rate."""
        return self.auth_successes / self.auth_attempts if self.auth_attempts > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Export metrics as dictionary."""
        return {
            "auth_attempts": self.auth_attempts,
            "auth_successes": self.auth_successes,
            "auth_failures": self.auth_failures,
            "auth_success_rate": round(self.auth_success_rate, 4),
            "permission_checks": self.permission_checks,
            "permission_grants": self.permission_grants,
            "permission_denials": self.permission_denials,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": round(self.cache_hit_rate, 4),
            "token_validations": self.token_validations,
        }
