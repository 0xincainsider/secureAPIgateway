"""
Structured JSON logging utility.

Provides a configured logger that outputs JSON-formatted log entries
with consistent fields for observability and auditing.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

from app.core.config import get_settings

settings = get_settings()


class JSONFormatter(logging.Formatter):
    """Custom formatter that outputs log records as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON string."""
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields from the record if present
        if hasattr(record, "request_id") and record.request_id:
            log_entry["request_id"] = record.request_id
        if hasattr(record, "ip") and record.ip:
            log_entry["ip"] = record.ip
        if hasattr(record, "user_id") and record.user_id:
            log_entry["user_id"] = record.user_id
        if hasattr(record, "endpoint") and record.endpoint:
            log_entry["endpoint"] = record.endpoint
        if hasattr(record, "status_code") and record.status_code:
            log_entry["status_code"] = record.status_code
        if hasattr(record, "duration_ms") and record.duration_ms:
            log_entry["duration_ms"] = record.duration_ms

        # Include exception info if present
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }

        return json.dumps(log_entry, default=str)


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger instance.

    Args:
        name: The logger name, typically __name__.

    Returns:
        A configured logger with JSON formatting.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(settings.log_level.upper())

    # Prevent propagation to root logger to avoid duplicate logs
    logger.propagate = False

    return logger


def log_security_event(
    logger: logging.Logger,
    event: str,
    level: int = logging.INFO,
    **extra: Any,
) -> None:
    """Log a security-related event with structured fields.

    Args:
        logger: The logger instance to use.
        event: Short name for the security event (e.g., 'login_success').
        level: Logging level (default: INFO).
        **extra: Additional fields to include in the log entry.
    """
    logger.log(level, "%s", event, extra=extra)


def generate_request_id() -> str:
    """Generate a unique request ID for tracing."""
    return uuid.uuid4().hex[:16]
