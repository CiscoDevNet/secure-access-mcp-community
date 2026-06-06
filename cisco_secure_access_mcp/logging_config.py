# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Structured JSON logging with secret redaction.

Provides observability required by the MCP security guidelines: structured logs
(stable field names), correlation IDs, and a redaction filter so credentials and
bearer tokens never reach the logs.  Logs are written to stderr so they never
contaminate the Streamable HTTP response stream.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

LOGGER_NAME = "cisco_secure_access_mcp"

# Patterns whose values must never be logged.  Matches common secret-bearing
# tokens in free-form text as a defense-in-depth backstop; structured code paths
# should avoid passing secrets in the first place.
_REDACT_PATTERNS = [
    # Authorization: Bearer <token>  /  Basic <token>
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic)\s+\S+"),
    # key=value style secrets (api_key, secret, token, password, access_token)
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|access[_-]?token)\b(\s*[:=]\s*)(\S+)"),
]
_REDACTED = "***REDACTED***"


def _scrub(text: str) -> str:
    scrubbed = _REDACT_PATTERNS[0].sub(rf"\1\2 {_REDACTED}", text)
    scrubbed = _REDACT_PATTERNS[1].sub(rf"\1\2{_REDACTED}", scrubbed)
    return scrubbed


class RedactionFilter(logging.Filter):
    """Redact secrets from both the message and structured ``extra`` fields."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        record.msg = _scrub(message)
        record.args = ()
        # Scrub known sensitive structured fields if present.
        for key in ("authorization", "api_key", "secret", "token", "password"):
            if hasattr(record, key):
                setattr(record, key, _REDACTED)
        return True


# Structured fields we promote from ``extra`` into the JSON payload.
_STRUCTURED_FIELDS = (
    "request_id",
    "client_ip",
    "method",
    "path",
    "status",
    "duration_ms",
    "event",
    "scope",
    "endpoint",
    "tool",
    "outcome",
)


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON with stable field names."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _STRUCTURED_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Configure and return the package logger (idempotent)."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level.upper())
    # Avoid duplicate handlers if called more than once.
    if not any(getattr(h, "_csa_mcp", False) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonFormatter())
        handler.addFilter(RedactionFilter())
        handler._csa_mcp = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
