# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Transport-layer security controls for the Streamable HTTP MCP server.

Implements the HTTP-transport controls called for by the MCP security
guidelines:

* Client -> server authentication via a static bearer token (constant-time
  comparison), with an explicit, loudly-warned "no auth" testing mode.
* Request payload size limits (large-payload DoS protection).
* Per-client rate limiting (in-memory fixed window).
* Correlation IDs (``X-Request-ID``) propagated to responses and logs.
* Structured access logging for every request.

DNS-rebinding / Host / Origin validation is delegated to FastMCP's built-in
``transport_security`` (configured in ``server.py``).

The middleware is implemented as pure ASGI (not Starlette ``BaseHTTPMiddleware``)
so it never buffers the streaming MCP response.
"""

from __future__ import annotations

import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field

from starlette.datastructures import Headers, MutableHeaders

from .logging_config import get_logger


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_list(name: str) -> list[str]:
    value = os.environ.get(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


class SecurityConfigError(RuntimeError):
    """Raised when the security configuration is unsafe or inconsistent."""


@dataclass
class SecurityConfig:
    """Resolved transport-security configuration loaded from the environment."""

    auth_token: str | None = field(default=None, repr=False)
    allow_no_auth: bool = False
    max_request_bytes: int = 1 * 1024 * 1024
    rate_limit_rpm: int = 120
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_origins: list[str] = field(default_factory=list)
    enable_dns_rebinding_protection: bool = True

    @property
    def auth_required(self) -> bool:
        return self.auth_token is not None

    @classmethod
    def from_env(cls) -> SecurityConfig:
        token = os.environ.get("MCP_AUTH_TOKEN", "").strip() or None
        allow_no_auth = _env_bool("MCP_ALLOW_NO_AUTH", default=False)

        # Secure by default: refuse to start without authentication unless the
        # operator has explicitly opted into the (not recommended) testing mode.
        if token is None and not allow_no_auth:
            raise SecurityConfigError(
                "No client authentication configured. Set MCP_AUTH_TOKEN to a strong secret "
                "to require 'Authorization: Bearer <token>' from MCP clients.\n"
                "For local testing ONLY (NOT RECOMMENDED), set MCP_ALLOW_NO_AUTH=true to run "
                "without client->server authentication."
            )
        if token is not None and allow_no_auth:
            raise SecurityConfigError(
                "MCP_AUTH_TOKEN and MCP_ALLOW_NO_AUTH are both set. Choose one: either require a "
                "token (recommended) or explicitly run the no-auth testing mode."
            )
        if token is not None and len(token) < 16:
            raise SecurityConfigError(
                "MCP_AUTH_TOKEN is too short. Use at least 16 characters of high-entropy secret "
                "(e.g. `python -c \"import secrets; print(secrets.token_urlsafe(32))\"`)."
            )

        return cls(
            auth_token=token,
            allow_no_auth=allow_no_auth,
            max_request_bytes=_env_int("MCP_MAX_REQUEST_BYTES", 1 * 1024 * 1024),
            rate_limit_rpm=_env_int("MCP_RATE_LIMIT_RPM", 120),
            allowed_hosts=_env_list("MCP_ALLOWED_HOSTS"),
            allowed_origins=_env_list("MCP_ALLOWED_ORIGINS"),
            enable_dns_rebinding_protection=not _env_bool(
                "MCP_DISABLE_DNS_REBINDING_PROTECTION", default=False
            ),
        )

    def public_summary(self) -> dict[str, object]:
        """Non-secret summary suitable for startup logging."""
        return {
            "auth_required": self.auth_required,
            "no_auth_testing_mode": self.allow_no_auth,
            "max_request_bytes": self.max_request_bytes,
            "rate_limit_rpm": self.rate_limit_rpm,
            "dns_rebinding_protection": self.enable_dns_rebinding_protection,
            "allowed_hosts": self.allowed_hosts or "(default)",
            "allowed_origins": self.allowed_origins or "(none)",
        }


class _FixedWindowRateLimiter:
    """Simple in-memory per-key fixed-window limiter.

    Note: state is per-process.  Behind multiple workers or replicas, enforce
    rate limits at the gateway/proxy instead.
    """

    def __init__(self, limit_per_minute: int) -> None:
        self.limit = limit_per_minute
        self._windows: dict[str, list[float]] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        if self.limit <= 0:
            return True, 0
        now = time.monotonic()
        window_start = now - 60.0
        timestamps = [t for t in self._windows.get(key, []) if t >= window_start]
        if len(timestamps) >= self.limit:
            retry_after = max(1, int(60 - (now - timestamps[0])))
            self._windows[key] = timestamps
            return False, retry_after
        timestamps.append(now)
        self._windows[key] = timestamps
        return True, 0


class SecurityMiddleware:
    """Pure-ASGI middleware enforcing auth, limits, rate limiting, and logging."""

    def __init__(self, app, config: SecurityConfig) -> None:
        self.app = app
        self.config = config
        self.logger = get_logger()
        self._limiter = _FixedWindowRateLimiter(config.rate_limit_rpm)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        client_ip = self._client_ip(scope)
        request_id = headers.get("x-request-id") or uuid.uuid4().hex
        method = scope.get("method", "")
        path = scope.get("path", "")
        start = time.monotonic()
        status_holder = {"status": 0}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                mutable = MutableHeaders(scope=message)
                mutable["x-request-id"] = request_id
            await send(message)

        def log_request(status: int, outcome: str) -> None:
            self.logger.info(
                "request",
                extra={
                    "event": "http_request",
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "method": method,
                    "path": path,
                    "status": status,
                    "outcome": outcome,
                    "duration_ms": round((time.monotonic() - start) * 1000, 1),
                },
            )

        # 1) Rate limiting (per client IP).
        allowed, retry_after = self._limiter.allow(client_ip)
        if not allowed:
            log_request(429, "rate_limited")
            await self._reject(send_wrapper, 429, "rate_limited", request_id, retry_after)
            return

        # 2) Payload size limit (based on Content-Length).
        content_length = headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > self.config.max_request_bytes:
            log_request(413, "payload_too_large")
            await self._reject(send_wrapper, 413, "payload_too_large", request_id)
            return

        # 3) Authentication.
        if self.config.auth_required and not self._authorized(headers):
            log_request(401, "unauthorized")
            await self._reject(send_wrapper, 401, "unauthorized", request_id)
            return

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            log_request(status_holder["status"], "served")

    def _authorized(self, headers: Headers) -> bool:
        assert self.config.auth_token is not None
        authorization = headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return False
        return hmac.compare_digest(token.strip(), self.config.auth_token)

    @staticmethod
    def _client_ip(scope) -> str:
        client = scope.get("client")
        if client and isinstance(client, (tuple, list)):
            return str(client[0])
        return "unknown"

    @staticmethod
    async def _reject(send, status: int, code: str, request_id: str, retry_after: int = 0) -> None:
        body = json.dumps({"error": code, "request_id": request_id}).encode()
        response_headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"x-request-id", request_id.encode()),
        ]
        if status == 401:
            response_headers.append((b"www-authenticate", b'Bearer realm="cisco-secure-access-mcp"'))
        if retry_after > 0:
            response_headers.append((b"retry-after", str(retry_after).encode()))
        await send({"type": "http.response.start", "status": status, "headers": response_headers})
        await send({"type": "http.response.body", "body": body})
