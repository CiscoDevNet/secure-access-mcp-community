# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""OAuth 2.0 token management for the Cisco Secure Access API.

Handles the client-credentials flow:

* One token is requested and cached for its full lifetime (typically one hour),
  so steady-state operation costs at most one token request per hour rather than
  one per API call.
* The token is refreshed automatically shortly before it expires.
* Token requests are retried with exponential backoff on rate limiting (429) and
  transient server/network errors.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx

from . import get_user_agent

DEFAULT_TOKEN_URL = "https://api.sse.cisco.com/auth/v2/token"

# Refresh slightly before the real expiry so in-flight calls never use a token
# that expires mid-request.
TOKEN_REFRESH_BUFFER_SECONDS = 60

TOKEN_REQUEST_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# Retry settings for the token endpoint.
MAX_TOKEN_ATTEMPTS = 3
RETRY_BACKOFF_BASE_SECONDS = 1.0
RETRY_BACKOFF_MAX_SECONDS = 30.0
RETRYABLE_TOKEN_STATUS = frozenset({429, 500, 502, 503, 504})


def _parse_retry_after(response: httpx.Response) -> float | None:
    """Return the Retry-After delay in seconds, if the server provided one."""
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


@dataclass
class TokenManager:
    """Manages OAuth 2.0 access tokens with caching and automatic refresh."""

    api_key: str = field(repr=False)
    api_secret: str = field(repr=False)
    token_url: str = DEFAULT_TOKEN_URL
    _access_token: str | None = field(default=None, init=False, repr=False)
    _expires_at: float = field(default=0.0, init=False, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    @property
    def is_expired(self) -> bool:
        return time.time() >= (self._expires_at - TOKEN_REFRESH_BUFFER_SECONDS)

    async def get_token(self) -> str:
        """Return a valid access token, refreshing only when needed."""
        if self._access_token is None or self.is_expired:
            async with self._lock:
                # Re-check inside the lock: a concurrent caller may have already
                # refreshed while we waited, so we avoid duplicate token requests.
                if self._access_token is None or self.is_expired:
                    await self._refresh_token()
        if self._access_token is None:
            raise RuntimeError(
                "Token unavailable after refresh. Check SECURE_ACCESS_API_KEY and SECURE_ACCESS_API_SECRET"
            )
        return self._access_token

    async def _refresh_token(self) -> None:
        """Request a new access token, retrying transient failures with backoff."""
        last_exc: Exception | None = None

        for attempt in range(1, MAX_TOKEN_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient(timeout=TOKEN_REQUEST_TIMEOUT) as client:
                    response = await client.post(
                        self.token_url,
                        auth=(self.api_key, self.api_secret),
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "User-Agent": get_user_agent(),
                        },
                        data={"grant_type": "client_credentials"},
                    )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt < MAX_TOKEN_ATTEMPTS:
                    await asyncio.sleep(self._backoff(attempt))
                    continue
                raise

            if response.status_code in RETRYABLE_TOKEN_STATUS and attempt < MAX_TOKEN_ATTEMPTS:
                delay = _parse_retry_after(response) or self._backoff(attempt)
                await asyncio.sleep(delay)
                continue

            response.raise_for_status()
            data = response.json()
            self._access_token = data["access_token"]
            self._expires_at = time.time() + data.get("expires_in", 3600)
            return

        if last_exc is not None:
            raise last_exc

    @staticmethod
    def _backoff(attempt: int) -> float:
        """Exponential backoff capped at RETRY_BACKOFF_MAX_SECONDS."""
        return min(RETRY_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)), RETRY_BACKOFF_MAX_SECONDS)
