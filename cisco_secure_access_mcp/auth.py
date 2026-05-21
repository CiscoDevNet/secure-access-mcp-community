# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""OAuth 2.0 token management for the Cisco Secure Access API.

Handles client credentials flow with automatic token refresh.
"""

import asyncio
import time
from dataclasses import dataclass, field

import httpx

DEFAULT_TOKEN_URL = "https://api.sse.cisco.com/auth/v2/token"

TOKEN_REFRESH_BUFFER_SECONDS = 60


@dataclass
class TokenManager:
    """Manages OAuth 2.0 access tokens with automatic refresh."""

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
        """Return a valid access token, refreshing if needed."""
        if self._access_token is None or self.is_expired:
            async with self._lock:
                if self._access_token is None or self.is_expired:
                    await self._refresh_token()
        if self._access_token is None:
            raise RuntimeError(
                "Token unavailable after refresh. Check SECURE_ACCESS_API_KEY and SECURE_ACCESS_API_SECRET"
            )
        return self._access_token

    async def _refresh_token(self) -> None:
        """Request a new access token from the Secure Access auth endpoint."""
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            response = await client.post(
                self.token_url,
                auth=(self.api_key, self.api_secret),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"grant_type": "client_credentials"},
            )
            response.raise_for_status()
            data = response.json()

        self._access_token = data["access_token"]
        self._expires_at = time.time() + data.get("expires_in", 3600)
