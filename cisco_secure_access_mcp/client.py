# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared async HTTP client for the Cisco Secure Access API.

All tool modules use SecureAccessClient to make authenticated API requests.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import httpx

from .auth import TokenManager

API_BASE_URL = "https://api.sse.cisco.com"
REQUEST_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
ALLOWED_REDIRECT_HOST_SUFFIXES = ("api.sse.cisco.com", ".cisco.com", ".umbrella.com")


class SecureAccessAPIError(Exception):
    """Raised when the Secure Access API returns an error response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Secure Access API error {status_code}: {detail}")


class SecureAccessClient:
    """Async HTTP client for the Cisco Secure Access REST API."""

    def __init__(self, token_manager: TokenManager) -> None:
        self.token_manager = token_manager

    async def _get_headers(self) -> dict[str, str]:
        token = await self.token_manager.get_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    async def request(
        self,
        method: str,
        scope: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
    ) -> Any:
        """Make an authenticated request to the Secure Access API.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE).
            scope: API scope path (e.g. "policies/v2").
            endpoint: Path after the scope (e.g. "destinationlists").
            params: Optional query parameters.
            json_data: Optional JSON request body.

        Returns:
            Parsed JSON response, or None for 204.
        """
        url = f"{API_BASE_URL}/{scope}/{endpoint}"
        return await self.request_url(method, url, params=params, json_data=json_data)

    async def request_url(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
    ) -> Any:
        """Make an authenticated request to an allow-listed Secure Access URL.

        Some Cisco reports endpoints return redirects.  We only follow HTTPS
        redirects to Cisco-controlled hosts and keep Authorization attached so
        report calls work consistently.
        """
        self._validate_url(url)
        headers = await self._get_headers()

        async with httpx.AsyncClient(follow_redirects=False) as http:
            response = await http.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_data,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code in (301, 302, 307, 308):
                redirect_url = response.headers.get("location", "")
                self._validate_url(redirect_url)
                response = await http.request(
                    method,
                    redirect_url,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                )

        if response.status_code >= 400:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            raise SecureAccessAPIError(response.status_code, str(detail))

        if response.status_code == 204:
            return None

        body = response.content
        if len(body) > MAX_RESPONSE_BYTES:
            raise RuntimeError(f"Response too large ({len(body):,} bytes). Narrow your query or reduce the limit.")
        data = response.json()
        if isinstance(data, dict):
            nested_data = data.get("data")
            if isinstance(nested_data, dict) and set(nested_data) == {"redirect"}:
                redirect_url = nested_data["redirect"]
                self._validate_url(redirect_url)
                headers = await self._get_headers()
                async with httpx.AsyncClient(follow_redirects=False) as http:
                    redirected_response = await http.request(
                        method,
                        redirect_url,
                        headers=headers,
                        timeout=REQUEST_TIMEOUT,
                    )
                redirected_response.raise_for_status()
                return redirected_response.json()
        return data

    async def get(self, scope: str, endpoint: str, **kwargs: Any) -> Any:
        return await self.request("GET", scope, endpoint, **kwargs)

    async def post(self, scope: str, endpoint: str, **kwargs: Any) -> Any:
        return await self.request("POST", scope, endpoint, **kwargs)

    async def patch(self, scope: str, endpoint: str, **kwargs: Any) -> Any:
        return await self.request("PATCH", scope, endpoint, **kwargs)

    async def delete(self, scope: str, endpoint: str, **kwargs: Any) -> Any:
        return await self.request("DELETE", scope, endpoint, **kwargs)

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or not any(
            host == suffix or host.endswith(suffix) for suffix in ALLOWED_REDIRECT_HOST_SUFFIXES
        ):
            raise RuntimeError("Blocked redirect outside allowed Cisco API hosts")


def format_error(e: Exception) -> str:
    """Format an exception into an actionable error message for the LLM."""
    if isinstance(e, SecureAccessAPIError):
        messages: dict[int, str] = {
            400: "Bad request. Check that all parameters are valid.",
            401: "Authentication failed. Verify your SECURE_ACCESS_API_KEY and SECURE_ACCESS_API_SECRET are correct.",
            403: "Permission denied. Your API key may lack the required scope for this operation.",
            404: "Resource not found. Verify the destination list ID you provided exists.",
            429: "Rate limit exceeded. Wait a moment before retrying.",
            500: "Secure Access server error. Try again shortly.",
            503: "Secure Access service temporarily unavailable. Try again shortly.",
        }
        hint = messages.get(e.status_code, "")
        detail = e.detail[:500] + "…" if len(e.detail) > 500 else e.detail
        return f"Error {e.status_code}: {detail}" + (f" — {hint}" if hint else "")
    if isinstance(e, httpx.TimeoutException):
        return "Error: Request timed out. Try again or use a smaller query."
    return f"Error: {type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _strip_empty(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_empty(v) for k, v in obj.items() if v is not None and v != "" and v != [] and v != {}}
    if isinstance(obj, list):
        return [_strip_empty(item) for item in obj]
    return obj


def compact_json(data: Any) -> str:
    """Serialise data to compact JSON with null/empty fields stripped."""
    return json.dumps(_strip_empty(data), separators=(",", ":"))
