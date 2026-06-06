# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared async HTTP client for the Cisco Secure Access API.

All tool modules use SecureAccessClient to make authenticated API requests.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from . import get_user_agent
from .auth import TokenManager
from .logging_config import get_logger

_logger = get_logger()

API_BASE_URL = "https://api.sse.cisco.com"
REQUEST_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
ALLOWED_REDIRECT_HOST_SUFFIXES = ("api.sse.cisco.com", ".cisco.com", ".umbrella.com")

# Connection pooling: reuse one AsyncClient (and its TCP/TLS connections) for the
# whole server lifetime instead of opening a new connection per request.
MAX_CONNECTIONS = 20
MAX_KEEPALIVE_CONNECTIONS = 10

# Retry settings mirroring the official SDK's retry configuration.
MAX_RETRY_ATTEMPTS = 3
RETRY_BACKOFF_BASE_SECONDS = 1.0
RETRY_BACKOFF_MAX_SECONDS = 30.0
# 429 is safe to retry for any method (the request was rejected, not applied).
RETRY_STATUS_ANY_METHOD = frozenset({429})
# 5xx / network failures are only retried for idempotent reads to avoid
# accidentally repeating a create/update/delete.
RETRY_STATUS_IDEMPOTENT = frozenset({500, 502, 503, 504})
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Pagination defaults. Most Secure Access page/limit endpoints cap page size at
# 100, though a few offset/limit endpoints allow larger windows.
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 100
MAX_OFFSET_PAGE_SIZE = 1000
# Hard safety cap on pages walked, to bound memory and request volume.
MAX_PAGES = 1000


class SecureAccessAPIError(Exception):
    """Raised when the Secure Access API returns an error response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Secure Access API error {status_code}: {detail}")


def _parse_retry_after(response: httpx.Response) -> float | None:
    """Return the Retry-After delay in seconds, if the server provided one."""
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


class SecureAccessClient:
    """Async HTTP client for the Cisco Secure Access REST API.

    Holds a single pooled ``httpx.AsyncClient`` for the server lifetime and
    transparently retries rate-limited and transient failures with exponential
    backoff.  Call :meth:`aclose` on shutdown to release pooled connections.
    """

    def __init__(self, token_manager: TokenManager, *, max_retries: int = MAX_RETRY_ATTEMPTS) -> None:
        self.token_manager = token_manager
        self.max_retries = max_retries
        self._http: httpx.AsyncClient | None = None
        self._http_lock = asyncio.Lock()

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None:
            async with self._http_lock:
                if self._http is None:
                    self._http = httpx.AsyncClient(
                        follow_redirects=False,
                        timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=10.0),
                        limits=httpx.Limits(
                            max_connections=MAX_CONNECTIONS,
                            max_keepalive_connections=MAX_KEEPALIVE_CONNECTIONS,
                        ),
                    )
        return self._http

    async def aclose(self) -> None:
        """Close the pooled HTTP client.  Safe to call multiple times."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _get_headers(self) -> dict[str, str]:
        token = await self.token_manager.get_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": get_user_agent(),
        }

    @staticmethod
    def _backoff(attempt: int) -> float:
        return min(RETRY_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)), RETRY_BACKOFF_MAX_SECONDS)

    async def _send_with_retries(
        self,
        http: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
    ) -> httpx.Response:
        """Send a request, retrying rate limits and transient failures."""
        is_idempotent = method.upper() in IDEMPOTENT_METHODS
        last_exc: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = await http.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_data,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if is_idempotent and attempt < self.max_retries:
                    await asyncio.sleep(self._backoff(attempt))
                    continue
                raise

            status = response.status_code
            retryable = status in RETRY_STATUS_ANY_METHOD or (
                is_idempotent and status in RETRY_STATUS_IDEMPOTENT
            )
            if retryable and attempt < self.max_retries:
                await response.aread()
                delay = _parse_retry_after(response) or self._backoff(attempt)
                await asyncio.sleep(delay)
                continue
            return response

        if last_exc is not None:
            raise last_exc
        return response

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
        http = await self._get_http()

        start = time.monotonic()
        # Log only the path (never query params or the Authorization header) to
        # avoid leaking secrets or PII into the audit log.
        audit_path = urlparse(url).path

        try:
            response = await self._send_with_retries(
                http, method, url, headers=headers, params=params, json_data=json_data
            )
            if response.status_code in (301, 302, 307, 308):
                redirect_url = response.headers.get("location", "")
                self._validate_url(redirect_url)
                response = await self._send_with_retries(
                    http, method, redirect_url, headers=headers
                )
        except Exception as exc:
            _logger.warning(
                "api call failed",
                extra={
                    "event": "api_call",
                    "method": method,
                    "path": audit_path,
                    "outcome": type(exc).__name__,
                    "duration_ms": round((time.monotonic() - start) * 1000, 1),
                },
            )
            raise

        _logger.info(
            "api call",
            extra={
                "event": "api_call",
                "method": method,
                "path": audit_path,
                "status": response.status_code,
                "outcome": "ok" if response.status_code < 400 else "error",
                "duration_ms": round((time.monotonic() - start) * 1000, 1),
            },
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
                redirected_response = await self._send_with_retries(
                    http, method, redirect_url, headers=headers
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

    async def paginate(
        self,
        scope: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_page_size: int = MAX_PAGE_SIZE,
        max_items: int | None = None,
        data_key: str | tuple[str, ...] = "data",
    ) -> list[Any]:
        """Walk every page of a paginated endpoint and return the combined items.

        Mirrors the SDK's page/limit pagination: it requests ``page_size`` items
        (capped at ``max_page_size``) per page and stops when a short page is
        returned, the reported total is reached, ``max_items`` is hit, or the
        ``MAX_PAGES`` safety cap is exceeded.

        Args:
            scope: API scope path (e.g. "policies/v2").
            endpoint: Path after the scope (e.g. "destinationlists").
            params: Optional extra query parameters merged into every page.
            page_size: Items per page (clamped to 1..max_page_size).
            max_page_size: Endpoint-specific maximum page size.
            max_items: Optional hard cap on the number of items returned.
            data_key: Key, or fallback keys, in the response dict that holds the page items.
        """
        page_size = max(1, min(page_size, max_page_size))
        base_params = dict(params or {})
        items: list[Any] = []

        for page in range(1, MAX_PAGES + 1):
            page_params = {**base_params, "page": page, "limit": page_size}
            data = await self.get(scope, endpoint, params=page_params)

            if isinstance(data, dict):
                page_items = self._extract_items(data, data_key)
                total = self._extract_total(data)
            elif isinstance(data, list):
                page_items = data
                total = None
            else:
                break

            items.extend(page_items)

            if max_items is not None and len(items) >= max_items:
                return items[:max_items]
            if not page_items or len(page_items) < page_size:
                break
            if total is not None and len(items) >= total:
                break

        return items

    async def paginate_offset(
        self,
        scope: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_page_size: int = MAX_OFFSET_PAGE_SIZE,
        max_items: int | None = None,
        data_key: str | tuple[str, ...] = "data",
    ) -> list[Any]:
        """Walk an offset/limit paginated endpoint and return combined items.

        Some Secure Access endpoints, including policy rules, use ``offset`` and
        ``limit`` instead of ``page`` and ``limit``.  This helper keeps that loop
        centralized and bounded like :meth:`paginate`.
        """
        page_size = max(1, min(page_size, max_page_size))
        base_params = dict(params or {})
        items: list[Any] = []
        offset = int(base_params.pop("offset", 0) or 0)

        for _ in range(MAX_PAGES):
            page_params = {**base_params, "offset": offset, "limit": page_size}
            data = await self.get(scope, endpoint, params=page_params)

            if isinstance(data, dict):
                page_items = self._extract_items(data, data_key)
                total = self._extract_total(data)
            elif isinstance(data, list):
                page_items = data
                total = None
            else:
                break

            items.extend(page_items)

            if max_items is not None and len(items) >= max_items:
                return items[:max_items]
            if not page_items or len(page_items) < page_size:
                break
            if total is not None and len(items) >= total:
                break
            offset += page_size

        return items

    @staticmethod
    def _extract_items(data: dict[str, Any], data_key: str | tuple[str, ...]) -> list[Any]:
        keys = (data_key,) if isinstance(data_key, str) else data_key
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
        return []

    @staticmethod
    def _extract_total(data: dict[str, Any]) -> int | None:
        meta = data.get("meta")
        if isinstance(meta, dict) and isinstance(meta.get("total"), int):
            return meta["total"]
        for key in ("total", "totalResults", "totalresults"):
            value = data.get(key)
            if isinstance(value, int):
                return value
        return None

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
