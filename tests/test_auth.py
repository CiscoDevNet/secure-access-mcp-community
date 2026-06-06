import asyncio
import time
import unittest
from unittest.mock import patch

from cisco_secure_access_mcp.auth import TokenManager


class CountingTokenManager(TokenManager):
    def __init__(self) -> None:
        super().__init__(api_key="api-key", api_secret="api-secret")
        self.refresh_count = 0

    async def _refresh_token(self) -> None:
        self.refresh_count += 1
        await asyncio.sleep(0)
        self._access_token = f"token-{self.refresh_count}"
        self._expires_at = time.time() + 3600


class FakeTokenResponse:
    def __init__(self, status_code: int, payload: dict[str, object], headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> dict[str, object]:
        return self._payload


class FakeAsyncClient:
    responses: list[FakeTokenResponse] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    async def __aenter__(self) -> "FakeAsyncClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        pass

    async def post(self, *args: object, **kwargs: object) -> FakeTokenResponse:
        return self.responses.pop(0)


class TokenManagerTests(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_calls_reuse_cached_token(self) -> None:
        token_manager = CountingTokenManager()

        first = await token_manager.get_token()
        second = await token_manager.get_token()

        self.assertEqual(first, "token-1")
        self.assertEqual(second, "token-1")
        self.assertEqual(token_manager.refresh_count, 1)

    async def test_expired_token_refreshes(self) -> None:
        token_manager = CountingTokenManager()

        self.assertEqual(await token_manager.get_token(), "token-1")
        token_manager._expires_at = 0

        self.assertEqual(await token_manager.get_token(), "token-2")
        self.assertEqual(token_manager.refresh_count, 2)

    async def test_concurrent_calls_share_one_refresh(self) -> None:
        token_manager = CountingTokenManager()

        tokens = await asyncio.gather(*(token_manager.get_token() for _ in range(10)))

        self.assertEqual(tokens, ["token-1"] * 10)
        self.assertEqual(token_manager.refresh_count, 1)

    async def test_retry_after_is_honored_for_rate_limited_refresh(self) -> None:
        FakeAsyncClient.responses = [
            FakeTokenResponse(429, {}, {"retry-after": "2.5"}),
            FakeTokenResponse(200, {"access_token": "fresh-token", "expires_in": 3600}),
        ]
        sleep_calls: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleep_calls.append(delay)

        token_manager = TokenManager(api_key="api-key", api_secret="api-secret")
        with (
            patch("cisco_secure_access_mcp.auth.httpx.AsyncClient", FakeAsyncClient),
            patch("cisco_secure_access_mcp.auth.asyncio.sleep", fake_sleep),
        ):
            token = await token_manager.get_token()

        self.assertEqual(token, "fresh-token")
        self.assertEqual(sleep_calls, [2.5])


if __name__ == "__main__":
    unittest.main()
