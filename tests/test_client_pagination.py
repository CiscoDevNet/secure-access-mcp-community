import unittest
from typing import Any
from unittest.mock import patch

from cisco_secure_access_mcp.client import SecureAccessClient


class RecordingClient(SecureAccessClient):
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def get(self, scope: str, endpoint: str, **kwargs: Any) -> Any:
        self.calls.append(
            {
                "scope": scope,
                "endpoint": endpoint,
                "params": kwargs.get("params"),
            }
        )
        return self.responses.pop(0)


class PaginationTests(unittest.IsolatedAsyncioTestCase):
    async def test_page_pagination_stops_on_meta_total(self) -> None:
        client = RecordingClient(
            [
                {"data": [{"id": 1}, {"id": 2}], "meta": {"total": 3}},
                {"data": [{"id": 3}], "meta": {"total": 3}},
            ]
        )

        items = await client.paginate("scope", "items", page_size=2)

        self.assertEqual(items, [{"id": 1}, {"id": 2}, {"id": 3}])
        self.assertEqual([call["params"] for call in client.calls], [{"page": 1, "limit": 2}, {"page": 2, "limit": 2}])

    async def test_page_pagination_stops_on_short_page(self) -> None:
        client = RecordingClient([{"data": [{"id": 1}], "meta": {"total": 100}}])

        items = await client.paginate("scope", "items", page_size=2)

        self.assertEqual(items, [{"id": 1}])
        self.assertEqual(len(client.calls), 1)

    async def test_page_pagination_stops_at_max_pages(self) -> None:
        client = RecordingClient(
            [
                {"data": [{"id": 1}]},
                {"data": [{"id": 2}]},
                {"data": [{"id": 3}]},
            ]
        )

        with patch("cisco_secure_access_mcp.client.MAX_PAGES", 2):
            items = await client.paginate("scope", "items", page_size=1)

        self.assertEqual(items, [{"id": 1}, {"id": 2}])
        self.assertEqual(len(client.calls), 2)

    async def test_offset_pagination_increments_by_limit(self) -> None:
        client = RecordingClient(
            [
                {"results": [{"id": 1}, {"id": 2}], "total": 3},
                {"results": [{"id": 3}], "total": 3},
            ]
        )

        items = await client.paginate_offset("scope", "rules", page_size=2, data_key="results")

        self.assertEqual(items, [{"id": 1}, {"id": 2}, {"id": 3}])
        self.assertEqual(
            [call["params"] for call in client.calls],
            [{"offset": 0, "limit": 2}, {"offset": 2, "limit": 2}],
        )

    async def test_offset_pagination_supports_fallback_data_keys(self) -> None:
        client = RecordingClient([{"data": [{"id": 1}], "total": 1}])

        items = await client.paginate_offset("scope", "rules", page_size=1000, data_key=("results", "data"))

        self.assertEqual(items, [{"id": 1}])
        self.assertEqual(client.calls[0]["params"], {"offset": 0, "limit": 1000})

    async def test_max_items_truncates_results(self) -> None:
        client = RecordingClient([{"data": [{"id": 1}, {"id": 2}, {"id": 3}], "meta": {"total": 10}}])

        items = await client.paginate("scope", "items", page_size=3, max_items=2)

        self.assertEqual(items, [{"id": 1}, {"id": 2}])
        self.assertEqual(len(client.calls), 1)


if __name__ == "__main__":
    unittest.main()
