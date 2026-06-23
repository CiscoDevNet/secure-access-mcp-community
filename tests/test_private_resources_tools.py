import json
import unittest
from unittest.mock import patch

from cisco_secure_access_mcp.tools import all_tools


class FakeClient:
    def __init__(self) -> None:
        self.paginate_offset_calls = []
        self.get_calls = []
        self.post_calls = []
        self.request_calls = []
        self.delete_calls = []

    async def paginate_offset(self, scope, endpoint, **kwargs):
        self.paginate_offset_calls.append({"scope": scope, "endpoint": endpoint, "kwargs": kwargs})
        return [{"resourceId": 1, "name": "Jira"}, {"resourceId": 2, "name": "GitLab"}]

    async def get(self, scope, endpoint, **kwargs):
        self.get_calls.append({"scope": scope, "endpoint": endpoint, "kwargs": kwargs})
        return {"resourceId": 99, "name": "Finance App"}

    async def post(self, scope, endpoint, **kwargs):
        self.post_calls.append({"scope": scope, "endpoint": endpoint, "kwargs": kwargs})
        return {"resourceId": 123, "name": kwargs["json_data"]["name"]}

    async def request(self, method, scope, endpoint, **kwargs):
        self.request_calls.append(
            {"method": method, "scope": scope, "endpoint": endpoint, "kwargs": kwargs}
        )
        return {"updated": True, "resourceId": 123}

    async def delete(self, scope, endpoint, **kwargs):
        self.delete_calls.append({"scope": scope, "endpoint": endpoint, "kwargs": kwargs})
        return None


class PrivateResourceToolsTests(unittest.IsolatedAsyncioTestCase):
    async def test_list_private_resources_uses_paginate_offset(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            result = await all_tools.list_private_resources(
                None,
                filters={"name": "Jira"},
                sort_by="name",
                sort_order="asc",
                limit=40,
            )

        payload = json.loads(result)
        self.assertEqual(payload["count"], 2)
        self.assertEqual(payload["private_resources"][0]["name"], "Jira")

        call = fake.paginate_offset_calls[0]
        self.assertEqual(call["scope"], "policies/v2")
        self.assertEqual(call["endpoint"], "privateResources")
        self.assertEqual(
            call["kwargs"]["params"],
            {"filters": '{"name":"Jira"}', "sortBy": "name", "sortOrder": "asc"},
        )
        self.assertEqual(call["kwargs"]["data_key"], ("items", "data"))
        self.assertEqual(call["kwargs"]["page_size"], 40)
        self.assertEqual(call["kwargs"]["max_items"], 40)

    async def test_list_private_resources_rejects_invalid_limit(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            result = await all_tools.list_private_resources(None, limit=1001)

        self.assertIn("Error: ValueError: limit must be <= 1000", result)

    async def test_list_private_resources_rejects_non_positive_limit(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            zero_result = await all_tools.list_private_resources(None, limit=0)
            negative_result = await all_tools.list_private_resources(None, limit=-1)

        self.assertIn("Error: ValueError: limit must be >= 1", zero_result)
        self.assertIn("Error: ValueError: limit must be >= 1", negative_result)

    async def test_list_private_resources_with_no_limit_uses_default_page_size(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            await all_tools.list_private_resources(None)

        call = fake.paginate_offset_calls[0]
        self.assertEqual(call["kwargs"]["page_size"], all_tools.DEFAULT_PAGE_SIZE)
        self.assertIsNone(call["kwargs"]["max_items"])

    async def test_create_private_resource_sends_expected_payload(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            result = await all_tools.create_private_resource(
                name="Jira",
                access_types=[{"type": "network"}],
                resource_addresses=[
                    {
                        "destinationAddr": ["example.com"],
                        "protocolPorts": [{"protocol": "http/https", "ports": "80"}],
                    }
                ],
                ctx=None,
                description="Critical app",
                resource_group_ids=[10],
            )

        payload = json.loads(result)
        self.assertEqual(payload["resourceId"], 123)

        body = fake.post_calls[0]["kwargs"]["json_data"]
        self.assertEqual(body["name"], "Jira")
        self.assertEqual(body["description"], "Critical app")
        self.assertEqual(body["resourceGroupIds"], [10])

    async def test_create_private_resource_rejects_invalid_name_length(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            result = await all_tools.create_private_resource(
                name="x" * 51,
                access_types=[{"type": "network"}],
                resource_addresses=[
                    {
                        "destinationAddr": ["example.com"],
                        "protocolPorts": [{"protocol": "http/https", "ports": "80"}],
                    }
                ],
                ctx=None,
            )

        self.assertIn("Error: ValueError: name must be ≤50 characters", result)

    async def test_create_private_resource_rejects_invalid_address_shape(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            result = await all_tools.create_private_resource(
                name="Jira",
                access_types=[{"type": "network"}],
                resource_addresses=[{"destinationAddr": ["example.com"]}],
                ctx=None,
            )

        self.assertIn(
            "Error: ValueError: each resource_addresses item must include 'destinationAddr' and 'protocolPorts'",
            result,
        )

    async def test_update_private_resource_requires_update_fields(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            result = await all_tools.update_private_resource(resource_id=1, ctx=None)

        self.assertIn("Error: ValueError: at least one update field must be provided", result)

    async def test_update_private_resource_includes_existing_name_when_omitted(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            result = await all_tools.update_private_resource(
                resource_id=1,
                ctx=None,
                description="updated",
            )

        payload = json.loads(result)
        self.assertTrue(payload["updated"])

        self.assertEqual(fake.get_calls[0]["endpoint"], "privateResources/1")
        body = fake.request_calls[0]["kwargs"]["json_data"]
        self.assertEqual(body["name"], "Finance App")
        self.assertEqual(body["description"], "updated")

    async def test_update_private_resource_uses_provided_name_without_lookup(self):
        fake = FakeClient()
        with patch.object(all_tools, "_get_client", return_value=fake):
            result = await all_tools.update_private_resource(
                resource_id=1,
                ctx=None,
                name="Renamed App",
                description="updated",
            )

        payload = json.loads(result)
        self.assertTrue(payload["updated"])

        self.assertEqual(len(fake.get_calls), 0)
        body = fake.request_calls[0]["kwargs"]["json_data"]
        self.assertEqual(body["name"], "Renamed App")
        self.assertEqual(body["description"], "updated")

    async def test_delete_private_resource_requires_confirmation_preview(self):
        fake = FakeClient()
        with (
            patch.object(all_tools, "_get_client", return_value=fake),
            patch.object(all_tools, "REQUIRE_CONFIRMATION", True),
        ):
            result = await all_tools.delete_private_resource(resource_id=99, ctx=None, force=True, confirm=False)

        payload = json.loads(result)
        self.assertTrue(payload["confirmationRequired"])
        self.assertEqual(payload["action"], "delete_private_resource")
        self.assertEqual(payload["force"], True)
        self.assertEqual(payload["target"]["resourceId"], 99)
        self.assertEqual(len(fake.delete_calls), 0)

    async def test_delete_private_resource_executes_when_confirmed(self):
        fake = FakeClient()
        with (
            patch.object(all_tools, "_get_client", return_value=fake),
            patch.object(all_tools, "REQUIRE_CONFIRMATION", True),
        ):
            result = await all_tools.delete_private_resource(resource_id=77, ctx=None, force=True, confirm=True)

        self.assertEqual(result, "Private resource deleted successfully.")
        self.assertEqual(fake.delete_calls[0]["endpoint"], "privateResources/77")
        self.assertEqual(fake.delete_calls[0]["kwargs"]["params"], {"force": True})


if __name__ == "__main__":
    unittest.main()
