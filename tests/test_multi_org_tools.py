import unittest

from cisco_secure_access_mcp.tools.all_tools import _extract_child_organizations, _validate_report_path


class MultiOrgToolHelperTests(unittest.TestCase):
    def test_extract_child_organizations_handles_common_response_shapes(self) -> None:
        data = {
            "data": [
                {"organizationId": 1234567, "organizationName": "tenant one"},
                {"organization_id": "2345678", "organization_name": "tenant two"},
                {"organizationId": 1234567, "organizationName": "duplicate"},
                {"name": "missing id"},
            ]
        }

        self.assertEqual(
            _extract_child_organizations(data),
            [
                {"organizationId": "1234567", "organizationName": "tenant one"},
                {"organizationId": "2345678", "organizationName": "tenant two"},
            ],
        )

    def test_validate_report_path_allows_only_reports_api_paths(self) -> None:
        self.assertEqual(_validate_report_path("reports/v2/top-categories"), "/reports/v2/top-categories")
        self.assertEqual(_validate_report_path("/reports/v2/activity/proxy"), "/reports/v2/activity/proxy")

        for value in (
            "https://example.com/reports/v2/activity",
            "/admin/v2/tenants/list",
            "/reports/v2/../admin/v2/tenants/list",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    _validate_report_path(value)


if __name__ == "__main__":
    unittest.main()
