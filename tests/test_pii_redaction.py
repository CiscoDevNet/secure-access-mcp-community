# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for PII key matching in report/activity redaction.

Regression coverage for over-broad substring matching, where keys like
``description``, ``recipient``, and ``userAgent`` were wrongly redacted
because they contained the substrings ``ip`` or ``user``.
"""

import unittest

from cisco_secure_access_mcp.tools.all_tools import _is_pii_key, _redact_pii, _REDACTED


class IsPIIKeyTests(unittest.TestCase):
    def test_real_pii_keys_match(self) -> None:
        for key in (
            "identity", "identities", "ip", "internalIp", "externalIp",
            "internalip", "email", "user", "username", "userId",
            "device", "deviceId", "source_ip", "destinationIp",
        ):
            self.assertTrue(_is_pii_key(key), f"expected PII match for {key!r}")

    def test_lookalike_keys_do_not_match(self) -> None:
        for key in (
            "description", "recipient", "zip", "relationship",
            "userAgent", "verdict", "tipping", "equipment",
        ):
            self.assertFalse(_is_pii_key(key), f"unexpected PII match for {key!r}")


class RedactPIITests(unittest.TestCase):
    def test_redacts_pii_preserves_lookalikes(self) -> None:
        data = {
            "identity": "alice@example.com",
            "internalIp": "10.0.0.5",
            "userAgent": "Mozilla/5.0",
            "description": "blocked by policy",
            "verdict": "blocked",
            "nested": {"externalIp": "8.8.8.8", "zip": "78645"},
        }
        out = _redact_pii(data)
        self.assertEqual(out["identity"], _REDACTED)
        self.assertEqual(out["internalIp"], _REDACTED)
        self.assertEqual(out["nested"]["externalIp"], _REDACTED)
        # Look-alikes must survive untouched.
        self.assertEqual(out["userAgent"], "Mozilla/5.0")
        self.assertEqual(out["description"], "blocked by policy")
        self.assertEqual(out["verdict"], "blocked")
        self.assertEqual(out["nested"]["zip"], "78645")

    def test_empty_values_not_replaced(self) -> None:
        out = _redact_pii({"ip": "", "email": None, "user": 0})
        self.assertEqual(out["ip"], "")
        self.assertIsNone(out["email"])
        self.assertEqual(out["user"], 0)


if __name__ == "__main__":
    unittest.main()
