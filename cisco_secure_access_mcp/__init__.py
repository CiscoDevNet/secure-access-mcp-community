# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Cisco Secure Access MCP Server package."""

from __future__ import annotations

import os

__version__ = "0.1.0"

# Default User-Agent sent on every Cisco Secure Access API request (token and
# data calls).  The Cisco backend uses this string to attribute traffic to this
# MCP server, so keep the product token (``secure-access-mcp-community``) stable
# and bump the version with releases.  Operators can override the whole value
# with the ``SECURE_ACCESS_USER_AGENT`` environment variable, e.g. to append a
# tenant or deployment identifier for finer-grained tracking.
DEFAULT_USER_AGENT = (
    f"secure-access-mcp-community/{__version__} "
    "(+https://github.com/CiscoDevNet/secure-access-mcp-community)"
)


def get_user_agent() -> str:
    """Return the User-Agent to send to the Cisco Secure Access API.

    Resolved lazily (at request time) so values loaded from ``.env`` via
    ``python-dotenv`` are honoured.  Set ``SECURE_ACCESS_USER_AGENT`` to override
    the default product token.
    """
    override = os.environ.get("SECURE_ACCESS_USER_AGENT", "").strip()
    return override or DEFAULT_USER_AGENT
