# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Cisco Secure Access MCP Server."""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from .auth import TokenManager
from .client import SecureAccessClient

load_dotenv()


@dataclass
class AppContext:
    """Shared application state available to all tools via lifespan."""

    client: SecureAccessClient


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialize the Secure Access API client for the server lifetime."""
    api_key = os.environ.get("SECURE_ACCESS_API_KEY", "")
    api_secret = os.environ.get("SECURE_ACCESS_API_SECRET", "")

    if not api_key or not api_secret:
        print(
            "Error: SECURE_ACCESS_API_KEY and SECURE_ACCESS_API_SECRET environment variables are required.\n"
            "Copy .env.example to .env and fill in your Cisco Secure Access API credentials.",
            file=sys.stderr,
        )
        sys.exit(1)

    token_url = os.environ.get("TOKEN_URL", "https://api.sse.cisco.com/auth/v2/token")
    if not token_url.startswith("https://api.sse.cisco.com/"):
        print(
            f"Error: TOKEN_URL must start with 'https://api.sse.cisco.com/' (got: {token_url!r}).\n"
            "This server only communicates with the Cisco Secure Access API.",
            file=sys.stderr,
        )
        sys.exit(1)

    token_manager = TokenManager(
        api_key=api_key,
        api_secret=api_secret,
        token_url=token_url,
    )
    client = SecureAccessClient(token_manager)

    yield AppContext(client=client)


mcp = FastMCP(
    "cisco-secure-access-mcp",
    lifespan=app_lifespan,
)

# Import tool modules to register them with the server.
from .tools import all_tools  # noqa: E402, F401


def main() -> None:
    """Entry point for the Streamable HTTP MCP server."""
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    mcp.settings.host = host
    mcp.settings.port = port
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
