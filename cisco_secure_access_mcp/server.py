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
from mcp.server.transport_security import TransportSecuritySettings

from .auth import TokenManager
from .client import SecureAccessClient
from .logging_config import configure_logging, get_logger
from .security import SecurityConfig, SecurityConfigError, SecurityMiddleware

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

    try:
        yield AppContext(client=client)
    finally:
        await client.aclose()


mcp = FastMCP(
    "cisco-secure-access-mcp",
    lifespan=app_lifespan,
)

# Import tool modules to register them with the server.
from .tools import all_tools  # noqa: E402, F401


def _build_transport_security(host: str, port: int, config: SecurityConfig) -> TransportSecuritySettings:
    """Configure FastMCP's DNS-rebinding / Host / Origin validation."""
    allowed_hosts = list(config.allowed_hosts)
    if not allowed_hosts:
        # Default to the bound host plus loopback names so a correctly addressed
        # client works while cross-origin DNS-rebinding attempts are rejected.
        defaults = {f"{host}:{port}", f"127.0.0.1:{port}", f"localhost:{port}"}
        allowed_hosts = sorted(defaults)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=config.enable_dns_rebinding_protection,
        allowed_hosts=allowed_hosts,
        allowed_origins=list(config.allowed_origins),
    )


def main() -> None:
    """Entry point for the Streamable HTTP MCP server."""
    logger = configure_logging(os.environ.get("LOG_LEVEL", "INFO"))

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))

    try:
        security = SecurityConfig.from_env()
    except SecurityConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if security.allow_no_auth:
        warning = (
            "SECURITY WARNING: running WITHOUT client->server authentication "
            "(MCP_ALLOW_NO_AUTH=true). This is NOT RECOMMENDED. Anyone who can reach "
            f"{host}:{port} can invoke every tool using your Cisco Secure Access "
            "credentials. Use this only for isolated local testing, never in production."
        )
        # Emit to stderr (human-visible) and the structured log.
        print(f"\n*** {warning} ***\n", file=sys.stderr)
        logger.warning(warning, extra={"event": "startup_no_auth"})
        if host not in {"127.0.0.1", "localhost", "::1"}:
            print(
                "Error: refusing to run the no-auth testing mode on a non-loopback host "
                f"({host!r}). Bind to 127.0.0.1 for no-auth testing, or set MCP_AUTH_TOKEN.",
                file=sys.stderr,
            )
            sys.exit(1)

    logger.info("starting server", extra={"event": "startup", **security.public_summary()})

    mcp.settings.host = host
    mcp.settings.port = port
    mcp.settings.transport_security = _build_transport_security(host, port, security)

    app = mcp.streamable_http_app()
    app.add_middleware(SecurityMiddleware, config=security)

    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level=os.environ.get("LOG_LEVEL", "info").lower())


if __name__ == "__main__":
    main()
