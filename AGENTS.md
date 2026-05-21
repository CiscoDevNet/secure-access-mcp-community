# AGENTS.md

This file provides guidance for AI coding agents (VS Code, GitHub Copilot, Cursor, Codex, Gemini CLI, etc.) working with the `secure-access-mcp-community` repository.

## Project overview

`secure-access-mcp-community` is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that exposes Cisco Secure Access API operations as agent-callable tools over **Streamable HTTP**. It provides 72 tools across destination list management, domain investigation, access policy inspection, reports, activity, and infrastructure inventory.

- **Repository:** https://github.com/CiscoDevNet/secure-access-mcp-community
- **Protocol:** Streamable HTTP
- **Default URL:** `http://127.0.0.1:8000/mcp`

## Reference documentation

When generating or modifying code that calls Cisco Secure Access APIs, prefer these authoritative sources:

- **Cisco Secure Access Authorization (OAuth2) API spec (OpenAPI YAML):**
  https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/secure-access/reference/auth/cisco_secure_access_token_authorization_api_2_0_0.yaml
- **Cisco Secure Access developer portal and API reference:**
  https://developer.cisco.com/docs/cloud-security/
- **Model Context Protocol specification:**
  https://modelcontextprotocol.io/

## Dev environment tips

- **Python version**: Use Python 3.10+ (Python 3.11 or newer recommended). The `mcp` package is not available for Python 3.9.
- **Virtual env (recommended)**:
  ```bash
  python3.11 -m venv venv
  source venv/bin/activate
  python -m pip install --upgrade pip
  python -m pip install -r requirements.txt
  ```
- **Credentials**: Never hardcode API keys. Copy `.env.example` to `.env` and populate `SECURE_ACCESS_API_KEY` and `SECURE_ACCESS_API_SECRET`, or export them as environment variables.

### Quick run examples

Start the Streamable HTTP MCP server on the default host/port (`127.0.0.1:8000`):

```bash
export SECURE_ACCESS_API_KEY="your-api-key"
export SECURE_ACCESS_API_SECRET="your-api-secret"
python -m cisco_secure_access_mcp
```

Bind to a different host/port (use `0.0.0.0` only behind HTTPS and access controls):

```bash
HOST=0.0.0.0 PORT=8080 python -m cisco_secure_access_mcp
```

Connect with MCP Inspector for interactive tool discovery:

```bash
npx @modelcontextprotocol/inspector http://127.0.0.1:8000/mcp
```

## MCP servers needed for this project

This repository **is** an MCP server. To exercise it end-to-end you typically wire it into an MCP-capable client:

- **Cursor** — add a `cisco-secure-access` server entry pointing at `http://127.0.0.1:8000/mcp`.
- **VS Code Copilot** — add an HTTP server entry to `.vscode/mcp.json` or user MCP settings.
- **MCP Inspector** — useful for ad-hoc tool calls during development.

See the `MCP Client Configuration` section of `README.md` and the `mcp_config.example.json` sample for the exact JSON snippets.

## Testing instructions

- **Local smoke test**: After starting the server, point MCP Inspector at `http://127.0.0.1:8000/mcp` and confirm the 72 tools are discoverable and that `list_destination_lists` returns successfully against your tenant.
- **Test the code with the Cisco DevNet sandbox**: Visit https://devnetsandbox.cisco.com/DevNet and book the Cisco Secure Access related sandbox to obtain test credentials when you do not have access to a production tenant.
- **Latest Cisco API documentation**: https://developer.cisco.com/docs/cloud-security/

## SDK and dependency guidance

The server depends on a small, well-known stack. When suggesting changes, stay on these libraries unless there is a strong reason to introduce another:

| Package | Purpose | Minimum version |
|---------|---------|-----------------|
| `mcp[cli]` | Model Context Protocol Python SDK (FastMCP) | `>=1.0.0` |
| `httpx` | Async HTTP client used by `client.py` | `>=0.27.0` |
| `pydantic` | Tool input models in `tools/destination_lists.py` | `>=2.0.0` |
| `python-dotenv` | Loads `.env` files for local development | `>=1.0.0` |

Code layout to respect:

```text
cisco_secure_access_mcp/
├── __main__.py          # Entry point: python -m cisco_secure_access_mcp
├── auth.py              # OAuth2 client-credentials token manager
├── client.py            # Async Cisco Secure Access REST client (httpx)
├── server.py            # FastMCP Streamable HTTP server
└── tools/
    ├── all_tools.py     # MCP tool definitions
    └── destination_lists.py
```

## PR instructions

- **Security**: Do not commit real credentials, tokens, or tenant identifiers. Use placeholders in examples and document required env vars in `README.md` and `.env.example`.
- **Transport**: The server is Streamable HTTP only (`transport="streamable-http"`). Do not add stdio or SSE transports without a maintainer discussion.
- **Network safety**: Redirects in the Cisco Secure Access client are only followed for HTTPS Cisco-controlled hosts; do not weaken this check.
- **Response limits**: Large API responses are capped to avoid oversized tool results. Preserve these guardrails when adding new tools.
- **Title / description**: Reference the affected tool group (e.g. `Reports - Top Aggregations`, `Destination Lists Management`) and mention any API spec or endpoint that changed.

## Contribution conventions

- **Backward compatibility**: Do not change existing tool names, parameter names, or response shapes unless clearly fixing a bug; MCP clients depend on stable tool schemas. Document any change in the PR description.
- **New tools**: Register new tools in `cisco_secure_access_mcp/tools/all_tools.py` (or a dedicated module under `tools/`) and update the tool table in `README.md` so the count and description stay accurate.
- **Async I/O**: All Cisco Secure Access calls go through `client.py` using `httpx.AsyncClient`; do not introduce blocking HTTP libraries.
- **Auth**: Reuse the OAuth2 token cache in `auth.py`; do not request a new token per call.
- **Input validation**: Prefer `pydantic` models for tool inputs that take more than a couple of primitive fields, mirroring `tools/destination_lists.py`.
