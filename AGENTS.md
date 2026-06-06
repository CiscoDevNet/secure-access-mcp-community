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
- **uv (recommended)**: [uv](https://docs.astral.sh/uv/) is a fast Python package and project manager. Install it with `curl -LsSf https://astral.sh/uv/install.sh | sh` (or `brew install uv` / `pipx install uv`), then:
 ```bash
 # Create a virtual environment on a supported interpreter (uv fetches Python if missing).
 uv venv --python 3.11
 # Install dependencies into the .venv.
 uv pip install -r requirements.txt
 # Run the server without manually activating the venv.
 uv run python -m cisco_secure_access_mcp
 ```
 `uv run` automatically targets the project's `.venv`, so there is no need to `source` an activate script.
- **Virtual env (pip alternative)**:
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

With uv (no manual venv activation):

```bash
export SECURE_ACCESS_API_KEY="your-api-key"
export SECURE_ACCESS_API_SECRET="your-api-secret"
uv run python -m cisco_secure_access_mcp
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
├── __init__.py          # Package version and get_user_agent() (User-Agent resolution)
├── __main__.py          # Entry point: python -m cisco_secure_access_mcp
├── auth.py              # OAuth2 client-credentials token manager (cache, refresh, retry)
├── client.py            # Async Cisco Secure Access REST client (httpx pool, retries, paginate, audit logs)
├── logging_config.py    # Structured JSON logging + secret redaction
├── security.py          # Transport security: auth, rate limit, payload limit, request IDs (ASGI middleware)
├── server.py            # FastMCP Streamable HTTP server + security wiring
└── tools/
    ├── all_tools.py     # MCP tool definitions
    └── destination_lists.py
```

### Client best practices (aligned with the official Cisco Secure Access Python SDK)

When adding or changing API access, preserve these behaviors:

- **One token per hour**: `auth.py` caches a single client-credentials token for its full lifetime and only refreshes ~60s before expiry. Never request a token per call.
- **Token & request retries**: both the token endpoint and data requests retry with exponential backoff. `429` is retried for any method (honoring `Retry-After`); `5xx`/network errors are retried only for idempotent reads.
- **Connection pooling**: reuse the single pooled `httpx.AsyncClient` from `SecureAccessClient` (created lazily, closed in the server lifespan). Do not open a new `httpx.AsyncClient` per request.
- **Pagination**: use `SecureAccessClient.paginate(scope, endpoint, ...)` for list endpoints rather than hand-rolling page loops. Page size is capped at 100 and a `MAX_PAGES` safety cap bounds request volume.

### Where to set the User-Agent (backend request tracking)

Cisco's backend attributes traffic by the `User-Agent` header. It is resolved by `get_user_agent()` in `cisco_secure_access_mcp/__init__.py` and attached in two places:

- `auth.py` → `TokenManager._refresh_token()` (token endpoint request).
- `client.py` → `SecureAccessClient._get_headers()` (every data request).

Change the default product token by editing `DEFAULT_USER_AGENT` in `__init__.py` (keep `secure-access-mcp-community` stable and bump `__version__` per release). Operators can override the entire value at runtime with the `SECURE_ACCESS_USER_AGENT` environment variable (e.g. to append a tenant or deployment ID) without code changes.

### Transport security model (MCP security guidelines)

The Streamable HTTP transport is hardened in `security.py` (pure-ASGI `SecurityMiddleware`) and `server.py`. Preserve these controls when changing the server:

- **Auth is required by default.** `SecurityConfig.from_env()` refuses to start without `MCP_AUTH_TOKEN` unless `MCP_ALLOW_NO_AUTH=true` (the documented, not-recommended testing mode, which is additionally rejected on non-loopback hosts). Token comparison uses `hmac.compare_digest`. Do not weaken default-deny.
- **Middleware order matters**: rate limit → payload-size limit → auth, then the app, with access logging in `finally`. It is pure ASGI on purpose — do not switch to Starlette `BaseHTTPMiddleware`, which buffers and breaks the streaming response.
- **DNS-rebinding protection** is delegated to FastMCP `transport_security` (configured in `server.py::_build_transport_security`). Keep it enabled.
- **Logging**: use the package logger from `logging_config.get_logger()` and pass structured fields via `extra=`. The `RedactionFilter` scrubs secrets; never log tokens, `Authorization`, query strings, or PII. Audit Cisco API calls in `client.py` by path only.
- **Destructive tools** must carry the `DESTRUCTIVE` annotation preset and honor the `REQUIRE_CONFIRMATION` two-stage commit (`confirm=true`). New write tools should validate inputs server-side with the `_validate_*` helpers (or pydantic) and use the appropriate annotation preset (`READ_ONLY` / `WRITE_CREATE` / `WRITE_UPDATE` / `DESTRUCTIVE`).
- **PII redaction** for report/activity outputs goes through `_maybe_redact` (gated by `SECURE_ACCESS_REDACT_PII`).

TLS/mTLS termination, secret-manager storage, and process sandboxing are operator responsibilities documented in `README.md`; do not assume the Python process terminates TLS itself.

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
