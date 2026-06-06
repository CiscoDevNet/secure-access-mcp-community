# Community MCP Server for Cisco Secure Access

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that exposes Cisco Secure Access API operations as agent-callable tools over **Streamable HTTP**.

**Repository:** https://github.com/CiscoDevNet/secure-access-mcp-community

## Overview

This server provides Cisco Secure Access tools for destination list management, domain investigation, access policy inspection, reports, activity, and infrastructure inventory. MCP-compatible clients can discover the tools, inspect their schemas, and call them from natural language prompts.

**Protocol:** Streamable HTTP  
**Default URL:** `http://127.0.0.1:8000/mcp`  
**Python:** 3.10+ (Python 3.11 or newer recommended)

## Tools (72)

### Destination Lists Management (Read)

| Tool | Description |
|------|-------------|
| `list_destination_lists` | List all destination lists in the organization |
| `get_destination_list` | Get details of a single destination list by ID |
| `get_destinations_in_list` | Get all destinations (domains, URLs, IPs) in a list |
| `search_domain_across_lists` | Search for a domain, URL, or IP across all destination lists |
| `find_repeating_destinations` | Find destinations that appear in multiple destination lists |
| `audit_stale_lists` | Audit destination lists for stale, empty, or low-count lists |
| `destination_usage_summary` | Show org-wide usage against the 250,000 destination limit |

### Destination Lists Management (Write)

| Tool | Description |
|------|-------------|
| `create_destination_list` | Create a new destination list with optional initial destinations |
| `update_destination_list` | Rename a destination list |
| `delete_destination_list` | Delete a destination list |
| `add_destinations_to_list` | Add domains, IPs, or URLs to a list, max 500 per request |
| `remove_destinations_from_list` | Remove destinations from a list by destination ID, max 500 per request |

### Domain Investigation

| Tool | Description |
|------|-------------|
| `investigate_domain` | Get security risk information for a domain |
| `get_domain_categorization` | Get content or security categorization for a domain |

### Access Rules (Policies)

| Tool | Description |
|------|-------------|
| `list_access_rules` | List access policy rules |
| `get_access_rule_detail` | Get full details of an access rule |
| `create_access_rule` | Create an allow or block rule by categories or destination lists |

### Reports - Summary & Totals

| Tool | Description |
|------|-------------|
| `get_security_summary` | Security summary for total, blocked, and allowed requests |
| `get_security_summary_by_type` | Security summary filtered by traffic type |
| `get_total_requests` | Total request counts across all traffic types |
| `get_total_requests_by_type` | Total request counts for a specific traffic type |

### Reports - Top Aggregations

| Tool | Description |
|------|-------------|
| `get_top_destinations` | Top accessed destinations |
| `get_top_destinations_by_type` | Top destinations filtered by traffic type |
| `get_top_urls` | Top accessed URLs |
| `get_top_identities` | Top identities by request count |
| `get_top_identities_by_type` | Top identities filtered by traffic type |
| `get_top_categories` | Top content categories |
| `get_top_categories_by_type` | Top categories filtered by traffic type |
| `get_top_threats` | Top threats |
| `get_top_threats_by_type` | Top threats filtered by traffic type |
| `get_top_threat_types` | Top threat types |
| `get_top_threat_types_by_type` | Top threat types filtered by traffic type |
| `get_top_event_types` | Top event types |
| `get_top_dns_query_types` | Top DNS query types |
| `get_top_ips` | Top IP addresses |
| `get_top_ips_internal` | Top internal IP addresses |
| `get_top_files` | Top files seen in proxy traffic |
| `get_top_resources` | Top private resources |
| `get_top_resources_by_type` | Top private resources filtered by type |

### Reports - Summaries by Dimension

| Tool | Description |
|------|-------------|
| `get_summaries_by_category` | Request summaries grouped by content category |
| `get_summaries_by_category_type` | Category summaries filtered by traffic type |
| `get_summaries_by_destination` | Request summaries grouped by destination |
| `get_summaries_by_destination_type` | Destination summaries filtered by traffic type |
| `get_summaries_by_rule_hitcount` | Access rule hit counts for specific rule IDs |
| `get_summaries_by_rule_firewall_hitcount` | Firewall rule hit counts |
| `get_summaries_by_rule_intrusion` | Intrusion prevention summaries grouped by rule |

### Reports - Time Series

| Tool | Description |
|------|-------------|
| `get_requests_by_hour` | Request counts aggregated by hour |
| `get_requests_by_hour_type` | Hourly request counts filtered by traffic type |
| `get_requests_by_timerange` | Request counts aggregated by time range |
| `get_requests_by_timerange_type` | Time-range request counts filtered by traffic type |
| `get_categories_by_hour` | Category counts aggregated by hour |
| `get_categories_by_hour_type` | Hourly category counts filtered by traffic type |
| `get_categories_by_timerange` | Category counts aggregated by time range |
| `get_categories_by_timerange_type` | Time-range category counts filtered by traffic type |
| `get_identity_distribution` | Identity distribution across requests |
| `get_identity_distribution_by_type` | Identity distribution filtered by traffic type |
| `get_bandwidth_by_hour` | Bandwidth usage by hour |
| `get_bandwidth_by_timerange` | Bandwidth usage by time range |

### Reports - Granular Activity

| Tool | Description |
|------|-------------|
| `get_activity` | Recent activity and security events |
| `get_activity_dns` | DNS-layer activity |
| `get_activity_proxy` | Web proxy activity |
| `get_activity_firewall` | Firewall activity |
| `get_activity_ip` | IP-layer activity |
| `get_activity_intrusion` | Intrusion prevention activity |
| `get_activity_amp` | AMP retrospective activity |
| `get_activity_ztna` | ZTNA activity |
| `get_activity_decryption` | SSL/TLS decryption activity |
| `get_rules_activity` | Policy rule activity |
| `get_unique_resources` | Count of unique private resources accessed |

### Infrastructure

| Tool | Description |
|------|-------------|
| `list_roaming_computers` | List roaming computers |
| `list_internal_networks` | List internal networks |
| `list_network_tunnels` | List network tunnel groups |

## Project Structure

```text
secure-access-mcp-community/
├── cisco_secure_access_mcp/
│   ├── __init__.py
│   ├── __main__.py          # Entry point: python -m cisco_secure_access_mcp
│   ├── auth.py              # OAuth2 client credentials token manager (cache, refresh, retry)
│   ├── client.py            # Async Cisco Secure Access REST client (pool, retries, paginate, audit logs)
│   ├── logging_config.py    # Structured JSON logging + secret redaction
│   ├── security.py          # Auth, rate limit, payload limit, request IDs (ASGI middleware)
│   ├── server.py            # FastMCP Streamable HTTP server + security wiring
│   └── tools/
│       ├── all_tools.py     # MCP tool definitions
│       └── destination_lists.py
├── README.md
├── requirements.txt
├── .env.example
└── mcp_config.example.json
```

## Prerequisites

- Python 3.10+ (Python 3.11 or newer recommended)
- Cisco Secure Access API key and secret with the scopes needed for the tools you plan to use:
  - Policies: destination lists and access rules
  - Investigate/Security: domain categorization and risk information
  - Reports: activity, summaries, top destinations, threats
  - Deployments/Admin: roaming computers, internal networks, tunnels

## Installation

### Option A: uv (recommended)

[uv](https://docs.astral.sh/uv/) is a fast Python package and project manager. If you don't have it yet:

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
# or: brew install uv / pipx install uv
```

Clone the repository, create a Python 3.11 environment, and install dependencies:

```bash
git clone https://github.com/CiscoDevNet/secure-access-mcp-community.git
cd secure-access-mcp-community

# Create a virtual environment pinned to a supported interpreter.
# uv downloads Python for you if it is not installed locally.
uv venv --python 3.11

# Install dependencies from requirements.txt into the environment.
uv pip install -r requirements.txt
```

Run the server without manually activating the venv:

```bash
uv run python -m cisco_secure_access_mcp
```

`uv run` automatically uses the project's `.venv`, so you do not need to `source` anything. You can still activate it the traditional way (`source .venv/bin/activate`) if you prefer.

### Option B: venv + pip

```bash
git clone https://github.com/CiscoDevNet/secure-access-mcp-community.git
cd secure-access-mcp-community
python3.11 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If `python3.11` is not available, use any Python 3.10+ interpreter. The `mcp` package is not available for Python 3.9, so `python3 -m venv venv` can fail on systems where `python3` still points to Python 3.9.

## Configuration

Copy the example environment file and fill in your credentials:

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECURE_ACCESS_API_KEY` | Yes | - | Cisco Secure Access OAuth client ID |
| `SECURE_ACCESS_API_SECRET` | Yes | - | Cisco Secure Access OAuth client secret |
| `TOKEN_URL` | No | `https://api.sse.cisco.com/auth/v2/token` | OAuth token endpoint |
| `HOST` | No | `127.0.0.1` | Streamable HTTP bind host |
| `PORT` | No | `8000` | Streamable HTTP bind port |
| `SECURE_ACCESS_USER_AGENT` | No | `secure-access-mcp-community/<version> (+<repo-url>)` | `User-Agent` sent on every API call so the Cisco backend can attribute traffic to this MCP server |
| `MCP_AUTH_TOKEN` | Yes* | - | Bearer token MCP clients must send (`Authorization: Bearer <token>`). *Required unless `MCP_ALLOW_NO_AUTH=true` |
| `MCP_ALLOW_NO_AUTH` | No | `false` | Run with **no client authentication** (testing only, not recommended; loopback host only) |
| `MCP_MAX_REQUEST_BYTES` | No | `1048576` | Max inbound request body size (large-payload DoS protection) |
| `MCP_RATE_LIMIT_RPM` | No | `120` | Per-client-IP rate limit (requests/min); `0` disables |
| `MCP_ALLOWED_HOSTS` | No | bound host + loopback | Comma-separated `Host` allowlist for DNS-rebinding protection |
| `MCP_ALLOWED_ORIGINS` | No | (none) | Comma-separated `Origin` allowlist |
| `MCP_DISABLE_DNS_REBINDING_PROTECTION` | No | `false` | Disable Host/Origin validation (testing only) |
| `SECURE_ACCESS_REQUIRE_CONFIRMATION` | No | `true` | Require `confirm=true` for destructive tools (two-stage commit) |
| `SECURE_ACCESS_REDACT_PII` | No | `false` | Redact PII (identities, IPs, emails) from report/activity outputs |
| `LOG_LEVEL` | No | `INFO` | Level for structured JSON logs (written to stderr) |

## Usage

Generate a strong client token, then run the server (authentication is required by default):

```bash
export SECURE_ACCESS_API_KEY="your-api-key"
export SECURE_ACCESS_API_SECRET="your-api-secret"
export MCP_AUTH_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m cisco_secure_access_mcp
```

MCP clients must then send `Authorization: Bearer $MCP_AUTH_TOKEN` on every request.

With uv (no manual venv activation needed):

```bash
export SECURE_ACCESS_API_KEY="your-api-key"
export SECURE_ACCESS_API_SECRET="your-api-secret"
export MCP_AUTH_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uv run python -m cisco_secure_access_mcp
```

### No-auth testing mode (not recommended)

For isolated local experimentation only, you can start the server without client→server authentication. The server refuses to start without **either** `MCP_AUTH_TOKEN` or this flag, and refuses the no-auth mode on any non-loopback host:

```bash
# NOT RECOMMENDED: anyone who can reach the port can use your Cisco credentials.
MCP_ALLOW_NO_AUTH=true python -m cisco_secure_access_mcp
```

A prominent warning is printed and logged at startup while in this mode.

The server listens at:

```text
http://127.0.0.1:8000/mcp
```

To use a different host or port:

```bash
HOST=0.0.0.0 PORT=8080 python -m cisco_secure_access_mcp
```

Use `127.0.0.1` for local-only access. Use `0.0.0.0` only when you intentionally need LAN or remote access, preferably behind HTTPS and access controls.

## MCP Client Configuration

Start the server first, then configure your MCP client to connect to the Streamable HTTP URL.

For Streamable HTTP, the recommended setup is to keep Cisco credentials in the server process environment or `.env` file and keep MCP client configuration URL-only. Clients must also present the bearer token from `MCP_AUTH_TOKEN` in the `Authorization` header.

### Cursor

Add to Cursor MCP settings (replace `YOUR_MCP_AUTH_TOKEN` with the value of `MCP_AUTH_TOKEN`):

```json
{
  "mcpServers": {
    "cisco-secure-access": {
      "url": "http://127.0.0.1:8000/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MCP_AUTH_TOKEN"
      }
    }
  }
}
```

### VS Code Copilot

Add to `.vscode/mcp.json` or user MCP settings:

```json
{
  "servers": {
    "cisco-secure-access": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MCP_AUTH_TOKEN"
      }
    }
  }
}
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector http://127.0.0.1:8000/mcp
# Set an "Authorization: Bearer <MCP_AUTH_TOKEN>" header in the Inspector UI,
# or start the server with MCP_ALLOW_NO_AUTH=true for local-only testing.
```

## Example Queries

Once connected, ask an MCP-compatible agent questions like:

| Query | Tools Used |
|-------|------------|
| "Show all destination lists" | `list_destination_lists` |
| "What is in destination list 12345?" | `get_destinations_in_list` |
| "Is evil.com present in any list?" | `search_domain_across_lists` |
| "Find duplicate destinations" | `find_repeating_destinations` |
| "Which lists are stale or empty?" | `audit_stale_lists` |
| "Create a block list called Malware Domains" | `create_destination_list` |
| "Add evil.com to list 12345" | `add_destinations_to_list` |
| "What category is example.com?" | `get_domain_categorization` |
| "Get the domain risk score for suspicious.example" | `investigate_domain` |
| "List access rules" | `list_access_rules` |
| "Show security summary for the past week" | `get_security_summary` |
| "Top threats in DNS traffic" | `get_top_threats_by_type` |
| "Show firewall activity from the last 24 hours" | `get_activity_firewall` |
| "How much of the destination limit is used?" | `destination_usage_summary` |

## Architecture

```text
MCP client
   |
   | Streamable HTTP + Authorization: Bearer <MCP_AUTH_TOKEN>
   v
Security middleware  (auth, rate limit, payload limit, request IDs, access logs)
   |
   v
FastMCP server  (DNS-rebinding / Host + Origin validation)
   |
   v
72 MCP tools  (input validation, destructive-action confirmation, optional PII redaction)
   |
   v
Async Secure Access client  (token cache/refresh, pooling, retries, audit logs)
   |
   v
Cisco Secure Access API
```

## Security

- **Client→server authentication (required by default).** Every request must carry `Authorization: Bearer <MCP_AUTH_TOKEN>`; the token is compared in constant time. The server refuses to start without either `MCP_AUTH_TOKEN` or the explicit `MCP_ALLOW_NO_AUTH=true` testing flag.
- **No-auth testing mode (not recommended).** `MCP_ALLOW_NO_AUTH=true` runs without authentication for isolated local testing only; it is rejected on non-loopback hosts and prints/logs a prominent warning.
- **DNS-rebinding protection.** Host/Origin validation via FastMCP `transport_security`, defaulting to the bound host plus loopback names (`MCP_ALLOWED_HOSTS` / `MCP_ALLOWED_ORIGINS`).
- **DoS protections.** Inbound payload size cap (`MCP_MAX_REQUEST_BYTES`) and per-client-IP rate limiting (`MCP_RATE_LIMIT_RPM`).
- **Auditability.** Structured JSON logs (stderr) with per-request correlation IDs (`X-Request-ID`) for transport requests and outbound Cisco API calls. A redaction filter keeps credentials/tokens out of logs.
- **Safer tools.** Destructive tools (`delete_destination_list`, `remove_destinations_from_list`) use two-stage commit (`confirm=true`) and carry `destructiveHint` annotations; write tools validate inputs server-side (allowlists, length/count caps). Optional PII redaction for report/activity outputs via `SECURE_ACCESS_REDACT_PII`.

Still operator-owned (recommended for production): terminate **TLS/mTLS** at a reverse proxy in front of this server, prefer a secret manager over `.env`, and run the process sandboxed/least-privilege. Rate limiting is per-process — enforce limits at the gateway when running multiple workers.

## Key Implementation Details

- Streamable HTTP only: the server always starts with `transport="streamable-http"`.
- OAuth2 token management: `auth.py` caches a single client-credentials token for its full lifetime (≈1 request/hour) and refreshes it ~60s before expiry, with exponential backoff retries on `429`/`5xx`/network errors.
- Connection pooling: `client.py` keeps one pooled `httpx.AsyncClient` for the whole server lifetime instead of opening a new connection per request, and closes it on shutdown.
- Automatic retries: rate-limited (`429`) responses are retried for any method (honoring `Retry-After`); `5xx` and transient network failures are retried only for idempotent reads.
- Pagination: `SecureAccessClient.paginate()` walks every page (`page`/`limit`, capped at 100/page) until a short page, the reported total, an optional `max_items` cap, or the page-count safety cap is reached.
- User-Agent tracking: every token and API request sends a `User-Agent` (see `get_user_agent()` in `cisco_secure_access_mcp/__init__.py`), overridable via `SECURE_ACCESS_USER_AGENT`, so Cisco can attribute backend traffic to this MCP server.
- Redirect handling: reports redirects are followed only for HTTPS Cisco-controlled hosts.
- Response limits: large responses are rejected to avoid oversized tool results.
- Credentials: API credentials are read from environment variables or `.env`, not source code.

## Dependencies

| Package | Purpose |
|---------|---------|
| `mcp[cli]` | Model Context Protocol SDK |
| `httpx` | Async HTTP client |
| `pydantic` | Tool input models in the destination-list module |
| `python-dotenv` | Load `.env` files |

## License

See LICENSE file for details.
