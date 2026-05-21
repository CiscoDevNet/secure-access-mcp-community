# Cisco Secure Access MCP Server

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
│   ├── auth.py              # OAuth2 client credentials token manager
│   ├── client.py            # Async Cisco Secure Access REST client
│   ├── server.py            # FastMCP Streamable HTTP server
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

Clone the repository and install dependencies:

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

## Usage

Run the Streamable HTTP server:

```bash
export SECURE_ACCESS_API_KEY="your-api-key"
export SECURE_ACCESS_API_SECRET="your-api-secret"
python -m cisco_secure_access_mcp
```

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

For Streamable HTTP, the recommended setup is to keep credentials in the server process environment or `.env` file and keep MCP client configuration URL-only. This avoids copying secrets into each client configuration file.

### Cursor

Add to Cursor MCP settings:

```json
{
  "mcpServers": {
    "cisco-secure-access": {
      "url": "http://127.0.0.1:8000/mcp"
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
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector http://127.0.0.1:8000/mcp
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
   | Streamable HTTP
   v
FastMCP server
   |
   v
72 MCP tools
   |
   v
Async Secure Access client
   |
   v
Cisco Secure Access API
```

## Key Implementation Details

- Streamable HTTP only: the server always starts with `transport="streamable-http"`.
- OAuth2 token management: `auth.py` caches and refreshes client-credentials tokens.
- Async HTTP client: `client.py` uses `httpx.AsyncClient` for Cisco Secure Access API calls.
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
