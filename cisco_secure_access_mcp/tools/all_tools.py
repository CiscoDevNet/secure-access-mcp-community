# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Cisco Secure Access MCP tools."""

from __future__ import annotations

import os
import re
import time
from datetime import datetime
from typing import Any

from mcp.server.fastmcp import Context

from ..client import API_BASE_URL, SecureAccessClient, compact_json, format_error
from ..server import AppContext, mcp

POLICIES_SCOPE = "policies/v2"
REPORTS_SCOPE = "reports/v2"
SECURITY_SCOPE = "security/v1"
DEPLOYMENTS_SCOPE = "deployments/v2"

ORG_DESTINATION_LIMIT = 250_000
DEFAULT_PAGE_SIZE = 100
ACCESS_RULES_PAGE_SIZE = 1000
BATCH_LIMIT = 500
MAX_NAME_LENGTH = 255
MAX_DESTINATION_LENGTH = 253

ACCESS_TYPES = {"allow", "block", "url_proxy", "no_decrypt", "warn", "none"}

# Standard MCP tool annotation presets so clients can distinguish safe reads from
# state-changing or destructive operations.
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
WRITE_CREATE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
WRITE_UPDATE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
DESTRUCTIVE = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Two-stage commit for destructive actions: when enabled (default), destructive
# tools require an explicit confirm=true and otherwise return a preview.  The LLM
# must not be relied on for authorization, so this is a server-side gate.
REQUIRE_CONFIRMATION = _env_bool("SECURE_ACCESS_REQUIRE_CONFIRMATION", default=True)

# Opt-in PII redaction for report/activity outputs (identities, IPs, emails).
REDACT_PII = _env_bool("SECURE_ACCESS_REDACT_PII", default=False)

# Keys whose (normalized) name means the value is PII and should be redacted.
# Matching is on whole, normalized key names and on split tokens — never raw
# substrings — so "description", "recipient", "zip", and "userAgent" are NOT
# treated as PII the way a naive substring match would.
_PII_KEYS = frozenset({
    "identity", "identities", "ip", "internalip", "externalip",
    "email", "emailaddress", "user", "username", "userid",
    "device", "deviceid",
})
# Tokens that are reliably PII even as one part of a compound key
# (e.g. "sourceIp", "destination_ip"). Deliberately excludes "user" so that
# "userAgent" is not redacted.
_PII_TOKENS = frozenset({"ip", "email", "identity", "identities"})
_REDACTED = "***REDACTED***"


def _is_pii_key(key: str) -> bool:
    """Return True if a key name denotes PII, using whole-name and token matches."""
    normalized = key.replace("_", "").replace("-", "").lower()
    if normalized in _PII_KEYS:
        return True
    tokens = re.split(r"[_\-\s]+|(?<=[a-z])(?=[A-Z])", key)
    return any(token.lower() in _PII_TOKENS for token in tokens)


def _get_client(ctx: Context) -> SecureAccessClient:
    app: AppContext = ctx.request_context.lifespan_context
    return app.client


def _json(data: Any) -> str:
    return compact_json(data)


def _validate_access(access: str) -> str:
    normalized = access.strip().lower()
    if normalized not in ACCESS_TYPES:
        raise ValueError(f"access must be one of {sorted(ACCESS_TYPES)}, got {access!r}")
    return normalized


def _validate_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("name must not be empty")
    if len(cleaned) > MAX_NAME_LENGTH:
        raise ValueError(f"name must be ≤{MAX_NAME_LENGTH} characters, got {len(cleaned)}")
    return cleaned


def _validate_destinations(destinations: list[str]) -> list[str]:
    cleaned: list[str] = []
    for d in destinations:
        d = (d or "").strip()
        if not d:
            raise ValueError("destination entries must not be empty")
        if len(d) > MAX_DESTINATION_LENGTH:
            raise ValueError(f"destination must be ≤{MAX_DESTINATION_LENGTH} characters, got {len(d)}")
        cleaned.append(d)
    if not cleaned:
        raise ValueError("at least one destination is required")
    return cleaned


def _redact_pii(obj: Any) -> Any:
    """Mask values under PII-like keys.  Best-effort defense-in-depth."""
    if isinstance(obj, dict):
        result: dict[str, Any] = {}
        for key, value in obj.items():
            if _is_pii_key(key) and not isinstance(value, (dict, list)):
                result[key] = _REDACTED if value not in (None, "", 0) else value
            else:
                result[key] = _redact_pii(value)
        return result
    if isinstance(obj, list):
        return [_redact_pii(item) for item in obj]
    return obj


def _maybe_redact(data: Any) -> Any:
    return _redact_pii(data) if REDACT_PII else data


async def _get_all_destination_lists(client: SecureAccessClient) -> list[dict[str, Any]]:
    return await client.paginate(POLICIES_SCOPE, "destinationlists", page_size=DEFAULT_PAGE_SIZE)


async def _get_all_destinations(client: SecureAccessClient, destination_list_id: int) -> list[dict[str, Any]]:
    return await client.paginate(
        POLICIES_SCOPE,
        f"destinationlists/{destination_list_id}/destinations",
        page_size=DEFAULT_PAGE_SIZE,
    )


async def _get_all_access_rules(client: SecureAccessClient) -> list[dict[str, Any]]:
    return await client.paginate_offset(
        POLICIES_SCOPE,
        "rules",
        page_size=ACCESS_RULES_PAGE_SIZE,
        max_page_size=ACCESS_RULES_PAGE_SIZE,
        data_key=("results", "data"),
    )


async def _get_all_roaming_computers(client: SecureAccessClient) -> list[dict[str, Any]]:
    return await client.paginate(DEPLOYMENTS_SCOPE, "roamingcomputers", page_size=DEFAULT_PAGE_SIZE)


async def _get_all_internal_networks(client: SecureAccessClient) -> list[dict[str, Any]]:
    return await client.paginate(DEPLOYMENTS_SCOPE, "internalnetworks", page_size=DEFAULT_PAGE_SIZE)


async def _get_all_network_tunnels(client: SecureAccessClient) -> list[dict[str, Any]]:
    return await client.paginate_offset(DEPLOYMENTS_SCOPE, "networktunnelgroups", page_size=DEFAULT_PAGE_SIZE)


async def _reports_get(ctx: Context, path: str, params: dict[str, Any]) -> str:
    client = _get_client(ctx)
    data = await client.request_url("GET", f"{API_BASE_URL}{path}", params=params)
    return _json(_maybe_redact(data))


def _time_params(from_time: str, to_time: str, limit: int | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"from": from_time, "to": to_time}
    if limit is not None:
        params["limit"] = limit
        params["offset"] = 0
    return params


# ============================================================================
# Destination Lists
# ============================================================================


@mcp.tool()
async def list_destination_lists(ctx: Context) -> str:
    """List all destination lists in the organization."""
    try:
        all_lists = await _get_all_destination_lists(_get_client(ctx))
        summary = [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "access": item.get("access"),
                "destinationCount": item.get("destinationCount") or item.get("meta", {}).get("destinationCount"),
                "isGlobal": item.get("isGlobal"),
                "createdAt": item.get("createdAt"),
            }
            for item in all_lists
        ]
        return _json({"count": len(summary), "destination_lists": summary})
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_destination_list(destination_list_id: int, ctx: Context) -> str:
    """Get details of a single destination list by its numeric ID."""
    try:
        data = await _get_client(ctx).get(POLICIES_SCOPE, f"destinationlists/{destination_list_id}")
        return _json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_destinations_in_list(destination_list_id: int, ctx: Context) -> str:
    """Get all destinations (domains/URLs/IPs) inside a specific destination list."""
    try:
        destinations = await _get_all_destinations(_get_client(ctx), destination_list_id)
        return _json({"count": len(destinations), "destinations": destinations})
    except Exception as e:
        return format_error(e)


@mcp.tool()
@mcp.tool(annotations=WRITE_CREATE)
async def create_destination_list(
    name: str,
    ctx: Context,
    access: str = "none",
    destinations: list[str] | None = None,
) -> str:
    """Create a new destination list with optional initial destinations."""
    try:
        body: dict[str, Any] = {
            "access": _validate_access(access),
            "bundleTypeId": 2,
            "isGlobal": False,
            "name": _validate_name(name),
        }
        if destinations:
            cleaned = _validate_destinations(destinations[:BATCH_LIMIT])
            body["destinations"] = [{"destination": destination} for destination in cleaned]
        data = await _get_client(ctx).post(POLICIES_SCOPE, "destinationlists", json_data=body)
        return _json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(annotations=WRITE_UPDATE)
async def update_destination_list(destination_list_id: int, name: str, ctx: Context) -> str:
    """Rename a destination list by its numeric ID."""
    try:
        data = await _get_client(ctx).patch(
            POLICIES_SCOPE,
            f"destinationlists/{destination_list_id}",
            json_data={"name": _validate_name(name)},
        )
        return _json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_destination_list(destination_list_id: int, ctx: Context, confirm: bool = False) -> str:
    """Delete a destination list by its numeric ID. This action cannot be undone.

    This is a destructive, irreversible action.  Unless confirmation is disabled
    server-side, you must call again with confirm=true to actually delete; the
    first call returns a preview of what would be deleted.
    """
    try:
        if REQUIRE_CONFIRMATION and not confirm:
            preview = await _get_client(ctx).get(
                POLICIES_SCOPE, f"destinationlists/{destination_list_id}"
            )
            target = preview.get("data", preview) if isinstance(preview, dict) else preview
            return _json(
                {
                    "confirmationRequired": True,
                    "action": "delete_destination_list",
                    "warning": "This permanently deletes the destination list and cannot be undone.",
                    "target": target,
                    "howToConfirm": "Call this tool again with confirm=true to proceed.",
                }
            )
        data = await _get_client(ctx).delete(POLICIES_SCOPE, f"destinationlists/{destination_list_id}")
        return _json(data) if data else "Destination list deleted successfully."
    except Exception as e:
        return format_error(e)


@mcp.tool(annotations=WRITE_CREATE)
async def add_destinations_to_list(
    destination_list_id: int,
    destinations: list[str],
    ctx: Context,
    comment: str = "",
) -> str:
    """Add destinations (domains, IPs, or URLs) to a destination list. Max 500 per request."""
    try:
        cleaned = _validate_destinations(destinations[:BATCH_LIMIT])
        items = [
            {"destination": destination, **({"comment": comment} if comment else {})}
            for destination in cleaned
        ]
        data = await _get_client(ctx).post(
            POLICIES_SCOPE,
            f"destinationlists/{destination_list_id}/destinations",
            json_data=items,
        )
        return _json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(annotations=DESTRUCTIVE)
async def remove_destinations_from_list(
    destination_list_id: int,
    destination_ids: list[int],
    ctx: Context,
    confirm: bool = False,
) -> str:
    """Remove destinations from a list by their numeric IDs. Max 500 per request.

    Destructive action.  Unless confirmation is disabled server-side, you must
    call again with confirm=true; the first call returns a preview of how many
    destinations would be removed.
    """
    try:
        ids = destination_ids[:BATCH_LIMIT]
        if not ids:
            raise ValueError("at least one destination_id is required")
        if REQUIRE_CONFIRMATION and not confirm:
            return _json(
                {
                    "confirmationRequired": True,
                    "action": "remove_destinations_from_list",
                    "destinationListId": destination_list_id,
                    "destinationIdCount": len(ids),
                    "destinationIds": ids,
                    "warning": "This removes the listed destinations from the list.",
                    "howToConfirm": "Call this tool again with confirm=true to proceed.",
                }
            )
        data = await _get_client(ctx).delete(
            POLICIES_SCOPE,
            f"destinationlists/{destination_list_id}/destinations/remove",
            json_data=ids,
        )
        return _json(data) if data else "Destinations removed successfully."
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def destination_usage_summary(ctx: Context) -> str:
    """Get organization-wide destination usage summary."""
    try:
        all_lists = await _get_all_destination_lists(_get_client(ctx))
        total_destinations = 0
        type_totals = {"domains": 0, "urls": 0, "ipv4": 0, "ipv6": 0, "applications": 0}
        list_summaries: list[dict[str, Any]] = []

        for destination_list in all_lists:
            meta = destination_list.get("meta", {})
            destination_count = destination_list.get("destinationCount") or meta.get("destinationCount") or 0
            total_destinations += destination_count
            type_totals["domains"] += meta.get("domainCount", 0)
            type_totals["urls"] += meta.get("urlCount", 0)
            type_totals["ipv4"] += meta.get("ipv4Count", 0)
            type_totals["ipv6"] += meta.get("ipv6Count", 0)
            type_totals["applications"] += meta.get("applicationCount", 0)
            list_summaries.append(
                {
                    "id": destination_list.get("id"),
                    "name": destination_list.get("name"),
                    "access": destination_list.get("access"),
                    "destinationCount": destination_count,
                }
            )

        list_summaries.sort(key=lambda item: item["destinationCount"], reverse=True)
        return _json(
            {
                "organizationLimit": ORG_DESTINATION_LIMIT,
                "totalDestinations": total_destinations,
                "remaining": ORG_DESTINATION_LIMIT - total_destinations,
                "usagePercent": round(total_destinations / ORG_DESTINATION_LIMIT * 100, 1),
                "totalLists": len(all_lists),
                "typeTotals": type_totals,
                "lists": list_summaries,
            }
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def search_domain_across_lists(domain: str, ctx: Context) -> str:
    """Search for a domain/URL/IP across all destination lists."""
    try:
        client = _get_client(ctx)
        search_value = domain.lower()
        matches: list[dict[str, Any]] = []
        for destination_list in await _get_all_destination_lists(client):
            list_id = destination_list.get("id")
            for item in await _get_all_destinations(client, list_id):
                destination = (item.get("destination", "") or "").lower()
                if search_value in destination or destination in search_value:
                    matches.append(
                        {
                            "list_id": list_id,
                            "list_name": destination_list.get("name", ""),
                            "list_access": destination_list.get("access", ""),
                            "destination": item.get("destination"),
                            "type": item.get("type"),
                            "comment": item.get("comment", ""),
                            "createdAt": item.get("createdAt"),
                        }
                    )
        return _json(
            {
                "searched_for": domain,
                "found_in_count": len(matches),
                "matches": matches,
                "recommendation": (
                    f"'{domain}' found in {len(matches)} list(s). "
                    + ("Consider consolidating to avoid duplicates." if len(matches) > 1 else "")
                    if matches
                    else f"'{domain}' not found in any destination list."
                ),
            }
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def find_repeating_destinations(ctx: Context) -> str:
    """Find destinations that appear in multiple destination lists."""
    try:
        client = _get_client(ctx)
        destination_to_lists: dict[str, list[dict[str, Any]]] = {}
        for destination_list in await _get_all_destination_lists(client):
            list_id = destination_list.get("id")
            for item in await _get_all_destinations(client, list_id):
                destination = item.get("destination", "")
                if destination:
                    destination_to_lists.setdefault(destination, []).append(
                        {
                            "list_id": list_id,
                            "list_name": destination_list.get("name", ""),
                            "access": destination_list.get("access", ""),
                        }
                    )
        repeating = {destination: lists for destination, lists in destination_to_lists.items() if len(lists) > 1}
        return _json(
            {
                "total_unique_destinations": len(destination_to_lists),
                "repeating_count": len(repeating),
                "repeating_destinations": {
                    destination: {"appears_in_count": len(lists), "lists": lists}
                    for destination, lists in sorted(repeating.items(), key=lambda item: -len(item[1]))
                },
            }
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def audit_stale_lists(ctx: Context, stale_days: int = 30) -> str:
    """Audit destination lists for staleness, emptiness, and hygiene issues."""
    try:
        stale_threshold = time.time() - (stale_days * 86_400)
        stale_lists: list[dict[str, Any]] = []
        empty_lists: list[dict[str, Any]] = []
        low_count_lists: list[dict[str, Any]] = []

        all_lists = await _get_all_destination_lists(_get_client(ctx))
        for destination_list in all_lists:
            destination_count = (
                destination_list.get("destinationCount")
                or destination_list.get("meta", {}).get("destinationCount")
                or 0
            )
            list_info = {
                "id": destination_list.get("id"),
                "name": destination_list.get("name"),
                "access": destination_list.get("access"),
                "isGlobal": destination_list.get("isGlobal"),
                "destinationCount": destination_count,
            }
            modified: str | int | float = destination_list.get("modifiedAt") or destination_list.get("createdAt") or 0
            if isinstance(modified, str):
                try:
                    modified = datetime.fromisoformat(modified.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    modified = 0
            if modified and float(modified) < stale_threshold:
                list_info["days_since_modified"] = int((time.time() - float(modified)) / 86_400)
                stale_lists.append(list_info)
            if destination_count == 0:
                empty_lists.append(list_info)
            elif destination_count <= 2:
                low_count_lists.append(list_info)

        recommendations: list[str] = []
        if stale_lists:
            recommendations.append(
                f"{len(stale_lists)} list(s) not modified in {stale_days}+ days. Review and update or remove."
            )
        if empty_lists:
            recommendations.append(f"{len(empty_lists)} list(s) have no destinations. Consider removing.")
        if low_count_lists:
            recommendations.append(
                f"{len(low_count_lists)} list(s) have very few destinations (<=2). Consider consolidating."
            )
        if not recommendations:
            recommendations.append("All destination lists look healthy!")
        return _json(
            {
                "total_lists": len(all_lists),
                "stale_threshold_days": stale_days,
                "stale_lists": {"count": len(stale_lists), "lists": stale_lists},
                "empty_lists": {"count": len(empty_lists), "lists": empty_lists},
                "low_destination_count_lists": {"count": len(low_count_lists), "lists": low_count_lists},
                "recommendations": recommendations,
            }
        )
    except Exception as e:
        return format_error(e)


# ============================================================================
# Domain Investigation
# ============================================================================


@mcp.tool()
async def investigate_domain(domain: str, ctx: Context) -> str:
    """Get security information for a domain."""
    try:
        data = await _get_client(ctx).get(SECURITY_SCOPE, f"domains/{domain}/risk-score")
        return _json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_domain_categorization(domain: str, ctx: Context) -> str:
    """Get the status and content categorization of a domain."""
    try:
        data = await _get_client(ctx).get(SECURITY_SCOPE, f"domains/{domain}/categorization")
        return _json(data)
    except Exception as e:
        return format_error(e)


# ============================================================================
# Access Rules (Policies)
# ============================================================================


@mcp.tool()
async def list_access_rules(ctx: Context) -> str:
    """List all access policy rules."""
    try:
        rules = await _get_all_access_rules(_get_client(ctx))
        return _json({"count": len(rules), "rules": rules})
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_access_rule_detail(rule_id: int, ctx: Context) -> str:
    """Get full details of an access rule."""
    try:
        data = await _get_client(ctx).get(POLICIES_SCOPE, f"rules/{rule_id}")
        conditions = data.get("ruleConditions", [])
        parsed_conditions = []
        for condition in conditions:
            attribute_name = condition.get("attributeName", "")
            attribute_value = condition.get("attributeValue", [])
            operator = condition.get("attributeOperator", "")
            if "category_ids" in attribute_name:
                condition_type = "content_categories"
                value_key = "category_ids"
            elif "identity_ids" in attribute_name:
                condition_type = "identities"
                value_key = "identity_ids"
            elif "dest_list_ids" in attribute_name or "destination" in attribute_name:
                condition_type = "destination_lists"
                value_key = "destination_list_ids"
            else:
                condition_type = attribute_name
                value_key = "values"
            parsed_conditions.append({"type": condition_type, "operator": operator, value_key: attribute_value})
        data["conditions"] = parsed_conditions
        return _json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(annotations=WRITE_CREATE)
async def create_access_rule(
    rule_name: str,
    action: str,
    ctx: Context,
    category_ids: list[int] | None = None,
    destination_list_ids: list[int] | None = None,
    description: str = "",
) -> str:
    """Create a new access rule by content categories or destination lists."""
    try:
        normalized_action = action.strip().upper()
        if normalized_action not in {"ALLOW", "BLOCK"}:
            raise ValueError(f"action must be 'allow' or 'block', got {action!r}")
        rule_name = _validate_name(rule_name)
        conditions: list[dict[str, Any]] = [
            {
                "attributeName": "umbrella.source.all",
                "attributeOperator": "EQUAL",
                "attributeValue": True,
            },
            {
                "attributeName": "umbrella.destination.all",
                "attributeOperator": "EQUAL",
                "attributeValue": True,
            },
        ]
        if category_ids:
            conditions.append(
                {
                    "attributeName": "umbrella.destination.category_ids",
                    "attributeOperator": "INTERSECT",
                    "attributeValue": category_ids,
                }
            )
        if destination_list_ids:
            conditions.append(
                {
                    "attributeName": "umbrella.destination.destination_list_ids",
                    "attributeOperator": "INTERSECT",
                    "attributeValue": destination_list_ids,
                }
            )
        request = {
            "ruleName": rule_name,
            "ruleAction": "BLOCK" if normalized_action == "BLOCK" else "ALLOW",
            "ruleIsEnabled": True,
            "ruleDescription": description,
            "ruleConditions": conditions,
            "ruleSettings": [
                {"settingName": "umbrella.log_level", "settingValue": "LOG_ALL"},
                {"settingName": "umbrella.default.traffic", "settingValue": "PUBLIC_INTERNET"},
            ],
        }
        data = await _get_client(ctx).post(POLICIES_SCOPE, "rules", json_data=request)
        return _json(
            {
                "success": True,
                "ruleId": data.get("ruleId"),
                "ruleName": data.get("ruleName"),
                "ruleAction": data.get("ruleAction"),
                "rulePriority": data.get("rulePriority"),
                "ruleIsEnabled": data.get("ruleIsEnabled"),
                "conditions_summary": {
                    "category_ids": category_ids or "none",
                    "destination_list_ids": destination_list_ids or "none",
                },
                "createdAt": data.get("createdAt"),
            }
        )
    except Exception as e:
        return format_error(e)


# ============================================================================
# Reports & Activity
# ============================================================================


@mcp.tool()
async def get_top_destinations(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 10) -> str:
    """Get the top accessed destinations in the organization."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-destinations", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_identities(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 10) -> str:
    """Get the top identities by DNS request count."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-identities", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_categories(ctx: Context, from_time: str = "-7days", to_time: str = "now") -> str:
    """Get the top content categories by request count."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-categories", _time_params(from_time, to_time))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_activity(ctx: Context, from_time: str = "-1days", to_time: str = "now", limit: int = 100) -> str:
    """Get recent DNS activity/security events."""
    try:
        return await _reports_get(ctx, "/reports/v2/activity", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_security_summary(ctx: Context, from_time: str = "-7days", to_time: str = "now") -> str:
    """Get the organization's security summary."""
    try:
        return await _reports_get(ctx, "/reports/v2/summary", _time_params(from_time, to_time))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_security_summary_by_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 100,
) -> str:
    """Get security summary filtered by traffic type."""
    try:
        return await _reports_get(ctx, f"/reports/v2/summary/{report_type}", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_destinations_by_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 10,
) -> str:
    """Get top destinations filtered by traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/top-destinations/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_urls(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 10) -> str:
    """Get the top URLs accessed in the organization."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-urls", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_categories_by_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 10,
) -> str:
    """Get top content categories filtered by traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/top-categories/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_identities_by_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 10,
) -> str:
    """Get top identities filtered by traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/top-identities/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_threats(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 10) -> str:
    """Get the top threats seen in the organization."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-threats", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_threats_by_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 10,
) -> str:
    """Get top threats filtered by traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/top-threats/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_threat_types(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 10) -> str:
    """Get the top threat types seen in the organization."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-threat-types", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_threat_types_by_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 10,
) -> str:
    """Get top threat types filtered by traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/top-threat-types/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_event_types(ctx: Context, from_time: str = "-7days", to_time: str = "now") -> str:
    """Get the top event types by count."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-eventtypes", _time_params(from_time, to_time))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_dns_query_types(ctx: Context, from_time: str = "-7days", to_time: str = "now") -> str:
    """Get the top DNS query types by count."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-dns-query-types", _time_params(from_time, to_time))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_ips(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 10) -> str:
    """Get the top IPs by request count."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-ips", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_ips_internal(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 10) -> str:
    """Get the top internal IPs by request count."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-ips/internal", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_files(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 10) -> str:
    """Get the top files seen in proxy traffic."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-files", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_resources(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 10) -> str:
    """Get the top private resources accessed by users."""
    try:
        return await _reports_get(ctx, "/reports/v2/top-resources", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_top_resources_by_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 10,
) -> str:
    """Get top private resources filtered by type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/top-resources/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_total_requests(ctx: Context, from_time: str = "-7days", to_time: str = "now") -> str:
    """Get total request counts across all traffic types."""
    try:
        return await _reports_get(ctx, "/reports/v2/total-requests", _time_params(from_time, to_time))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_total_requests_by_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
) -> str:
    """Get total request counts for a specific traffic type."""
    try:
        return await _reports_get(ctx, f"/reports/v2/total-requests/{report_type}", _time_params(from_time, to_time))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_summaries_by_category(
    ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100
) -> str:
    """Get request summaries grouped by content category."""
    try:
        return await _reports_get(ctx, "/reports/v2/summaries-by-category", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_summaries_by_category_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 100,
) -> str:
    """Get request summaries by category filtered by traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/summaries-by-category/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_summaries_by_destination(
    ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100
) -> str:
    """Get request summaries grouped by destination domain/IP."""
    try:
        return await _reports_get(ctx, "/reports/v2/summaries-by-destination", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_summaries_by_destination_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 100,
) -> str:
    """Get request summaries by destination filtered by traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/summaries-by-destination/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_summaries_by_rule_hitcount(
    rule_ids: str, ctx: Context, from_time: str = "-7days", to_time: str = "now"
) -> str:
    """Get hit counts for specific access rules. rule_ids: comma-separated rule IDs."""
    try:
        params = _time_params(from_time, to_time)
        params["ruleids"] = rule_ids
        return await _reports_get(ctx, "/reports/v2/summaries-by-rule/hitcount", params)
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_summaries_by_rule_firewall_hitcount(
    rule_ids: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
) -> str:
    """Get firewall rule hit counts."""
    try:
        params = _time_params(from_time, to_time)
        params["ruleids"] = rule_ids
        return await _reports_get(ctx, "/reports/v2/summaries-by-rule/firewall-hitcount", params)
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_summaries_by_rule_intrusion(
    ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100
) -> str:
    """Get intrusion prevention summaries grouped by rule."""
    try:
        return await _reports_get(
            ctx, "/reports/v2/summaries-by-rule/intrusion", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_requests_by_hour(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100) -> str:
    """Get request counts aggregated by hour across all traffic types."""
    try:
        return await _reports_get(ctx, "/reports/v2/requests-by-hour", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_requests_by_hour_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 100,
) -> str:
    """Get request counts by hour for a specific traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/requests-by-hour/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_requests_by_timerange(
    ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100
) -> str:
    """Get request counts aggregated by time range across all traffic types."""
    try:
        return await _reports_get(ctx, "/reports/v2/requests-by-timerange", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_requests_by_timerange_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 100,
) -> str:
    """Get request counts by time range for a specific traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/requests-by-timerange/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_categories_by_hour(
    ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100
) -> str:
    """Get request counts by hour broken down by content category."""
    try:
        return await _reports_get(ctx, "/reports/v2/categories-by-hour", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_categories_by_hour_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 100,
) -> str:
    """Get request counts by hour and category for a specific traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/categories-by-hour/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_categories_by_timerange(
    ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100
) -> str:
    """Get request counts by time range broken down by content category."""
    try:
        return await _reports_get(ctx, "/reports/v2/categories-by-timerange", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_categories_by_timerange_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 100,
) -> str:
    """Get request counts by time range and category for a specific traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/categories-by-timerange/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_identity_distribution(
    ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100
) -> str:
    """Get identity distribution across identities."""
    try:
        return await _reports_get(ctx, "/reports/v2/identity-distribution", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_identity_distribution_by_type(
    report_type: str,
    ctx: Context,
    from_time: str = "-7days",
    to_time: str = "now",
    limit: int = 100,
) -> str:
    """Get identity distribution filtered by traffic type."""
    try:
        return await _reports_get(
            ctx, f"/reports/v2/identity-distribution/{report_type}", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_bandwidth_by_hour(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100) -> str:
    """Get bandwidth usage aggregated by hour."""
    try:
        return await _reports_get(ctx, "/reports/v2/bandwidth-by-hour", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_bandwidth_by_timerange(
    ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100
) -> str:
    """Get bandwidth usage aggregated by time range."""
    try:
        return await _reports_get(ctx, "/reports/v2/bandwidth-by-timerange", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_rules_activity(ctx: Context, from_time: str = "-7days", to_time: str = "now", limit: int = 100) -> str:
    """Get events related to policy rules."""
    try:
        return await _reports_get(ctx, "/reports/v2/rules-activity", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_unique_resources(ctx: Context, from_time: str = "-7days", to_time: str = "now") -> str:
    """Get a count of unique private resources accessed."""
    try:
        return await _reports_get(ctx, "/reports/v2/unique-resources", _time_params(from_time, to_time))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_activity_dns(ctx: Context, from_time: str = "-1days", to_time: str = "now", limit: int = 100) -> str:
    """Get recent DNS-layer security activity events."""
    try:
        return await _reports_get(ctx, "/reports/v2/activity/dns", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_activity_proxy(ctx: Context, from_time: str = "-1days", to_time: str = "now", limit: int = 100) -> str:
    """Get recent web proxy activity events."""
    try:
        return await _reports_get(ctx, "/reports/v2/activity/proxy", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_activity_firewall(ctx: Context, from_time: str = "-1days", to_time: str = "now", limit: int = 100) -> str:
    """Get recent cloud firewall activity events."""
    try:
        return await _reports_get(ctx, "/reports/v2/activity/firewall", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_activity_ip(ctx: Context, from_time: str = "-1days", to_time: str = "now", limit: int = 100) -> str:
    """Get recent IP-layer activity events."""
    try:
        return await _reports_get(ctx, "/reports/v2/activity/ip", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_activity_intrusion(
    ctx: Context, from_time: str = "-1days", to_time: str = "now", limit: int = 100
) -> str:
    """Get recent intrusion prevention activity events."""
    try:
        return await _reports_get(ctx, "/reports/v2/activity/intrusion", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_activity_amp(ctx: Context, from_time: str = "-1days", to_time: str = "now", limit: int = 100) -> str:
    """Get recent AMP retrospective activity events."""
    try:
        return await _reports_get(
            ctx, "/reports/v2/activity/amp-retrospective", _time_params(from_time, to_time, limit)
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_activity_ztna(ctx: Context, from_time: str = "-1days", to_time: str = "now", limit: int = 100) -> str:
    """Get recent ZTNA activity events."""
    try:
        return await _reports_get(ctx, "/reports/v2/activity/ztna", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def get_activity_decryption(
    ctx: Context, from_time: str = "-1days", to_time: str = "now", limit: int = 100
) -> str:
    """Get recent SSL/TLS decryption activity events."""
    try:
        return await _reports_get(ctx, "/reports/v2/activity/decryption", _time_params(from_time, to_time, limit))
    except Exception as e:
        return format_error(e)


# ============================================================================
# Infrastructure
# ============================================================================


@mcp.tool()
async def list_roaming_computers(ctx: Context) -> str:
    """List all roaming computers registered in the organization."""
    try:
        computers = await _get_all_roaming_computers(_get_client(ctx))
        return _json({"count": len(computers), "roaming_computers": computers})
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def list_internal_networks(ctx: Context) -> str:
    """List internal networks configured in the organization."""
    try:
        networks = await _get_all_internal_networks(_get_client(ctx))
        return _json({"count": len(networks), "internal_networks": networks})
    except Exception as e:
        return format_error(e)


@mcp.tool()
async def list_network_tunnels(ctx: Context) -> str:
    """List network tunnel groups configured in the organization."""
    try:
        tunnels = await _get_all_network_tunnels(_get_client(ctx))
        return _json({"count": len(tunnels), "network_tunnels": tunnels})
    except Exception as e:
        return format_error(e)
