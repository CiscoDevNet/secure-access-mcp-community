# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Destination list tools — CRUD operations and intelligent list analysis.

Secure Access supports a maximum of 250,000 destinations spread across all
destination lists in an organization.  Each API request accepts at most 500
destination objects.  These tools help customers stay within limits by
surfacing usage data, duplicates, and cleanup opportunities.
"""

from __future__ import annotations

import json
from typing import Optional

from mcp.server.fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..client import SecureAccessClient, compact_json, format_error
from ..server import AppContext, mcp

SCOPE = "policies/v2"

ORG_DESTINATION_LIMIT = 250_000
BATCH_LIMIT = 500


def _get_client(ctx: Context) -> SecureAccessClient:
    app: AppContext = ctx.request_context.lifespan_context
    return app.client


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class PaginationInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    page: Optional[int] = Field(default=1, description="Page number (starts at 1)", ge=1)
    limit: Optional[int] = Field(default=100, description="Records per page (max 100)", ge=1, le=100)


class DestinationListIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list")


class DestinationListCreateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(..., description="Name for the new destination list", min_length=1, max_length=255)
    access: str = Field(
        default="none",
        description="Access type: 'allow', 'block', 'url_proxy', 'no_decrypt', 'warn', or 'none'",
    )
    destinations: Optional[list[str]] = Field(
        default=None,
        description="Optional initial destinations (domains, IPs, or URLs). Max 500.",
        max_length=500,
    )

    @field_validator("access")
    @classmethod
    def validate_access(cls, v: str) -> str:
        allowed = {"allow", "block", "url_proxy", "no_decrypt", "warn", "none"}
        v_lower = v.lower()
        if v_lower not in allowed:
            raise ValueError(f"access must be one of {sorted(allowed)}, got {v!r}")
        return v_lower


class DestinationListUpdateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list to update")
    name: str = Field(..., description="New name for the destination list", min_length=1, max_length=255)


class DestinationsGetInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list")
    page: Optional[int] = Field(default=1, ge=1)
    limit: Optional[int] = Field(default=100, ge=1, le=100)


class DestinationsAddInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list")
    destinations: list[str] = Field(
        ...,
        description="Destinations to add (domains, IPs, or URLs). Max 500 per request.",
        min_length=1,
        max_length=500,
    )
    comment: Optional[str] = Field(default=None, description="Comment for the new destinations")

    @field_validator("destinations")
    @classmethod
    def validate_destinations(cls, v: list[str]) -> list[str]:
        cleaned = []
        for d in v:
            d = d.strip()
            if not d:
                raise ValueError("destination entries must not be empty")
            if len(d) > 253:
                raise ValueError(f"FQDN must be ≤253 characters, got {len(d)}")
            cleaned.append(d)
        return cleaned


class DestinationsRemoveInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_id: int = Field(..., description="ID of the destination list")
    destination_ids: list[int] = Field(
        ...,
        description="IDs of the destinations to remove. Max 500 per request.",
        min_length=1,
        max_length=500,
    )


class DuplicateCheckInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    destination_list_ids: list[int] = Field(
        ...,
        description="Two or more destination list IDs to compare for overlapping destinations",
        min_length=2,
    )
    page_limit: Optional[int] = Field(
        default=100,
        description="Max pages to fetch per list (100 destinations/page). Use lower values for a quick scan.",
        ge=1,
        le=2500,
    )


# ---------------------------------------------------------------------------
# Destination List CRUD tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="secure_access_list_destination_lists",
    annotations={
        "title": "List Destination Lists",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def secure_access_list_destination_lists(params: PaginationInput, ctx: Context) -> str:
    """Get all destination lists in the organization.

    Returns list metadata including name, access type, destination counts,
    and per-type breakdowns (domains, URLs, IPv4, IPv6, applications).
    Use this to understand the org's current list landscape and total
    destination usage toward the 250,000 limit.
    """
    try:
        data = await _get_client(ctx).get(
            SCOPE, "destinationlists", params={"page": params.page, "limit": params.limit}
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="secure_access_get_destination_list",
    annotations={
        "title": "Get Destination List",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def secure_access_get_destination_list(params: DestinationListIdInput, ctx: Context) -> str:
    """Get details of a specific destination list by ID.

    Returns the list's name, access type, creation/modification timestamps,
    and destination count metadata.
    """
    try:
        data = await _get_client(ctx).get(SCOPE, f"destinationlists/{params.destination_list_id}")
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="secure_access_create_destination_list",
    annotations={
        "title": "Create Destination List",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def secure_access_create_destination_list(params: DestinationListCreateInput, ctx: Context) -> str:
    """Create a new destination list.

    Optionally provide initial destinations (max 500).  Secure Access requires
    bundleTypeId=2 and isGlobal=false, which are set automatically.
    Access types: allow, block, url_proxy, no_decrypt, warn, none.
    """
    try:
        body: dict = {
            "access": params.access,
            "isGlobal": False,
            "name": params.name,
            "bundleTypeId": 2,
        }
        if params.destinations:
            body["destinations"] = [{"destination": d} for d in params.destinations]
        data = await _get_client(ctx).post(SCOPE, "destinationlists", json_data=body)
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="secure_access_update_destination_list",
    annotations={
        "title": "Update Destination List",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def secure_access_update_destination_list(params: DestinationListUpdateInput, ctx: Context) -> str:
    """Rename a destination list."""
    try:
        data = await _get_client(ctx).patch(
            SCOPE,
            f"destinationlists/{params.destination_list_id}",
            json_data={"name": params.name},
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="secure_access_delete_destination_list",
    annotations={
        "title": "Delete Destination List",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def secure_access_delete_destination_list(params: DestinationListIdInput, ctx: Context) -> str:
    """Delete a destination list by ID. This action cannot be undone."""
    try:
        data = await _get_client(ctx).delete(SCOPE, f"destinationlists/{params.destination_list_id}")
        return compact_json(data) if data else "Destination list deleted successfully."
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Destination CRUD tools (items within a list)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="secure_access_get_destinations",
    annotations={
        "title": "Get Destinations in a List",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def secure_access_get_destinations(params: DestinationsGetInput, ctx: Context) -> str:
    """Get destinations (domains, IPs, URLs) in a specific destination list.

    Returns paginated results with destination value, type, comment, and creation date.
    Use page/limit to iterate through large lists.
    """
    try:
        data = await _get_client(ctx).get(
            SCOPE,
            f"destinationlists/{params.destination_list_id}/destinations",
            params={"page": params.page, "limit": params.limit},
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="secure_access_add_destinations",
    annotations={
        "title": "Add Destinations to List",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def secure_access_add_destinations(params: DestinationsAddInput, ctx: Context) -> str:
    """Add domains, IPs, or URLs to a destination list. Max 500 per request.

    The org-wide limit is 250,000 destinations across all lists.
    URLs on high-volume domains may be rejected — add the domain instead.
    """
    try:
        if params.comment:
            items = [{"destination": d, "comment": params.comment} for d in params.destinations]
        else:
            items = [{"destination": d} for d in params.destinations]
        data = await _get_client(ctx).post(
            SCOPE,
            f"destinationlists/{params.destination_list_id}/destinations",
            json_data=items,
        )
        return compact_json(data)
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="secure_access_remove_destinations",
    annotations={
        "title": "Remove Destinations from List",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def secure_access_remove_destinations(params: DestinationsRemoveInput, ctx: Context) -> str:
    """Remove destinations from a destination list by their IDs. Max 500 per request.

    First use secure_access_get_destinations to find destination IDs,
    then pass those IDs here to remove them.
    """
    try:
        data = await _get_client(ctx).delete(
            SCOPE,
            f"destinationlists/{params.destination_list_id}/destinations/remove",
            json_data=params.destination_ids,
        )
        return compact_json(data) if data else "Destinations removed successfully."
    except Exception as e:
        return format_error(e)


# ---------------------------------------------------------------------------
# Analysis / Intelligence tools — the "250K conundrum" helpers
# ---------------------------------------------------------------------------


@mcp.tool(
    name="secure_access_destination_usage_summary",
    annotations={
        "title": "Destination Usage Summary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def secure_access_destination_usage_summary(ctx: Context) -> str:
    """Get an organization-wide destination usage summary.

    Fetches ALL destination lists and computes:
    - Total destinations across the org vs the 250,000 limit
    - Usage percentage and remaining capacity
    - Per-list breakdown sorted by destination count (largest first)
    - Per-type totals (domains, URLs, IPv4, IPv6, applications)

    Use this as the starting point to understand capacity pressure
    and identify which lists are consuming the most space.
    """
    try:
        client = _get_client(ctx)
        all_lists: list[dict] = []
        page = 1
        while True:
            data = await client.get(SCOPE, "destinationlists", params={"page": page, "limit": 100})
            items = data.get("data", [])
            all_lists.extend(items)
            meta = data.get("meta", {})
            total_lists = meta.get("total", len(items))
            if len(all_lists) >= total_lists or not items:
                break
            page += 1

        total_destinations = 0
        total_domains = 0
        total_urls = 0
        total_ipv4 = 0
        total_ipv6 = 0
        total_apps = 0

        list_summaries = []
        for dl in all_lists:
            m = dl.get("meta", {})
            dest_count = m.get("destinationCount", 0)
            total_destinations += dest_count
            total_domains += m.get("domainCount", 0)
            total_urls += m.get("urlCount", 0)
            total_ipv4 += m.get("ipv4Count", 0)
            total_ipv6 += m.get("ipv6Count", 0)
            total_apps += m.get("applicationCount", 0)

            list_summaries.append(
                {
                    "id": dl.get("id"),
                    "name": dl.get("name"),
                    "access": dl.get("access"),
                    "destinationCount": dest_count,
                    "domainCount": m.get("domainCount", 0),
                    "urlCount": m.get("urlCount", 0),
                    "ipv4Count": m.get("ipv4Count", 0),
                    "ipv6Count": m.get("ipv6Count", 0),
                    "applicationCount": m.get("applicationCount", 0),
                }
            )

        list_summaries.sort(key=lambda x: x["destinationCount"], reverse=True)
        remaining = ORG_DESTINATION_LIMIT - total_destinations
        pct_used = round(total_destinations / ORG_DESTINATION_LIMIT * 100, 1) if ORG_DESTINATION_LIMIT else 0

        summary = {
            "organizationLimit": ORG_DESTINATION_LIMIT,
            "totalDestinations": total_destinations,
            "remaining": remaining,
            "usagePercent": pct_used,
            "totalLists": len(all_lists),
            "typeTotals": {
                "domains": total_domains,
                "urls": total_urls,
                "ipv4": total_ipv4,
                "ipv6": total_ipv6,
                "applications": total_apps,
            },
            "lists": list_summaries,
        }
        return json.dumps(summary, separators=(",", ":"))
    except Exception as e:
        return format_error(e)


@mcp.tool(
    name="secure_access_find_duplicate_destinations",
    annotations={
        "title": "Find Duplicate Destinations Across Lists",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def secure_access_find_duplicate_destinations(params: DuplicateCheckInput, ctx: Context) -> str:
    """Compare two or more destination lists and find overlapping entries.

    Iterates through each list's destinations (up to page_limit pages of 100)
    and identifies destinations that appear in multiple lists.  Returns:
    - Number of unique destinations per list
    - Duplicate destinations with the list IDs they appear in
    - Total duplicates and potential savings if consolidated

    This helps identify redundant entries that waste space against the
    250,000 org-wide limit.  Consider removing duplicates from less
    critical lists or consolidating into fewer lists.

    WARNING: For very large lists this may take time — use a lower page_limit
    for a quick sample scan.
    """
    try:
        client = _get_client(ctx)
        list_destinations: dict[int, set[str]] = {}

        for list_id in params.destination_list_ids:
            destinations: set[str] = set()
            page = 1
            while page <= (params.page_limit or 100):
                data = await client.get(
                    SCOPE,
                    f"destinationlists/{list_id}/destinations",
                    params={"page": page, "limit": 100},
                )
                items = data.get("data", [])
                if not items:
                    break
                for item in items:
                    dest = item.get("destination", "").lower().strip()
                    if dest:
                        destinations.add(dest)
                meta = data.get("meta", {})
                total = meta.get("total", 0)
                if len(destinations) >= total or not items:
                    break
                page += 1
            list_destinations[list_id] = destinations

        dest_to_lists: dict[str, list[int]] = {}
        for list_id, dests in list_destinations.items():
            for d in dests:
                dest_to_lists.setdefault(d, []).append(list_id)

        duplicates = {d: lists for d, lists in dest_to_lists.items() if len(lists) > 1}

        duplicate_count = sum(len(lists) - 1 for lists in duplicates.values())

        duplicate_entries = [{"destination": d, "inLists": lists} for d, lists in sorted(duplicates.items())]

        result = {
            "listsCompared": [
                {"listId": lid, "uniqueDestinations": len(dests)} for lid, dests in list_destinations.items()
            ],
            "duplicateDestinations": len(duplicates),
            "duplicateEntries": duplicate_count,
            "potentialSavings": duplicate_count,
            "duplicates": duplicate_entries[:1000],
            "truncated": len(duplicate_entries) > 1000,
        }
        return json.dumps(result, separators=(",", ":"))
    except Exception as e:
        return format_error(e)
