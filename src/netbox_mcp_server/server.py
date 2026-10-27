import argparse
import asyncio
import hashlib
import hmac
import logging
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Annotated, Any, NoReturn
from urllib.parse import urlparse

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from pydantic import Field, SecretStr
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from netbox_mcp_server.config import Settings, configure_logging
from netbox_mcp_server.netbox_client import (
    BRANCHABLE_ENDPOINT_PREFIXES,
    BRANCHES_ENDPOINT,
    NetBoxRestClient,
    is_branchable_endpoint,
)
from netbox_mcp_server.netbox_types import NETBOX_OBJECT_TYPES


def parse_cli_args() -> dict[str, Any]:
    """
    Parse command-line arguments for configuration overrides.

    Returns:
        dict of configuration overrides (only includes explicitly set values)
    """
    parser = argparse.ArgumentParser(
        description="NetBox MCP Server - Model Context Protocol server for NetBox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Core NetBox settings
    parser.add_argument(
        "--netbox-url",
        type=str,
        help="Base URL of the NetBox instance (e.g., https://netbox.example.com/)",
    )
    parser.add_argument(
        "--netbox-token",
        type=str,
        help="API token for NetBox authentication",
    )

    # Transport settings
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "http"],
        help="MCP transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        type=str,
        help="Host address for HTTP server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Port for HTTP server (default: 8000)",
    )
    parser.add_argument(
        "--cors-origins",
        action="append",
        help="CORS origins (repeat flag). Use * to allow any origin (default: none)",
    )
    parser.add_argument(
        "--mcp-auth-token",
        type=str,
        help=(
            "Bearer token required on the HTTP transport endpoint "
            "(prefer the MCP_AUTH_TOKEN env var; default: none)"
        ),
    )

    # Security settings
    ssl_group = parser.add_mutually_exclusive_group()
    ssl_group.add_argument(
        "--verify-ssl",
        action="store_true",
        dest="verify_ssl",
        default=None,
        help="Verify SSL certificates (default)",
    )
    ssl_group.add_argument(
        "--no-verify-ssl",
        action="store_false",
        dest="verify_ssl",
        help="Disable SSL certificate verification (not recommended)",
    )

    # Plugin discovery settings
    parser.add_argument(
        "--enable-plugin-discovery",
        action="store_true",
        default=None,
        dest="enable_plugin_discovery",
        help="Auto-discover plugin object types from NetBox at startup",
    )
    parser.add_argument(
        "--enable-write",
        action="store_true",
        default=None,
        dest="enable_write",
        help="Expose create/update/delete tools (requires a write-capable token)",
    )
    parser.add_argument(
        "--netbox-username",
        type=str,
        dest="netbox_username",
        help="Username of the API token's user (needed for branch ownership on NetBox < 4.5)",
    )
    parser.add_argument(
        "--allow-branch-events",
        action="store_true",
        default=None,
        dest="allow_branch_events",
        help="Let branch writes proceed while event rules or notifications would fire on them",
    )
    parser.add_argument(
        "--allowed-branch-event-rule",
        action="append",
        dest="allowed_branch_event_rules",
        metavar="ID",
        help="ID of an event rule that may fire on branch changes (repeat for several)",
    )
    parser.add_argument(
        "--unrestricted-token",
        action="store_true",
        default=None,
        dest="unrestricted_token",
        help="Confirm the API token's user can view everything unconstrained (e.g. a superuser)",
    )
    parser.add_argument(
        "--allow-foreign-branches",
        action="store_true",
        default=None,
        dest="allow_foreign_branches",
        help="Let write tools target branches owned by other users",
    )

    # Observability settings
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity level (default: INFO)",
    )

    args: argparse.Namespace = parser.parse_args()

    overlay: dict[str, Any] = {}
    if args.netbox_url is not None:
        overlay["netbox_url"] = args.netbox_url
    if args.netbox_token is not None:
        overlay["netbox_token"] = args.netbox_token
    if args.transport is not None:
        overlay["transport"] = args.transport
    if args.host is not None:
        overlay["host"] = args.host
    if args.port is not None:
        overlay["port"] = args.port
    if args.cors_origins is not None:
        overlay["cors_origins"] = args.cors_origins
    if args.mcp_auth_token is not None:
        overlay["mcp_auth_token"] = args.mcp_auth_token
    if args.verify_ssl is not None:
        overlay["verify_ssl"] = args.verify_ssl
    if args.enable_plugin_discovery is not None:
        overlay["enable_plugin_discovery"] = args.enable_plugin_discovery
    if args.enable_write is not None:
        overlay["enable_write"] = args.enable_write
    if args.netbox_username is not None:
        overlay["netbox_username"] = args.netbox_username
    if args.allow_branch_events is not None:
        overlay["allow_branch_events"] = args.allow_branch_events
    if args.allowed_branch_event_rules is not None:
        overlay["allowed_branch_event_rules"] = args.allowed_branch_event_rules
    if args.unrestricted_token is not None:
        overlay["unrestricted_token"] = args.unrestricted_token
    if args.allow_foreign_branches is not None:
        overlay["allow_foreign_branches"] = args.allow_foreign_branches
    if args.log_level is not None:
        overlay["log_level"] = args.log_level

    return overlay


class BearerTokenVerifier(TokenVerifier):
    """Constant-time single-secret bearer check for the HTTP transport.

    This is a FastMCP Resource Server verifier: it only validates an incoming
    'Authorization: Bearer <token>' against one configured secret and issues no
    tokens itself. FastMCP mounts its own auth middleware around this, returning
    401 (+ WWW-Authenticate) for unauthenticated requests to the MCP endpoint.
    """

    def __init__(self, secret: str) -> None:
        super().__init__()
        # Digest, not raw secret: lets verify_token compare in constant time.
        self._secret_digest = hashlib.sha256(secret.encode("utf-8")).digest()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an AccessToken for a matching bearer, or None to reject."""
        if not token:
            return None
        # Hash both sides: compare_digest raises TypeError on a non-ASCII str, and
        # the bearer is attacker-controlled (header bytes decode as latin-1).
        token_digest = hashlib.sha256(token.encode("utf-8", "surrogatepass")).digest()
        if not hmac.compare_digest(token_digest, self._secret_digest):
            return None
        return AccessToken(token=token, client_id="netbox-mcp-server", scopes=[])


def build_http_auth(token: SecretStr | None) -> TokenVerifier | None:
    """
    Build the HTTP transport auth provider from an optional bearer token.

    Returns a verifier that makes FastMCP reject unauthenticated requests to the
    MCP endpoint with 401, or None when no token is configured. Empty or
    whitespace-only values are normalized to None upstream in Settings, so a
    non-None token here is always a real secret.

    Args:
        token: Optional bearer token to require on the HTTP transport endpoint

    Returns:
        A TokenVerifier requiring the token, or None when no token is set
    """
    if token is None:
        return None
    return BearerTokenVerifier(token.get_secret_value())


# Default object types for global search
DEFAULT_SEARCH_TYPES = [
    "dcim.device",  # Most common search target
    "dcim.site",  # Site names frequently searched
    "ipam.ipaddress",  # IP searches very common
    "dcim.interface",  # Interface names/descriptions
    "dcim.rack",  # Rack identifiers
    "ipam.vlan",  # VLAN names/IDs
    "circuits.circuit",  # Circuit identifiers
    "virtualization.virtualmachine",  # VM names
]

mcp = FastMCP("NetBox")
netbox = None


def validate_filters(filters: dict) -> None:
    """
    Validate that filters don't use unsupported lookup suffixes or multi-hop
    relationship traversal.

    NetBox API does not support:
    - __in suffix (pass a list as the field value instead: {'id': [1, 2, 3]})
    - nested relationship queries like device__site_id or interface__device__site

    Valid patterns:
    - Direct field filters: site_id, name, status
    - List values for multi-value filters: {'site_id': [1, 2]}
    - Lookup expressions supported by the target NetBox field: name__ic, id__gt

    Args:
        filters: Dictionary of filter parameters

    Raises:
        ValueError: If filter uses an unsupported lookup suffix or multi-hop
                    relationship traversal
    """
    valid_suffixes = {
        "n",
        "ic",
        "nic",
        "isw",
        "nisw",
        "iew",
        "niew",
        "ie",
        "nie",
        "empty",
        "regex",
        "iregex",
        "lt",
        "lte",
        "gt",
        "gte",
    }

    for filter_name in filters:
        # Skip special parameters
        if filter_name in ("limit", "offset", "fields", "q"):
            continue

        if "__" not in filter_name:
            continue

        parts = filter_name.split("__")

        if len(parts) == 2 and parts[-1] == "in":
            base = parts[0]
            raise ValueError(
                f"Invalid filter '{filter_name}': '__in' lookup suffix is not "
                "supported and may be silently ignored by NetBox. "
                f"Pass a list to the field directly instead: {{'{base}': [1, 2, 3]}}"
            )

        # Allow field__suffix pattern (e.g., name__ic, id__gt)
        if len(parts) == 2 and parts[-1] in valid_suffixes:
            continue
        # Block multi-hop patterns and invalid suffixes
        if len(parts) >= 2:
            raise ValueError(
                f"Invalid filter '{filter_name}': Multi-hop relationship "
                f"traversal or invalid lookup suffix not supported. Use direct field filters like "
                f"'site_id' or two-step queries."
            )


@mcp.tool(
    description="""
    Get objects from NetBox based on their type and filters

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        filters: dict of filters to apply to the API call based on the NetBox API filtering options

                FILTER RULES:
                Valid: Direct fields like {'site_id': 1, 'name': 'router', 'status': 'active'}
                Valid: Field-supported lookups like {'name__ic': 'switch', 'vid__gte': 100}
                Invalid: Multi-hop like {'device__site_id': 1} - NOT supported

                Lookup suffixes: n, ic, nic, isw, nisw, iew, niew, ie, nie,
                                 empty, regex, iregex, lt, lte, gt, gte
                Lookup support is field-specific. NetBox may silently ignore unsupported
                lookups and return overly broad results. The '__in' suffix is not supported
                and is rejected by this tool. For multiple values, pass a list as the field
                value directly: {'vminterface_id': [621493, 631527]} or {'id': [1, 2, 3]}.

                Two-step pattern for cross-relationship queries:
                  sites = netbox_get_objects('dcim.site', {'name': 'NYC'})
                  netbox_get_objects('dcim.device', {'site_id': sites[0]['id']})

        fields: Optional list of specific fields to return
                **IMPORTANT: ALWAYS USE THIS PARAMETER TO MINIMIZE TOKEN USAGE**
                Field filtering significantly reduces response payload and is critical for performance.

                - None or [] = returns all fields (NOT RECOMMENDED - use only when you need complete objects)
                - ['id', 'name'] = returns only specified fields (RECOMMENDED)

                Examples:
                - For counting: ['id'] (minimal payload)
                - For listings: ['id', 'name', 'status']
                - For IP addresses: ['address', 'dns_name', 'description']

                Uses NetBox's native field filtering via ?fields= parameter.
                **Always specify only the fields you actually need.**

        brief: returns only a minimal representation of each object in the response.
               This is useful when you need only a list of available objects without any related data.

        limit: Maximum results to return (default 5, max 100)
               Start with default, increase only if needed

        offset: Skip this many results for pagination (default 0)
                Example: offset=0 (page 1), offset=5 (page 2), offset=10 (page 3)

        ordering: Fields used to determine sort order of results.
                  Field names may be prefixed with '-' to invert the sort order.
                  Multiple fields may be specified with a list of strings.

                  Examples:
                  - 'name' (alphabetical by name)
                  - '-id' (ordered by ID descending)
                  - ['facility', '-name'] (by facility, then by name descending)
                  - None, '' or [] (default NetBox ordering)

        branch: Optional NetBox Branching branch (name or schema_id) to read from.
                Omit to read from main.


    Returns:
        Paginated response dict with the following structure:
            - count: Total number of objects matching the query
                     ALWAYS REFER TO THIS FIELD FOR THE TOTAL NUMBER OF OBJECTS MATCHING THE QUERY
            - next: URL to next page (or null if no more pages)
                    ALWAYS REFER TO THIS FIELD FOR THE NEXT PAGE OF RESULTS
            - previous: URL to previous page (or null if on first page)
                        ALWAYS REFER TO THIS FIELD FOR THE PREVIOUS PAGE OF RESULTS
            - results: Array of objects for this page
                       ALWAYS REFER TO THIS FIELD FOR THE OBJECTS ON THIS PAGE

    ENSURE YOU ARE AWARE THE RESULTS ARE PAGINATED BEFORE PROVIDING RESPONSE TO THE USER.

    Valid object_type values:

    """
    + "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
    + """

    See NetBox API documentation for filtering options for each object type.
    """
)
def netbox_get_objects(
    object_type: str,
    filters: dict,
    fields: list[str] | None = None,
    brief: bool = False,
    limit: Annotated[int, Field(default=5, ge=1, le=100)] = 5,
    offset: Annotated[int, Field(default=0, ge=0)] = 0,
    ordering: str | list[str] | None = None,
    branch: str | None = None,
):
    """
    Get objects from NetBox based on their type and filters
    """
    # Validate object_type exists in mapping
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    # Validate filter patterns
    validate_filters(filters)

    # Get API endpoint and fallback from mapping
    endpoint, fallback = _get_endpoint_info(object_type)

    # Build params with pagination (parameters override filters dict)
    params = filters.copy()
    params["limit"] = limit
    params["offset"] = offset

    if fields:
        params["fields"] = ",".join(fields)

    if brief:
        params["brief"] = "1"

    if ordering:
        if isinstance(ordering, list):
            ordering = ",".join(ordering)
        if ordering.strip() != "":
            params["ordering"] = ordering

    return _read(branch, endpoint, params=params, fallback_endpoint=fallback)


@mcp.tool
def netbox_get_object_by_id(
    object_type: str,
    object_id: int,
    fields: list[str] | None = None,
    brief: bool = False,
    branch: str | None = None,
):
    """
    Get detailed information about a specific NetBox object by its ID.

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        object_id: The numeric ID of the object
        fields: Optional list of specific fields to return
                **IMPORTANT: ALWAYS USE THIS PARAMETER TO MINIMIZE TOKEN USAGE**
                Field filtering reduces response payload by 80-90% and is critical for performance.

                - None or [] = returns all fields (NOT RECOMMENDED - use only when you need complete objects)
                - ['id', 'name'] = returns only specified fields (RECOMMENDED)

                Examples:
                - For basic info: ['id', 'name', 'status']
                - For devices: ['id', 'name', 'status', 'site']
                - For IP addresses: ['address', 'dns_name', 'vrf', 'status']

                Uses NetBox's native field filtering via ?fields= parameter.
                **Always specify only the fields you actually need.**
        brief: returns only a minimal representation of the object in the response.
               This is useful when you need only a summary of the object without any related data.
        branch: Optional NetBox Branching branch (name or schema_id) to read from.
                Omit to read from main.

    Returns:
        Object dict (complete or with only requested fields based on fields parameter)
    """
    # Validate object_type exists in mapping
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    # Get API endpoint and fallback from mapping
    endpoint, fallback = _get_endpoint_info(object_type)
    full_endpoint = f"{endpoint}/{object_id}"
    full_fallback = f"{fallback}/{object_id}" if fallback else None

    params = {}
    if fields:
        params["fields"] = ",".join(fields)

    if brief:
        params["brief"] = "1"

    return _read(branch, full_endpoint, params=params, fallback_endpoint=full_fallback)


@mcp.tool
def netbox_get_changelogs(filters: dict, branch: str | None = None):
    """
    Get object change records (changelogs) from NetBox based on filters.

    Args:
        filters: dict of filters to apply to the API call based on the NetBox API filtering options
        branch: Optional NetBox Branching branch (name or schema_id) to read from.
                Omit to read from main.

    Returns:
        Paginated response dict with the following structure:
            - count: Total number of changelog entries matching the query
                     ALWAYS REFER TO THIS FIELD FOR THE TOTAL NUMBER OF CHANGELOG ENTRIES MATCHING THE QUERY
            - next: URL to next page (or null if no more pages)
                    ALWAYS REFER TO THIS FIELD FOR THE NEXT PAGE OF RESULTS
            - previous: URL to previous page (or null if on first page)
                        ALWAYS REFER TO THIS FIELD FOR THE PREVIOUS PAGE OF RESULTS
            - results: Array of changelog entries for this page
                       ALWAYS REFER TO THIS FIELD FOR THE CHANGELOG ENTRIES ON THIS PAGE

    Filtering options include:
    - user_id: Filter by user ID who made the change
    - user: Filter by username who made the change
    - changed_object_type_id: Filter by numeric ContentType ID (e.g., 21 for dcim.device)
                              Note: This expects a numeric ID, not an object type string
    - changed_object_id: Filter by ID of the changed object
    - object_repr: Filter by object representation (usually contains object name)
    - action: Filter by action type (created, updated, deleted)
    - time_before: Filter for changes made before a given time (ISO 8601 format)
    - time_after: Filter for changes made after a given time (ISO 8601 format)
    - q: Search term to filter by object representation

    Examples:
    To find all changes made to a specific object by ID:
    {"changed_object_id": 123}

    To find changes by object name pattern:
    {"object_repr": "router-01"}

    To find all deletions in the last 24 hours:
    {"action": "delete", "time_after": "2023-01-01T00:00:00Z"}

    Each changelog entry contains:
    - id: The unique identifier of the changelog entry
    - user: The user who made the change
    - user_name: The username of the user who made the change
    - request_id: The unique identifier of the request that made the change
    - action: The type of action performed (created, updated, deleted)
    - changed_object_type: The type of object that was changed
    - changed_object_id: The ID of the object that was changed
    - object_repr: String representation of the changed object
    - object_data: The object's data after the change (null for deletions)
    - object_data_v2: Enhanced data representation
    - prechange_data: The object's data before the change (null for creations)
    - postchange_data: The object's data after the change (null for deletions)
    - time: The timestamp when the change was made
    """
    endpoint = "core/object-changes"

    return _read(branch, endpoint, params=filters)


@mcp.tool(
    description="""
    Perform global search across NetBox infrastructure.

    Searches names, descriptions, IP addresses, serial numbers, asset tags,
    and other key fields across multiple object types.

    Args:
        query: Search term (device names, IPs, serial numbers, hostnames, site names)
               Examples: 'switch01', '192.168.1.1', 'NYC-DC1', 'SN123456'
        object_types: Limit search to specific types (optional)
                     Default: ["""
    + "', '".join(DEFAULT_SEARCH_TYPES)
    + """]
                     Examples: ['dcim.device', 'ipam.ipaddress', 'dcim.site']
        fields: Optional list of specific fields to return (reduces response size) IT IS STRONGLY RECOMMENDED TO USE THIS PARAMETER TO MINIMIZE TOKEN USAGE.
                - None or [] = returns all fields (no filtering)
                - ['id', 'name'] = returns only specified fields
                Examples: ['id', 'name', 'status'], ['address', 'dns_name']
                Uses NetBox's native field filtering via ?fields= parameter
        limit: Max results per object type (default 5, max 100)
        branch: Optional NetBox Branching branch (name or schema_id) to search in.
                Omit to search main. Use this to confirm changes staged in a branch.

    Returns:
        Dictionary with object_type keys and list of matching objects.
        All searched types present in result (empty list if no matches).

    Example:
        # Search for anything matching "switch"
        results = netbox_search_objects('switch')
        # Returns: {
        #   'dcim.device': [{'id': 1, 'name': 'switch-01', ...}],
        #   'dcim.site': [],
        #   ...
        # }

        # Search for IP address
        results = netbox_search_objects('192.168.1.100')
        # Returns: {
        #   'ipam.ipaddress': [{'id': 42, 'address': '192.168.1.100/24', ...}],
        #   ...
        # }

        # Limit search to specific types with field projection
        results = netbox_search_objects(
            'NYC',
            object_types=['dcim.site', 'dcim.location'],
            fields=['id', 'name', 'status']
        )
    """
)
def netbox_search_objects(
    query: str,
    object_types: list[str] | None = None,
    fields: list[str] | None = None,
    limit: Annotated[int, Field(default=5, ge=1, le=100)] = 5,
    branch: str | None = None,
) -> dict[str, list[dict]]:
    """
    Perform global search across NetBox infrastructure.
    """
    search_types = object_types if object_types is not None else DEFAULT_SEARCH_TYPES

    # Validate all object types exist in mapping
    for obj_type in search_types:
        if obj_type not in NETBOX_OBJECT_TYPES:
            valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
            raise ValueError(f"Invalid object_type '{obj_type}'. Must be one of:\n{valid_types}")

    results = {obj_type: [] for obj_type in search_types}
    headers = _branch_headers(branch)
    branch_errors = False

    # Build results dictionary (error-resilient)
    for obj_type in search_types:
        try:
            endpoint, fallback = _get_endpoint_info(obj_type)
            response = netbox.get(
                endpoint,
                params={
                    "q": query,
                    "limit": limit,
                    "fields": ",".join(fields) if fields else None,
                },
                fallback_endpoint=fallback,
                headers=headers,
            )
            # Extract results array from paginated response
            results[obj_type] = response.get("results", [])
        except httpx.HTTPStatusError as e:
            # Per-type errors are skipped as on main; in a branch, one that may mean the
            # branch became unusable (e.g. merged mid-search) is re-checked below
            branch_errors = branch_errors or bool(branch and _is_branch_error(e))
            continue
        except Exception:  # noqa: S112 - intentional error-resilient search
            # Continue searching other types if one fails
            # results[obj_type] already has empty list
            continue

    if branch_errors:
        # Empty results would wrongly suggest no matches if the branch became unusable
        # during the search; checked once, after every type was tried
        _recheck_branch(branch)
    return results


def _validate_object_type(object_type: str) -> str:
    """Validate object_type and return its primary API endpoint."""
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")
    endpoint, _ = _get_endpoint_info(object_type)
    return endpoint


def _validate_writable_type(object_type: str) -> str:
    """Validate that object_type can be written inside a branch; return its endpoint."""
    endpoint = _validate_object_type(object_type)
    if netbox.is_writable_endpoint(endpoint):
        return endpoint
    if is_branchable_endpoint(endpoint):
        # Passed the static allow-list, but NetBox reported its branchable models at
        # startup and this one isn't among them
        raise ValueError(
            f"NetBox reports that '{object_type}' does not support branching, so it "
            "cannot be written (changes would hit main)."
        )
    writable = ", ".join(p.rstrip("/") for p in BRANCHABLE_ENDPOINT_PREFIXES)
    raise ValueError(
        f"'{object_type}' is not isolated by NetBox Branching (changes would hit main), "
        f"so it cannot be written. Writable endpoints are at most: {writable}"
    )


MAX_ERROR_BODY = 2000


def _raise_with_body(e: httpx.HTTPStatusError) -> NoReturn:
    """Re-raise an HTTP error including NetBox's response body (field validation errors)."""
    body = e.response.text
    if len(body) > MAX_ERROR_BODY:
        body = body[:MAX_ERROR_BODY] + f"... [truncated {len(body) - MAX_ERROR_BODY} chars]"
    raise ValueError(
        f"NetBox returned {e.response.status_code} for {e.request.method} {e.request.url}: {body}"
    ) from e


def _raise_branching_error(e: httpx.HTTPStatusError) -> NoReturn:
    """Re-raise an error from the branches endpoint, explaining a missing plugin."""
    if e.response.status_code == 404:
        raise ValueError(
            "The netbox-branching plugin is not available on this NetBox instance"
        ) from e
    _raise_with_body(e)


BRANCH_FIELDS = "id,name,schema_id,status,owner"

# Resolved branches are cached briefly to avoid a lookup on every write. Only ready
# branches are cached; a stale "ready" status is safe because the plugin itself rejects
# writes to a branch that is not ready.
BRANCH_CACHE_TTL = 60.0

# NetBox Branching schema IDs are eight lowercase alphanumeric characters. Inputs of this
# shape are matched by both name and schema ID, so a name can never shadow another
# branch's schema ID. The column holds at most 8 characters in any format.
SCHEMA_ID_MAX_LENGTH = 8
SCHEMA_ID_PATTERN = re.compile(rf"[a-z0-9]{{{SCHEMA_ID_MAX_LENGTH}}}")

# How long a failed lookup of the token's user is remembered before retrying
USER_LOOKUP_RETRY_SECONDS = 60.0

# Each branch is a full copy of the database schema, so cap how many a user keeps open.
# Branches in these statuses can't be used again and don't count toward the cap.
MAX_OPEN_BRANCHES = 10
CLOSED_BRANCH_STATUSES = frozenset({"merged", "archived", "failed"})


@dataclass
class BranchPolicy:
    """Branch write policy and per-token lookup state, created from Settings in main().

    Attributes:
        write_enabled: Whether the write tools are exposed (ENABLE_WRITE)
        allow_foreign_branches: Whether writes may target branches owned by other users
        allow_branch_events: Whether writes may proceed while event rules would fire on them
        allowed_event_rules: IDs of event rules that may fire on branch changes
        unrestricted_token: Whether the token's user can view everything without
            permission constraints (UNRESTRICTED_TOKEN)
        branchable_types: Object types NetBox reported as branchable at startup, mapped
            to their API endpoints (None without REST API); None if it couldn't report them
        configured_username: NETBOX_USERNAME, the token's user on NetBox < 4.5
        current_user_id: Cached ID of the API token's user, once known
        current_username: Cached username of the API token's user, once known
        user_lookup_error: (time, message) of the last failed user lookup, if any
        cache: Ready branches by lookup string, as (time, branch) pairs
    """

    write_enabled: bool = False
    allow_foreign_branches: bool = False
    allow_branch_events: bool = False
    allowed_event_rules: frozenset[int] = frozenset()
    unrestricted_token: bool = False
    branchable_types: dict[str, str | None] | None = None
    configured_username: str | None = None
    current_user_id: int | None = None
    current_username: str | None = None
    user_lookup_error: tuple[float, str] | None = None
    cache: dict[str, tuple[float, dict]] = field(default_factory=dict)


branch_policy = BranchPolicy()


def _branch_status(found: dict) -> str | None:
    """Return a branch's status value (the API may return a {value, label} dict)."""
    status = found.get("status")
    return status.get("value") if isinstance(status, dict) else status


def _get_all(
    endpoint: str,
    params: dict[str, Any],
    headers: dict[str, str] | None = None,
    client: NetBoxRestClient | None = None,
    fallback_endpoint: str | None = None,
) -> list[dict]:
    """Every result of a NetBox list request, paged by id (keyset pagination).

    Rows are ordered by id and each page asks for ids above the last one received, so a
    row deleted or added mid-read can't shift later rows past a page boundary (offset
    paging would skip one). NetBox may cap the page size (MAX_PAGE_SIZE) below the
    requested limit, so pages are followed until "next" is empty. Every row must carry
    an "id". A page that doesn't advance (e.g. an endpoint or proxy ignoring the id__gt
    filter) is refused, since the callers' safety checks must not pass on a partial
    list.

    Args:
        endpoint: API endpoint, e.g. "dcim/devices"
        params: Query parameters (filters, fields, limit); ordering and id__gt are added
        headers: Optional extra request headers (e.g. X-NetBox-Branch)
        client: NetBox client to use (default: the server's client)
        fallback_endpoint: Optional endpoint to try if the primary returns 404

    Raises:
        httpx.HTTPStatusError: If NetBox returns an error status.
        ValueError: If paging doesn't advance, so the full list can't be read.
    """
    client = client or netbox
    results: list[dict] = []
    after: int | None = None
    while True:
        page_params = {**params, "ordering": "id"}
        if after is not None:
            page_params["id__gt"] = after
        page = client.get(
            endpoint, params=page_params, headers=headers, fallback_endpoint=fallback_endpoint
        )
        batch = list(page.get("results") or [])
        results.extend(batch)
        if not page.get("next") or not batch:
            return results
        last = max(row["id"] for row in batch)
        if after is not None and last <= after:
            raise ValueError(
                f"Paging /api/{endpoint}/ by id didn't advance (is the 'id__gt' filter being "
                "ignored?), so the full list can't be read; refusing."
            )
        after = last


def _find_branches(params: dict) -> list[dict]:
    """Fetch every page of branches matching params (only the fields needed to resolve)."""
    return _get_all(BRANCHES_ENDPOINT, {**params, "fields": BRANCH_FIELDS, "limit": 1000})


def _lookup_branch(branch: str) -> dict:
    """Find the single branch whose name or schema ID is exactly `branch`."""
    cached = branch_policy.cache.get(branch)
    if cached and time.monotonic() - cached[0] < BRANCH_CACHE_TTL:
        return cached[1]
    try:
        # netbox-branching has no schema_id filter, so input shaped like a schema ID is
        # matched against every branch, by name and schema ID at once: a branch *named*
        # like another branch's schema ID is then ambiguous instead of winning. Other
        # input is looked up by name (filtered server-side, matched exactly here so an
        # ignored filter can never select the wrong branch), and if no branch has that
        # name and it is short enough, against every branch in case it is a schema ID of
        # another format.
        candidates: list[dict] = []
        if not SCHEMA_ID_PATTERN.fullmatch(branch):
            candidates = _find_branches({"name": branch})
        if len(branch) <= SCHEMA_ID_MAX_LENGTH and not any(
            b.get("name") == branch for b in candidates
        ):
            candidates = _find_branches({})
        matches = {b["id"]: b for b in candidates if branch in (b.get("name"), b.get("schema_id"))}
    except httpx.HTTPStatusError as e:
        _raise_branching_error(e)
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one branch matching '{branch}' by name or schema_id, "
            f"found {len(matches)}. Use netbox_list_branches to see available branches."
        )
    found = next(iter(matches.values()))
    if _branch_status(found) == "ready":
        branch_policy.cache[branch] = (time.monotonic(), found)
    return found


def _get_token_user() -> tuple[int | None, str | None]:
    """Return (id, username) of the NetBox user that owns the API token (cached).

    NetBox 4.5+ reports this at /api/authentication-check/. Older versions that
    netbox-branching still supports (4.1-4.4) have no such endpoint, so the operator
    names the user with NETBOX_USERNAME; the id is then unknown until this server creates
    a branch, whose recorded owner is authoritative (see _learn_owner).

    A definitive failure (HTTP error status or unexpected response) is remembered for
    USER_LOOKUP_RETRY_SECONDS so every call doesn't repeat a request that is known to fail.
    Network errors are not remembered.

    Returns:
        (user_id, username); user_id is None when only NETBOX_USERNAME is known.

    Raises:
        ValueError: If the token's user can't be determined.
    """
    if branch_policy.current_user_id is not None or branch_policy.current_username:
        return branch_policy.current_user_id, branch_policy.current_username
    failed = branch_policy.user_lookup_error
    if failed and time.monotonic() - failed[0] < USER_LOOKUP_RETRY_SECONDS:
        raise ValueError(failed[1])
    configured = branch_policy.configured_username
    try:
        user = netbox.get("authentication-check")
        user_id = user["id"]
        if not isinstance(user_id, int):
            raise TypeError(f"unexpected user id {user_id!r}")
    except httpx.RequestError as e:
        # Network trouble (timeout, reset) is transient: don't remember it, retry next call
        raise ValueError(
            f"Couldn't reach NetBox to look up the API token's user ({type(e).__name__}); "
            "try again."
        ) from e
    except (httpx.HTTPStatusError, ValueError, KeyError, TypeError) as e:
        missing = isinstance(e, httpx.HTTPStatusError) and e.response.status_code == 404
        if missing and configured:
            # NetBox < 4.5: no way to ask, so trust the operator's NETBOX_USERNAME
            branch_policy.current_username = configured
            return None, configured
        if missing:
            message = (
                "Can't determine the API token's user: this NetBox has no "
                "/api/authentication-check/ (added in NetBox 4.5), so branch ownership "
                "can't be checked. Set NETBOX_USERNAME to the token's username, or set "
                "ALLOW_FOREIGN_BRANCHES."
            )
        else:
            reason = (
                f"returned {e.response.status_code}"
                if isinstance(e, httpx.HTTPStatusError)
                else f"failed: {type(e).__name__}"
            )
            message = (
                f"Can't determine the API token's user (GET /api/authentication-check/ "
                f"{reason}), so branch ownership can't be checked. Allow that endpoint "
                "through the proxy, set NETBOX_USERNAME, or set ALLOW_FOREIGN_BRANCHES."
            )
        branch_policy.user_lookup_error = (time.monotonic(), message)
        raise ValueError(message) from e
    username = user.get("username")
    if configured and username and configured != username:
        logging.getLogger(__name__).warning(
            f"NETBOX_USERNAME is '{configured}' but the API token belongs to '{username}'; "
            "using the token's user"
        )
    branch_policy.current_user_id = user_id
    branch_policy.current_username = username
    return user_id, username


def _owned_by_token(found: dict) -> bool:
    """Whether a branch is owned by the API token's user."""
    user_id, username = _get_token_user()
    owner = found.get("owner") or {}
    if user_id is not None:
        return owner.get("id") == user_id
    return username is not None and owner.get("username") == username


def _learn_owner(created: dict) -> str | None:
    """Adopt the owner NetBox recorded on a branch this server just created.

    The owner of a branch created with the API token is the token's user, so it replaces
    a NETBOX_USERNAME guess (NetBox < 4.5) with an authoritative id and username.

    Args:
        created: The branch returned by the create request

    Returns:
        A warning if NETBOX_USERNAME named a different user, else None.
    """
    owner = created.get("owner") or {}
    if not isinstance(owner.get("id"), int) or branch_policy.current_user_id is not None:
        return None
    guessed = branch_policy.current_username
    branch_policy.current_user_id = owner["id"]
    branch_policy.current_username = owner.get("username")
    if guessed and owner.get("username") and guessed != owner.get("username"):
        warning = (
            f"NETBOX_USERNAME is '{guessed}' but the API token belongs to "
            f"'{owner.get('username')}'; ownership checks now use '{owner.get('username')}'. "
            "Fix NETBOX_USERNAME."
        )
        logging.getLogger(__name__).warning(warning)
        return warning
    return None


def _resolve_branch(branch: str, for_write: bool = True) -> dict:
    """
    Look up a NetBox Branching branch by name or schema ID.

    Raises ValueError unless exactly one matching branch exists and it is "ready", and,
    for writes, unless it is owned by the token's user (or ALLOW_FOREIGN_BRANCHES is set).
    The ready check is a pre-check for clear errors: the branch can still change state
    before the write lands. The authoritative guard is the plugin itself, which fails any
    request whose X-NetBox-Branch names a branch that is not ready (netbox-branching 1.1.3
    answers HTTP 500 rather than its intended 400 "Selected branch is not ready.").
    """
    if not branch or not branch.strip():
        raise ValueError("A branch is required; changes are never written to main")
    found = _lookup_branch(branch.strip())
    status = _branch_status(found)
    if status != "ready":
        raise ValueError(
            f"Branch '{found['name']}' has status '{status}'; it must be 'ready' to accept changes"
        )
    if not found.get("schema_id"):
        raise ValueError(f"Branch '{found['name']}' has no schema_id")
    if for_write and not branch_policy.allow_foreign_branches and not _owned_by_token(found):
        owner = found.get("owner") or {}
        raise ValueError(
            f"Branch '{found['name']}' belongs to "
            f"'{owner.get('display') or owner.get('username') or 'nobody'}', not to this "
            "token's user. Create your own branch with netbox_create_branch."
        )
    return found


def _branch_schema_id(branch: str) -> str:
    """Return the schema ID of a ready branch this token may write to."""
    return _resolve_branch(branch)["schema_id"]


def _branch_headers(branch: str | None) -> dict[str, str] | None:
    """Return the X-NetBox-Branch header for reading from a ready branch, or None for main."""
    if not branch:
        return None
    return {"X-NetBox-Branch": _resolve_branch(branch, for_write=False)["schema_id"]}


def _is_branch_error(e: httpx.HTTPStatusError) -> bool:
    """Whether an error reading a branch may mean the branch itself is unusable.

    netbox-branching 1.1.3 answers 500 for a branch that isn't ready (e.g. merged while
    cached as ready here) and 400 for an unknown one; its messages are translatable, so
    the status is all there is to go on.
    """
    status = e.response.status_code
    return status == 400 or status >= 500


def _recheck_branch(branch: str) -> None:
    """Look the branch up again, bypassing the cache.

    Raises:
        ValueError: If it no longer exists or isn't ready (e.g. it was merged).
    """
    branch_policy.cache.pop(branch.strip(), None)
    _resolve_branch(branch, for_write=False)


def _read(branch: str | None, endpoint: str, **kwargs: Any) -> Any:
    """GET from main, or from a ready branch, explaining a branch that became unusable.

    Args:
        branch: Branch name or schema_id to read from, or None for main
        endpoint: API endpoint, e.g. "dcim/devices"
        **kwargs: Passed on to netbox.get (params, fallback_endpoint)

    Raises:
        ValueError: If the branch is no longer ready (e.g. merged while cached).
        httpx.HTTPStatusError: For other errors.
    """
    headers = _branch_headers(branch)
    try:
        return netbox.get(endpoint, headers=headers, **kwargs)
    except httpx.HTTPStatusError as e:
        if branch and _is_branch_error(e):
            _recheck_branch(branch)
        raise


@mcp.tool(annotations={"readOnlyHint": True})
def netbox_list_branches(
    status: str | None = None,
    limit: Annotated[int, Field(default=50, ge=1, le=100)] = 50,
    offset: Annotated[int, Field(default=0, ge=0)] = 0,
) -> dict[str, Any]:
    """
    List NetBox Branching branches. Changes can only be written to a branch, never to main.

    Each branch has two flags:
    - "mine": owned by the API token's user (null if that user can't be determined)
    - "writable": the write tools accept it now, i.e. write tools are enabled, status is
      "ready" and it is mine (or ALLOW_FOREIGN_BRANCHES is set). Always false when the
      server runs read-only; branches can still be read with the "branch" parameter.
    A branch that is mine but not yet writable is still provisioning (status "new" or
    "provisioning"): wait and list again rather than creating another branch. Create a
    branch with netbox_create_branch only when none of yours fits.

    Args:
        status: Optional status filter (e.g. "ready", "merged", "new")
        limit: Maximum results to return (default 50, max 100)
        offset: Skip this many results for pagination (default 0)

    Returns:
        Paginated response (count, next, previous, results) of branches with id, name,
        schema_id, status, owner, description, mine and writable. Check "next" for more pages.
    """
    params = {
        "limit": limit,
        "offset": offset,
        "fields": "id,name,schema_id,status,owner,description,last_updated",
    }
    if status:
        params["status"] = status
    try:
        page = netbox.get(BRANCHES_ENDPOINT, params=params)
    except httpx.HTTPStatusError as e:
        _raise_branching_error(e)
    results = page.get("results", [])
    try:
        mine = [_owned_by_token(found) for found in results]
    except ValueError:
        # The token's user is unknown; the write tools explain why if one is attempted
        mine = [None] * len(results)
    for found, is_mine in zip(results, mine, strict=True):
        found["mine"] = is_mine
        found["writable"] = (
            branch_policy.write_enabled
            and _branch_status(found) == "ready"
            and bool(found.get("schema_id"))
            and (branch_policy.allow_foreign_branches or bool(is_mine))
        )
    return page


def netbox_create_branch(name: str, description: str = "") -> dict[str, Any]:
    """
    Create a new NetBox Branching branch to stage changes in.

    The branch is provisioned in the background: its status starts as "new" and
    becomes "ready" once provisioning finishes. Check with netbox_list_branches
    before writing to it. Merging a branch into main is done by a person in the
    NetBox UI after review; this server cannot merge.

    Each branch is a full copy of the database, so creation is limited: if you already
    have a branch with this name it is returned (with "existing": true) instead of
    creating another (unless it is merged, archived or failed: then choose another name),
    a name used by someone else is refused, and at most MAX_OPEN_BRANCHES open branches
    per user are allowed. If the token's user can't be determined (NetBox < 4.5 without
    NETBOX_USERNAME), creation is only allowed with ALLOW_FOREIGN_BRANCHES, and the
    per-user limit applies once the first created branch reveals the user.

    Args:
        name: Branch name (describe the change, e.g. "Add rack R12 in Oslo")
        description: Optional longer description

    Returns:
        The created branch, including its schema_id.
    """
    # NetBox trims names on save, and lookups strip their input, so compare trimmed names
    name = name.strip()
    if not name:
        raise ValueError("A branch name is required")
    try:
        user_id, _ = _get_token_user()
        user_known = True
    except ValueError:
        # NetBox < 4.5 without NETBOX_USERNAME: only allowed when ownership isn't enforced.
        # The created branch's owner then identifies the token's user (_learn_owner).
        if not branch_policy.allow_foreign_branches:
            raise
        user_id, user_known = None, False
    try:
        same_name = [b for b in _find_branches({"name": name}) if b.get("name") == name]
        if same_name:
            found = same_name[0]
            if len(same_name) > 1 or (user_known and not _owned_by_token(found)):
                raise ValueError(
                    f"A branch named '{name}' already exists and isn't yours; choose another name"
                )
            status = _branch_status(found)
            if status in CLOSED_BRANCH_STATUSES:
                raise ValueError(
                    f"Your branch '{name}' already exists with status '{status}' and can't be "
                    "used again; choose another name"
                )
            return {**found, "existing": True}
        mine_open = (
            [
                b
                for b in _find_branches({"owner_id": user_id} if user_id is not None else {})
                if _owned_by_token(b) and _branch_status(b) not in CLOSED_BRANCH_STATUSES
            ]
            if user_known
            else []
        )
        if len(mine_open) >= MAX_OPEN_BRANCHES:
            raise ValueError(
                f"You already have {len(mine_open)} open branches (limit {MAX_OPEN_BRANCHES}): "
                + ", ".join(b["name"] for b in mine_open)
                + ". Reuse one of them, or ask a person to merge or delete some."
            )
        # Creating a branch is the one write the client allows on main
        created = netbox.create(
            BRANCHES_ENDPOINT, {"name": name, "description": description}, branch=None
        )
    except httpx.HTTPStatusError as e:
        _raise_branching_error(e)
    if warning := _learn_owner(created):
        created = {**created, "warning": warning}
    return created


def netbox_create_objects(
    object_type: str, branch: str, data: dict | list[dict]
) -> dict[str, Any] | list[dict[str, Any]]:
    """
    Create one or more objects in NetBox, inside a branch.

    Only inventory types that NetBox Branching isolates can be written (circuits, dcim,
    ipam, tenancy, virtualization, vpn, wireless, and extras journal entries and tags).

    NetBox runs event rules (webhooks, scripts) for changes made inside branches too, so
    every write (create, update, delete) is refused while an enabled event rule on a
    branchable type could fire. Rules whose conditions require active_branch to be null
    (e.g. {"and": [{"attr": "active_branch", "value": null}]}) only fire on main and don't
    block, provided the NetBox operator has put 'netbox_branching.events.add_branch_context'
    before 'extras.events.process_event_queue' in EVENTS_PIPELINE (not visible via the API).
    If a write is refused for this, tell the user; only the operator can change it.

    Args:
        object_type: The NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        branch: Name or schema_id of a writable branch: "ready" and owned by the API token's
                user (see netbox_list_branches). Required; main is never written.
        data: A dict for a single object, or a non-empty list of dicts to bulk-create.
              Use the same field names as the NetBox REST API. Related objects are
              referenced by ID (e.g. {"site": 3}) or by a dict of unique attributes
              (e.g. {"site": {"slug": "oslo"}}). Choice fields use their value
              (e.g. {"status": "active"}).

    Examples:
        netbox_create_objects("dcim.site", "my-branch", {"name": "Oslo", "slug": "oslo", "status": "active"})
        netbox_create_objects("ipam.ipaddress", "my-branch", [{"address": "10.0.0.1/24"}, {"address": "10.0.0.2/24"}])

    Returns:
        The created object, or a list of created objects for bulk creation.
    """
    endpoint = _validate_writable_type(object_type)
    if isinstance(data, list) and not data:
        raise ValueError("data is an empty list; nothing to create")
    schema_id = _branch_schema_id(branch)
    _check_branch_events()
    try:
        if isinstance(data, list):
            return netbox.bulk_create(endpoint, data, branch=schema_id)
        return netbox.create(endpoint, data, branch=schema_id)
    except httpx.HTTPStatusError as e:
        _raise_with_body(e)


def netbox_update_objects(
    object_type: str,
    branch: str,
    data: dict | list[dict],
    object_id: int | None = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    """
    Update (PATCH) one or more existing objects in NetBox, inside a branch.
    Only the supplied fields change. Writable types are the same as netbox_create_objects.

    The event rule check described in netbox_create_objects applies too.

    Args:
        object_type: The NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        branch: Name or schema_id of a writable branch: "ready" and owned by the API token's
                user (see netbox_list_branches). Required; main is never written.
        data: Fields to change. Either:
              - a dict together with object_id, to update a single object, or
              - a non-empty list of dicts that each include "id", to bulk-update several objects.
        object_id: ID of the object to update (single-object form only)

    Examples:
        netbox_update_objects("dcim.device", "my-branch", {"status": "offline"}, object_id=42)
        netbox_update_objects("dcim.interface", "my-branch", [{"id": 1, "enabled": False}, {"id": 2, "enabled": False}])

    Returns:
        The updated object, or a list of updated objects for bulk updates.
    """
    endpoint = _validate_writable_type(object_type)
    if isinstance(data, list):
        if object_id is not None:
            raise ValueError("object_id cannot be combined with a list; put 'id' in each dict")
        if not data:
            raise ValueError("data is an empty list; nothing to update")
        if any("id" not in item for item in data):
            raise ValueError("Every dict in a bulk update must include 'id'")
    elif object_id is None:
        raise ValueError("object_id is required when data is a single dict")
    schema_id = _branch_schema_id(branch)
    if file_fields := FILE_FIELDS.get(object_type):
        items = data if isinstance(data, list) else [data]
        if changed := sorted({f for item in items for f in file_fields if f in item}):
            raise ValueError(
                f"Refusing to change {', '.join(changed)}: uploaded files aren't isolated by "
                "NetBox Branching, so replacing an image inside a branch deletes main's file "
                "at once. Change images in NetBox after merging."
            )
    _check_branch_events()
    try:
        if isinstance(data, list):
            return netbox.bulk_update(endpoint, data, branch=schema_id)
        return netbox.update(endpoint, object_id, data, branch=schema_id)
    except httpx.HTTPStatusError as e:
        _raise_with_body(e)


# Deleting an object also deletes rows linked to it through NetBox's generic relations.
# These related models aren't isolated by NetBox Branching, so a delete inside a branch
# removes their rows from main immediately, before any merge (verified with
# netbox-branching 1.1.3 on NetBox 4.5). Image attachments, contact assignments and
# journal entries are branch-isolated and safe. All three endpoints exist on every NetBox
# version netbox-branching supports (4.1+). A model NetBox reports as branchable at
# startup is skipped (see _active_unbranched_dependents).
UNBRANCHED_DEPENDENTS = (
    ("bookmarks", "extras/bookmarks"),
    ("subscriptions", "extras/subscriptions"),
    ("jobs", "core/jobs"),
)

# Uploaded files live in media storage, which NetBox Branching doesn't isolate: changing a
# device type's image or deleting the device type removes the old file at once
# (DeviceType.save() and delete() in NetBox 4.5). The only file fields on writable models.
FILE_FIELDS = {"dcim.devicetype": ("front_image", "rear_image")}

# Versions the delete and event-rule behaviour was verified against
VERIFIED_NETBOX = "4.5."
VERIFIED_BRANCHING = "1.1."


def _active_unbranched_dependents() -> list[tuple[str, str]]:
    """UNBRANCHED_DEPENDENTS minus models NetBox reported as branchable at startup."""
    reported = netbox.branchable_endpoints
    return [
        (label, endpoint)
        for label, endpoint in UNBRANCHED_DEPENDENTS
        if reported is None or endpoint not in reported
    ]


DELETE_REFUSAL = (
    "Deleting inside a branch would remove them from main immediately, so the delete is "
    "refused. Use a token that can view them, or delete in the NetBox UI after merging."
)


def _require_unrestricted_token(label: str, refusal: str) -> None:
    """Refuse unless the operator confirmed the token sees every row of what is checked.

    NetBox filters API lists by the token user's permission constraints without saying so
    (by default users see only their own bookmarks and subscriptions), so a check reading
    a filtered list would pass on partial data.

    Raises:
        ValueError: If UNRESTRICTED_TOKEN isn't set.
    """
    if not branch_policy.unrestricted_token:
        raise ValueError(
            f"Can't be sure the API token sees all {label}: NetBox filters lists by the "
            "token user's permission constraints (by default users see only their own "
            f"bookmarks and subscriptions). {refusal} Once the token's user can view "
            "everything unconstrained (e.g. a superuser), set UNRESTRICTED_TOKEN=true."
        )


def _fetch_dependent_rows(
    label: str, endpoint: str, refusal: str = DELETE_REFUSAL
) -> list[tuple[str, int]]:
    """Return (object_type, object_id) of every row of one dependent model in main.

    All rows are fetched (not just ones for the deleted objects) so cascaded children can
    be found, and because the subscriptions API ignores object filters anyway. Jobs are
    narrowed server-side to branchable object types, since only those can be deleted.

    Args:
        label: Name of the dependent model, for messages
        endpoint: API endpoint of the dependent model
        refusal: Why the write is refused when the rows can't be read
    """
    _require_unrestricted_token(label, refusal)
    params: dict[str, Any] = {"fields": "id,object_type,object_id", "limit": 1000}
    filters: list[dict[str, Any]] = [{}]
    if label == "jobs" and branch_policy.branchable_types is not None:
        # In chunks, to keep the request line within server limits (gunicorn: 4094 bytes)
        types = sorted(branch_policy.branchable_types)
        filters = [{"object_type": types[i : i + 40]} for i in range(0, len(types), 40)]
    try:
        return [
            (row["object_type"], row["object_id"])
            for extra in filters
            for row in _get_all(endpoint, {**params, **extra})
            if row.get("object_type") and row.get("object_id") is not None
        ]
    except httpx.HTTPStatusError as e:
        # Every NetBox version netbox-branching supports has these endpoints, so even a
        # 404 means the check can't be trusted (e.g. a proxy blocking the path)
        raise ValueError(
            f"Can't check for {label} (GET /api/{endpoint}/ returned "
            f"{e.response.status_code}). {refusal}"
        ) from e


# Upper bound on objects fetched to trace cascades for one delete; beyond it, refuse
MAX_CASCADE_OBJECTS = 2000


def _api_ref(url: str, branchable: frozenset[str]) -> tuple[str, int] | None:
    """(endpoint, id) of a NetBox API object URL whose endpoint is branchable, or None."""
    path = urlparse(url).path
    start = path.rfind("/api/")
    if start < 0:
        return None
    parts = path[start + len("/api/") :].strip("/").split("/")
    if len(parts) < 2 or not parts[-1].isdigit():
        return None
    endpoint = "/".join(parts[:-1])
    return (endpoint, int(parts[-1])) if endpoint in branchable else None


# Links that never make the linking object part of a cascade delete: deleting a tag only
# removes its (branch-isolated) assignments, not the tagged objects
NON_CASCADING_LINKS = frozenset({"tags"})


def _nested_refs(value: Any, branchable: frozenset[str], top: bool = True) -> set[tuple[str, int]]:
    """Branchable objects a NetBox object (JSON) links to, excluding its own URL and tags.

    Args:
        value: The object, or a value nested in it
        branchable: API endpoints of branchable models, e.g. "dcim/devices"
        top: Whether value is the object itself (whose own URL isn't a link)
    """
    refs: set[tuple[str, int]] = set()
    if isinstance(value, dict):
        url = value.get("url")
        if not top and isinstance(url, str) and (ref := _api_ref(url, branchable)):
            refs.add(ref)
        for key, item in value.items():
            if key != "url" and key not in NON_CASCADING_LINKS:
                refs |= _nested_refs(item, branchable, top=False)
    elif isinstance(value, list):
        for item in value:
            refs |= _nested_refs(item, branchable, top=False)
    return refs


ObjectRef = tuple[str, int]


def _fetch_by_ids(endpoint: str, ids: list[int], headers: dict[str, str] | None) -> list[dict]:
    """Fetch the objects with these IDs that the token can see, batched.

    Raises:
        ValueError: If NetBox returns an error status.
    """
    found: list[dict] = []
    ids = sorted(set(ids))
    for start in range(0, len(ids), 100):
        chunk = ids[start : start + 100]
        wanted = set(chunk)
        try:
            batch = _get_all(endpoint, {"id": chunk, "limit": len(chunk)}, headers)
        except httpx.HTTPStatusError as e:
            raise ValueError(
                f"Can't check the {endpoint} objects this write affects (NetBox returned "
                f"{e.response.status_code}); refusing."
            ) from e
        found.extend(obj for obj in batch if obj.get("id") in wanted)
    return found


def _fetch_links(
    objects: set[ObjectRef], headers: dict[str, str] | None, branchable: frozenset[str]
) -> dict[ObjectRef, set[ObjectRef]]:
    """Fetch objects, batched per endpoint, and return what each one found links to."""
    by_endpoint: dict[str, list[int]] = {}
    for endpoint, obj_id in objects:
        by_endpoint.setdefault(endpoint, []).append(obj_id)

    def links(endpoint: str, obj: dict) -> set[ObjectRef]:
        refs = _nested_refs(obj, branchable)
        for field_name, target in BARE_ID_LINKS.get(endpoint, {}).items():
            if isinstance(obj.get(field_name), int):
                refs.add((target, obj[field_name]))
        return refs

    def fetch(endpoint: str) -> dict[ObjectRef, set[ObjectRef]]:
        return {
            (endpoint, obj["id"]): links(endpoint, obj)
            for obj in _fetch_by_ids(endpoint, by_endpoint[endpoint], headers)
        }

    result: dict[ObjectRef, set[ObjectRef]] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(by_endpoint) or 1)) as pool:
        for part in pool.map(fetch, by_endpoint):
            result.update(part)
    return result


# Models that cache their scope's region, site group, site and location in CASCADE fields,
# which NetBox only updates when the object itself is saved (dcim/models/mixins.py)
CACHED_SCOPE_ENDPOINTS = ("ipam/prefixes", "virtualization/clusters", "wireless/wireless-lans")

# CASCADE links the API JSON shows only as a bare ID, by endpoint of the holder: field name
# and endpoint of the linked-to object. Followed like any other link.
BARE_ID_LINKS: dict[str, dict[str, str]] = {
    "dcim/inventory-items": {"parent": "dcim/inventory-items"},
}

# CASCADE links the trace doesn't follow from the holder's API JSON (a hidden field, a bare
# ID, or a cache NetBox doesn't keep current), verified against NetBox 4.5: for each endpoint of a
# linked-to object, the (endpoint, filter) pairs that list the objects holding such a link
# to it. ModuleBay.parent is hidden and isn't updated when a module moves, so it can point
# at a bay of another device or module; a doomed device or module therefore also dooms its
# whole module bay subtree, found downward through these filters.
HIDDEN_CASCADES: dict[str, tuple[tuple[str, str], ...]] = {
    "dcim/devices": (("dcim/module-bays", "device_id"), ("dcim/modules", "device_id")),
    "dcim/modules": (("dcim/module-bays", "module_id"),),
    "dcim/module-bays": (("dcim/module-bays", "parent_id"), ("dcim/modules", "module_bay_id")),
    "ipam/vlan-translation-policies": (("ipam/vlan-translation-rules", "policy_id"),),
    **{
        scope: tuple((holder, scope_filter) for holder in CACHED_SCOPE_ENDPOINTS)
        for scope, scope_filter in (
            ("dcim/regions", "region_id"),
            ("dcim/site-groups", "site_group_id"),
            ("dcim/sites", "site_id"),
            ("dcim/locations", "location_id"),
        )
    },
}


def _hidden_dependents(objects: set[ObjectRef], headers: dict[str, str]) -> set[ObjectRef]:
    """Objects holding a HIDDEN_CASCADES link to any of these objects, inside the branch.

    Raises:
        ValueError: If NetBox returns an error status.
    """
    by_endpoint: dict[str, list[int]] = {}
    for endpoint, obj_id in objects:
        if endpoint in HIDDEN_CASCADES:
            by_endpoint.setdefault(endpoint, []).append(obj_id)
    found: set[ObjectRef] = set()
    for endpoint, ids in by_endpoint.items():
        ids = sorted(ids)
        for holder, link_filter in HIDDEN_CASCADES[endpoint]:
            for start in range(0, len(ids), 100):
                params = {link_filter: ids[start : start + 100], "fields": "id", "limit": 1000}
                try:
                    rows = _get_all(holder, params, headers)
                except httpx.HTTPStatusError as e:
                    raise ValueError(
                        f"Can't check which {holder} objects would be deleted along with "
                        f"these objects (NetBox returned {e.response.status_code}); refusing."
                    ) from e
                found.update((holder, row["id"]) for row in rows)
    return found


def _fetch_refs(
    objects: set[ObjectRef], schema_id: str, branchable: frozenset[str]
) -> dict[ObjectRef, set[ObjectRef]]:
    """Return what each object links to inside the branch, where the delete cascades.

    An object missing from the branch but present in main (created in main after the
    branch, or already deleted in the branch) can't be reached by the delete, so it links
    to nothing.

    Raises:
        ValueError: If an object is in neither, e.g. hidden from the token by a permission
            constraint, since its links are then unknown.
    """
    headers = {"X-NetBox-Branch": schema_id}
    found = _fetch_links(objects, headers, branchable)
    if missing := objects - found.keys():
        in_main = _fetch_links(missing, None, branchable)
        if hidden := missing - in_main.keys():
            raise ValueError(
                f"Can't see {len(hidden)} bookmarked, subscribed or job-linked objects (the "
                "API token may not be allowed to view them), so it's unknown whether this "
                "delete would remove those rows from main; refusing. Use a token that can view "
                "them, or delete in the NetBox UI after merging."
            )
        found.update((ref, set()) for ref in missing)
    return found


def _unbranched_dependents(endpoint: str, ids: list[int], schema_id: str) -> dict[str, int]:
    """Count rows in main that deleting these objects inside a branch would remove from main.

    Covers rows linked to the objects themselves and to every object that links to them,
    directly or through other objects (a device's interfaces, a location's child and
    grandchild locations), which NetBox deletes along with them. Links are followed
    inside the branch, batched per type, plus the CASCADE links the API doesn't show
    (BARE_ID_LINKS, HIDDEN_CASCADES). An object that would only be set to null rather
    than deleted is counted too, and so is everything linking to it: refusing is the safe
    side, at the cost of refusing some deletes that would remove nothing (e.g. a tenant
    whose devices have bookmarked interfaces).

    Known limitation: a row created after this check but before the delete lands is
    still removed from main.

    Args:
        endpoint: API endpoint of the deleted objects, e.g. "dcim/devices"
        ids: IDs of the objects about to be deleted
        schema_id: Schema ID of the branch the delete runs in

    Returns:
        {label: count} for each dependent model with rows that would be removed.

    Raises:
        ValueError: If NetBox didn't report its branchable models, a dependent model or a
            linked object can't be checked, or tracing would need more than
            MAX_CASCADE_OBJECTS objects.
    """
    dependents = _active_unbranched_dependents()
    if not dependents:
        return {}
    types = branch_policy.branchable_types
    if types is None:
        raise ValueError(
            "NetBox didn't report which models support branching (see the server log), so "
            "it's unknown which bookmarked, subscribed or job-linked objects a delete could "
            "reach; refusing. Restart the server once NetBox reports them, or delete in the "
            "NetBox UI after merging."
        )
    branchable = frozenset(endpoint.strip("/") for endpoint in types.values() if endpoint)
    with ThreadPoolExecutor(max_workers=len(dependents)) as pool:
        fetched = list(pool.map(lambda d: _fetch_dependent_rows(*d), dependents))
    deleted = {(endpoint.strip("/"), obj_id) for obj_id in ids}

    def row_ref(row_type: str, row_id: int) -> tuple[str, int] | None:
        if row_type not in types:
            return None  # Only branchable objects can be deleted in a branch
        if not (endpoint := types[row_type]):
            raise ValueError(
                f"{row_type} objects have bookmarks, subscriptions or jobs in main but no "
                "REST API, so it's unknown whether this delete reaches them; refusing. "
                "Delete in the NetBox UI after merging."
            )
        return (endpoint.strip("/"), row_id)

    rows_by_label = {
        label: [r for r in (row_ref(*row) for row in rows) if r]
        for (label, _), rows in zip(dependents, fetched, strict=True)
    }
    if not any(rows_by_label.values()):
        return {}  # Nothing in main that a delete could remove
    # Trace links upward through the branch until every reachable object is known
    graph: dict[ObjectRef, set[ObjectRef]] = {}
    frontier = {r for refs in rows_by_label.values() for r in refs} - deleted
    while frontier:
        if len(graph) + len(frontier) > MAX_CASCADE_OBJECTS:
            raise ValueError(
                f"Checking which bookmarked, subscribed or job-linked objects would be deleted "
                f"along with these objects needs more than {MAX_CASCADE_OBJECTS} lookups; "
                "refusing. Delete in the NetBox UI after merging."
            )
        new = _fetch_refs(frontier, schema_id, branchable)
        graph.update(new)
        frontier = {r for refs in new.values() for r in refs} - graph.keys() - deleted

    # Everything that links (directly or through others) to a deleted object: walk the
    # links backwards from the deleted objects, which handles reference cycles, and add
    # the holders of hidden links until nothing new turns up
    linked_from: dict[ObjectRef, set[ObjectRef]] = {}
    for obj, links in graph.items():
        for target in links:
            linked_from.setdefault(target, set()).add(obj)
    doomed = set(deleted)
    queue = list(deleted)
    unqueried = set(deleted)
    while queue:
        while queue:
            for obj in linked_from.get(queue.pop(), ()):
                if obj not in doomed:
                    doomed.add(obj)
                    unqueried.add(obj)
                    queue.append(obj)
        hidden = _hidden_dependents(unqueried, {"X-NetBox-Branch": schema_id}) - doomed
        unqueried = set(hidden)
        doomed |= hidden
        queue.extend(hidden)

    found: dict[str, int] = {}
    for label, refs in rows_by_label.items():
        count = sum(1 for ref in refs if ref in doomed)
        if count:
            found[label] = count
    return found


def _check_branch_events() -> None:
    """Refuse a branch write that NetBox would react to in main, unless ALLOW_BRANCH_EVENTS."""
    if branch_policy.allow_branch_events:
        return
    _check_event_rules()
    _check_subscriptions()


def _check_subscriptions() -> None:
    """Refuse a branch write while users are subscribed to branchable objects.

    NetBox notifies subscribers whenever a subscribed object is saved or deleted, also
    inside a branch, and the notification lands in main (verified with netbox-branching
    1.1.3 on NetBox 4.5). A write also saves objects other than the ones it names (a
    cable's terminations, a wireless link's interfaces, the device of a deleted primary
    IP), so any subscription to an object NetBox reports as branchable counts (plugin
    models included), as with event rules; if it didn't report them, any subscription.

    Raises:
        ValueError: If such a subscription exists, or subscriptions can't be checked.
    """
    reported = netbox.branchable_endpoints
    if reported is not None and "extras/notifications" in reported:
        return  # Notifications would stay in the branch
    rows = _fetch_dependent_rows(
        "subscriptions",
        "extras/subscriptions",
        refusal="NetBox notifies subscribers in main about changes made inside branches, "
        "so the write is refused. Use a token that can view subscriptions, or set "
        "ALLOW_BRANCH_EVENTS.",
    )
    types = branch_policy.branchable_types
    count = sum(1 for row_type, _ in rows if types is None or row_type in types)
    if count:
        raise ValueError(
            f"Refusing to write: users have {count} subscriptions to objects in NetBox, and "
            "NetBox notifies subscribers in main about changes made inside branches (also "
            "to objects a write only touches, like a cable's interfaces), so they could be "
            "told about this unreviewed change. Ask them to unsubscribe, or set "
            "ALLOW_BRANCH_EVENTS=true if such notifications are acceptable."
        )


# Event rule condition that makes a rule skip changes made inside branches, documented by
# netbox-branching. It needs 'netbox_branching.events.add_branch_context' before
# 'extras.events.process_event_queue' in NetBox's EVENTS_PIPELINE, which the API can't show.
MAIN_ONLY_CONDITION = {"attr": "active_branch", "value": None}


def _fires_only_on_main(conditions: object) -> bool:
    """Whether event rule conditions require active_branch to be null.

    Only a plain active_branch == null test counts, on its own or ANDed with other tests at
    the top level. OR, negation, other operators and nested sets don't, so those rules
    still block branch writes.
    """
    if not isinstance(conditions, dict):
        return False
    if len(conditions) == 1:
        logic, rules = next(iter(conditions.items()))
        if not isinstance(logic, str) or logic.lower() != "and" or not isinstance(rules, list):
            return False
    else:
        rules = [conditions]
    return any(
        isinstance(rule, dict)
        and rule.get("attr") == MAIN_ONLY_CONDITION["attr"]
        and "value" in rule
        and rule["value"] is None
        and rule.get("op", "eq") == "eq"
        and rule.get("negate", False) is False
        for rule in rules
    )


def _check_event_rules() -> None:
    """Refuse a branch write while event rules could fire on it.

    NetBox runs event rules for changes made inside branches too, so webhooks and scripts
    would act on unreviewed changes as if they had happened in main (verified with
    netbox-branching 1.1.3 on NetBox 4.5). A write can also create, change or delete
    related objects of other types (a device's interfaces, cascades), so any enabled rule
    on an object type NetBox reports as branchable counts (plugin models and image
    attachments included; any rule if it didn't report them), except rules whose IDs are
    listed in ALLOWED_BRANCH_EVENT_RULES (IDs, not names: a name can be reused) and rules
    whose conditions require active_branch to be null (main only). That condition only
    works when NetBox's EVENTS_PIPELINE runs 'netbox_branching.events.add_branch_context'
    before 'extras.events.process_event_queue'; the API doesn't expose EVENTS_PIPELINE, so
    this trusts the operator to have set it.

    Raises:
        ValueError: If such a rule exists, or event rules can't be checked.
    """
    _require_unrestricted_token(
        "event rules",
        "Event rules fire for changes made inside branches, so the write is refused.",
    )
    try:
        rules = _get_all(
            "extras/event-rules",
            {"fields": "id,name,enabled,object_types,conditions", "limit": 1000},
        )
    except httpx.HTTPStatusError as e:
        raise ValueError(
            f"Can't check NetBox event rules (GET /api/extras/event-rules/ returned "
            f"{e.response.status_code}). Event rules fire for changes made inside branches, "
            "so the write is refused. Use a token that can view event rules, or set "
            "ALLOW_BRANCH_EVENTS."
        ) from e
    types = branch_policy.branchable_types
    firing = sorted(
        f"{rule.get('name')} (ID {rule.get('id')})"
        for rule in rules
        if rule.get("enabled")
        and rule.get("id") not in branch_policy.allowed_event_rules
        and not _fires_only_on_main(rule.get("conditions"))
        and (types is None or any(t in types for t in rule.get("object_types") or []))
    )
    if firing:
        raise ValueError(
            "Refusing to write: NetBox runs event rules for changes made inside branches, so "
            "these enabled rules would fire (webhooks/scripts) on this unreviewed change: "
            f"{', '.join(firing)}. Ask the NetBox operator to do one of: make the rules fire "
            'only on main by adding {"attr": "active_branch", "value": null} to their '
            'conditions (top level, ANDed; e.g. {"and": [{"attr": "active_branch", '
            '"value": null}]}), which only works once NetBox\'s EVENTS_PIPELINE lists '
            "'netbox_branching.events.add_branch_context' before "
            "'extras.events.process_event_queue' (this server can't check that setting, so "
            "the operator must configure it); disable the rules; list the IDs of the ones "
            "that are safe to run on branch changes in ALLOWED_BRANCH_EVENT_RULES; or set "
            "ALLOW_BRANCH_EVENTS=true to allow all."
        )


def netbox_delete_objects(
    object_type: str, branch: str, object_ids: int | list[int]
) -> dict[str, Any]:
    """
    Delete one or more objects in NetBox, inside a branch.

    The deletion only affects the branch until someone merges it. Look up the
    objects first so you are sure the IDs are correct. Writable types are the same
    as netbox_create_objects.

    Deleting an object also deletes users' bookmarks of it, subscriptions to it and jobs
    attached to it (and those of child objects deleted with it, like a device's
    interfaces), and NetBox Branching doesn't isolate those: they would vanish from main
    at once. So the delete is refused if any exist; delete such objects in the NetBox UI
    after merging, or remove the bookmarks/subscriptions/jobs first. The check only sees
    rows the API token may view, and if it can't check at all the delete is refused too.
    A bookmark or subscription created in the moment between the check and the delete is
    still removed from main. The event rule check described in netbox_create_objects
    applies too.

    Args:
        object_type: The NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        branch: Name or schema_id of a writable branch: "ready" and owned by the API token's
                user (see netbox_list_branches). Required; main is never written.
        object_ids: A single ID or a non-empty list of IDs to delete

    Returns:
        {"deleted": [ids], "branch": schema_id} on success
    """
    endpoint = _validate_writable_type(object_type)
    ids = object_ids if isinstance(object_ids, list) else [object_ids]
    if not ids:
        raise ValueError("object_ids is an empty list; nothing to delete")
    schema_id = _branch_schema_id(branch)
    if file_fields := FILE_FIELDS.get(object_type):
        branch_objects = _fetch_by_ids(endpoint, ids, {"X-NetBox-Branch": schema_id})
        if with_files := sorted(
            o["id"] for o in branch_objects if any(o.get(f) for f in file_fields)
        ):
            raise ValueError(
                f"Refusing to delete {object_type} {', '.join(map(str, with_files))}: they have "
                "uploaded images, which aren't isolated by NetBox Branching, so deleting them "
                "inside a branch deletes main's files at once. Delete in NetBox after merging."
            )
    _check_branch_events()
    if dependents := _unbranched_dependents(endpoint, ids, schema_id):
        found = ", ".join(f"{count} {label}" for label, count in dependents.items())
        raise ValueError(
            f"Refusing to delete: main has {found} linked to these objects. NetBox Branching "
            "doesn't isolate those, so deleting inside the branch would remove them from main "
            "immediately. Delete in the NetBox UI after merging, or remove them first."
        )
    try:
        if len(ids) == 1:
            netbox.delete(endpoint, ids[0], branch=schema_id)
        else:
            netbox.bulk_delete(endpoint, ids, branch=schema_id)
    except httpx.HTTPStatusError as e:
        _raise_with_body(e)
    return {"deleted": ids, "branch": schema_id}


WRITE_TOOLS = (
    (netbox_create_branch, {"readOnlyHint": False, "destructiveHint": False}),
    (netbox_create_objects, {"readOnlyHint": False, "destructiveHint": False}),
    (
        netbox_update_objects,
        {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
    ),
    (netbox_delete_objects, {"readOnlyHint": False, "destructiveHint": True}),
)


def check_write_settings(settings: Settings) -> None:
    """Refuse to expose write tools on an unauthenticated HTTP endpoint.

    Args:
        settings: The effective server settings

    Raises:
        ValueError: If ENABLE_WRITE is set with HTTP transport and no MCP_AUTH_TOKEN
    """
    if settings.enable_write and settings.transport == "http" and settings.mcp_auth_token is None:
        raise ValueError(
            "ENABLE_WRITE with TRANSPORT=http requires MCP_AUTH_TOKEN; refusing to expose "
            "write tools on an unauthenticated endpoint"
        )


def register_write_tools() -> None:
    """Expose the branch-creation and create/update/delete tools (only with ENABLE_WRITE)."""
    for fn, annotations in WRITE_TOOLS:
        mcp.tool(fn, annotations=annotations)


def _get_endpoint_info(object_type: str) -> tuple[str, str | None]:
    """
    Returns (endpoint, fallback_endpoint) for the given object type.

    The fallback_endpoint is used for NetBox version compatibility when
    an endpoint path has changed between versions.

    Args:
        object_type: The NetBox object type (e.g., "dcim.device")

    Returns:
        Tuple of (endpoint, fallback_endpoint). fallback_endpoint is None
        if no fallback is needed for this object type.
    """
    type_info = NETBOX_OBJECT_TYPES[object_type]
    return type_info["endpoint"], type_info.get("fallback_endpoint")


def warn_if_unverified_versions(client: NetBoxRestClient) -> None:
    """Log a reminder when NetBox or netbox-branching is outside the verified versions.

    Which related models leak on delete (UNBRANCHED_DEPENDENTS) and that event rules fire
    for branch changes were verified against specific versions; others may differ.

    Args:
        client: Initialized NetBox REST API client
    """
    logger = logging.getLogger(__name__)
    try:
        status = client.get("status")
    except (httpx.HTTPError, ValueError) as e:
        logger.warning(f"Couldn't read NetBox versions to compare with verified ones: {e}")
        return
    netbox_version = str(status.get("netbox-version") or "")
    plugins = status.get("plugins") or {}
    branching = next((str(v) for k, v in plugins.items() if "branching" in str(k)), "")
    if not netbox_version.startswith(VERIFIED_NETBOX) or not branching.startswith(
        VERIFIED_BRANCHING
    ):
        logger.warning(
            f"Branch write safety checks were verified with NetBox {VERIFIED_NETBOX}x and "
            f"netbox-branching {VERIFIED_BRANCHING}x; this is NetBox {netbox_version or '?'} "
            f"with netbox-branching {branching or '?'}. Re-verify which related objects leak "
            "into main on delete and how event rules behave before relying on them."
        )


def _rest_endpoint(path: str | None) -> str | None:
    """API endpoint ("dcim/sites") of an object type's REST path, which may carry NetBox's
    BASE_PATH ("/netbox/api/dcim/sites/"); None if it has no REST API."""
    path = f"/{(path or '').strip('/')}/"
    start = path.find("/api/")
    endpoint = path[start + len("/api/") :].strip("/") if start >= 0 else ""
    return endpoint or None


def discover_branchable_types(client: NetBoxRestClient) -> dict[str, str | None] | None:
    """Ask NetBox which models support branching.

    netbox-branching records a "branching" model feature, which NetBox exposes on each
    object type. The result narrows writes (an endpoint must pass both the static
    BRANCHABLE_ENDPOINT_PREFIXES check and appear here) and tells the side-effect checks
    which objects a branch write can change, plugin models included.

    Args:
        client: Initialized NetBox REST API client

    Returns:
        {object type: endpoint} (e.g. {"dcim.site": "dcim/sites"}) of models NetBox
        reports as branchable (endpoint None for a model without REST API), or None if
        NetBox doesn't report the feature (the static allow-list then applies, and deletes
        are refused).
    """
    logger = logging.getLogger(__name__)
    types: dict[str, str | None] = {}
    try:
        object_types = _get_all(
            "core/object-types",
            {"features": "branching", "limit": 1000},
            client=client,
            fallback_endpoint="extras/object-types",  # NetBox < 4.4
        )
        for obj_type in object_types:
            if "branching" not in (obj_type.get("features") or []):
                continue
            if obj_type.get("app_label") and obj_type.get("model"):
                name = f"{obj_type['app_label']}.{obj_type['model']}"
                types[name] = _rest_endpoint(obj_type.get("rest_api_endpoint"))
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as e:
        logger.warning(f"Couldn't read branchable models from NetBox, using static list: {e}")
        return None
    if not types:
        logger.warning(
            "NetBox doesn't report a 'branching' model feature; using the static allow-list"
        )
        return None
    endpoints = {endpoint for endpoint in types.values() if endpoint}
    narrowed = sorted(
        info["endpoint"]
        for info in NETBOX_OBJECT_TYPES.values()
        if is_branchable_endpoint(info["endpoint"]) and info["endpoint"] not in endpoints
    )
    if narrowed:
        logger.warning(
            "NetBox reports these allow-listed endpoints as not branchable; writes to them "
            f"are refused: {', '.join(narrowed)}"
        )
    return types


def discover_plugin_types(client: NetBoxRestClient) -> dict[str, dict[str, str]]:
    """Discover plugin object types from NetBox's object-types API.

    Queries the NetBox instance for installed plugin models that have REST API
    endpoints and returns them in the same format as NETBOX_OBJECT_TYPES.

    Args:
        client: Initialized NetBox REST API client

    Returns:
        Dict mapping type keys (e.g. "netbox_dns.zone") to endpoint info dicts.
        Returns empty dict on any error (graceful degradation).
    """
    logger = logging.getLogger(__name__)
    plugin_types: dict[str, dict[str, str]] = {}

    try:
        # Paginate through all object types
        offset = 0
        limit = 100
        while True:
            response = client.get(
                "core/object-types",
                params={"limit": limit, "offset": offset},
                fallback_endpoint="extras/object-types",  # NetBox < 4.4
            )

            results = response.get("results", [])
            for obj_type in results:
                # Only include plugin models with REST API endpoints
                if not obj_type.get("is_plugin_model", False):
                    continue

                rest_url = obj_type.get("rest_api_endpoint")
                if not rest_url:
                    continue

                app_label = obj_type.get("app_label", "")
                model = obj_type.get("model", "")
                if not app_label or not model:
                    continue

                type_key = f"{app_label}.{model}"

                # Skip if it would collide with a core type
                if type_key in NETBOX_OBJECT_TYPES:
                    logger.debug(f"Skipping plugin type '{type_key}': collides with core type")
                    continue

                # Convert REST URL to endpoint path:
                # "/api/plugins/netbox-dns/zones/" -> "plugins/netbox-dns/zones"
                endpoint = rest_url.strip("/")
                if endpoint.startswith("api/"):
                    endpoint = endpoint[4:]

                # Build a display name from the model name
                display_name = obj_type.get("display", model)

                plugin_types[type_key] = {
                    "name": display_name,
                    "endpoint": endpoint,
                }

            # Check if there are more pages
            if not response.get("next"):
                break
            offset += limit

    except (httpx.HTTPError, ValueError, KeyError) as e:
        logger.warning(f"Plugin discovery failed, continuing with core types only: {e}")
        return {}

    if plugin_types:
        logger.info(
            f"Discovered {len(plugin_types)} plugin object types: "
            + ", ".join(sorted(plugin_types.keys()))
        )
    else:
        logger.info("No plugin object types discovered")

    return plugin_types


async def _update_tool_descriptions() -> None:
    """Update tool descriptions to reflect the current NETBOX_OBJECT_TYPES registry.

    The type list in netbox_get_objects's description is built at import time.
    After plugin discovery adds new types, this refreshes the description so
    LLMs see the full list of available types.
    """
    type_list = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
    tool = await mcp.get_tool("netbox_get_objects")
    if tool:
        # Replace the type list portion of the description
        desc = tool.description
        marker = "Valid object_type values:"
        idx = desc.find(marker)
        if idx != -1:
            # Keep everything up to and including the marker, then append new list
            prefix = desc[: idx + len(marker)]
            suffix_marker = "See NetBox API documentation"
            suffix_idx = desc.find(suffix_marker)
            suffix = (
                f"\n\n    {suffix_marker}" + desc[suffix_idx + len(suffix_marker) :]
                if suffix_idx != -1
                else ""
            )
            tool.description = f"{prefix}\n\n{type_list}{suffix}"


def main() -> None:
    """Main entry point for the MCP server."""
    global netbox, branch_policy

    cli_overlay: dict[str, Any] = parse_cli_args()

    try:
        settings = Settings(**cli_overlay)
        check_write_settings(settings)
    except Exception as e:
        print(f"Configuration error: {e}", file=sys.stderr)  # noqa: T201 - before logging configured
        sys.exit(1)

    configure_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    logger.info("Starting NetBox MCP Server")
    logger.info(f"Effective configuration: {settings.get_effective_config_summary()}")

    if not settings.verify_ssl:
        logger.warning(
            "SSL certificate verification is DISABLED. "
            "This is insecure and should only be used for testing."
        )

    if settings.transport == "http" and settings.host in ["0.0.0.0", "::", "[::]"]:  # noqa: S104 - checking, not binding
        logger.warning(
            f"HTTP transport is bound to {settings.host}:{settings.port}, which exposes the "
            "service to all network interfaces (IPv4/IPv6). This is insecure and should only be "
            "used for testing. Ensure this is secured with TLS/reverse proxy if exposed to network."
        )
    elif settings.transport == "http" and settings.host not in [
        "127.0.0.1",
        "localhost",
    ]:
        logger.info(
            f"HTTP transport is bound to {settings.host}:{settings.port}. "
            "Ensure this is secured with TLS/reverse proxy if exposed to network."
        )

    try:
        netbox = NetBoxRestClient(
            url=str(settings.netbox_url),
            token=settings.netbox_token.get_secret_value(),
            verify_ssl=settings.verify_ssl,
        )
        logger.debug("NetBox client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize NetBox client: {e}")
        sys.exit(1)

    branch_policy = BranchPolicy(
        write_enabled=settings.enable_write,
        allow_foreign_branches=settings.allow_foreign_branches,
        allow_branch_events=settings.allow_branch_events,
        allowed_event_rules=frozenset(settings.allowed_branch_event_rules),
        unrestricted_token=settings.unrestricted_token,
        configured_username=settings.netbox_username,
    )
    if settings.enable_write:
        branch_policy.branchable_types = discover_branchable_types(netbox)
        if branch_policy.branchable_types is not None:
            netbox.branchable_endpoints = frozenset(
                endpoint for endpoint in branch_policy.branchable_types.values() if endpoint
            )
        warn_if_unverified_versions(netbox)
        register_write_tools()
        logger.warning("Write tools enabled: changes can be made inside NetBox Branching branches")

    if settings.enable_plugin_discovery:
        plugin_types = discover_plugin_types(netbox)
        if plugin_types:
            NETBOX_OBJECT_TYPES.update(plugin_types)
            asyncio.run(_update_tool_descriptions())

    try:
        if settings.transport == "stdio":
            logger.info("Starting stdio transport")
            mcp.run(transport="stdio")
        elif settings.transport == "http":
            logger.info(f"Starting HTTP transport on {settings.host}:{settings.port}")
            auth = build_http_auth(settings.mcp_auth_token)
            if auth is not None:
                # FastMCP reads mcp.auth when it builds the HTTP app at run time,
                # so this assignment wires it (the 401 tests verify enforcement).
                mcp.auth = auth
                logger.info("HTTP transport authentication enabled (bearer token required)")
            else:
                logger.warning(
                    "HTTP transport is running without authentication. Set "
                    "MCP_AUTH_TOKEN, or place the server behind an authenticating "
                    "TLS reverse proxy or gateway before exposing it to a network."
                )
            middleware = [
                Middleware(
                    CORSMiddleware,
                    allow_origins=settings.cors_origins,
                    allow_methods=["GET", "POST", "OPTIONS"],
                    allow_headers=[
                        "Authorization",
                        "mcp-protocol-version",
                        "mcp-session-id",
                    ],
                    expose_headers=["mcp-session-id"],
                )
            ]
            mcp.run(transport="http", host=settings.host, port=settings.port, middleware=middleware)
    except Exception as e:
        logger.error(f"Failed to start MCP server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
