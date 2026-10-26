"""NetBox MCP Server (rw fork) - read-only by default, with branch-only write tools."""

__version__ = "1.2.2"  # Auto-managed by semantic-release

__all__ = ["NETBOX_OBJECT_TYPES", "NetBoxRestClient", "Settings"]

from netbox_mcp_server.config import Settings
from netbox_mcp_server.netbox_client import NetBoxRestClient
from netbox_mcp_server.netbox_types import NETBOX_OBJECT_TYPES
