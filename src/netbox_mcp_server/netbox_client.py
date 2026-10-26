#!/usr/bin/env python3
"""
NetBox Client Library

This module provides a base class for NetBox client implementations and a REST API implementation.
"""

import abc
import re
from typing import Any

import httpx

# The only write allowed without a branch: creating a branch (POST to this endpoint)
BRANCHES_ENDPOINT = "plugins/branching/branches"

# NetBox Branching only isolates change-logged, non-exempt models. Writes to anything else
# (users, tokens, permissions, core, bookmarks, branches themselves) land in main
# immediately even with X-NetBox-Branch set, so branch writes are allow-listed to these
# endpoint prefixes: the core inventory apps plus the change-logged extras whose writes
# have no side effects in main. Config contexts and templates are left out: saving one
# creates or deletes its core.AutoSyncRecord, which lives in main. Plugin models are left
# out because their side effects in main are unknown.
BRANCHABLE_ENDPOINT_PREFIXES = (
    "circuits/",
    "dcim/",
    "ipam/",
    "tenancy/",
    "virtualization/",
    "vpn/",
    "wireless/",
    "extras/journal-entries/",
    "extras/tags/",
)


# Plain path segments only: rejects '.', '..', empty and percent-encoded segments, which
# httpx or the server would normalize into a different endpoint after the prefix check
_ENDPOINT_PATTERN = re.compile(r"[a-z0-9_-]+(/[a-z0-9_-]+)*")


def is_branchable_endpoint(endpoint: str) -> bool:
    """Whether writes to this endpoint are isolated by NetBox Branching.

    Args:
        endpoint: API endpoint path, e.g. "dcim/sites" (leading/trailing slashes ignored)

    Returns:
        True only for plain lowercase path segments (no '.', '..', empty or
        percent-encoded segments) under one of BRANCHABLE_ENDPOINT_PREFIXES.
    """
    endpoint = endpoint.strip("/")
    if not _ENDPOINT_PATTERN.fullmatch(endpoint):
        return False
    return (endpoint + "/").startswith(BRANCHABLE_ENDPOINT_PREFIXES)


class NetBoxClientBase(abc.ABC):
    """
    Abstract base class for NetBox client implementations.

    This class defines the interface for CRUD operations that can be implemented
    either via the REST API or directly via the ORM in a NetBox plugin.

    Every mutating method takes a required keyword-only ``branch``: the schema ID of
    the NetBox Branching branch to write to. Implementations must build their request
    headers with _write_headers(), which refuses writes to main (the only exception is
    creating a branch) and writes to endpoints that branching does not isolate.
    """

    # Endpoints NetBox reports as branchable, set at startup to narrow the static
    # allow-list; None means only the static BRANCHABLE_ENDPOINT_PREFIXES check applies
    branchable_endpoints: frozenset[str] | None = None

    def is_writable_endpoint(self, endpoint: str) -> bool:
        """Whether branch writes to this endpoint are allowed.

        Args:
            endpoint: API endpoint path, e.g. "dcim/sites"

        Returns:
            True if the endpoint passes the static allow-list and, when NetBox reported
            its branchable models, is one of them.
        """
        if not is_branchable_endpoint(endpoint):
            return False
        return self.branchable_endpoints is None or endpoint.strip("/") in (
            self.branchable_endpoints
        )

    def _write_headers(
        self, method: str, endpoint: str, branch: str | None
    ) -> dict[str, str] | None:
        """Return the X-NetBox-Branch header for a write, refusing anything that could hit main."""
        if method == "create" and branch is None and endpoint.strip("/") == BRANCHES_ENDPOINT:
            return None
        if not branch:
            raise ValueError(f"Refusing to write to main: no branch given for '{endpoint}'")
        if not self.is_writable_endpoint(endpoint):
            raise ValueError(
                f"Refusing to write to '{endpoint}': NetBox Branching does not isolate it, "
                "so the change would land in main"
            )
        return {"X-NetBox-Branch": branch}

    @abc.abstractmethod
    def get(
        self,
        endpoint: str,
        id: int | None = None,
        params: dict[str, Any] | None = None,
        fallback_endpoint: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """
        Retrieve one or more objects from NetBox.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            id: Optional ID to retrieve a specific object
            params: Optional query parameters for filtering
            fallback_endpoint: Optional alternative endpoint to try if primary returns 404
                               (used for NetBox version compatibility)
            headers: Optional extra request headers (e.g. X-NetBox-Branch to read a branch)

        Returns:
            For single object queries (with id): Returns the object dict
            For list queries (without id): Returns the full paginated response dict with:
                - count: Total number of objects matching the query
                - next: URL to next page (or null if no more pages)
                - previous: URL to previous page (or null if on first page)
                - results: Array of objects for this page
        """
        pass

    @abc.abstractmethod
    def create(self, endpoint: str, data: dict[str, Any], *, branch: str | None) -> dict[str, Any]:
        """
        Create a new object in NetBox.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            data: Object data to create
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            The created object as a dict
        """
        pass

    @abc.abstractmethod
    def update(
        self, endpoint: str, id: int, data: dict[str, Any], *, branch: str | None
    ) -> dict[str, Any]:
        """
        Update an existing object in NetBox.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            id: ID of the object to update
            data: Object data to update
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            The updated object as a dict
        """
        pass

    @abc.abstractmethod
    def delete(self, endpoint: str, id: int, *, branch: str | None) -> bool:
        """
        Delete an object from NetBox.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            id: ID of the object to delete
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            True if deletion was successful, False otherwise
        """
        pass

    @abc.abstractmethod
    def bulk_create(
        self, endpoint: str, data: list[dict[str, Any]], *, branch: str | None
    ) -> list[dict[str, Any]]:
        """
        Create multiple objects in NetBox.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            data: List of object data to create
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            List of created objects as dicts
        """
        pass

    @abc.abstractmethod
    def bulk_update(
        self, endpoint: str, data: list[dict[str, Any]], *, branch: str | None
    ) -> list[dict[str, Any]]:
        """
        Update multiple objects in NetBox.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            data: List of object data to update (must include ID)
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            List of updated objects as dicts
        """
        pass

    @abc.abstractmethod
    def bulk_delete(self, endpoint: str, ids: list[int], *, branch: str | None) -> bool:
        """
        Delete multiple objects from NetBox.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            ids: List of IDs to delete
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            True if deletion was successful, False otherwise
        """
        pass


class NetBoxRestClient(NetBoxClientBase):
    """
    NetBox client implementation using the REST API.
    """

    # # Example of how to use the client
    # client = NetBoxRestClient(
    #     url="https://netbox.example.com",
    #     token="your_api_token_here",
    #     verify_ssl=True
    # )

    # # Get all sites
    # sites = client.get("dcim/sites")
    # print(f"Found {len(sites)} sites")

    # # Get a specific site
    # site = client.get("dcim/sites", id=1)
    # print(f"Site name: {site.get('name')}")

    # # Create a new site
    # new_site = client.create("dcim/sites", {
    #     "name": "New Site",
    #     "slug": "new-site",
    #     "status": "active"
    # })
    # print(f"Created site: {new_site.get('name')} (ID: {new_site.get('id')})")

    def __init__(self, url: str, token: str, verify_ssl: bool = True):
        """
        Initialize the REST API client.

        Args:
            url: The base URL of the NetBox instance (e.g., 'https://netbox.example.com')
            token: API token for authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = url.rstrip("/")
        self.api_url = f"{self.base_url}/api"
        self.token = token
        self.verify_ssl = verify_ssl
        auth_scheme = "Bearer" if token.startswith("nbt_") else "Token"
        self.session = httpx.Client(verify=self.verify_ssl)
        self.session.headers.update(
            {
                "Authorization": f"{auth_scheme} {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def _build_url(self, endpoint: str, id: int | None = None) -> str:
        """Build the full URL for an API request."""
        endpoint = endpoint.strip("/")
        if id is not None:
            return f"{self.api_url}/{endpoint}/{id}/"
        return f"{self.api_url}/{endpoint}/"

    def get(
        self,
        endpoint: str,
        id: int | None = None,
        params: dict[str, Any] | None = None,
        fallback_endpoint: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """
        Retrieve one or more objects from NetBox via the REST API.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            id: Optional ID to retrieve a specific object
            params: Optional query parameters for filtering
            fallback_endpoint: Optional alternative endpoint to try if primary returns 404
                               (used for NetBox version compatibility)

        Returns:
            For single object queries (with id): Returns the object dict
            For list queries (without id): Returns the full paginated response dict with:
                - count: Total number of objects matching the query
                - next: URL to next page (or null)
                - previous: URL to previous page (or null)
                - results: Array of objects for this page

        Raises:
            httpx.HTTPStatusError: If the request fails
        """
        url = self._build_url(endpoint, id)
        response = self.session.get(url, params=params, headers=headers)

        # Try fallback endpoint if primary returns 404
        if response.status_code == 404 and fallback_endpoint:
            fallback_url = self._build_url(fallback_endpoint, id)
            response = self.session.get(fallback_url, params=params, headers=headers)

        response.raise_for_status()

        return response.json()

    def create(self, endpoint: str, data: dict[str, Any], *, branch: str | None) -> dict[str, Any]:
        """
        Create a new object in NetBox via the REST API.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            data: Object data to create
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            The created object as a dict

        Raises:
            httpx.HTTPStatusError: If the request fails
        """
        url = self._build_url(endpoint)
        headers = self._write_headers("create", endpoint, branch)
        response = self.session.post(url, json=data, headers=headers)
        response.raise_for_status()
        return response.json()

    def update(
        self, endpoint: str, id: int, data: dict[str, Any], *, branch: str | None
    ) -> dict[str, Any]:
        """
        Update an existing object in NetBox via the REST API.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            id: ID of the object to update
            data: Object data to update
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            The updated object as a dict

        Raises:
            httpx.HTTPStatusError: If the request fails
        """
        url = self._build_url(endpoint, id)
        headers = self._write_headers("update", endpoint, branch)
        response = self.session.patch(url, json=data, headers=headers)
        response.raise_for_status()
        return response.json()

    def delete(self, endpoint: str, id: int, *, branch: str | None) -> bool:
        """
        Delete an object from NetBox via the REST API.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            id: ID of the object to delete
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            True if deletion was successful, False otherwise

        Raises:
            httpx.HTTPStatusError: If the request fails
        """
        url = self._build_url(endpoint, id)
        headers = self._write_headers("delete", endpoint, branch)
        response = self.session.delete(url, headers=headers)
        response.raise_for_status()
        return response.status_code == 204

    def bulk_create(
        self, endpoint: str, data: list[dict[str, Any]], *, branch: str | None
    ) -> list[dict[str, Any]]:
        """
        Create multiple objects in NetBox via the REST API.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            data: List of object data to create
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            List of created objects as dicts

        Raises:
            httpx.HTTPStatusError: If the request fails
        """
        url = self._build_url(endpoint)  # NetBox does bulk operations on the list URL
        headers = self._write_headers("bulk_create", endpoint, branch)
        response = self.session.post(url, json=data, headers=headers)
        response.raise_for_status()
        return response.json()

    def bulk_update(
        self, endpoint: str, data: list[dict[str, Any]], *, branch: str | None
    ) -> list[dict[str, Any]]:
        """
        Update multiple objects in NetBox via the REST API.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            data: List of object data to update (must include ID)
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            List of updated objects as dicts

        Raises:
            httpx.HTTPStatusError: If the request fails
        """
        url = self._build_url(endpoint)  # NetBox does bulk operations on the list URL
        headers = self._write_headers("bulk_update", endpoint, branch)
        response = self.session.patch(url, json=data, headers=headers)
        response.raise_for_status()
        return response.json()

    def bulk_delete(self, endpoint: str, ids: list[int], *, branch: str | None) -> bool:
        """
        Delete multiple objects from NetBox via the REST API.

        Args:
            endpoint: The API endpoint (e.g., 'dcim/sites', 'ipam/prefixes')
            ids: List of IDs to delete
            branch: Schema ID of the branch to write to (None only to create a branch)

        Returns:
            True if deletion was successful, False otherwise

        Raises:
            httpx.HTTPStatusError: If the request fails
        """
        url = self._build_url(endpoint)  # NetBox does bulk operations on the list URL
        headers = self._write_headers("bulk_delete", endpoint, branch)
        data = [{"id": id} for id in ids]
        response = self.session.request("DELETE", url, json=data, headers=headers)
        response.raise_for_status()
        return response.status_code == 204
