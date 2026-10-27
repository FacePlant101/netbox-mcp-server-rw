"""Tests for the branch-only write tools."""

import asyncio
import sys
from unittest.mock import MagicMock, patch

import httpx
import pytest
from pydantic import SecretStr

from netbox_mcp_server import server
from netbox_mcp_server.config import Settings
from netbox_mcp_server.netbox_client import NetBoxRestClient, is_branchable_endpoint
from netbox_mcp_server.netbox_types import NETBOX_OBJECT_TYPES
from netbox_mcp_server.server import (
    WRITE_TOOLS,
    BranchPolicy,
    check_write_settings,
    discover_branchable_types,
    main,
    mcp,
    netbox_create_branch,
    netbox_create_objects,
    netbox_delete_objects,
    netbox_get_changelogs,
    netbox_get_object_by_id,
    netbox_get_objects,
    netbox_list_branches,
    netbox_search_objects,
    netbox_update_objects,
)

ME = {"id": 7, "username": "me"}
OTHER = {"id": 8, "username": "colleague", "display": "colleague"}
READY = {
    "id": 1,
    "name": "my-branch",
    "schema_id": "abcd1234",
    "status": {"value": "ready"},
    "owner": ME,
}
MERGED = {
    "id": 2,
    "name": "old-branch",
    "schema_id": "zzzz9999",
    "status": {"value": "merged"},
    "owner": ME,
}
FOREIGN = {**READY, "id": 3, "name": "their-branch", "schema_id": "ffff0000", "owner": OTHER}
SCHEMA_ID = "abcd1234"


# What NetBox would report as branchable: the allow-listed core types
STATIC_TYPES = {
    t: info["endpoint"]
    for t, info in NETBOX_OBJECT_TYPES.items()
    if is_branchable_endpoint(info["endpoint"])
}


@pytest.fixture(autouse=True)
def _reset_branch_policy(monkeypatch):
    """Give each test a fresh branch policy acting as user ME, with a token that sees all."""
    policy = BranchPolicy(
        write_enabled=True,
        current_user_id=ME["id"],
        unrestricted_token=True,
        branchable_types=dict(STATIC_TYPES),
    )
    monkeypatch.setattr(server, "branch_policy", policy)


def _branches(*branches, next_url=None, count=None):
    """A page of branches; count is the total across pages, as NetBox reports it."""
    total = len(branches) if count is None else count
    return {"count": total, "next": next_url, "previous": None, "results": list(branches)}


# ============================================================================
# Branch enforcement
# ============================================================================


@pytest.mark.parametrize("branch", ["", "   ", None])
@patch("netbox_mcp_server.server.netbox")
def test_write_without_branch_is_rejected(mock_netbox, branch):
    with pytest.raises(ValueError, match="never written to main"):
        netbox_create_objects("dcim.site", branch, {"name": "x", "slug": "x"})
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_unknown_branch_is_rejected(mock_netbox):
    mock_netbox.get.return_value = _branches(READY)
    with pytest.raises(ValueError, match="exactly one branch"):
        netbox_create_objects("dcim.site", "nope", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_branch_that_is_not_ready_is_rejected(mock_netbox):
    mock_netbox.get.return_value = _branches(READY, MERGED)
    with pytest.raises(ValueError, match="must be 'ready'"):
        netbox_delete_objects("dcim.site", "old-branch", 5)
    mock_netbox.delete.assert_not_called()


@pytest.mark.parametrize("branch", ["my-branch", "abcd1234"])
@patch("netbox_mcp_server.server.netbox")
def test_branch_resolves_by_name_or_schema_id(mock_netbox, branch):
    mock_netbox.get.return_value = _branches(READY, MERGED)
    netbox_create_objects("dcim.site", branch, {"name": "x", "slug": "x"})
    mock_netbox.create.assert_called_once_with(
        "dcim/sites", {"name": "x", "slug": "x"}, branch=SCHEMA_ID
    )


@patch("netbox_mcp_server.server.netbox")
def test_branch_resolution_filters_and_paginates(mock_netbox):
    """A branch beyond the first page is found; lookups are filtered and minimal."""
    mock_netbox.get.side_effect = [
        _branches(MERGED, next_url="https://nb/next", count=2),
        _branches(READY, count=2),
        {"next": None, "results": []},  # event rules
        {"next": None, "results": []},  # subscriptions
    ]
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    first, second = (c.kwargs["params"] for c in mock_netbox.get.call_args_list[:2])
    assert first["name"] == "my-branch"
    assert first["fields"] == "id,name,schema_id,status,owner"
    # Keyset paging: the second page asks for ids above the last one received
    assert "id__gt" not in first
    assert "offset" not in first
    assert second["id__gt"] == MERGED["id"]
    mock_netbox.create.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_name_lookup_needs_one_request_and_is_cached(mock_netbox):
    mock_netbox.get.return_value = _branches(READY)
    for _ in range(3):
        netbox_update_objects("dcim.device", "my-branch", {"status": "offline"}, object_id=1)
    branch_lookups = [
        c for c in mock_netbox.get.call_args_list if c.args[0] == "plugins/branching/branches"
    ]
    assert len(branch_lookups) == 1
    assert mock_netbox.update.call_count == 3


@patch("netbox_mcp_server.server.netbox")
def test_foreign_branch_is_rejected_for_writes(mock_netbox):
    mock_netbox.get.return_value = _branches(FOREIGN)
    with pytest.raises(ValueError, match="belongs to 'colleague'"):
        netbox_create_objects("dcim.site", "their-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_foreign_branch_allowed_with_opt_in_and_for_reads(mock_netbox, monkeypatch):
    mock_netbox.get.return_value = _branches(FOREIGN)
    netbox_get_objects("dcim.site", {}, branch="their-branch")
    server.branch_policy.allow_foreign_branches = True
    netbox_create_objects("dcim.site", "their-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_current_user_comes_from_authentication_check(mock_netbox, monkeypatch):
    server.branch_policy.current_user_id = None
    mock_netbox.get.side_effect = lambda endpoint, **kw: (
        ME if endpoint == "authentication-check" else _branches(READY)
    )
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    netbox_create_objects("dcim.site", "my-branch", {"name": "y", "slug": "y"})
    endpoints = [c.args[0] for c in mock_netbox.get.call_args_list]
    assert endpoints.count("authentication-check") == 1


@pytest.mark.parametrize(
    "object_type",
    ["users.token", "users.user", "core.datasource", "extras.bookmark", "extras.webhook"],
)
@patch("netbox_mcp_server.server.netbox")
def test_non_branchable_types_are_rejected(mock_netbox, object_type):
    # The real client's check with no discovered endpoints is the static allow-list
    mock_netbox.is_writable_endpoint.side_effect = is_branchable_endpoint
    for call in (
        lambda: netbox_create_objects(object_type, "my-branch", {"name": "x"}),
        lambda: netbox_update_objects(object_type, "my-branch", {"name": "x"}, object_id=1),
        lambda: netbox_delete_objects(object_type, "my-branch", 1),
    ):
        with pytest.raises(ValueError, match="not isolated by NetBox Branching"):
            call()
    mock_netbox.get.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_branchable_extras_type_is_allowed(mock_netbox):
    mock_netbox.get.return_value = _branches(READY)
    netbox_create_objects("extras.tag", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_called_once()


# ============================================================================
# Create / update / delete pass the branch to the client
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_bulk_create_uses_branch(mock_netbox):
    mock_netbox.get.return_value = _branches(READY)
    data = [{"address": "10.0.0.1/24"}, {"address": "10.0.0.2/24"}]
    netbox_create_objects("ipam.ipaddress", "my-branch", data)
    mock_netbox.bulk_create.assert_called_once_with("ipam/ip-addresses", data, branch=SCHEMA_ID)


@patch("netbox_mcp_server.server.netbox")
def test_update_single_and_bulk(mock_netbox):
    mock_netbox.get.return_value = _branches(READY)
    netbox_update_objects("dcim.device", "my-branch", {"status": "offline"}, object_id=42)
    mock_netbox.update.assert_called_once_with(
        "dcim/devices", 42, {"status": "offline"}, branch=SCHEMA_ID
    )

    data = [{"id": 1, "enabled": False}, {"id": 2, "enabled": False}]
    netbox_update_objects("dcim.interface", "my-branch", data)
    mock_netbox.bulk_update.assert_called_once_with("dcim/interfaces", data, branch=SCHEMA_ID)


@patch("netbox_mcp_server.server.netbox")
def test_update_argument_validation(mock_netbox):
    with pytest.raises(ValueError, match="object_id is required"):
        netbox_update_objects("dcim.device", "my-branch", {"status": "offline"})
    with pytest.raises(ValueError, match="must include 'id'"):
        netbox_update_objects("dcim.device", "my-branch", [{"status": "offline"}])
    mock_netbox.update.assert_not_called()
    mock_netbox.bulk_update.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_empty_lists_are_rejected(mock_netbox):
    with pytest.raises(ValueError, match="nothing to create"):
        netbox_create_objects("dcim.site", "my-branch", [])
    with pytest.raises(ValueError, match="nothing to update"):
        netbox_update_objects("dcim.site", "my-branch", [])
    with pytest.raises(ValueError, match="nothing to delete"):
        netbox_delete_objects("dcim.site", "my-branch", [])
    mock_netbox.get.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_single_and_bulk(mock_netbox):
    mock_netbox.get.return_value = _branches(READY)
    assert netbox_delete_objects("dcim.site", "my-branch", 5) == {
        "deleted": [5],
        "branch": SCHEMA_ID,
    }
    mock_netbox.delete.assert_called_once_with("dcim/sites", 5, branch=SCHEMA_ID)

    netbox_delete_objects("dcim.site", "my-branch", [5, 6])
    mock_netbox.bulk_delete.assert_called_once_with("dcim/sites", [5, 6], branch=SCHEMA_ID)


@patch("netbox_mcp_server.server.netbox")
def test_invalid_object_type_is_rejected(mock_netbox):
    with pytest.raises(ValueError, match="Invalid object_type"):
        netbox_create_objects("dcim.nonsense", "my-branch", {})
    mock_netbox.get.assert_not_called()


# ============================================================================
# Branch tools
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_create_branch_writes_to_main_explicitly(mock_netbox):
    netbox_create_branch("my-branch", "desc")
    mock_netbox.create.assert_called_once_with(
        "plugins/branching/branches", {"name": "my-branch", "description": "desc"}, branch=None
    )


def _http_error(status, text="", method="GET"):
    request = httpx.Request(method, "https://netbox.example.com/api/plugins/branching/branches/")
    return httpx.HTTPStatusError(
        "error", request=request, response=httpx.Response(status, text=text, request=request)
    )


@pytest.mark.parametrize(
    "call",
    [
        lambda: netbox_list_branches(),
        lambda: netbox_create_branch("b"),
        lambda: netbox_create_objects("dcim.site", "my-branch", {"name": "x"}),
    ],
)
@patch("netbox_mcp_server.server.netbox")
def test_missing_branching_plugin_is_explained(mock_netbox, call):
    mock_netbox.get.side_effect = _http_error(404)
    mock_netbox.create.side_effect = _http_error(404, method="POST")
    with pytest.raises(ValueError, match="netbox-branching plugin is not available"):
        call()


@patch("netbox_mcp_server.server.netbox")
def test_error_body_is_truncated(mock_netbox):
    mock_netbox.get.return_value = _branches(READY)
    mock_netbox.create.side_effect = _http_error(500, text="x" * 50_000, method="POST")
    with pytest.raises(ValueError, match="NetBox returned 500") as exc:
        netbox_create_objects("dcim.site", "my-branch", {"name": "x"})
    assert len(str(exc.value)) < 2500
    assert "truncated" in str(exc.value)


@patch("netbox_mcp_server.server.netbox")
def test_list_branches_paginates(mock_netbox):
    netbox_list_branches(limit=10, offset=20)
    params = mock_netbox.get.call_args.kwargs["params"]
    assert (params["limit"], params["offset"]) == (10, 20)


# ============================================================================
# Client-level enforcement
# ============================================================================


@pytest.fixture
def client():
    c = NetBoxRestClient(url="https://netbox.example.com", token="x")
    c.session = MagicMock()
    c.session.post.return_value.status_code = 201
    c.session.request.return_value.status_code = 204
    return c


def test_client_refuses_writes_to_main(client):
    with pytest.raises(ValueError, match="Refusing to write to main"):
        client.create("dcim/sites", {"name": "x"}, branch=None)
    with pytest.raises(ValueError, match="Refusing to write to main"):
        client.bulk_delete("dcim/sites", [1, 2], branch=None)
    client.session.post.assert_not_called()
    client.session.request.assert_not_called()


def test_client_requires_branch_argument(client):
    with pytest.raises(TypeError):
        client.create("dcim/sites", {"name": "x"})


def test_client_sends_branch_header(client):
    client.create("dcim/sites", {"name": "x"}, branch="abcd1234")
    assert client.session.post.call_args.kwargs["headers"] == {"X-NetBox-Branch": "abcd1234"}
    client.bulk_delete("dcim/sites", [1, 2], branch="abcd1234")
    assert client.session.request.call_args.kwargs["headers"] == {"X-NetBox-Branch": "abcd1234"}


def test_client_allows_only_branch_creation_on_main(client):
    client.create("plugins/branching/branches", {"name": "b"}, branch=None)
    assert client.session.post.call_args.kwargs["headers"] is None
    with pytest.raises(ValueError, match="Refusing to write to main"):
        client.delete("plugins/branching/branches", 7, branch=None)
    with pytest.raises(ValueError, match="Refusing to write to main"):
        client.update("plugins/branching/branches", 7, {"name": "x"}, branch=None)


@pytest.mark.parametrize(
    "endpoint",
    [
        "users/tokens",
        "users/users",
        "core/data-sources",
        "extras/webhooks",
        "plugins/x/y",
        # Saving these creates or deletes their core.AutoSyncRecord, which lives in main
        "extras/config-contexts",
        "extras/config-templates",
    ],
)
def test_client_refuses_non_branchable_endpoints_even_with_branch(client, endpoint):
    with pytest.raises(ValueError, match="does not isolate it"):
        client.create(endpoint, {"name": "x"}, branch="abcd1234")
    client.session.post.assert_not_called()


@pytest.mark.parametrize("endpoint", ["dcim/sites", "/ipam/prefixes/", "extras/tags"])
def test_client_allows_branchable_endpoints(client, endpoint):
    client.create(endpoint, {"name": "x"}, branch="abcd1234")
    client.session.post.assert_called_once()


# ============================================================================
# Reads
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_get_objects_reads_from_main_without_branch(mock_netbox):
    netbox_get_objects("dcim.site", {})
    assert mock_netbox.get.call_args.kwargs["headers"] is None


@patch("netbox_mcp_server.server.netbox")
def test_search_reads_from_branch(mock_netbox):
    mock_netbox.get.side_effect = [_branches(READY), {"results": [{"id": 1}]}]
    result = netbox_search_objects("x", object_types=["dcim.site"], branch="my-branch")
    assert result == {"dcim.site": [{"id": 1}]}
    assert mock_netbox.get.call_args.kwargs["headers"] == {"X-NetBox-Branch": SCHEMA_ID}


@patch("netbox_mcp_server.server.netbox")
def test_get_objects_reads_from_branch(mock_netbox):
    mock_netbox.get.side_effect = [_branches(READY), {"results": []}]
    netbox_get_objects("dcim.site", {}, branch="my-branch")
    assert mock_netbox.get.call_args.kwargs["headers"] == {"X-NetBox-Branch": SCHEMA_ID}


# ============================================================================
# Registration and settings
# ============================================================================


def test_write_tools_not_registered_by_default():
    tools = {t.name for t in asyncio.run(mcp.list_tools())}
    assert not tools & {fn.__name__ for fn, _ in WRITE_TOOLS}


def test_delete_is_not_marked_idempotent():
    annotations = {fn.__name__: a for fn, a in WRITE_TOOLS}["netbox_delete_objects"]
    assert "idempotentHint" not in annotations


def _settings(**overrides):
    return Settings(
        netbox_url="https://netbox.example.com/",
        netbox_token="x",
        _env_file=None,
        **overrides,
    )


def test_enable_write_defaults_to_false():
    assert _settings().enable_write is False


def test_write_over_unauthenticated_http_is_refused():
    with pytest.raises(ValueError, match="requires MCP_AUTH_TOKEN"):
        check_write_settings(_settings(enable_write=True, transport="http"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"enable_write": True, "transport": "http", "mcp_auth_token": SecretStr("s3cret")},
        {"enable_write": True, "transport": "stdio"},
        {"enable_write": False, "transport": "http"},
    ],
)
def test_write_settings_allowed(overrides):
    check_write_settings(_settings(**overrides))


# ============================================================================
# main() wiring
# ============================================================================


@pytest.fixture
def main_env(monkeypatch, tmp_path):
    """Run main() from an empty directory (no .env) with mcp.run and the client stubbed."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["netbox-mcp-server"])
    monkeypatch.setenv("NETBOX_URL", "https://netbox.example.com/")
    monkeypatch.setenv("NETBOX_TOKEN", "x")
    for var in ("TRANSPORT", "ENABLE_WRITE", "MCP_AUTH_TOKEN", "ALLOW_FOREIGN_BRANCHES"):
        monkeypatch.delenv(var, raising=False)
    with (
        patch("netbox_mcp_server.server.NetBoxRestClient"),
        patch.object(mcp, "run") as run,
        patch("netbox_mcp_server.server.register_write_tools") as register,
    ):
        yield monkeypatch, run, register


def test_main_refuses_write_over_unauthenticated_http(main_env):
    monkeypatch, run, register = main_env
    monkeypatch.setenv("TRANSPORT", "http")
    monkeypatch.setenv("ENABLE_WRITE", "true")
    with pytest.raises(SystemExit):
        main()
    run.assert_not_called()
    register.assert_not_called()


def test_main_registers_write_tools_when_enabled(main_env):
    monkeypatch, run, register = main_env
    monkeypatch.setenv("ENABLE_WRITE", "true")
    monkeypatch.setenv("ALLOW_FOREIGN_BRANCHES", "true")
    discovered = {"dcim.site": "dcim/sites"}
    with patch(
        "netbox_mcp_server.server.discover_branchable_types", return_value=discovered
    ) as discover:
        main()
    discover.assert_called_once_with(server.netbox)
    assert server.branch_policy.branchable_types == discovered
    assert server.netbox.branchable_endpoints == frozenset({"dcim/sites"})
    register.assert_called_once()
    assert server.branch_policy.allow_foreign_branches is True
    run.assert_called_once()


def test_main_does_not_register_write_tools_by_default(main_env):
    _, run, register = main_env
    main()
    register.assert_not_called()
    run.assert_called_once()


# ============================================================================
# Branch lookup edge cases
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_branch_that_is_not_ready_is_not_cached(mock_netbox):
    provisioning = {**READY, "status": {"value": "new"}}
    mock_netbox.get.return_value = _branches(provisioning)
    with pytest.raises(ValueError, match="has status 'new'"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.get.return_value = _branches(READY)
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_name_shadowing_a_schema_id_is_ambiguous(mock_netbox):
    impostor = {**READY, "id": 9, "name": "abcd1234", "schema_id": "eeee1111"}
    mock_netbox.get.side_effect = [_branches(impostor, READY)]
    with pytest.raises(ValueError, match="found 2"):
        netbox_create_objects("dcim.site", "abcd1234", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_not_called()
    # netbox-branching has no schema_id filter: one unfiltered listing, not two queries
    assert mock_netbox.get.call_count == 1
    assert "name" not in mock_netbox.get.call_args.kwargs["params"]


@patch("netbox_mcp_server.server.netbox")
def test_unknown_token_user_gives_clear_error(mock_netbox):
    server.branch_policy.current_user_id = None

    def fake_get(endpoint, **kwargs):
        if endpoint == "authentication-check":
            raise _http_error(404)
        return _branches(READY)

    mock_netbox.get.side_effect = fake_get
    with pytest.raises(ValueError, match="Can't determine the API token's user"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_list_branches_marks_writable(mock_netbox):
    provisioning = {**READY, "id": 4, "name": "new-branch", "status": {"value": "new"}}
    mock_netbox.get.return_value = _branches(READY, MERGED, FOREIGN, provisioning)
    results = netbox_list_branches()["results"]
    assert [b["mine"] for b in results] == [True, True, False, True]
    assert [b["writable"] for b in results] == [True, False, False, False]


@patch("netbox_mcp_server.server.netbox")
def test_list_branches_without_known_user_still_lists(mock_netbox):
    server.branch_policy.current_user_id = None

    def fake_get(endpoint, **kwargs):
        if endpoint == "authentication-check":
            raise _http_error(403)
        return _branches(READY, FOREIGN)

    mock_netbox.get.side_effect = fake_get
    results = netbox_list_branches()["results"]
    assert [b["mine"] for b in results] == [None, None]
    assert [b["writable"] for b in results] == [False, False]


@patch("netbox_mcp_server.server.netbox")
@pytest.mark.parametrize("status", [500, 400])
def test_search_in_branch_surfaces_branch_errors(mock_netbox, status):
    """Detected by re-checking the branch, not by matching the (translatable) message.

    netbox-branching 1.1.3 answers 500 for a branch that isn't ready (e.g. merged while
    still cached as ready here), 400 for an unknown one.
    """
    merged_now = {**READY, "status": {"value": "merged"}}
    mock_netbox.get.side_effect = [
        _branches(READY),
        _http_error(status, "Selected branch is not ready."),
        _branches(merged_now),
    ]
    with pytest.raises(ValueError, match="has status 'merged'"):
        netbox_search_objects("x", object_types=["dcim.site"], branch="my-branch")


@pytest.mark.parametrize(
    "endpoint",
    ["dcim/../users/tokens", "dcim/./sites", "dcim//sites", "dcim/%2e%2e/users/tokens"],
)
def test_client_refuses_dot_and_encoded_segments(client, endpoint):
    with pytest.raises(ValueError, match="does not isolate it"):
        client.create(endpoint, {"name": "x"}, branch="abcd1234")
    client.session.post.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_unexpected_auth_check_response_gives_clear_error(mock_netbox):
    """A proxy login page (200 but not the user JSON) is explained, not a raw KeyError."""
    server.branch_policy.current_user_id = None
    mock_netbox.get.side_effect = lambda endpoint, **kw: (
        {"html": "<login>"} if endpoint == "authentication-check" else _branches(READY)
    )
    with pytest.raises(ValueError, match="failed: KeyError"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})


@patch("netbox_mcp_server.server.netbox")
def test_failed_user_lookup_is_not_retried_immediately(mock_netbox):
    server.branch_policy.current_user_id = None

    def fake_get(endpoint, **kwargs):
        if endpoint == "authentication-check":
            raise _http_error(404)
        return _branches(READY)

    mock_netbox.get.side_effect = fake_get
    for _ in range(3):
        with pytest.raises(ValueError, match="Can't determine the API token's user"):
            netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    netbox_list_branches()
    endpoints = [c.args[0] for c in mock_netbox.get.call_args_list]
    assert endpoints.count("authentication-check") == 1


@patch("netbox_mcp_server.server.netbox")
def test_search_in_branch_skips_type_specific_errors(mock_netbox):
    mock_netbox.get.side_effect = [
        _branches(READY),
        _http_error(403, "You do not have permission"),
        {"results": [{"id": 1}]},
    ]
    result = netbox_search_objects(
        "x", object_types=["circuits.circuit", "dcim.site"], branch="my-branch"
    )
    assert result == {"circuits.circuit": [], "dcim.site": [{"id": 1}]}


@patch("netbox_mcp_server.server.netbox")
def test_search_on_main_still_skips_http_errors(mock_netbox):
    mock_netbox.get.side_effect = [
        _http_error(400, "Selected branch is not ready."),
        {"results": [{"id": 1}]},
    ]
    result = netbox_search_objects("x", object_types=["circuits.circuit", "dcim.site"])
    assert result == {"circuits.circuit": [], "dcim.site": [{"id": 1}]}


@patch("netbox_mcp_server.server.netbox")
def test_search_error_in_ready_branch_is_skipped_and_rechecked_once(mock_netbox):
    """The branch is re-checked once, after every type was tried."""
    mock_netbox.get.side_effect = [
        _branches(READY),
        _http_error(400, "bad query"),
        _http_error(500, "type-specific failure"),
        {"results": [{"id": 1}]},
        _branches(READY),
    ]
    result = netbox_search_objects(
        "x", object_types=["circuits.circuit", "dcim.rack", "dcim.site"], branch="my-branch"
    )
    assert result == {"circuits.circuit": [], "dcim.rack": [], "dcim.site": [{"id": 1}]}
    assert mock_netbox.get.call_count == 5


@patch("netbox_mcp_server.server.netbox")
def test_search_catches_branch_merged_after_a_type_specific_error(mock_netbox):
    """An early per-type 500 doesn't use up the check for a branch merged later."""
    merged_now = {**READY, "status": {"value": "merged"}}
    mock_netbox.get.side_effect = [
        _branches(READY),
        _http_error(500, "type-specific failure"),
        {"results": [{"id": 1}]},
        _http_error(500, "branch merged"),
        _branches(merged_now),
    ]
    with pytest.raises(ValueError, match="has status 'merged'"):
        netbox_search_objects(
            "x", object_types=["circuits.circuit", "dcim.rack", "dcim.site"], branch="my-branch"
        )


@pytest.mark.parametrize(
    "read",
    [
        lambda: netbox_get_objects("dcim.site", {}, branch="my-branch"),
        lambda: netbox_get_object_by_id("dcim.site", 1, branch="my-branch"),
        lambda: netbox_get_changelogs({}, branch="my-branch"),
    ],
)
@patch("netbox_mcp_server.server.netbox")
def test_reads_explain_a_branch_merged_while_cached(mock_netbox, read):
    merged_now = {**READY, "status": {"value": "merged"}}
    mock_netbox.get.side_effect = [
        _branches(READY),
        _http_error(500, "Server Error"),
        _branches(merged_now),
    ]
    with pytest.raises(ValueError, match="has status 'merged'"):
        read()


@patch("netbox_mcp_server.server.netbox")
def test_reads_in_a_ready_branch_still_raise_their_own_errors(mock_netbox):
    mock_netbox.get.side_effect = [_branches(READY), _http_error(404), _branches(READY)]
    with pytest.raises(httpx.HTTPStatusError):
        netbox_get_object_by_id("dcim.site", 999, branch="my-branch")


@pytest.mark.parametrize("branch", ["backbone", "AB-12"])
@patch("netbox_mcp_server.server.netbox")
def test_branch_resolves_by_schema_shaped_name_or_other_schema_id_format(mock_netbox, branch):
    """'backbone' is a name shaped like a schema ID; the other is a schema ID of another
    format, found by the fallback listing when no branch has that name."""
    shaped = {**READY, "name": "backbone", "schema_id": "zzzz0000"}
    odd = {**READY, "id": 5, "name": "odd", "schema_id": "AB-12"}
    mock_netbox.get.side_effect = lambda endpoint, params=None, **kw: (
        _branches(*[b for b in (shaped, odd) if b["name"] == params["name"]])
        if params and "name" in params
        else _branches(shaped, odd)
        if endpoint == "plugins/branching/branches"
        else {"next": None, "results": []}
    )
    netbox_create_objects("dcim.site", branch, {"name": "x", "slug": "x"})
    expected = "zzzz0000" if branch == "backbone" else "AB-12"
    assert mock_netbox.create.call_args.kwargs["branch"] == expected


def test_get_all_pages_by_id():
    """Keyset paging: ordered by id, each page asks for ids above the last one received,
    so a row deleted mid-read can't shift a later row past a page boundary."""
    client = MagicMock()
    client.get.side_effect = [
        {"next": "https://nb/next", "results": [{"id": 1}, {"id": 4}]},
        {"next": None, "results": [{"id": 7}]},
    ]
    rows = server._get_all("core/jobs", {"limit": 2}, client=client)
    assert [r["id"] for r in rows] == [1, 4, 7]
    first, second = (c.kwargs["params"] for c in client.get.call_args_list)
    assert first["ordering"] == second["ordering"] == "id"
    assert "id__gt" not in first
    assert second["id__gt"] == 4
    assert server.SCHEMA_ID_PATTERN.pattern == "[a-z0-9]{8}"


def test_get_all_refuses_a_repeated_page():
    """An ignored id__gt filter repeats page 1: refuse rather than return partial data."""
    client = MagicMock()
    client.get.return_value = {"count": 3, "next": "https://nb/next", "results": [{"id": 1}]}
    with pytest.raises(ValueError, match="didn't advance"):
        server._get_all("dcim/sites", {"limit": 1}, client=client)
    assert client.get.call_count == 2


@patch("netbox_mcp_server.server.netbox")
def test_event_rule_check_refuses_when_pages_repeat(mock_netbox):
    rule_page = {"count": 2, "next": "https://nb/next", "results": [DEVICE_RULE]}
    mock_netbox.get.side_effect = lambda endpoint, **kw: (
        rule_page if endpoint == "extras/event-rules" else _branches(READY)
    )
    with pytest.raises(ValueError, match="didn't advance"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_not_called()


# ============================================================================
# Branch creation limits
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_create_branch_returns_my_existing_branch(mock_netbox):
    mock_netbox.get.return_value = _branches(READY)
    result = netbox_create_branch("my-branch")
    assert result["existing"] is True
    assert result["schema_id"] == SCHEMA_ID
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_create_branch_refuses_someone_elses_name(mock_netbox):
    mock_netbox.get.return_value = _branches(FOREIGN)
    with pytest.raises(ValueError, match="already exists and isn't yours"):
        netbox_create_branch("their-branch")
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_create_branch_caps_open_branches(mock_netbox):
    open_ones = [
        {**READY, "id": 100 + i, "name": f"b{i}", "schema_id": f"s{i:07d}"}
        for i in range(server.MAX_OPEN_BRANCHES)
    ]
    closed = {**MERGED, "id": 99, "name": "done"}
    mock_netbox.get.side_effect = [_branches(), _branches(*open_ones, closed)]
    with pytest.raises(ValueError, match="open branches"):
        netbox_create_branch("one-more")
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_create_branch_ignores_closed_branches_for_cap(mock_netbox):
    closed = [{**MERGED, "id": 100 + i, "name": f"old{i}"} for i in range(20)]
    mock_netbox.get.side_effect = [_branches(), _branches(*closed)]
    netbox_create_branch("fresh")
    mock_netbox.create.assert_called_once()


# ============================================================================
# User lookup: transient vs definitive failures
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_network_error_on_user_lookup_is_retried(mock_netbox):
    server.branch_policy.current_user_id = None
    calls = {"auth": 0}

    def fake_get(endpoint, **kwargs):
        if endpoint == "authentication-check":
            calls["auth"] += 1
            if calls["auth"] == 1:
                raise httpx.ConnectError("reset")
            return ME
        return _branches(READY)

    mock_netbox.get.side_effect = fake_get
    with pytest.raises(ValueError, match="Couldn't reach NetBox"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    assert calls["auth"] == 2
    mock_netbox.create.assert_called_once()


# ============================================================================
# Read-only mode
# ============================================================================


def test_list_branches_is_registered_without_write_mode():
    tools = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "netbox_list_branches" in tools


@patch("netbox_mcp_server.server.netbox")
def test_list_branches_not_writable_in_read_only_mode(mock_netbox):
    server.branch_policy.write_enabled = False
    mock_netbox.get.return_value = _branches(READY)
    (found,) = netbox_list_branches()["results"]
    assert found["mine"] is True
    assert found["writable"] is False


# ============================================================================
# Branchable endpoints reported by NetBox
# ============================================================================


def test_client_narrows_to_reported_branchable_endpoints(client):
    client.branchable_endpoints = frozenset({"dcim/sites"})
    client.create("dcim/sites", {"name": "x"}, branch="abcd1234")
    with pytest.raises(ValueError, match="does not isolate it"):
        client.create("dcim/devices", {"name": "x"}, branch="abcd1234")
    assert client.session.post.call_count == 1


def test_client_never_widens_beyond_static_list(client):
    client.branchable_endpoints = frozenset({"users/tokens"})
    with pytest.raises(ValueError, match="does not isolate it"):
        client.create("users/tokens", {"name": "x"}, branch="abcd1234")


@patch("netbox_mcp_server.server.netbox")
def test_write_type_check_uses_client_reported_endpoints(mock_netbox):
    mock_netbox.is_writable_endpoint.return_value = False
    with pytest.raises(ValueError, match=r"NetBox reports that 'dcim\.site' does not support"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x"})
    mock_netbox.get.assert_not_called()


def _object_types(*entries):
    return {"next": None, "results": list(entries)}


def _object_type(app_label, model, endpoint, features):
    return {
        "app_label": app_label,
        "model": model,
        "rest_api_endpoint": endpoint,
        "features": features,
    }


def test_discover_branchable_types_reads_feature():
    client = MagicMock()
    client.get.return_value = _object_types(
        _object_type("dcim", "site", "/api/dcim/sites/", ["branching", "tags"]),
        _object_type("users", "token", "/api/users/tokens/", ["tags"]),
        _object_type("acme", "widget", "/api/plugins/acme/widgets/", ["branching"]),
    )
    assert discover_branchable_types(client) == {
        "dcim.site": "dcim/sites",
        "acme.widget": "plugins/acme/widgets",
    }
    assert client.get.call_args.kwargs["params"]["features"] == "branching"


def test_discover_branchable_types_falls_back_when_feature_missing():
    client = MagicMock()
    client.get.return_value = _object_types(_object_type("dcim", "site", "/api/dcim/sites/", []))
    assert discover_branchable_types(client) is None


def test_discover_branchable_types_falls_back_on_error():
    client = MagicMock()
    client.get.side_effect = _http_error(500)
    assert discover_branchable_types(client) is None


@pytest.mark.parametrize("status", ["merged", "archived", "failed"])
@patch("netbox_mcp_server.server.netbox")
def test_create_branch_refuses_reusing_a_dead_branch_name(mock_netbox, status):
    mock_netbox.get.return_value = _branches({**READY, "status": {"value": status}})
    with pytest.raises(ValueError, match=f"status '{status}' and can't be used again"):
        netbox_create_branch("my-branch")
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_failed_branches_do_not_count_toward_cap(mock_netbox):
    failed = [
        {**READY, "id": 100 + i, "name": f"f{i}", "status": {"value": "failed"}}
        for i in range(server.MAX_OPEN_BRANCHES)
    ]
    mock_netbox.get.side_effect = [_branches(), _branches(*failed)]
    netbox_create_branch("fresh")
    mock_netbox.create.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_create_branch_trims_name_before_reuse_check(mock_netbox):
    mock_netbox.get.return_value = _branches(READY)
    assert netbox_create_branch("  my-branch ")["existing"] is True
    mock_netbox.create.assert_not_called()
    with pytest.raises(ValueError, match="branch name is required"):
        netbox_create_branch("   ")


def test_allow_foreign_branches_cli_flag(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["netbox-mcp-server", "--allow-foreign-branches"])
    assert server.parse_cli_args()["allow_foreign_branches"] is True


# ============================================================================
# NetBox versions: 4.5+ reports the token's user, 4.1-4.4 need NETBOX_USERNAME
# ============================================================================


def _old_netbox(branches):
    """A fake NetBox < 4.5: no /api/authentication-check/ endpoint."""

    def fake_get(endpoint, **kwargs):
        if endpoint == "authentication-check":
            raise _http_error(404)
        return branches

    return fake_get


@pytest.fixture
def unknown_user():
    server.branch_policy.current_user_id = None
    server.branch_policy.current_username = None


@patch("netbox_mcp_server.server.netbox")
def test_new_netbox_reports_user_and_overrides_wrong_username(mock_netbox, unknown_user):
    server.branch_policy.configured_username = "someone-else"
    mock_netbox.get.side_effect = lambda endpoint, **kw: (
        ME if endpoint == "authentication-check" else _branches(READY)
    )
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    assert server.branch_policy.current_user_id == ME["id"]
    assert server.branch_policy.current_username == ME["username"]


@patch("netbox_mcp_server.server.netbox")
def test_old_netbox_uses_netbox_username_for_ownership(mock_netbox, unknown_user):
    server.branch_policy.configured_username = "me"
    mock_netbox.get.side_effect = _old_netbox(_branches(READY, FOREIGN))
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    with pytest.raises(ValueError, match="belongs to 'colleague'"):
        netbox_create_objects("dcim.site", "their-branch", {"name": "x", "slug": "x"})
    mine = [b["mine"] for b in netbox_list_branches()["results"]]
    assert mine == [True, False]
    mock_netbox.create.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_old_netbox_without_username_explains_setting(mock_netbox, unknown_user):
    mock_netbox.get.side_effect = _old_netbox(_branches(READY))
    with pytest.raises(ValueError, match=r"added in NetBox 4\.5.*NETBOX_USERNAME"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    with pytest.raises(ValueError, match="NETBOX_USERNAME"):
        netbox_create_branch("fresh")
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_old_netbox_without_username_works_with_foreign_branches(mock_netbox, unknown_user):
    server.branch_policy.allow_foreign_branches = True
    mock_netbox.get.side_effect = _old_netbox(_branches())
    mock_netbox.create.return_value = {**READY, "status": {"value": "new"}}
    netbox_create_branch("my-branch")
    # The created branch's owner identifies the token's user from now on
    assert server.branch_policy.current_user_id == ME["id"]
    mock_netbox.get.side_effect = _old_netbox(_branches(READY))
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    assert mock_netbox.create.call_count == 2


@patch("netbox_mcp_server.server.netbox")
def test_old_netbox_create_branch_learns_owner_and_flags_wrong_username(mock_netbox, unknown_user):
    server.branch_policy.configured_username = "typo"
    mock_netbox.get.side_effect = _old_netbox(_branches())
    mock_netbox.create.return_value = {**READY, "status": {"value": "new"}}
    result = netbox_create_branch("my-branch")
    assert "NETBOX_USERNAME is 'typo'" in result["warning"]
    assert server.branch_policy.current_user_id == ME["id"]
    assert server.branch_policy.current_username == "me"


@patch("netbox_mcp_server.server.netbox")
def test_old_netbox_create_branch_with_correct_username_has_no_warning(mock_netbox, unknown_user):
    server.branch_policy.configured_username = "me"
    mock_netbox.get.side_effect = _old_netbox(_branches())
    mock_netbox.create.return_value = {**READY, "status": {"value": "new"}}
    assert "warning" not in netbox_create_branch("my-branch")
    assert server.branch_policy.current_user_id == ME["id"]


def test_discovery_on_netbox_before_4_4_falls_back():
    """NetBox < 4.4 object types have no 'features' field: use the static list."""
    client = MagicMock()
    client.get.return_value = _object_types({"rest_api_endpoint": "/api/dcim/sites/"})
    assert discover_branchable_types(client) is None
    assert client.get.call_args.kwargs["fallback_endpoint"] == "extras/object-types"


def test_netbox_username_cli_flag_and_normalization(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["netbox-mcp-server", "--netbox-username", "me"])
    assert server.parse_cli_args()["netbox_username"] == "me"
    assert _settings(netbox_username="  ").netbox_username is None
    assert _settings(netbox_username=" me ").netbox_username == "me"


# ============================================================================
# Deletes that would remove unbranched rows (bookmarks, subscriptions, jobs) from main
# ============================================================================


def _rows(rows, params):
    """Rows matching an object_type filter, as NetBox applies it (jobs are filtered)."""
    types = (params or {}).get("object_type")
    return [r for r in rows if types is None or r.get("object_type") in types]


def _netbox_with(dependents, errors=None):
    """Fake GET: branches for the branch lookup, given rows per dependent endpoint."""
    errors = errors or {}

    def fake_get(endpoint, params=None, **kwargs):
        if endpoint in errors:
            raise errors[endpoint]
        if endpoint in dependents:
            return {"next": None, "results": _rows(dependents[endpoint], params)}
        return _branches(READY)

    return fake_get


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_when_main_has_bookmarks(mock_netbox):
    mock_netbox.get.side_effect = _netbox_with(
        {"extras/bookmarks": [{"id": 1, "object_type": "dcim.device", "object_id": 5}]}
    )
    with pytest.raises(ValueError, match="main has 1 bookmarks"):
        netbox_delete_objects("dcim.device", "my-branch", [5, 6])
    mock_netbox.bulk_delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_check_matches_client_side(mock_netbox):
    """The subscriptions API ignores filters: rows for other objects must not count."""
    server.branch_policy.allow_branch_events = True  # Notifications allowed, rows still kept
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {
            "extras/subscriptions": [
                {"id": 1, "object_type": "dcim.device", "object_id": 99},
                {"id": 2, "object_type": "dcim.site", "object_id": 5},
            ]
        },
        {("dcim/devices", 99): {"id": 99}, ("dcim/sites", 5): {"id": 5}},
    )
    netbox_delete_objects("dcim.device", "my-branch", 5)
    mock_netbox.delete.assert_called_once_with("dcim/devices", 5, branch=SCHEMA_ID)


@patch("netbox_mcp_server.server.netbox")
def test_delete_check_counts_each_dependent_kind(mock_netbox):
    server.branch_policy.allow_branch_events = True
    mock_netbox.get.side_effect = _netbox_with(
        {
            "extras/subscriptions": [{"id": 1, "object_type": "dcim.device", "object_id": 5}],
            "core/jobs": [
                {"id": 1, "object_type": "dcim.device", "object_id": 5},
                {"id": 2, "object_type": "dcim.device", "object_id": 5},
            ],
        }
    )
    with pytest.raises(ValueError, match="1 subscriptions, 2 jobs"):
        netbox_delete_objects("dcim.device", "my-branch", 5)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_when_dependent_endpoint_returns_404(mock_netbox):
    """Every supported NetBox has these endpoints, so a 404 can't be trusted."""
    mock_netbox.get.side_effect = _netbox_with(
        {}, errors={"extras/subscriptions": _http_error(404)}
    )
    with pytest.raises(ValueError, match="Can't check for subscriptions"):
        netbox_delete_objects("dcim.device", "my-branch", 5)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_when_dependents_cannot_be_checked(mock_netbox):
    mock_netbox.get.side_effect = _netbox_with({}, errors={"extras/bookmarks": _http_error(403)})
    with pytest.raises(ValueError, match="Can't check for bookmarks"):
        netbox_delete_objects("dcim.device", "my-branch", 5)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_check_reads_main_not_the_branch(mock_netbox):
    mock_netbox.get.side_effect = _netbox_with({})
    netbox_delete_objects("dcim.device", "my-branch", 5)
    dependent_calls = [
        c
        for c in mock_netbox.get.call_args_list
        if c.args[0] in ("extras/bookmarks", "extras/subscriptions", "core/jobs")
    ]
    assert dependent_calls
    assert all(c.kwargs.get("headers") is None for c in dependent_calls)


# ============================================================================
# Cascaded children, event rules, verified versions
# ============================================================================


HIDDEN_FILTERS = {
    "parent_id",
    "policy_id",
    "region_id",
    "site_group_id",
    "site_id",
    "location_id",
    "device_id",
    "module_id",
    "module_bay_id",
}


def _cascade_netbox(dependents, objects, rules=(), main_only=None, hidden=None):
    """Fake GET with dependent rows, objects by (endpoint, id), and event rules.

    `objects` exist in the branch and in main; `main_only` ones only in main. `hidden`
    maps (holder endpoint, filter, linked-to id) to the IDs holding that hidden link.
    """

    def fake_get(endpoint, id=None, params=None, headers=None, **kwargs):
        if link_filter := HIDDEN_FILTERS & set(params or {}):
            (name,) = link_filter
            ids = {i for t in params[name] for i in (hidden or {}).get((endpoint, name, t), [])}
            return {"next": None, "results": [{"id": i} for i in sorted(ids)]}
        wanted = (params or {}).get("id")
        if wanted is not None:
            visible = objects if headers else {**objects, **(main_only or {})}
            found = [visible[(endpoint, i)] for i in wanted if (endpoint, i) in visible]
            return {"next": None, "results": found}
        if endpoint == "extras/event-rules":
            return {"next": None, "results": list(rules)}
        if endpoint in dependents:
            return {"next": None, "results": _rows(dependents[endpoint], params)}
        return _branches(READY)

    return fake_get


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_when_cascaded_child_has_subscription(mock_netbox):
    """A subscription on device 42's interface is removed along with the device."""
    server.branch_policy.allow_branch_events = True
    mock_netbox.branchable_endpoints = None
    interface = {
        "id": 7,
        "url": "http://nb/api/dcim/interfaces/7/",
        "device": {"id": 42, "url": "http://nb/api/dcim/devices/42/", "name": "sw1"},
    }
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/subscriptions": [{"object_type": "dcim.interface", "object_id": 7}]},
        {("dcim/interfaces", 7): interface},
    )
    with pytest.raises(ValueError, match="main has 1 subscriptions"):
        netbox_delete_objects("dcim.device", "my-branch", 42)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_ignores_rows_on_unrelated_objects(mock_netbox):
    mock_netbox.branchable_endpoints = None
    other_interface = {
        "id": 8,
        "url": "http://nb/api/dcim/interfaces/8/",
        "device": {"id": 99, "url": "http://nb/api/dcim/devices/99/"},
    }
    mock_netbox.get.side_effect = _cascade_netbox(
        {
            "extras/bookmarks": [
                {"object_type": "dcim.interface", "object_id": 8},  # other device's child
                {"object_type": "users.user", "object_id": 42},  # not branchable
            ]
        },
        {("dcim/interfaces", 8): other_interface, ("dcim/devices", 99): {"id": 99}},
    )
    netbox_delete_objects("dcim.device", "my-branch", 42)
    mock_netbox.delete.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_dependents_reported_branchable_are_skipped(mock_netbox):
    mock_netbox.branchable_endpoints = frozenset({"extras/bookmarks", "dcim/devices"})
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.device", "object_id": 42}]}, {}
    )
    netbox_delete_objects("dcim.device", "my-branch", 42)
    assert "extras/bookmarks" not in [c.args[0] for c in mock_netbox.get.call_args_list]
    mock_netbox.delete.assert_called_once()


def test_nested_refs_finds_linked_branchable_objects_only():
    obj = {
        "url": "https://nb/x/api/dcim/interfaces/7/",
        "device": {"url": "https://nb/x/api/dcim/devices/42/"},
        "tags": [{"url": "https://nb/x/api/extras/tags/3/"}],
        "owner": {"url": "https://nb/x/api/users/users/1/"},
        "note": "/api/dcim/devices/9/",
    }
    # Tags are not followed: deleting a tag never deletes the tagged object
    branchable = frozenset({"dcim/devices", "dcim/interfaces", "extras/tags"})
    assert server._nested_refs(obj, branchable) == {("dcim/devices", 42)}


DEVICE_RULE = {"id": 1, "name": "provision", "enabled": True, "object_types": ["dcim.interface"]}


@pytest.mark.parametrize(
    "write",
    [
        lambda: netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"}),
        lambda: netbox_update_objects("dcim.site", "my-branch", {"name": "y"}, object_id=1),
        lambda: netbox_delete_objects("dcim.site", "my-branch", 1),
    ],
)
@patch("netbox_mcp_server.server.netbox")
def test_writes_refused_while_event_rules_would_fire(mock_netbox, write):
    """Any enabled rule on a branchable type counts (writes cascade to other types)."""
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[DEVICE_RULE])
    with pytest.raises(ValueError, match=r"these enabled rules would fire.*provision"):
        write()
    mock_netbox.create.assert_not_called()
    mock_netbox.update.assert_not_called()
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_disabled_or_unbranchable_event_rules_are_ignored(mock_netbox):
    rules = [
        {**DEVICE_RULE, "enabled": False},
        {"id": 2, "name": "users", "enabled": True, "object_types": ["users.user"]},
    ]
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=rules)
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_allow_branch_events_opt_in(mock_netbox):
    server.branch_policy.allow_branch_events = True
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[DEVICE_RULE])
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_called_once()
    assert "extras/event-rules" not in [c.args[0] for c in mock_netbox.get.call_args_list]


@patch("netbox_mcp_server.server.netbox")
def test_writes_refused_when_event_rules_cannot_be_checked(mock_netbox):
    mock_netbox.get.side_effect = _netbox_with({}, errors={"extras/event-rules": _http_error(403)})
    with pytest.raises(ValueError, match="Can't check NetBox event rules"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_not_called()


@pytest.mark.parametrize(
    ("status", "warns"),
    [
        ({"netbox-version": "4.5.10", "plugins": {"netbox_branching": "1.1.3"}}, False),
        ({"netbox-version": "4.7.0", "plugins": {"netbox_branching": "1.2.1"}}, True),
        ({"netbox-version": "4.5.1", "plugins": {}}, True),
    ],
)
def test_unverified_versions_logged(status, warns, caplog):
    client = MagicMock()
    client.get.return_value = status
    with caplog.at_level("WARNING"):
        server.warn_if_unverified_versions(client)
    assert ("verified with NetBox" in caplog.text) is warns


def test_allow_branch_events_cli_flag(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["netbox-mcp-server", "--allow-branch-events"])
    assert server.parse_cli_args()["allow_branch_events"] is True


def _loc(i, parent=None):
    return {
        "id": i,
        "url": f"http://nb/api/dcim/locations/{i}/",
        "parent": parent and {"id": parent, "url": f"http://nb/api/dcim/locations/{parent}/"},
    }


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_for_same_type_child(mock_netbox):
    """Deleting location 1 cascades to its child location 2, which is bookmarked."""
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.location", "object_id": 2}]},
        {("dcim/locations", 2): _loc(2, parent=1)},
    )
    with pytest.raises(ValueError, match="main has 1 bookmarks"):
        netbox_delete_objects("dcim.location", "my-branch", 1)


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_for_grandchild_through_unbookmarked_parent(mock_netbox):
    """Room 3 -> Floor 2 -> Building 1: only Room 3 is subscribed."""
    server.branch_policy.allow_branch_events = True
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/subscriptions": [{"object_type": "dcim.location", "object_id": 3}]},
        {("dcim/locations", 3): _loc(3, parent=2), ("dcim/locations", 2): _loc(2, parent=1)},
    )
    with pytest.raises(ValueError, match="main has 1 subscriptions"):
        netbox_delete_objects("dcim.location", "my-branch", 1)


@patch("netbox_mcp_server.server.netbox")
def test_delete_allowed_when_chain_leads_elsewhere(mock_netbox):
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.location", "object_id": 3}]},
        {
            ("dcim/locations", 3): _loc(3, parent=2),
            ("dcim/locations", 2): _loc(2, parent=9),
            ("dcim/locations", 9): _loc(9),
        },
    )
    netbox_delete_objects("dcim.location", "my-branch", 1)
    mock_netbox.delete.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_cascade_lookups_are_batched_per_type(mock_netbox):
    mock_netbox.branchable_endpoints = None
    rows = [{"object_type": "dcim.interface", "object_id": i} for i in range(1, 51)]
    objects = {
        ("dcim/interfaces", i): {"id": i, "url": f"http://nb/api/dcim/interfaces/{i}/"}
        for i in range(1, 51)
    }
    mock_netbox.get.side_effect = _cascade_netbox({"extras/bookmarks": rows}, objects)
    netbox_delete_objects("dcim.device", "my-branch", 42)
    interface_calls = [c for c in mock_netbox.get.call_args_list if c.args[0] == "dcim/interfaces"]
    assert len(interface_calls) == 1


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_when_tracing_exceeds_cap(mock_netbox, monkeypatch):
    monkeypatch.setattr(server, "MAX_CASCADE_OBJECTS", 3)
    mock_netbox.branchable_endpoints = None
    rows = [{"object_type": "dcim.interface", "object_id": i} for i in range(1, 6)]
    mock_netbox.get.side_effect = _cascade_netbox({"extras/bookmarks": rows}, {})
    with pytest.raises(ValueError, match="needs more than 3 lookups"):
        netbox_delete_objects("dcim.device", "my-branch", 42)


SUBSCRIBED_INTERFACE = {"extras/subscriptions": [{"object_type": "dcim.interface", "object_id": 7}]}


@pytest.mark.parametrize(
    "write",
    [
        # Creating a cable saves its terminating interfaces, notifying their subscribers
        lambda: netbox_create_objects("dcim.cable", "my-branch", {"a_terminations": []}),
        lambda: netbox_update_objects("dcim.device", "my-branch", {"name": "y"}, object_id=1),
        lambda: netbox_delete_objects("dcim.site", "my-branch", 1),
    ],
)
@patch("netbox_mcp_server.server.netbox")
def test_writes_refused_while_anyone_is_subscribed(mock_netbox, write):
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(SUBSCRIBED_INTERFACE, {})
    with pytest.raises(ValueError, match="users have 1 subscriptions"):
        write()
    mock_netbox.create.assert_not_called()
    mock_netbox.update.assert_not_called()
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_subscriptions_to_unbranchable_objects_are_ignored(mock_netbox):
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/subscriptions": [{"object_type": "users.user", "object_id": 7}]}, {}
    )
    netbox_update_objects("dcim.device", "my-branch", {"status": "offline"}, object_id=5)
    mock_netbox.update.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_subscriptions_ignored_when_notifications_are_branchable(mock_netbox):
    mock_netbox.branchable_endpoints = frozenset({"extras/notifications", "dcim/devices"})
    mock_netbox.get.side_effect = _cascade_netbox(SUBSCRIBED_INTERFACE, {})
    netbox_update_objects("dcim.device", "my-branch", {"status": "offline"}, object_id=5)
    mock_netbox.update.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_update_refused_when_subscriptions_cannot_be_checked(mock_netbox):
    mock_netbox.get.side_effect = _netbox_with(
        {"extras/event-rules": []}, errors={"extras/subscriptions": _http_error(403)}
    )
    with pytest.raises(ValueError, match="Can't check for subscriptions") as exc:
        netbox_update_objects("dcim.device", "my-branch", {"status": "offline"}, object_id=5)
    assert "delete" not in str(exc.value)
    mock_netbox.update.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_allow_branch_events_also_allows_notifications(mock_netbox):
    server.branch_policy.allow_branch_events = True
    mock_netbox.get.side_effect = _cascade_netbox(SUBSCRIBED_INTERFACE, {})
    netbox_update_objects("dcim.device", "my-branch", {"status": "offline"}, object_id=5)
    mock_netbox.update.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_allowed_event_rules_by_id(mock_netbox):
    server.branch_policy.allowed_event_rules = frozenset({1})
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[DEVICE_RULE])
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_unlisted_event_rule_still_refused(mock_netbox):
    """Only IDs count: a rule reusing an allowed rule's name is still refused."""
    server.branch_policy.allowed_event_rules = frozenset({2})
    renamed = {**DEVICE_RULE, "id": 3, "name": "chat-notify"}
    allowed = {"id": 2, "name": "chat-notify", "enabled": True, "object_types": ["dcim.site"]}
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[renamed, allowed])
    with pytest.raises(ValueError, match=r"would fire.*: chat-notify \(ID 3\)\."):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})


MAIN_ONLY = {"attr": "active_branch", "value": None}


@pytest.mark.parametrize(
    "conditions",
    [
        {"and": [MAIN_ONLY]},
        {"AND": [MAIN_ONLY]},
        {"and": [{"attr": "status.value", "value": "active"}, {**MAIN_ONLY, "op": "eq"}]},
        {**MAIN_ONLY, "negate": False},
    ],
)
@patch("netbox_mcp_server.server.netbox")
def test_main_only_event_rules_are_ignored(mock_netbox, conditions):
    rule = {**DEVICE_RULE, "conditions": conditions}
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[rule])
    netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_called_once()
    rule_calls = [c for c in mock_netbox.get.call_args_list if c.args[0] == "extras/event-rules"]
    assert "conditions" in rule_calls[0].kwargs["params"]["fields"].split(",")


@pytest.mark.parametrize(
    "conditions",
    [
        None,
        {},
        {"and": []},
        {"and": [{**MAIN_ONLY, "negate": True}]},
        {"or": [MAIN_ONLY, {"attr": "status.value", "value": "active"}]},
        {"and": [{"or": [MAIN_ONLY]}]},
        {"and": [{"and": [MAIN_ONLY]}]},
        {"and": [{"attr": "active_branch.name", "value": None}]},
        {"and": [{"attr": "active_branch", "value": "main"}]},
        {"and": [{"attr": "active_branch"}]},
        {"and": [{**MAIN_ONLY, "op": "in"}]},
        {"and": MAIN_ONLY},
        [MAIN_ONLY],
    ],
)
@patch("netbox_mcp_server.server.netbox")
def test_event_rules_not_limited_to_main_still_block(mock_netbox, conditions):
    rule = {**DEVICE_RULE, "conditions": conditions}
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[rule])
    with pytest.raises(ValueError, match=r"would fire.*: provision \(ID 1\)\..*EVENTS_PIPELINE"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_main_only_rule_does_not_excuse_other_rules(mock_netbox):
    main_only = {"id": 3, "name": "main-hook", "enabled": True, "object_types": ["dcim.site"]}
    main_only["conditions"] = {"and": [MAIN_ONLY]}
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[main_only, DEVICE_RULE])
    with pytest.raises(ValueError, match=r"would fire.*: provision \(ID 1\)\."):
        netbox_delete_objects("dcim.site", "my-branch", 1)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_allowlist_still_applies_alongside_main_only_rules(mock_netbox):
    server.branch_policy.allowed_event_rules = frozenset({1})
    main_only = {"id": 3, "name": "main-hook", "enabled": True, "object_types": ["dcim.site"]}
    main_only["conditions"] = {"and": [MAIN_ONLY]}
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[main_only, DEVICE_RULE])
    netbox_update_objects("dcim.site", "my-branch", {"name": "y"}, object_id=1)
    mock_netbox.update.assert_called_once()


def test_allowed_event_rules_from_env_and_cli(monkeypatch):
    monkeypatch.setenv("ALLOWED_BRANCH_EVENT_RULES", "12, 7")
    assert _settings().allowed_branch_event_rules == [12, 7]
    monkeypatch.delenv("ALLOWED_BRANCH_EVENT_RULES")
    argv = [
        "netbox-mcp-server",
        "--allowed-branch-event-rule",
        " 3,4 ",
        "--allowed-branch-event-rule",
        "5",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    cli = server.parse_cli_args()["allowed_branch_event_rules"]
    assert _settings(allowed_branch_event_rules=cli).allowed_branch_event_rules == [3, 4, 5]
    with pytest.raises(ValueError, match="allowed_branch_event_rules"):
        _settings(allowed_branch_event_rules=["chat-notify"])


def _iface(i, device=None, extra=None):
    obj = {"id": i, "url": f"http://nb/api/dcim/interfaces/{i}/"}
    if device:
        obj["device"] = {"url": f"http://nb/api/dcim/devices/{device}/"}
    obj.update(extra or {})
    return obj


@patch("netbox_mcp_server.server.netbox")
def test_cascade_through_reference_cycle_is_found(mock_netbox):
    """Bookmarked IP 1 -> interface 7 -> device 42 (deleted), with 7 <-> IP 1 a cycle."""
    mock_netbox.branchable_endpoints = None
    ip = {
        "id": 1,
        "url": "http://nb/api/ipam/ip-addresses/1/",
        "assigned_object": {"url": "http://nb/api/dcim/interfaces/7/"},
    }
    iface = _iface(7, device=42, extra={"ip": {"url": "http://nb/api/ipam/ip-addresses/1/"}})
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "ipam.ipaddress", "object_id": 1}]},
        {("ipam/ip-addresses", 1): ip, ("dcim/interfaces", 7): iface},
    )
    with pytest.raises(ValueError, match="main has 1 bookmarks"):
        netbox_delete_objects("dcim.device", "my-branch", 42)


@patch("netbox_mcp_server.server.netbox")
def test_cycle_evaluated_through_sibling_first_is_found(mock_netbox):
    """Interface 8's only link is interface 7, which links to 8 and to device 42."""
    server.branch_policy.allow_branch_events = True
    mock_netbox.branchable_endpoints = None
    i7 = {
        "id": 7,
        "url": "http://nb/api/dcim/interfaces/7/",
        "peer": {"url": "http://nb/api/dcim/interfaces/8/"},
        "device": {"url": "http://nb/api/dcim/devices/42/"},
    }
    i8 = {
        "id": 8,
        "url": "http://nb/api/dcim/interfaces/8/",
        "peer": {"url": "http://nb/api/dcim/interfaces/7/"},
    }
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/subscriptions": [{"object_type": "dcim.interface", "object_id": 8}]},
        {("dcim/interfaces", 7): i7, ("dcim/interfaces", 8): i8},
    )
    with pytest.raises(ValueError, match="main has 1 subscriptions"):
        netbox_delete_objects("dcim.device", "my-branch", 42)


@patch("netbox_mcp_server.server.netbox")
def test_batched_fetch_follows_pages_when_netbox_caps_page_size(mock_netbox):
    mock_netbox.branchable_endpoints = None
    rows = [{"object_type": "dcim.interface", "object_id": i} for i in range(1, 6)]
    objects = {i: _iface(i, device=42 if i == 5 else 99) for i in range(1, 6)}

    def fake_get(endpoint, id=None, params=None, **kwargs):
        if endpoint == "dcim/devices":
            return {"next": None, "results": [{"id": i} for i in params["id"]]}
        if endpoint == "dcim/interfaces":
            after = params.get("id__gt", 0)
            wanted = [objects[i] for i in sorted(params["id"]) if i > after]
            page = wanted[:2]  # MAX_PAGE_SIZE = 2
            return {"next": "http://nb/next" if len(wanted) > 2 else None, "results": page}
        if endpoint == "extras/bookmarks":
            return {"next": None, "results": rows}
        if endpoint in ("extras/subscriptions", "core/jobs", "extras/event-rules"):
            return {"next": None, "results": []}
        return _branches(READY)

    mock_netbox.get.side_effect = fake_get
    with pytest.raises(ValueError, match="main has 1 bookmarks"):
        netbox_delete_objects("dcim.device", "my-branch", 42)


@patch("netbox_mcp_server.server.netbox")
def test_delete_traces_links_inside_the_branch(mock_netbox):
    """In main interface 7 is on device 99; in the branch it was moved to device 42."""
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.interface", "object_id": 7}]},
        {("dcim/interfaces", 7): _iface(7, device=42)},
        main_only={("dcim/interfaces", 7): _iface(7, device=99)},
    )
    with pytest.raises(ValueError, match="main has 1 bookmarks"):
        netbox_delete_objects("dcim.device", "my-branch", 42)
    traced = [c for c in mock_netbox.get.call_args_list if c.args[0] == "dcim/interfaces"]
    assert traced[0].kwargs["headers"] == {"X-NetBox-Branch": SCHEMA_ID}


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_when_linked_object_is_hidden(mock_netbox):
    """An object the token can't see (in branch or main) has unknown links."""
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.interface", "object_id": 7}]}, {}
    )
    with pytest.raises(ValueError, match="Can't see 1 bookmarked"):
        netbox_delete_objects("dcim.device", "my-branch", 42)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_ignores_objects_only_in_main(mock_netbox):
    """An object created in main after the branch can't be reached by the branch delete."""
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.interface", "object_id": 7}]},
        {},
        main_only={("dcim/interfaces", 7): _iface(7, device=42)},
    )
    netbox_delete_objects("dcim.device", "my-branch", 42)
    mock_netbox.delete.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_deleting_a_tag_is_not_blocked_by_tagged_bookmarked_objects(mock_netbox):
    mock_netbox.branchable_endpoints = None
    device = {
        "id": 5,
        "url": "http://nb/api/dcim/devices/5/",
        "tags": [{"id": 3, "url": "http://nb/api/extras/tags/3/"}],
    }
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.device", "object_id": 5}]},
        {("dcim/devices", 5): device},
    )
    netbox_delete_objects("extras.tag", "my-branch", 3)
    mock_netbox.delete.assert_called_once_with("extras/tags", 3, branch=SCHEMA_ID)


# ============================================================================
# Refuse unless known safe: token visibility, reported branchable types
# ============================================================================


@pytest.mark.parametrize(
    "write",
    [
        lambda: netbox_update_objects("dcim.device", "my-branch", {"name": "y"}, object_id=1),
        lambda: netbox_delete_objects("dcim.device", "my-branch", 1),
    ],
)
@patch("netbox_mcp_server.server.netbox")
def test_writes_refused_unless_unrestricted_token(mock_netbox, write):
    """NetBox's default permissions show a user only their own bookmarks/subscriptions."""
    server.branch_policy.unrestricted_token = False
    mock_netbox.get.side_effect = _cascade_netbox({}, {})
    with pytest.raises(ValueError, match="UNRESTRICTED_TOKEN"):
        write()
    mock_netbox.update.assert_not_called()
    mock_netbox.delete.assert_not_called()


def test_unrestricted_token_setting_and_cli_flag(monkeypatch):
    assert _settings().unrestricted_token is False
    monkeypatch.setattr(sys, "argv", ["netbox-mcp-server", "--unrestricted-token"])
    assert server.parse_cli_args()["unrestricted_token"] is True


@patch("netbox_mcp_server.server.netbox")
def test_event_rules_on_reported_branchable_types_count(mock_netbox):
    """Image attachments aren't writable, but a device delete cascades to them."""
    server.branch_policy.branchable_types["extras.imageattachment"] = "extras/image-attachments"
    rule = {**DEVICE_RULE, "object_types": ["extras.imageattachment"]}
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[rule])
    with pytest.raises(ValueError, match="would fire"):
        netbox_delete_objects("dcim.device", "my-branch", 1)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_every_enabled_rule_counts_when_types_unknown(mock_netbox):
    server.branch_policy.branchable_types = None
    rule = {"id": 2, "name": "users", "enabled": True, "object_types": ["users.user"]}
    mock_netbox.get.side_effect = _cascade_netbox({}, {}, rules=[rule])
    with pytest.raises(ValueError, match="would fire"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})


@patch("netbox_mcp_server.server.netbox")
def test_subscriptions_to_plugin_objects_count(mock_netbox):
    server.branch_policy.branchable_types["acme.widget"] = "plugins/acme/widgets"
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/subscriptions": [{"object_type": "acme.widget", "object_id": 3}]}, {}
    )
    with pytest.raises(ValueError, match="users have 1 subscriptions"):
        netbox_update_objects("dcim.device", "my-branch", {"name": "y"}, object_id=1)


@patch("netbox_mcp_server.server.netbox")
def test_delete_traces_bookmarked_plugin_objects(mock_netbox):
    """A plugin row with a CASCADE FK to the device is deleted along with it."""
    mock_netbox.branchable_endpoints = None
    server.branch_policy.branchable_types["acme.widget"] = "plugins/acme/widgets"
    widget = {
        "id": 3,
        "url": "http://nb/api/plugins/acme/widgets/3/",
        "device": {"url": "http://nb/api/dcim/devices/42/"},
    }
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "acme.widget", "object_id": 3}]},
        {("plugins/acme/widgets", 3): widget},
    )
    with pytest.raises(ValueError, match="main has 1 bookmarks"):
        netbox_delete_objects("dcim.device", "my-branch", 42)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_when_branchable_types_unknown(mock_netbox):
    server.branch_policy.branchable_types = None
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox({}, {})
    with pytest.raises(ValueError, match="didn't report which models support branching"):
        netbox_delete_objects("dcim.device", "my-branch", 42)
    mock_netbox.delete.assert_not_called()


# ============================================================================
# Round 3: unrestricted token, device type images, bulk URLs, BASE_PATH
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_event_rule_check_needs_unrestricted_token(mock_netbox):
    """A permission constraint can hide enabled rules from the token's list."""
    server.branch_policy.unrestricted_token = False
    mock_netbox.get.side_effect = _cascade_netbox({}, {})
    with pytest.raises(ValueError, match="sees all event rules"):
        netbox_create_objects("dcim.site", "my-branch", {"name": "x", "slug": "x"})
    mock_netbox.create.assert_not_called()


@pytest.mark.parametrize("data", [{"front_image": None}, [{"id": 7, "rear_image": None}]])
@patch("netbox_mcp_server.server.netbox")
def test_device_type_image_changes_refused(mock_netbox, data):
    """DeviceType.save() deletes the old image file from shared media storage."""
    mock_netbox.get.side_effect = _cascade_netbox({}, {})
    object_id = None if isinstance(data, list) else 7
    with pytest.raises(ValueError, match="uploaded files aren't isolated"):
        netbox_update_objects("dcim.devicetype", "my-branch", data, object_id=object_id)
    mock_netbox.update.assert_not_called()
    mock_netbox.bulk_update.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_of_device_type_with_image_refused(mock_netbox):
    mock_netbox.branchable_endpoints = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {},
        {
            ("dcim/device-types", 7): {"id": 7, "front_image": "devicetype-images/a.png"},
            ("dcim/device-types", 8): {"id": 8, "front_image": None, "rear_image": None},
        },
    )
    with pytest.raises(ValueError, match=r"Refusing to delete dcim\.devicetype 7:"):
        netbox_delete_objects("dcim.devicetype", "my-branch", [7, 8])
    netbox_delete_objects("dcim.devicetype", "my-branch", 8)
    mock_netbox.delete.assert_called_once_with("dcim/device-types", 8, branch=SCHEMA_ID)


def test_client_bulk_operations_use_the_list_url(client):
    """NetBox has no bulk/ route: bulk writes go to the list URL."""
    list_url = "https://netbox.example.com/api/dcim/sites/"
    client.session.patch.return_value.status_code = 200
    client.bulk_create("dcim/sites", [{"name": "a"}], branch="abcd1234")
    client.bulk_update("dcim/sites", [{"id": 1, "name": "b"}], branch="abcd1234")
    client.bulk_delete("dcim/sites", [1], branch="abcd1234")
    assert client.session.post.call_args.args[0] == list_url
    assert client.session.patch.call_args.args[0] == list_url
    assert client.session.request.call_args.args[1] == list_url


def test_discovery_handles_base_path_and_models_without_rest_api():
    client = MagicMock()
    client.get.return_value = _object_types(
        _object_type("dcim", "site", "/netbox/api/dcim/sites/", ["branching"]),
        _object_type("acme", "hidden", None, ["branching"]),
    )
    assert discover_branchable_types(client) == {"dcim.site": "dcim/sites", "acme.hidden": None}


@patch("netbox_mcp_server.server.netbox")
def test_delete_refused_when_bookmarked_branchable_type_has_no_rest_api(mock_netbox):
    mock_netbox.branchable_endpoints = None
    server.branch_policy.branchable_types["acme.hidden"] = None
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "acme.hidden", "object_id": 1}]}, {}
    )
    with pytest.raises(ValueError, match="no REST API"):
        netbox_delete_objects("dcim.device", "my-branch", 42)
    mock_netbox.delete.assert_not_called()


# ============================================================================
# Round 4: hidden ModuleBay.parent, jobs request length
# ============================================================================


@pytest.mark.parametrize(
    ("deleted", "bookmarked", "hidden"),
    [
        # VLANTranslationRule.policy isn't in the API at all
        (
            ("ipam.vlantranslationpolicy", 1),
            ("ipam.vlantranslationrule", 3),
            {("ipam/vlan-translation-rules", "policy_id", 1): [3]},
        ),
        # A prefix's cached _region can be stale after its location moved
        (
            ("dcim.region", 1),
            ("ipam.prefix", 5),
            {("ipam/prefixes", "region_id", 1): [5]},
        ),
        # ModuleBay.parent is hidden, and can point at a bay on another device
        (
            ("dcim.modulebay", 1),
            ("dcim.modulebay", 2),
            {("dcim/module-bays", "parent_id", 1): [2]},
        ),
    ],
)
@patch("netbox_mcp_server.server.netbox")
def test_delete_reaches_objects_through_hidden_cascades(mock_netbox, deleted, bookmarked, hidden):
    mock_netbox.branchable_endpoints = None
    object_type, object_id = bookmarked
    endpoint = STATIC_TYPES[object_type]
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": object_type, "object_id": object_id}]},
        {(endpoint, object_id): {"id": object_id}},
        hidden=hidden,
    )
    with pytest.raises(ValueError, match="main has 1 bookmarks"):
        netbox_delete_objects(deleted[0], "my-branch", deleted[1])
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_hidden_cascade_queries_read_the_branch(mock_netbox):
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.site", "object_id": 9}]},
        {("dcim/sites", 9): {"id": 9}},
    )
    netbox_delete_objects("dcim.region", "my-branch", 1)
    queries = [c for c in mock_netbox.get.call_args_list if "region_id" in c.kwargs["params"]]
    assert {c.args[0] for c in queries} == set(server.CACHED_SCOPE_ENDPOINTS)
    assert all(c.kwargs["headers"] == {"X-NetBox-Branch": SCHEMA_ID} for c in queries)
    mock_netbox.delete.assert_called_once()


@patch("netbox_mcp_server.server.netbox")
def test_jobs_filter_is_sent_in_short_chunks(mock_netbox):
    mock_netbox.get.side_effect = _cascade_netbox({}, {})
    netbox_delete_objects("dcim.device", "my-branch", 42)
    chunks = [
        c.kwargs["params"]["object_type"]
        for c in mock_netbox.get.call_args_list
        if c.args[0] == "core/jobs"
    ]
    assert all(len(chunk) <= 40 for chunk in chunks)
    assert sorted(t for chunk in chunks for t in chunk) == sorted(STATIC_TYPES)


# ============================================================================
# Round 6: hidden links in the middle of a cascade chain
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_inventory_item_bare_parent_is_followed_through_a_component(mock_netbox):
    """Interface 7 -> item 1 (GenericRelation) -> item 3 (bare-ID parent), bookmarked."""
    mock_netbox.branchable_endpoints = None
    item1 = {
        "id": 1,
        "parent": None,
        "device": {"url": "http://nb/api/dcim/devices/9/"},
        "component": {"url": "http://nb/api/dcim/interfaces/7/"},
    }
    item3 = {"id": 3, "parent": 1, "device": {"url": "http://nb/api/dcim/devices/2/"}}
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.inventoryitem", "object_id": 3}]},
        {
            ("dcim/inventory-items", 1): item1,
            ("dcim/inventory-items", 3): item3,
            ("dcim/devices", 9): {"id": 9},
            ("dcim/devices", 2): {"id": 2},
        },
    )
    with pytest.raises(ValueError, match="main has 1 bookmarks"):
        netbox_delete_objects("dcim.interface", "my-branch", 7)
    mock_netbox.delete.assert_not_called()


@pytest.mark.parametrize(
    ("deleted", "hidden"),
    [
        # Module 8 -> its bay 3 -> bay 2, whose stale hidden parent is bay 3
        (
            ("dcim.module", 8),
            {
                ("dcim/module-bays", "module_id", 8): [3],
                ("dcim/module-bays", "parent_id", 3): [2],
            },
        ),
        # Device 1 -> its bay 3 -> bay 2 on another device (stale hidden parent)
        (
            ("dcim.device", 1),
            {
                ("dcim/module-bays", "device_id", 1): [3],
                ("dcim/module-bays", "parent_id", 3): [2],
            },
        ),
        # Bay 3 -> module 4 installed in it -> its bay 5 -> bay 2 (stale parent 5)
        (
            ("dcim.modulebay", 3),
            {
                ("dcim/modules", "module_bay_id", 3): [4],
                ("dcim/module-bays", "module_id", 4): [5],
                ("dcim/module-bays", "parent_id", 5): [2],
            },
        ),
    ],
)
@patch("netbox_mcp_server.server.netbox")
def test_module_bay_subtree_is_walked_downward(mock_netbox, deleted, hidden):
    mock_netbox.branchable_endpoints = None
    bay2 = {"id": 2, "device": {"url": "http://nb/api/dcim/devices/6/"}}
    mock_netbox.get.side_effect = _cascade_netbox(
        {"extras/bookmarks": [{"object_type": "dcim.modulebay", "object_id": 2}]},
        {("dcim/module-bays", 2): bay2, ("dcim/devices", 6): {"id": 6}},
        hidden=hidden,
    )
    with pytest.raises(ValueError, match="main has 1 bookmarks"):
        netbox_delete_objects(deleted[0], "my-branch", deleted[1])
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_unknown_long_branch_name_is_not_looked_up_as_schema_id(mock_netbox):
    """Schema IDs are at most 8 characters, so a longer unknown name needs one query."""
    mock_netbox.get.return_value = _branches()
    with pytest.raises(ValueError, match="found 0"):
        netbox_create_objects("dcim.site", "my-typoed-branch", {"name": "x", "slug": "x"})
    assert mock_netbox.get.call_count == 1
