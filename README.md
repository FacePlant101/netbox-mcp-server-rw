# NetBox MCP Server

[![M8ven Score](https://m8ven.ai/badge/mcp/faceplant101-netbox-mcp-server-rw-ao1twa?v=38c2440bbc330fa24fef49f5b524ad03)](https://m8ven.ai/mcp/faceplant101-netbox-mcp-server-rw-ao1twa?s=readme)

> **⚠️ Breaking Change in v1.0.0**: The project structure has changed.
> If upgrading from v0.1.0, update your configuration:
> - Change `uv run server.py` to `uv run netbox-mcp-server`
> - Update Claude Desktop/Code configs to use `netbox-mcp-server` instead of `server.py`
> - Docker users: rebuild images with updated CMD
> - See [CHANGELOG.md](CHANGELOG.md) for full details

This is a [Model Context Protocol](https://modelcontextprotocol.io/) server for NetBox, forked from [netboxlabs/netbox-mcp-server](https://github.com/netboxlabs/netbox-mcp-server). It enables you to interact with your data in NetBox directly via LLMs that support MCP. It is read-only by default; with `ENABLE_WRITE=true` it can also stage changes in NetBox Branching branches, never in main. See [Branch-Only Writes](#branch-only-writes).

The server is intentionally simple: easy to get started with, hard to misuse (read-only by default, no plugin surface), and easy to fork and adapt. Forking under Apache 2.0 is a first-class path for users who need capabilities beyond the project's scope.

## Community

For chat, use cases, and general MCP discussion, join the NetBox community at [netdev.chat](https://netdev.chat). The **#ai** channel is the right home for MCP integrations, questions, and sharing use cases. Bugs and feature ideas specific to this server go in [issues](https://github.com/netboxlabs/netbox-mcp-server/issues).

## Tools

| Tool | Description |
|------|-------------|
| netbox_get_objects | Retrieves NetBox core objects based on their type and filters |
| netbox_get_object_by_id | Gets detailed information about a specific NetBox object by its ID |
| netbox_get_changelogs | Retrieves change history records (audit trail) based on filters |
| netbox_search_objects | Searches names, IPs, serials and other key fields across object types |
| netbox_list_branches | Lists NetBox Branching branches (read-only; marks your own and writable ones) |

> Note: Core NetBox object types are always available. Plugin object types can be auto-discovered. See [Plugin Object Type Discovery](#plugin-object-type-discovery). Advanced features (GraphQL, dynamic model discovery, etc.) are deliberately out of scope. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full scope statement and rationale.

## Usage

1. Create an API token in NetBox with sufficient permissions for the tool to access the data you want to make available via MCP. Use a read-only token unless you enable [Branch-Only Writes](#branch-only-writes), which needs write permissions.

2. Install dependencies:

    ```bash
    # Using UV (recommended)
    uv sync

    # Or using pip
    pip install -e .
    ```

3. Verify the server can run: `NETBOX_URL=https://netbox.example.com/ NETBOX_TOKEN=<your-api-token> uv run netbox-mcp-server`

4. Add the MCP server to your LLM client. See below for some examples with Claude.

### Claude Code

#### Stdio Transport (Default)

Add the server using the `claude mcp add` command:

```bash
claude mcp add --transport stdio netbox \
  --env NETBOX_URL=https://netbox.example.com/ \
  --env NETBOX_TOKEN=<your-api-token> \
  -- uv --directory /path/to/netbox-mcp-server run netbox-mcp-server
```

**Important notes:**

- Replace `/path/to/netbox-mcp-server` with the absolute path to your local clone
- The `--` separator distinguishes Claude Code flags from the server command
- Use `--scope project` to share the configuration via `.mcp.json` in version control
- Use `--scope user` to make it available across all your projects (default is `local`)

After adding, verify with `/mcp` in Claude Code or `claude mcp list` in your terminal.

#### HTTP Transport

For HTTP transport, first start the server manually:

```bash
# Start the server with HTTP transport (using .env or environment variables)
NETBOX_URL=https://netbox.example.com/ \
NETBOX_TOKEN=<your-api-token> \
TRANSPORT=http \
uv run netbox-mcp-server
```

Then add the running server to Claude Code:

```bash
# Add the HTTP MCP server (note: URL must include http:// or https:// prefix)
claude mcp add --transport http netbox http://127.0.0.1:8000/mcp
```

**Important notes:**

- The URL **must** include the protocol prefix (`http://` or `https://`)
- The default endpoint is `/mcp` when using HTTP transport
- The server must be running before Claude Code can connect
- Verify the connection with `claude mcp list` - you should see a ✓ next to the server name

### Claude Desktop

Add the server configuration to your Claude Desktop config file. On Mac, edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
    "mcpServers": {
        "netbox": {
            "command": "uv",
            "args": [
                "--directory",
                "/path/to/netbox-mcp-server",
                "run",
                "netbox-mcp-server"
            ],
            "env": {
                "NETBOX_URL": "https://netbox.example.com/",
                "NETBOX_TOKEN": "<your-api-token>"
            }
        }
    }
}
```

> On Windows, use full, escaped path to your instance, such as `C:\\Users\\myuser\\.local\\bin\\uv` and `C:\\Users\\myuser\\netbox-mcp-server`.
> For detailed troubleshooting, consult the [MCP quickstart](https://modelcontextprotocol.io/quickstart/user).

5. Use the tools in your LLM client.  For example:

```text
> Get all devices in the 'Equinix DC14' site
...
> Tell me about my IPAM utilization
...
> What Cisco devices are in my network?
...
> Who made changes to the NYC site in the last week?
...
> Show me all configuration changes to the core router in the last month
```

### Field Filtering (Token Optimization)

Both `netbox_get_objects()` and `netbox_get_object_by_id()` support an optional `fields` parameter to reduce token usage:

```python
# Without fields: ~5000 tokens for 50 devices
devices = netbox_get_objects("devices", {"site": "datacenter-1"})

# With fields: ~500 tokens (90% reduction)
devices = netbox_get_objects(
    "devices", {"site": "datacenter-1"}, fields=["id", "name", "status", "site"]
)
```

**Common field patterns:**

- **Devices:** `['id', 'name', 'status', 'device_type', 'site', 'primary_ip4']`
- **IP Addresses:** `['id', 'address', 'status', 'dns_name', 'description']`
- **Interfaces:** `['id', 'name', 'type', 'enabled', 'device']`
- **Sites:** `['id', 'name', 'status', 'region', 'description']`

The `fields` parameter uses NetBox's native field filtering. See the [NetBox API documentation](https://docs.netbox.dev/en/stable/integrations/rest-api/) for details.

### Branch-Only Writes

With `ENABLE_WRITE=true` the server adds write tools that **only ever write inside a
[NetBox Branching](https://github.com/netboxlabs/netbox-branching) branch**, never to main:

| Tool | Description |
|------|-------------|
| netbox_create_branch | Creates a branch to stage changes in (provisions to `ready` in the background) |
| netbox_create_objects | Creates one or many objects in a branch |
| netbox_update_objects | Updates (PATCH) one or many objects in a branch |
| netbox_delete_objects | Deletes one or many objects in a branch |

Every write tool requires a `branch` (name or schema ID). The server checks that exactly one
branch matches, that its status is `ready` and that it is owned by the API token's user, then
sends the request with the `X-NetBox-Branch` header. Set `ALLOW_FOREIGN_BRANCHES=true` to also
write into other users' branches. `netbox_list_branches` (available in every mode) lists the
branches. `netbox_list_branches` marks each branch `mine` (owned by the token's user) and `writable` (ready and usable by the write tools now). `netbox_get_objects`, `netbox_get_object_by_id`,
`netbox_search_objects` and `netbox_get_changelogs` take an optional `branch` to read the
staged state. There is deliberately no merge tool: review and merge
branches in the NetBox UI.

Only object types that NetBox Branching actually isolates can be written: `circuits`, `dcim`,
`ipam`, `tenancy`, `virtualization`, `vpn`, `wireless`, plus `extras.journalentry` and
`extras.tag`. Other types (users, tokens, permissions, `core`) would be changed in main
immediately, so they are refused. Config contexts and config templates are refused too, since
saving one creates or deletes its auto-sync record in main, and so are plugin models, whose side
effects in main are unknown.
This is enforced in the NetBox client itself: the only request it will send to main is
creating a branch.

Deleting an object also deletes users' bookmarks of it, subscriptions to it and jobs attached
to it (and those of objects deleted with it: a device's interfaces, a location's child and
grandchild locations), and NetBox Branching doesn't isolate those, so a delete inside a branch
would remove them from main immediately. `netbox_delete_objects` therefore refuses such
deletes. Which objects the delete reaches is traced inside the branch, by following the links
of every bookmarked, subscribed or job-linked object. An inventory item's parent, which the API
shows only as an ID, is followed too. Other links are looked up with filters from the deleted
side: a VLAN translation rule's policy, a module bay's hidden parent (which can be stale; a
deleted device's or module's whole module bay subtree is walked), and the cached region, site
group, site and location of prefixes, clusters and wireless LANs. The check only sees rows the API token may
view; if it can't check, or can't see one of those objects, the delete is refused too. It
counts objects that would only be unlinked (set to null) as deleted, so it also refuses some
deletes that would remove nothing, e.g. a tenant whose devices have bookmarked interfaces, and
it refuses when tracing needs more than 2000 lookups. A bookmark or subscription created in
the moment between the check and the delete is still lost. Tags, journal entries, image
attachments and contact assignments are branch-isolated.

NetBox also notifies users subscribed to an object whenever it is saved or deleted, including
inside a branch, and a write saves more objects than it names (a cable's interfaces, a wireless
link's interfaces). So while anyone is subscribed to a branchable object, every branch write is
refused.

NetBox also runs **event rules** (webhooks, scripts) for changes made inside a branch, as if
they had happened in main. So while any enabled event rule covers a branchable object type,
every branch write is refused, except for rules that only fire on main (below). Plugin models
and image attachments count, since a delete cascades to them. List the IDs of rules that are
safe to run on unreviewed branch changes (e.g. a chat notification) in
`ALLOWED_BRANCH_EVENT_RULES`. `ALLOW_BRANCH_EVENTS=true` allows all event rules and subscriber
notifications.

**Restricting event rules to main.** netbox-branching can tell event rules whether a change was
made in a branch. The NetBox operator must configure this; the server can't do it or check it:

1. In NetBox's `configuration.py`, list the plugin's `add_branch_context` **before**
   `process_event_queue` in `EVENTS_PIPELINE` (list both: NetBox puts `process_event_queue`
   first if it is missing), then restart NetBox:

   ```python
   EVENTS_PIPELINE = [
       'netbox_branching.events.add_branch_context',
       'extras.events.process_event_queue',
   ]
   ```

2. Give each event rule that must not act on branch changes this condition (or add the
   `active_branch` test to the top-level `and` of its existing conditions):

   ```json
   {"and": [{"attr": "active_branch", "value": null}]}
   ```

The server reads each rule's conditions and doesn't count a rule whose top-level `and` contains
`{"attr": "active_branch", "value": null}` (operator `eq`, not negated). Anything else still
blocks branch writes: the test under `or`, negated, nested in a sub-group, or missing.

`EVENTS_PIPELINE` isn't visible through the API, so the server trusts that step 1 is done.
Without it, events carry no `active_branch`: before NetBox 4.3.4 the condition then matches every
change, so the rule **fires on branch changes after all**; from NetBox 4.3.4 the condition fails
to evaluate and the rule stops firing entirely, in main too. Check the pipeline before
relying on these conditions. (This follows netbox-branching's event rule documentation; unlike
the behaviours below, it hasn't been tested against a live NetBox.)

The event rule, bookmark, subscription and job checks need an API token that sees every row:
NetBox silently filters API lists by the token user's permission constraints (by default users
see only their own bookmarks and subscriptions), and the API can't tell, so writes that need
these checks are refused until you set `UNRESTRICTED_TOKEN=true`. Set it only when the token's
user can view everything without constraints, e.g. a superuser.

Uploaded files aren't isolated either: changing a device type's front or rear image, or
deleting a device type that has images, would delete main's image file at once, so both are
refused. Which models are branchable is read from NetBox at startup;
if NetBox can't report it, deletes are refused.

These behaviours were verified with netbox-branching 1.1.3 on NetBox 4.5; on other versions the
server logs a reminder at startup to re-verify them.
With `TRANSPORT=http`, `ENABLE_WRITE` requires `MCP_AUTH_TOKEN`; the server will not start otherwise.

#### Supported NetBox versions

Branch-only writes work on every NetBox version that netbox-branching supports (4.1 through
4.7; see its [compatibility matrix](https://github.com/netboxlabs/netbox-branching/blob/main/COMPATIBILITY.md)).
Some parts depend on the NetBox version:

| NetBox | Token's user (for branch ownership) | Writable models | Deletes |
|--------|-------------------------------------|-----------------|---------|
| 4.5+ | Reported by NetBox (`/api/authentication-check/`) | Static allow-list, narrowed to what NetBox reports as branchable | Checked |
| 4.4 | Set `NETBOX_USERNAME` | Static allow-list, narrowed to what NetBox reports as branchable | Checked |
| 4.1-4.3 | Set `NETBOX_USERNAME` | Static allow-list | Refused (NetBox can't report branchable models) |

Before NetBox 4.5 there is no API to ask which user owns a token, so set `NETBOX_USERNAME` to
that user's username. When the server creates a branch, NetBox records the real owner, which
the server then uses (and warns if `NETBOX_USERNAME` named someone else). Without
`NETBOX_USERNAME`, writes on these versions need `ALLOW_FOREIGN_BRANCHES=true`.

## Configuration

The server supports multiple configuration sources with the following precedence (highest to lowest):

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **`.env` file** in the project root
4. **Default values** (lowest priority)

### Configuration Reference

| Setting | Type | Default | Required | Description |
|---------|------|---------|----------|-------------|
| `NETBOX_URL` | URL | - | Yes | Base URL of your NetBox instance (e.g., https://netbox.example.com/) |
| `NETBOX_TOKEN` | String | - | Yes | API token for authentication |
| `TRANSPORT` | `stdio` \| `http` | `stdio` | No | MCP transport protocol |
| `HOST` | String | `127.0.0.1` | If HTTP | Host address for HTTP server |
| `PORT` | Integer | `8000` | If HTTP | Port for HTTP server |
| `MCP_AUTH_TOKEN` | String | - | No | Bearer token required on the HTTP endpoint. When unset, the HTTP transport is unauthenticated. Clients send `Authorization: Bearer <token>`. |
| `VERIFY_SSL` | Boolean | `true` | No | Whether to verify SSL certificates |
| `ENABLE_PLUGIN_DISCOVERY` | Boolean | `false` | No | Auto-discover plugin object types at startup |
| `ENABLE_WRITE` | Boolean | `false` | No | Expose branch-only write tools (requires the netbox-branching plugin and a write-capable token). See [Branch-Only Writes](#branch-only-writes). |
| `ALLOW_FOREIGN_BRANCHES` | Boolean | `false` | No | Let write tools target branches owned by other users |
| `ALLOW_BRANCH_EVENTS` | Boolean | `false` | No | Let branch writes proceed while enabled event rules (webhooks, scripts) or subscriber notifications would fire on them |
| `ALLOWED_BRANCH_EVENT_RULES` | List | - | No | Comma-separated IDs of event rules that may fire on branch changes |
| `UNRESTRICTED_TOKEN` | Boolean | `false` | No | Confirm the API token's user can view everything without permission constraints (e.g. a superuser); required for the checks that read event rules, bookmarks, subscriptions and jobs |
| `NETBOX_USERNAME` | String | - | NetBox < 4.5 | Username of the API token's user, for branch ownership on NetBox versions that can't report it |
| `LOG_LEVEL` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` \| `CRITICAL` | `INFO` | No | Logging verbosity |

### Transport Examples

#### Stdio Transport (Claude Desktop/Code)

For local Claude Desktop or Claude Code usage with stdio transport:

```json
{
    "mcpServers": {
        "netbox": {
            "command": "uv",
            "args": ["--directory", "/path/to/netbox-mcp-server", "run", "netbox-mcp-server"],
            "env": {
                "NETBOX_URL": "https://netbox.example.com/",
                "NETBOX_TOKEN": "<your-api-token>"
            }
        }
    }
}
```

#### HTTP Transport (Web Clients)

For web-based MCP clients using HTTP/SSE transport:

```bash
# Using environment variables
export NETBOX_URL=https://netbox.example.com/
export NETBOX_TOKEN=<your-api-token>
export TRANSPORT=http
export HOST=127.0.0.1
export PORT=8000

uv run netbox-mcp-server

# Or using CLI arguments
uv run netbox-mcp-server \
  --netbox-url https://netbox.example.com/ \
  --netbox-token <your-api-token> \
  --transport http \
  --host 127.0.0.1 \
  --port 8000
```

### Example .env File

Create a `.env` file in the project root:

```env
# Core NetBox Configuration
NETBOX_URL=https://netbox.example.com/
NETBOX_TOKEN=your_api_token_here

# Transport Configuration (optional, defaults to stdio)
TRANSPORT=stdio

# HTTP Transport Settings (only used if TRANSPORT=http)
# HOST=127.0.0.1
# PORT=8000
# Bearer token required on the HTTP endpoint. When unset, the endpoint is unauthenticated.
# MCP_AUTH_TOKEN=a-strong-random-token

# Security (optional, defaults to true)
VERIFY_SSL=true

# Plugin Discovery (optional, defaults to false)
# ENABLE_PLUGIN_DISCOVERY=true

# Logging (optional, defaults to INFO)
LOG_LEVEL=INFO
```

### CLI Arguments

All configuration options can be overridden via CLI arguments:

```bash
uv run netbox-mcp-server --help

# Common examples:
uv run netbox-mcp-server --log-level DEBUG --no-verify-ssl  # Development
uv run netbox-mcp-server --transport http --port 9000       # Custom HTTP port
```

## Docker Usage

### Pre-built Image (Docker Hub)

Pre-built multi-arch images (`linux/amd64`, `linux/arm64`) are published to Docker Hub on every tagged release:

```bash
docker pull netboxlabs/netbox-mcp-server:latest
```

Pin to a specific version in production. The `latest` tag tracks the most recent release and can change without notice. See the [releases page](https://github.com/netboxlabs/netbox-mcp-server/releases) for available versions:

```bash
docker pull netboxlabs/netbox-mcp-server:<X.Y.Z>   # exact version
docker pull netboxlabs/netbox-mcp-server:<X.Y>     # latest within a minor
docker pull netboxlabs/netbox-mcp-server:<X>       # latest within a major
```

**Verify image provenance (optional but recommended).** Images are signed with [cosign](https://github.com/sigstore/cosign) (keyless, via GitHub OIDC) and ship with SLSA build provenance:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/netboxlabs/netbox-mcp-server/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  netboxlabs/netbox-mcp-server:<tag>
```

### Standard Docker Image

Build and run the NetBox MCP server in a container:

```bash
# Build the image
docker build -t netbox-mcp-server:latest .

# Run with HTTP transport (required for Docker containers)
docker run --rm \
  -e NETBOX_URL=https://netbox.example.com/ \
  -e NETBOX_TOKEN=<your-api-token> \
  -e TRANSPORT=http \
  -e HOST=0.0.0.0 \
  -e PORT=8000 \
  -e MCP_AUTH_TOKEN=<a-strong-random-token> \
  -p 8000:8000 \
  netbox-mcp-server:latest
```

> **Note:** Docker containers require `TRANSPORT=http` since stdio transport doesn't work in containerized environments.

> **⚠️ Security:** The HTTP transport has **no authentication** unless you set `MCP_AUTH_TOKEN`. Binding to `HOST=0.0.0.0` exposes read access to all NetBox data your token can see to anyone who can reach the port. Set a strong `MCP_AUTH_TOKEN` (clients then send `Authorization: Bearer <token>`) and terminate TLS at a reverse proxy or gateway before exposing the server to a network. A bearer token sent over plain HTTP can be intercepted, so TLS is required for real deployments.

**Connecting to NetBox on your host machine:**

If your NetBox instance is running on your host machine (not in a container), you need to use `host.docker.internal` instead of `localhost` on macOS and Windows:

```bash
# For NetBox running on host (macOS/Windows)
docker run --rm \
  -e NETBOX_URL=http://host.docker.internal:18000/ \
  -e NETBOX_TOKEN=<your-api-token> \
  -e TRANSPORT=http \
  -e HOST=0.0.0.0 \
  -e PORT=8000 \
  -e MCP_AUTH_TOKEN=<a-strong-random-token> \
  -p 8000:8000 \
  netbox-mcp-server:latest
```

> **Note:** On Linux, you can use `--network host` instead, or use the host's IP address directly.

**With additional configuration options:**

```bash
docker run --rm \
  -e NETBOX_URL=https://netbox.example.com/ \
  -e NETBOX_TOKEN=<your-api-token> \
  -e TRANSPORT=http \
  -e HOST=0.0.0.0 \
  -e MCP_AUTH_TOKEN=<a-strong-random-token> \
  -e LOG_LEVEL=DEBUG \
  -e VERIFY_SSL=false \
  -p 8000:8000 \
  netbox-mcp-server:latest
```

The server will be accessible at `http://localhost:8000/mcp` for MCP clients. You can connect to it using your preferred method.

## Plugin Object Type Discovery

By default, only core NetBox object types are available. If your NetBox instance has plugins installed (e.g., `netbox-dns`, `netbox-inventory`), you can enable automatic discovery to make their object types available as well.

### Enabling Discovery

Set the `ENABLE_PLUGIN_DISCOVERY` environment variable or use the `--enable-plugin-discovery` CLI flag:

```bash
# Via environment variable
ENABLE_PLUGIN_DISCOVERY=true uv run netbox-mcp-server

# Via CLI flag
uv run netbox-mcp-server --enable-plugin-discovery

# In Claude Desktop config
{
    "mcpServers": {
        "netbox": {
            "command": "uv",
            "args": ["--directory", "/path/to/netbox-mcp-server", "run", "netbox-mcp-server"],
            "env": {
                "NETBOX_URL": "https://netbox.example.com/",
                "NETBOX_TOKEN": "<your-api-token>",
                "ENABLE_PLUGIN_DISCOVERY": "true"
            }
        }
    }
}
```

### How It Works

At startup, the server queries NetBox's `core/object-types` API endpoint (with `extras/object-types` fallback for NetBox < 4.4) to find all installed plugin models that have REST API endpoints. These are merged into the runtime type registry alongside the core types.

Discovered plugin types use the `app_label.model` naming convention (e.g., `netbox_dns.zone`, `netbox_inventory.asset`) and work with all existing tools (`netbox_get_objects`, `netbox_get_object_by_id`, `netbox_search_objects`).

### Requirements

- NetBox 4.2 or later
- API token must have read access to the object-types endpoint
- Plugin models must expose a REST API endpoint to be discovered

### Failure Behavior

If discovery fails for any reason (network error, insufficient permissions, unsupported NetBox version), the server logs a warning and continues with core types only. This ensures the server always starts successfully regardless of discovery outcome.

## Development

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing new features. We encourage filing an issue for discussion first to confirm scope fit.

If your use case needs capabilities outside this project's scope, forking under Apache 2.0 is an actively supported path.

## License

This project is licensed under the Apache 2.0 license.  See the LICENSE file for details.


