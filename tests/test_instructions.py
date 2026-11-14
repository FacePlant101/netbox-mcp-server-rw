"""Tests for the MCP instructions sent to clients."""

import asyncio

from fastmcp import Client

from netbox_mcp_server.server import (
    READ_INSTRUCTIONS,
    WRITE_INSTRUCTIONS,
    build_instructions,
    mcp,
)


def test_read_only_instructions():
    """Without writes, only the read overview is sent."""
    text = build_instructions(write_enabled=False, extra=None)
    assert text == READ_INSTRUCTIONS
    assert "netbox_create_objects" not in text


def test_write_instructions_follow_read():
    """With writes, the branch workflow follows the read overview."""
    text = build_instructions(write_enabled=True, extra=None)
    assert text == f"{READ_INSTRUCTIONS}\n\n{WRITE_INSTRUCTIONS}"


def test_extra_instructions_come_last():
    """MCP_INSTRUCTIONS text is appended after the built-in parts."""
    text = build_instructions(write_enabled=True, extra="Site notes.")
    assert text.endswith("\n\nSite notes.")
    assert text.startswith(READ_INSTRUCTIONS)


def test_instructions_named_tools_exist():
    """Every tool the instructions name is a real tool function in the server."""
    import netbox_mcp_server.server as server

    text = build_instructions(write_enabled=True, extra=None)
    named = {word.strip(".,:;()") for word in text.split() if word.startswith("netbox_")}
    assert named
    assert all(callable(getattr(server, name, None)) for name in named), named


def test_client_receives_instructions():
    """A client sees the instructions in the initialize result."""

    async def initialize() -> str | None:
        async with Client(mcp) as client:
            return client.initialize_result.instructions

    original = mcp.instructions
    try:
        mcp.instructions = build_instructions(write_enabled=False, extra="Site notes.")
        assert asyncio.run(initialize()) == mcp.instructions
    finally:
        mcp.instructions = original
