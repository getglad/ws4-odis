"""MCP protocol glue — exposes a Router as an MCP `Server`.

Isolates the `mcp` SDK dependency from the forward engine (`router.py` stays
SDK-free). `build_mcp_server(router)` wires the SDK's low-level `Server` with
`tools/list` (from the discovery cache) and `tools/call` (dispatch to
`Router.forward`).

`tools/call` is registered with `validate_input=False`: the Router's own
policy + action-limit pipeline is the authority and audits every call. Letting
the SDK reject on inputSchema first would bypass that audit trail.
"""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

from mcp.server.lowlevel import Server
from mcp.types import CallToolResult, ContentBlock, TextContent, Tool

from odis_harness.mcp_forwarder.audit import audit_refused
from odis_harness.mcp_forwarder.names import UnroutedToolName, parse_tool_name
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from odis_harness.mcp_forwarder.router import McpRefusal

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

    from odis_harness.mcp_forwarder.router import Router
    from odis_harness.mcp_forwarder.vendor_client import ToolResult

#: Server name advertised in the MCP `initialize` handshake.
SERVER_NAME = "odis-router"


def build_mcp_server(router: Router) -> Server:
    """Construct an MCP `Server` backed by `router`."""
    server: Server = Server(SERVER_NAME)

    # The SDK's list_tools/call_tool decorators are untyped; the ignores are
    # the documented pattern for a third-party stub limitation.
    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def _list_tools() -> list[Tool]:
        return _tool_catalog(router)

    @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
    async def _call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        return await _call(router, name, arguments)

    return server


def _tool_catalog(router: Router) -> list[Tool]:
    if router.discovery is None:
        return []
    descriptors = router.discovery.aggregate(router.bundle)
    return [
        Tool(
            name=d.name,
            description=d.description,
            inputSchema=dict(d.input_schema),
        )
        for d in descriptors
    ]


async def _call(router: Router, name: str, arguments: Mapping[str, Any]) -> CallToolResult:
    args = dict(arguments or {})
    try:
        family_name, tool = parse_tool_name(name)
    except UnroutedToolName:
        _audit_handler_refusal(
            router, family_name=None, tool=name, reason_code=ReasonCode.UNROUTED_FAMILY
        )
        return _refusal_result(ReasonCode.UNROUTED_FAMILY)

    family = router.bundle.family(family_name)
    if family is None:
        # family_name is None: the bundle declares no such family, so there is no
        # resource family to name. The sink derives `apf_semantic_enforcement` from
        # the presence of one, and a call refused before policy was not enforced.
        _audit_handler_refusal(
            router, family_name=None, tool=tool, reason_code=ReasonCode.UNROUTED_FAMILY
        )
        return _refusal_result(ReasonCode.UNROUTED_FAMILY)

    try:
        result = await router.forward(family_name, family, tool, args)
    except McpRefusal as refusal:
        return _refusal_result(refusal.reason_code)
    except Exception:  # noqa: BLE001 - handler boundary: fail closed, audit, never leak internals
        # An unexpected error (a bug, not a policy refusal) still fails closed
        # AND is audited. The agent gets a generic refusal — never the
        # exception text, which could leak internal detail.
        _audit_handler_refusal(
            router, family_name=family_name, tool=tool, reason_code=ReasonCode.INTERNAL_ERROR
        )
        return _refusal_result(ReasonCode.INTERNAL_ERROR)
    return _success_result(result)


def _audit_handler_refusal(
    router: Router, *, family_name: str | None, tool: str, reason_code: ReasonCode
) -> None:
    """Emit the refusal audit for a call rejected at the handler, before `forward`.

    `forward` audits its own refusals; this covers the two it never sees — an
    unroutable tool name and an unexpected error at the protocol boundary.
    """
    # No identity context: this fires before routing resolved a family, and minting one
    # would call the identity providers — network I/O in a real deployment — on
    # agent-controlled input that is already being rejected. `family_name` is None for an
    # unroutable name so the sink does not derive `apf_semantic_enforcement` for a call
    # that reached neither policy nor an enforcer.
    audit_refused(
        router.audit,
        correlation_id=str(uuid.uuid4()),
        bundle=router.bundle,
        family_name=family_name,
        tool=tool,
        reason_code=reason_code,
        runtime_context=None,
    )


def _refusal_result(reason_code: ReasonCode) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=f"refused: {reason_code}")],
        isError=True,
    )


def _success_result(result: ToolResult) -> CallToolResult:
    # The Router forwarded successfully, but the vendor may have returned an
    # in-band tool error — relay its real status rather than hard-coding success.
    return CallToolResult(content=_to_text_blocks(result.content), isError=result.is_error)


def _to_text_blocks(blocks: list[Mapping[str, Any]]) -> list[ContentBlock]:
    """Convert vendor MCP content blocks into SDK content blocks.

    Text blocks pass through; non-text blocks are JSON-serialized into a text
    block (PoC fidelity limit — image/resource passthrough is future work).
    """
    out: list[ContentBlock] = []
    for block in blocks:
        if block.get("type") == "text" and "text" in block:
            out.append(TextContent(type="text", text=str(block["text"])))
        else:
            out.append(TextContent(type="text", text=json.dumps(block)))
    return out


__all__ = ["SERVER_NAME", "build_mcp_server"]
