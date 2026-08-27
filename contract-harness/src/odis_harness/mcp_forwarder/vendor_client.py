"""The `McpClient` Protocol — the vendor-transport seam.

The Router holds one `McpClient` per family (per the bundle's routing table)
and calls it during forward orchestration. The production implementation
wraps the official `mcp` Python SDK's client primitives over HTTP; this module
defines the Protocol the Router programs against and ships an in-memory test
double that exercises the same surface.

`VendorUnreachable` is the typed transport-failure error; the Router catches
it at the forward boundary and converts to `odis.mcp.forward_refused` with
`reason_code: vendor_unreachable`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any


class VendorUnreachable(RuntimeError):  # noqa: N818 - domain term reads clearer without the Error suffix
    """Vendor MCP server cannot be contacted (transport-level failure).

    Distinct from refusals the vendor returns inside an MCP response — those
    bubble up as ToolResult content the Router passes through unchanged.
    """


@dataclass(frozen=True, kw_only=True, slots=True)
class ToolDescriptor:
    """An MCP tool entry returned by `tools/list`.

    Mirrors the MCP spec's tool shape (`name`, `description`, `inputSchema`)
    without binding to the SDK's concrete `Tool` class — the Router treats
    vendor catalogs structurally.
    """

    name: str
    description: str
    input_schema: Mapping[str, Any]


@dataclass(frozen=True, kw_only=True, slots=True)
class ToolResult:
    """The result of a `tools/call` the Router forwarded.

    `content` mirrors the MCP spec's content list (text/image/resource).
    `is_error` mirrors the spec's `isError`: a tool-level failure the vendor
    reported in-band (distinct from `VendorUnreachable`, a transport failure).
    The Router relays it so the agent sees the vendor's success/error status.
    """

    content: list[Mapping[str, Any]]
    is_error: bool = False


@runtime_checkable
class McpClient(Protocol):
    """The Router's view of an upstream vendor MCP server.

    Production implementations wrap the `mcp` Python SDK client over HTTP;
    the in-memory variant below is for tests.
    """

    async def list_tools(self) -> list[ToolDescriptor]:
        """Return the vendor's tool catalog.

        Raises `VendorUnreachable` on transport failure.
        """

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        """Forward an invocation; return the vendor's response.

        Raises `VendorUnreachable` on transport failure.
        """


@runtime_checkable
class SupportsSessionEstablish(Protocol):
    """Opt-in capability: a vendor client that can eagerly prime its leg-2 session.

    Deliberately NARROW and SEPARATE from `McpClient` (which stays a pure
    call/list surface, and `InMemoryMcpClient` need not grow this method). At
    boot the Router establishes leg-2 sessions for clients that satisfy this
    Protocol (`HttpMcpClient` with a `BridgeAuth`), priming one token per family
    before discovery, so discovery's own `tools/list` reuses it instead of paying the
    exchange itself. Only `BridgeAuth` primes — an RFC 8693 exchange against the token
    broker, machine-to-machine. The interactive OAuth path (`oauth.py`) is deliberately
    not primed here.
    """

    async def establish(self) -> str | None:
        """Prime the leg-2 session/token, returning what was established.

        Returns the established audience (RFC 8707) when a token was actually
        minted, or `None` when nothing was established (not bridged). Idempotent.
        """


__all__ = [
    "McpClient",
    "SupportsSessionEstablish",
    "ToolDescriptor",
    "ToolResult",
    "VendorUnreachable",
]
