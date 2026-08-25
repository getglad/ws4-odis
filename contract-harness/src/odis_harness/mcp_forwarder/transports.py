"""HTTP transport for the Router's MCP server.

HTTP only (Streamable HTTP per the MCP spec). No stdio: the Router is a network
chokepoint an agent is routed *through*, not a subprocess it launches.
Any standard MCP client (Inspector, Claude Code, Cursor) connects to the server's URL
with no special handling — unless `serve --inbound-key` configured a token verifier, in
which case the client must also present a bearer the Router accepts.

`build_asgi_app` constructs the Starlette app (testable / mountable);
`serve_http` runs it under uvicorn until shutdown.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

import uvicorn
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Mount

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from mcp.server.auth.provider import TokenVerifier
    from mcp.server.lowlevel import Server
    from starlette.types import ASGIApp, Receive, Scope, Send

#: Path the MCP endpoint is mounted at. Clients connect to `http://host:port/mcp`.
MCP_MOUNT_PATH = "/mcp"


def build_asgi_app(
    server: Server,
    *,
    token_verifier: TokenVerifier | None = None,
    json_response: bool = True,
) -> Starlette:
    """Wrap an MCP `Server` in a Starlette ASGI app via Streamable HTTP.

    `stateless=True`: each request is self-contained (no server-side session
    persistence) — appropriate for a stateless policy forwarder. `json_response`
    returns plain JSON responses (simpler for clients than an SSE stream) while
    remaining MCP-spec compliant.

    Security note: `StreamableHTTPSessionManager` accepts a
    `security_settings` (`TransportSecuritySettings`) param for Origin/Host
    validation, which defends against browser-driven DNS-rebinding. We do not
    set it here: our client is an MCP agent (not a browser), and the default
    CLI bind is loopback. A production deployment exposed to browsers, or bound
    to a non-loopback interface, SHOULD configure allowed Origins/Hosts.
    """
    session_manager = StreamableHTTPSessionManager(
        app=server,
        json_response=json_response,
        stateless=True,
    )

    async def handle_mcp(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    mounted: ASGIApp = handle_mcp
    middleware: list[Middleware] = []
    if token_verifier is not None:
        # Order matters: authenticate, publish the result to the request context, then
        # require it. `RequireAuthMiddleware` answers 401 before the MCP handler runs,
        # so an unauthenticated call never reaches the Router at all.
        #
        # No `resource_metadata_url`, so the `WWW-Authenticate` header carries RFC 6750's
        # `error`/`error_description` but not RFC 9728's `resource_metadata` pointer. A
        # client cannot discover where to get a token from the 401 alone; here it is
        # provisioned with one out of band (Vault, SPIRE). Serving that discovery would
        # mean publishing a protected-resource metadata document, which is a deployment
        # decision this harness does not make for an operator.
        mounted = RequireAuthMiddleware(handle_mcp, required_scopes=[])
        middleware = [
            Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(token_verifier)),
            Middleware(AuthContextMiddleware),
        ]

    return Starlette(
        routes=[Mount(MCP_MOUNT_PATH, app=mounted)],
        middleware=middleware,
        lifespan=lifespan,
    )


async def serve_http(
    server: Server,
    *,
    host: str,
    port: int,
    token_verifier: TokenVerifier | None = None,
) -> None:
    """Serve the MCP `Server` over HTTP until the process is shut down."""
    app = build_asgi_app(server, token_verifier=token_verifier)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    await uvicorn.Server(config).serve()


__all__ = ["MCP_MOUNT_PATH", "build_asgi_app", "serve_http"]
