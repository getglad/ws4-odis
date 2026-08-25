"""Audit emission helpers for the Router.

Three emitters: `audit_forward`, `audit_refused`, and `audit_discovery_failed`. Every
audit event the harness produces comes from this module.

The `odis.mcp.*` event types are written as literals rather than as an enum:
`contracts.audit_taxonomy` owns the registered vocabulary and `AuditSink` validates
every event against it, so a typo surfaces as an `EnvelopeValidationError` on emission.

Each helper constructs its event and hands it to the provided `AuditSink`, stamping the
supplied `policy_digest` (bound to the bundle the decision was made against) so the
audit trail attests to the exact bundle in force.

`vendor_endpoint_id` (from `Family.vendor_mcp`) is recorded in the event's
`extra`. The vendor's URL is NOT recorded: audit records reference
the stable endpoint id from the bundle so URL changes don't break the trail.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Literal

from odis_harness.contracts import AuditEvent, now_iso
from odis_harness.mcp_forwarder.reason_codes import ReasonCode

if TYPE_CHECKING:
    from odis_harness.audit.sink import AuditSink
    from odis_harness.bundle import Family


ForwardMode = Literal["policy_allow", "permissive"]


def audit_forward(  # noqa: PLR0913 - audit event has many independent kw-only fields
    audit: AuditSink,
    *,
    correlation_id: str,
    policy_digest: str,
    family_name: str,
    family: Family,
    tool: str,
    decision_id: str | None,
    mode: ForwardMode,
) -> None:
    """Emit `odis.mcp.forward` for a successful (or permissive) forward.

    `decision_id` is the RPV decision that authorized the call for
    `mode="policy_allow"`; `None` when the call was a permissive-mode
    passthrough (no policy was evaluated).
    """
    audit.emit(
        AuditEvent(
            correlation_id=correlation_id,
            event_id=str(uuid.uuid4()),
            timestamp=now_iso(),
            event_type="odis.mcp.forward",
            policy_digest=policy_digest,
            resource_family=family_name,
            extra={
                "tool": tool,
                "vendor_endpoint_id": family.vendor_mcp.endpoint_id,
                "decision_id": decision_id,
                "mode": mode,
            },
        )
    )


def audit_refused(  # noqa: PLR0913 - audit event has many independent kw-only fields
    audit: AuditSink,
    *,
    correlation_id: str,
    policy_digest: str,
    family_name: str,
    tool: str,
    reason_code: ReasonCode,
) -> None:
    """Emit `odis.mcp.forward_refused` with a structured reason_code.

    The vocabulary is `ReasonCode` — iterate it rather than maintaining a list here,
    which is how the previous enumeration in this docstring came to omit two members.
    """
    audit.emit(
        AuditEvent(
            correlation_id=correlation_id,
            event_id=str(uuid.uuid4()),
            timestamp=now_iso(),
            event_type="odis.mcp.forward_refused",
            policy_digest=policy_digest,
            resource_family=family_name,
            reason_code=reason_code,
            extra={"tool": tool},
        )
    )


def audit_discovery_failed(audit: AuditSink, *, policy_digest: str, family_name: str) -> None:
    """Emit `odis.mcp.discovery_failed` when a family's tool catalog cannot be fetched.

    The underlying error is deliberately not carried into the event: it can hold vendor
    detail. Each failure gets its own `correlation_id` — it belongs to no agent call.
    """
    audit.emit(
        AuditEvent(
            correlation_id=str(uuid.uuid4()),
            event_id=str(uuid.uuid4()),
            timestamp=now_iso(),
            event_type="odis.mcp.discovery_failed",
            policy_digest=policy_digest,
            resource_family=family_name,
            reason_code=ReasonCode.VENDOR_UNREACHABLE,
        )
    )


__all__ = [
    "ForwardMode",
    "audit_discovery_failed",
    "audit_forward",
    "audit_refused",
]
