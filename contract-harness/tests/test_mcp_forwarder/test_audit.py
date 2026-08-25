"""audit emission helpers + new event types."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

from odis_harness.contracts.audit_taxonomy import (
    ODIS_EXTENSION_TYPES,
    is_valid_event_type,
)
from odis_harness.mcp_forwarder.audit import (
    ForwardMode,
    audit_discovery_failed,
    audit_forward,
    audit_refused,
)
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from tests import factories

if TYPE_CHECKING:
    from odis_harness.contracts import AuditEvent


# pytest-asyncio's event-loop setup touches sockets; these tests don't use sockets.
pytestmark = pytest.mark.enable_socket


# -- new event types are registered ------------------------------------------


@pytest.mark.parametrize(
    "event_type",
    [
        "odis.mcp.forward",
        "odis.mcp.forward_refused",
        "odis.mcp.discovery_failed",
    ],
)
def test_mcp_audit_events_are_registered(event_type: str) -> None:
    assert event_type in ODIS_EXTENSION_TYPES
    assert is_valid_event_type(event_type)


# -- audit_forward / audit_refused helpers -----------------------------------


#: A vendor URL with a host:port the audit event must never carry.
_VENDOR_URL = "https://jira-prod-mcp.internal:8443/"
_CORRELATION_ID = "00000000-0000-4000-8000-000000000001"


def _forward_event(
    *, mode: ForwardMode = "policy_allow", decision_id: str | None = "dec-1"
) -> AuditEvent:
    sink = factories.CapturingAuditSink()
    audit_forward(
        sink,
        correlation_id=_CORRELATION_ID,
        policy_digest="a" * 64,
        family_name="jira-prod",
        family=factories.family(url=_VENDOR_URL, policy="package odis_policy\n"),
        tool="update_issue",
        decision_id=decision_id,
        mode=mode,
    )
    return sink.events[0]


def _refused_event(*, reason_code: str = "deny") -> AuditEvent:
    sink = factories.CapturingAuditSink()
    audit_refused(
        sink,
        correlation_id=_CORRELATION_ID,
        policy_digest="a" * 64,
        family_name="jira-prod",
        tool="update_issue",
        reason_code=reason_code,
    )
    return sink.events[0]


def test_audit_forward_shape_and_redaction() -> None:
    event = _forward_event()
    extra = event.extra or {}
    assert event.event_type == "odis.mcp.forward"
    assert event.resource_family == "jira-prod"
    # Compared exactly, not key-by-key: the audit event is a published contract, so a
    # new or renamed key has to be a deliberate edit here rather than a silent addition.
    assert extra == {
        "tool": "update_issue",
        "vendor_endpoint_id": "jira-prod-mcp-v1",
        "decision_id": "dec-1",
        "mode": "policy_allow",
    }
    uuid.UUID(event.event_id)
    for value in extra.values():
        assert "internal:8443" not in str(value)
    assert "args" not in extra
    assert "arguments" not in extra


def test_audit_forward_permissive_shape() -> None:
    event = _forward_event(mode="permissive", decision_id=None)
    extra = event.extra or {}
    assert extra["mode"] == "permissive"
    assert extra["decision_id"] is None


def test_audit_discovery_failed_shape() -> None:
    """The third emitter: a family whose tool catalog could not be fetched."""
    sink = factories.CapturingAuditSink()
    audit_discovery_failed(sink, policy_digest="a" * 64, family_name="jira-prod")
    event = sink.events[0]
    assert event.event_type == "odis.mcp.discovery_failed"
    assert event.resource_family == "jira-prod"
    assert event.reason_code == ReasonCode.VENDOR_UNREACHABLE
    # Each discovery failure belongs to no agent call, so it carries its own id.
    uuid.UUID(event.correlation_id)
    # The underlying exception can hold vendor detail and must not be carried.
    assert event.extra is None


def test_audit_refused_shape() -> None:
    event = _refused_event(reason_code="obligation_violation")
    assert event.event_type == "odis.mcp.forward_refused"
    assert event.reason_code == "obligation_violation"
    assert event.extra == {"tool": "update_issue"}
