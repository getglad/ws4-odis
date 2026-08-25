"""Router.forward + _permissive_forward."""

from __future__ import annotations

import pytest

from odis_harness.mcp_forwarder.router import McpRefusal
from tests import factories

pytestmark = [pytest.mark.enable_socket, pytest.mark.requires_opa]

_ALLOWED_ARGS = {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}}
_OUTSIDE_PROJECT_ARGS = {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}}
_ALLOW_ALL = 'package odis_policy\ndefault decision := {"decision": "allow", "obligations": {}}\n'


# -- policy path --------------------------------------------------------


async def test_forward_allow_calls_vendor_and_emits_forward_audit(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert result.content == [{"type": "text", "text": "ok"}]
    assert vendor.calls == [("update_issue", _ALLOWED_ARGS)]
    assert audit.event_types == ["odis.mcp.forward"]


async def test_forward_returns_vendor_response_unchanged(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor(tools={"update_issue": "the vendor's exact bytes"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert result.content == [{"type": "text", "text": "the vendor's exact bytes"}]


async def test_forward_emits_decision_id_in_audit_when_policy_evaluated(
    opa_binary: str,
) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    router = factories.router(family, opa_binary=opa_binary, audit=audit)
    await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    extra = audit.events[0].extra
    assert extra is not None
    assert extra["decision_id"]  # non-empty
    assert extra["mode"] == "policy_allow"


async def test_forward_deny_does_not_call_vendor_emits_refused(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _OUTSIDE_PROJECT_ARGS)
    assert exc.value.reason_code == "deny"
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]


async def test_forward_obligation_violation_does_not_call_vendor(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    # Policy allows (APF- prefix), but the call mutates a field outside
    # the decision's obligations (allowed_fields=[labels]).
    with pytest.raises(McpRefusal) as exc:
        await router.forward(
            "jira-prod",
            family,
            "update_issue",
            {"issue_key": "APF-1", "fields": {"summary": "nope"}},
        )
    assert exc.value.reason_code == "obligation_violation"
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]


async def test_forward_vendor_unreachable_emits_refused(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor(unreachable=True)
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert exc.value.reason_code == "vendor_unreachable"
    assert audit.event_types == ["odis.mcp.forward_refused"]


async def test_forward_policed_but_unenforceable_tool_fails_closed(opa_binary: str) -> None:
    """A tool the bundle declares as policed but the harness can't enforce
    denies (fail closed) rather than crashing or reaching the vendor."""
    audit = factories.CapturingAuditSink()
    # `transition_issue` is governed, but there is no registered action-limit
    # enforcer for it (only update_issue exists).
    family = factories.family(
        policy=_ALLOW_ALL,
        action_limits_by_tool={"transition_issue": {"allowed_fields": ["status"]}},
    )
    vendor = factories.in_memory_vendor(tools={"transition_issue": "ok"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "transition_issue", {"issue_key": "APF-1"})
    assert exc.value.reason_code == "unenforceable_tool"
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]


async def test_forward_unpoliced_tool_strict_refuses(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    # Family declares policy for update_issue only; agent calls delete_issue.
    family = factories.family()
    vendor = factories.in_memory_vendor(tools={"delete_issue": "deleted"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "delete_issue", {"issue_key": "APF-1"})
    assert exc.value.reason_code == "unpoliced_tool"
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]


# -- permissive path -----------------------------------------------------


async def test_permissive_unpoliced_tool_forwards(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family(default_mode="permissive")
    vendor = factories.in_memory_vendor(tools={"delete_issue": "deleted"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "delete_issue", {"issue_key": "X-1"})
    assert result.content == [{"type": "text", "text": "deleted"}]
    assert vendor.calls == [("delete_issue", {"issue_key": "X-1"})]
    assert audit.event_types == ["odis.mcp.forward"]


async def test_permissive_forward_audit_has_permissive_mode_no_decision_id(
    opa_binary: str,
) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family(default_mode="permissive")
    vendor = factories.in_memory_vendor(tools={"delete_issue": "deleted"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    await router.forward("jira-prod", family, "delete_issue", {"issue_key": "X-1"})
    extra = audit.events[0].extra
    assert extra is not None
    assert extra["mode"] == "permissive"
    assert extra["decision_id"] is None


async def test_permissive_policed_tool_still_evaluates_policy(opa_binary: str) -> None:
    """Permissive only affects unpoliced tools; a policed tool still gets policy."""
    audit = factories.CapturingAuditSink()
    family = factories.family(default_mode="permissive")  # update_issue IS policed
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    # Outside-project issue_key -> policy denies even in a permissive family.
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _OUTSIDE_PROJECT_ARGS)
    assert exc.value.reason_code == "deny"
    assert vendor.calls == []


async def test_permissive_vendor_unreachable_emits_refused(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family(default_mode="permissive")
    vendor = factories.in_memory_vendor(tools={"delete_issue": "deleted"}, unreachable=True)
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "delete_issue", {"issue_key": "X-1"})
    assert exc.value.reason_code == "vendor_unreachable"
    assert audit.event_types == ["odis.mcp.forward_refused"]


# -- end-to-end against the shipped example bundle ---------------------------
# Guards against Rego-vs-OPA-input-shape drift: the example bundle's policy
# must agree with what the Router actually sends (bare verb + raw args).


async def test_example_bundle_jira_prod_allows_labels_on_apf(opa_binary: str) -> None:
    bundle = factories.example_bundle()
    family = bundle.family("jira-prod")
    assert family is not None
    audit = factories.CapturingAuditSink()
    vendor = factories.in_memory_vendor()
    router = factories.router(bundle, vendor=vendor, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert result.content == [{"type": "text", "text": "ok"}]
    assert audit.event_types == ["odis.mcp.forward"]


async def test_example_bundle_jira_prod_denies_other_project(opa_binary: str) -> None:
    bundle = factories.example_bundle()
    family = bundle.family("jira-prod")
    assert family is not None
    audit = factories.CapturingAuditSink()
    vendor = factories.in_memory_vendor()
    router = factories.router(bundle, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _OUTSIDE_PROJECT_ARGS)
    assert exc.value.reason_code == "deny"
    assert vendor.calls == []
