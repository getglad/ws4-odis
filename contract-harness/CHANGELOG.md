# Changelog

All notable changes to the ODIS Contract Harness are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

## [Unreleased]

### Changed

- **Breaking (envelope wire format).** The per-call identity field is `originating_principal`,
  not `sponsor`, in `odis.runtime.context.v1` and in `odis.authz.request.v1`'s `subject`.
  ODIS separates three identities: `sponsor_ref` and `owner_ref` (§6.1, who is accountable
  for an agent and where it belongs, on an Agent Registration Record) from
  `originating_principal` (§6.3, on whose authority it is acting right now). The harness had
  one per-call field under the sponsor name doing originating-principal work. The Python API
  follows: `OriginatingPrincipal`, `OriginatingPrincipalProvider`,
  `FixtureOriginatingPrincipalProvider`, `RuntimeContextFactory(principal_provider=...)`,
  `WorkloadIdentityProvider.issue(principal_id=...)`. Both schemas keep
  `additionalProperties: false`, so a payload carrying `sponsor` is now rejected.
- Envelopes carry the loaded Authority Grant's `bundle_id`, `bundle_version` and
  `trust_root_id` instead of fixture constants, so an audit event names the grant that
  authorized the call. Those three are no longer `const`-pinned in the envelope schemas.
- Refusal reasons are a typed `ReasonCode`, and the Router audits the evaluator's own
  reason, so a fail-closed `policy_error` is distinguishable from a policy `deny`.

### Fixed

- `resolve_opa_binary` rejects an unusable `$ODIS_OPA_BIN` instead of returning it, and the
  schemas directory resolves by probing for `odis.bundle.v1.json` rather than for any
  directory named `schemas`.
- `VendorMcp` validates `url` against the schema's `^https?://`.
- `mise run install` honours `uv.lock`; `mise run test-all` reaches the Vault test slice.


### Added

- Initial contribution to the CoSAI ODIS workstream: a runnable, 100%-open-source
  candidate implementation of the ODIS Router / governance-checkpoint wedge, built as an
  MCP policy-forwarder and contributed as a technical demonstration.
  - The Router forward pipeline: trusted identity context, policed-tool gate, real OPA
    (Rego) policy decisions, per-argument action limits, and schema-validated audit
    events — fail-closed at every step.
  - The `apf-bundle-issuer` HashiCorp Vault plugin (Go): workload-JWT validation,
    grant union with fail-closed collision rules, tier ceilings, policy-DSL-to-Rego
    projection, and Ed25519 transit-signed canonical bundles the Python harness
    verifies offline.
  - A Terraform module provisioning a persistent Vault's non-secret resources, with an
    out-of-band signing configuration step that keeps the AppRole `secret_id` out of
    Terraform state.
  - An OpenShell-gated example where a real sandbox makes the Router the agent's only
    network path — the gate as mandatory enforcement, not advisory convention.
  - Three proof levels runnable via mise: `demo` (local, zero infrastructure),
    `smoke-vault` (signed bundles), and `demo-openshell` (substrate-enforced).
