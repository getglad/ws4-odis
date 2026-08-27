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
- An `obligation_violation` refusal audits the enforcer's own message, naming the argument
  that failed, instead of a bare reason code. The agent still receives only the code.
- Schema `$id`s are URNs. They pointed at `https://apf.local/`, under a TLD RFC 6762
  reserves for mDNS, so a consumer treating them as fetchable would emit a link-local
  multicast lookup. Nothing dereferences them: the validator keys on the file stem and
  every `$ref` is local.
- The OpenShell example's sandbox image pinned `mcp>=1.27`, which resolved to a 2.x client
  whose API the agent script is not written against — inside a sandbox egress-locked to the
  Router and unable to reach PyPI to correct it. Pinned to the version in `uv.lock`.


### Added

- `demo --signed` and `mise run demo-signed`: the canonical scenarios against a Vault-issued
  grant whose ed25519 signature is verified offline. Same Router, gate, transport and vendor
  as `demo` — one axis changed.
- `serve` and `demo` require an explicit grant-trust choice for a local `--bundle`:
  `--bundle-pubkey-file` or `--trust-bundle-unverified`. There is no default, and the startup
  banner names which is in force. Previously a verifier that accepts any payload was
  hardcoded, so the deploy-shaped command trusted an unverified grant silently.


- `serve --inbound-key/--inbound-issuer/--inbound-audience` makes the Router's MCP surface
  an OAuth 2.1 resource server. A caller presents a workload JWT, validated for signature,
  issuer, audience and expiry against an asymmetric-algorithm allowlist matching the Vault
  plugin's, before any handler runs; `agent_id` is then the verified subject rather than a
  constant. Audit events record how the identity was established, so a received identity is
  distinguishable from an asserted one. Trust material is parsed strictly at startup — a
  private-key PEM, malformed material, or a key that cannot verify any allowed algorithm
  exits non-zero instead of serving. Without `--inbound-key` the surface still accepts any
  caller, which the startup banner states outright. It listens on plain HTTP and takes no certificate or key.

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
