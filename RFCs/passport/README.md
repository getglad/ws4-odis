# The ODIS Passport

## Summary

ODIS divides agent access across three layers. The Passport checks the agent's software and running instance, then issues or accepts a short-lived credential bound to that instance; the Bridge records who the agent acts for and what authority it holds; the Router governs calls to tools and services. This document specifies the evidence the Passport accepts, the checks it performs, and the credential it gives the Bridge.

It consolidates the Layer 1 discussion in issues #5, #6, #14–#20, #22, #26–#28, #30, #32 and #33, and proposes positions on the open points. Requirements that change ODIS.md are marked in italics at the end of the Ref column: Agreed, Proposed, or New (Section 2). The PR description lists every change in one table.

## Scope

This document specifies the Passport as a component: the evidence it accepts, how it appraises that evidence, how it checks the agent's registration, the Agent Runtime Credential it issues, and how that credential changes, expires, and is revoked.

Out of scope:

1. Delegation and call governance, which the Bridge ([§3.2](../ODIS.md#32-layer-2--the-bridge-delegation--access)) and the Router (proposed in PR #37) define. This document specifies only what the Passport supplies to them.
2. Wire formats. The credential is an abstract data model; binding profiles map it onto X.509 SVIDs, workload identity tokens, or JWTs (Section 5).
3. Deployment patterns, including the endpoint pattern raised in #13. Section 1.3 states the placement rules; worked patterns belong in a companion document.
4. The content of Agent Manifest, TRACE, or other external formats. Where they appear, they enter through Agent Registration Record fields (PR #38) and are not normative here.

## 1. Architecture

Before an agent receives authority, the Passport establishes which instance is running and whether it runs software its organization approved. [Section 4.1](#41-issuance) follows one agent through issuance.

### 1.1 Components and flow

```
  Running agent instance
    │  observed by components outside the agent
    ▼
  ╔═ Passport ══════════════════════════════════════════════════════╗

    1 Evidence collector ◀── node agent, runtime, signer, hardware
    │
    ▼
    2 Appraiser          ◀── verification keys, evidence profiles
    │
    ▼
    3 Registration check ◀── Agent Registration Record
    │
    ▼
    4 Issuer             signs the credential, bound to the holder key
    │
  ╚═│═══════════════════════════════════════════════════════════════╝
    │  credential: results only; evidence stays with the appraiser
    ▼
  Bridge     verifies the credential, resolves the current registration
             (L2-14), and issues its own token (RTR-07)
```

1. **Collect:** components outside the agent gather agent runtime evidence about the instance, its software, and its holder key ([2.1.2](#212-evidence-and-appraisal)).
2. **Appraise:** the appraiser authenticates each evidence source and decides what the evidence proves ([2.1.2](#212-evidence-and-appraisal), [2.1.3](#213-software-and-instance)).
3. **Check registration:** the issuer, or under registration lookup the Bridge, matches the results against the active Agent Registration Record ([2.1.4](#214-registration)).
4. **Issue:** the issuer signs a short-lived Agent Runtime Credential carrying the results, bound to a holder key the agent cannot read ([2.1.5](#215-credential)).

The Passport is a role. The evidence collector, appraiser, and credential issuer may be one component or several, and a platform that also runs the Bridge may host them (PSP-06). The agent cannot reach any of them (PSP-01).

Today §6.2 places raw evidence (`attestation_evidence`) inside the credential, and §6.4 sends the whole descriptor to the policy engine. Every later layer must then parse evidence formats it has no reason to understand (#27). This document separates the two: agent runtime evidence is the Passport's input and stays with the appraiser; the Agent Runtime Credential is its output and carries only appraisal results. This follows the RATS distinction between evidence and attestation results ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)) and matches what the Router expects from the Bridge.

### 1.2 Trust inputs

The Passport draws on two kinds of system.

A workload identity system, such as SPIFFE/SPIRE, a cloud workload identity service, or a platform attestor, observes running processes. It can say which instance is running, what artifact that instance executes, and which key it holds. It cannot say which logical agent the instance belongs to, or whether its organization approved that agent's software.

The agent registration system holds the Agent Registration Record. It can say which logical agent exists, who sponsors it, which software and issuers are approved, and whether the agent is active. It cannot observe a running instance.

The credential combines facts from both. The distinction matters when a component relies on one system for facts only the other can supply: an issuer that copies `agent_id` from the agent's own request asserts what only the registration can establish (#28), and a registration entry approving digest D does not show whether instance R runs D (#15).

| Fact | Source | What makes it trustworthy | Checked by |
|---|---|---|---|
| Running instance and its holder key | Workload identity system | Collected outside the agent by an authenticated, authorized source (PSP-05) | Appraiser |
| Software the instance is executing | Workload attestor, container runtime, independent monitor, or hardware | Same as above; hardware removes the need to trust the host (PSP-13) | Appraiser |
| Software approval | Agent Registration Record | Entered through the governed registration workflow (PSP-18) | Registration check (PSP-15) |
| Software origin | Signing or provenance service, or the governed approval entry | A verified signature or provenance statement, or the governed workflow (PSP-10) | Registration check |
| Logical agent, sponsor, lifecycle state | Agent Registration Record | Authoritative record issuer and §6.1 resolution rule (PSP-19) | Registration check |
| Platform state and key protection | Hardware root (TEE, TPM) | Evidence profile that defines what the quote proves (PSP-13) | Appraiser |
| Current risk or compromise | Security monitors | L1-12 signal checks and declared freshness (PSP-30) | Issuer at issuance and renewal |
| Requested agent identity or software | The agent itself | Not trusted; never sufficient for any check (PSP-05) | — |

### 1.3 Placement

The Passport runs outside the agent harness. Whether the agent cooperates changes how the credential reaches it, not what is trusted (#13):

- **Cooperating agent:** requests its credential from a local endpoint that identifies the caller from the connection, as the SPIFFE Workload API does.
- **Agent that cannot be modified:** such as a third-party harness on a managed laptop, never sees the credential. A privileged component outside it, such as an endpoint security agent, collects evidence and presents proofs on the agent's behalf.

Placement depends on:

- **Isolation:** nothing the model controls may read the Passport's keys or the holder key, alter its configuration, or author its evidence (PSP-01, PSP-21).
- **Visibility:** the evidence collector must be able to observe the process and the artifact it runs. A component with only the agent's privileges cannot.
- **Assurance:** a host-level collector trusts the host; an independent observer or hardware evidence reduces the trust placed in the host (PSP-13).

### 1.4 Threats addressed

- A rogue agent claiming a registered identity.
- An approved artifact registered, but a different one running.
- An agent asserting its own `agent_id` or software digest.
- An agent reading its credential or holder key and using it outside the authorized path.
- A shared platform identity standing in for several agents.
- A stale registration version keeping authority after its approvals changed.
- A failed risk-signal feed read as "no risk".
- Evidence checked against keys the agent chose.

## 2. Requirements

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals. Each requirement names the party it binds; most bind the Passport.

- **Required** ([2.1](#21-required)) applies to every Passport, and to every deployment that uses one.
- **Optional** ([2.2](#22-optional)) may be omitted. A Passport or deployment that implements an optional capability MUST meet its requirements.
- **Profile** is a provisional tag naming the lowest ODIS conformance profile ([ODIS §8.1](../ODIS.md#81-profile-definitions)) at which the requirement applies.
- **Ref** lists related ODIS requirements, without the `ODIS-` prefix ([ODIS §5](../ODIS.md#5-requirements)), ODIS sections (§), and Router requirements (RTR) from PR #37. Where a requirement changes ODIS.md, Ref ends with its status in italics: *Agreed #n*, a change the thread on issue #n agreed; *Proposed #n*, a change this document proposes that the thread on #n did not settle; or *New*, a change with no existing issue, covered by a companion issue. A requirement with no status restates ODIS.md.

### 2.1 Required

#### 2.1.1 General

| ID | Title | Requirement | Profile | Ref |
|---|---|---|---|---|
| PSP-01 | Passport isolation | The evidence collector, appraiser, credential issuer, and holder-key store MUST be outside the control of the model-visible process. That process MUST NOT be able to read their keys, alter their code or configuration, supply any input to them other than its own request, or block their output. Evidence an agent can write about itself is not attestation. The conformance declaration MUST state the mechanism that separates each component from the agent, such as a separate process and user, container, host, administrative domain, or hardware isolation (Section 3.5). | Core | L1-01, L1-11, §9.2 · *Proposed #32, #14* |
| PSP-02 | No static secrets | The agent MUST authenticate to ODIS components with short-lived, automatically rotated, cryptographically verifiable credentials. Static API keys, long-lived service-account secrets, and credentials in agent-visible environment variables MUST NOT be used on that path. L1-01 continues to govern legacy target secrets held by a Provider Adapter. | Core | L1-01 |
| PSP-03 | Fail closed | The issuer MUST NOT issue, renew, or accept an Agent Runtime Credential if it cannot complete any required check, including when evidence, verification keys, collateral, registration data, or a required risk-signal source is unavailable. | Core | L1-11, §9.2 |

#### 2.1.2 Evidence and appraisal

Evidence comes in many formats, which change as platforms change. Layers that rely on the agent's identity need to know what was proven, not how. The appraiser handles that variety so later layers do not parse evidence.

| ID | Title | Requirement | Profile | Ref |
|---|---|---|---|---|
| PSP-04 | Evidence and results | Agent runtime evidence (Section 3.1) is input to appraisal. The appraiser MUST appraise it, and the issuer MUST carry only the results in the Agent Runtime Credential (Section 3.2). The Bridge, the Router, and policy engines MUST NOT be required to parse evidence. The appraiser MUST retain each evidence object, or an authenticated reference to it, for the deployment's declared audit retention period, so that auditors and relying parties can follow the credential's `evidence_refs`. | Core | L1-11, §6.2, §6.4 · *New* |
| PSP-05 | Evidence admission | A component outside the model-visible process (PSP-01) MUST produce each evidence object. The appraiser MUST authenticate that component, MUST confirm that it is authorized to report on runtime instances in the agent's `trust_domain`, and MUST reject evidence outside its `expires_at` or `maximum_age`. Evidence supplied only by the agent process MUST NOT satisfy any requirement in this document. | Core | L1-11, §6.2 · *Agreed #15* |
| PSP-06 | Appraiser and issuer | The appraiser and the credential issuer MAY be one component or separate components. When separate, the issuer MUST authenticate the appraiser and its results before issuing. A platform that also runs the Bridge MAY host either, provided PSP-01 holds. | Core | §3.5 · *New* |
| PSP-07 | Verification method | Each evidence object MUST state how it is verified (`verification_method`, Section 3.1). The appraiser MUST obtain verification keys from an authoritative source, such as OIDC discovery from the authenticated issuer or a configured trust bundle, and MUST NOT use a location supplied by the agent process. Evidence verifiable only through platform-specific tooling (`platform_attestor_api`) MAY be used where the appraiser has that tooling, and MUST carry `federatable: false`. The appraiser MUST reject evidence that states no method. | Core | L1-07, L1-11, §3.1 · *Proposed #5, #21* |
| PSP-08 | Platform credentials | A platform-provisioned credential, such as a Kubernetes service-account token, cloud instance token, or SPIFFE SVID, MAY serve as evidence, and MAY be accepted as the Agent Runtime Credential only if it meets every requirement in [2.1.5](#215-credential) and carries the fields in Section 3.2. A platform credential that the model-visible process can read, for example a token projected onto the agent's filesystem, MUST NOT be accepted as the Agent Runtime Credential. It MAY serve as evidence only when a collector outside that process obtains it from the platform. | Core | §3.1, L1-09 · *Proposed #14* |

#### 2.1.3 Software and instance

ODIS-L1-02 approves software and ODIS-L1-03 attests the instance, but neither requires evidence that the instance runs the approved software (#15). These requirements add that evidence without changing the profile split for hardware evidence.

| ID | Title | Requirement | Profile | Ref |
|---|---|---|---|---|
| PSP-09 | Software approval | Before an Agent Runtime Credential is used to obtain delegated authority, the component performing the registration check (PSP-15) MUST verify the software artifact's identity by digest, signature, or authenticated provenance statement, and MUST match it against `approved_software_refs` in the active Agent Registration Record. A digest match against a governed entry satisfies this in Core; signatures and provenance statements are stronger options. An SBOM alone MUST NOT satisfy this requirement. The conformance declaration MUST state `software_evidence_method` (Section 3.5). | Core | L1-02, §8.2 · *Agreed #26; Proposed #33 (timing)* |
| PSP-10 | Trusted origin | The issuer MUST issue an Agent Runtime Credential only to an instance whose software artifact has a trusted origin. In Core, an artifact has a trusted origin when its digest, package identity, signing identity, or provenance reference entered `approved_software_refs` through the governed registration workflow (PSP-18). Deployments SHOULD use signed artifacts or authenticated provenance statements where tooling allows. A governed approval shows that an accountable owner approved the artifact, not how it was built. | Core | L1-08 · *Proposed #18* |
| PSP-11 | Running software | The runtime/workload evidence MUST identify, by digest, the software artifact the instance is executing, and the appraiser MUST confirm that this is the artifact verified under PSP-09 and recorded in `software_hash`. A single evidence object MAY satisfy both the software and the runtime/workload requirement when it attests both. If the appraiser cannot establish this binding, the issuer MUST NOT issue or accept the credential. | Core | L1-03, §3.1 · *Agreed #15* |
| PSP-12 | Scope of `software_hash` | `software_hash` is the digest of the software artifact as packaged. It covers skills, prompts, or model files bundled into the artifact, but not components managed separately, such as a model selected at runtime. An Agent Registration Record MAY declare an approved composition and the evidence it requires (Section 3.4). Where the record requires composition evidence, issuance and continued acceptance MUST satisfy it. The Router governs actions that result from changing behavior within an approved composition. | Core | L1-02, §6.1, §6.2 · *Agreed #16* |
| PSP-13 | Assurance results | The issuer MUST state, for each relationship in Section 3.3, the assurance level the appraisal reached, and MUST state `holder_key_protection`. Only the issuer sets these values. A relying party MUST read a missing or unknown value as the lowest level. A level MUST NOT be claimed unless the evidence profile defines what the evidence proves for that relationship: a hardware quote that commits to the holder key supports `instance_to_key` but not `instance_to_software`. | Core | L1-03, L1-04, §8.2 · *Proposed #15, #21* |
| PSP-14 | Hardware evidence | Safety-critical and high-assurance agents SHOULD use hardware evidence about the execution environment, platform measurements, or holder-key protection; the Safety profile requires it. Hardware evidence MUST supplement, and MUST NOT replace, software and runtime/workload evidence. | Extended | L1-04, §8.1 |

#### 2.1.4 Registration

The current text holds two positions on whether the credential issuer reads the Agent Registration Record (#33). Issuance-time checking gives the strongest guarantee: no credential exists for an unregistered or unapproved agent. Some issuers cannot read registration records, such as a workload identity service in another administrative domain, and PR #36 asks that ODIS allow them. These requirements make issuance-time checking the default, allow one declared alternative, and define what the credential carries under each.

| ID | Title | Requirement | Profile | Ref |
|---|---|---|---|---|
| PSP-15 | Registration check | Exactly one component MUST check the credential against the active Agent Registration Record, including PSP-09, before the Bridge issues delegated authority, and the conformance declaration MUST name it (`registration_check`, Section 3.5). The issuer SHOULD perform the check at issuance (*registration-aware issuance*). Where the issuer cannot read registration records, the Bridge MUST perform it before issuing delegated authority (*registration lookup*). Under either route, the Bridge still resolves the current record under L2-14. | Core | L1-02, L2-14, CC-05, §1.3 · *Proposed #33, PR #36* |
| PSP-16 | Source of `agent_id` | `agent_id` MUST come from the resolved Agent Registration Record, never from evidence or from the agent. Under registration-aware issuance, the credential MUST carry `agent_id` and `registration_record_ref` copied from that record. Under registration lookup, the credential MUST NOT carry them. A verifier MUST reject a credential whose `agent_id` differs from the record it resolves to. | Core | L2-14, §6.2, §6.3 · *Proposed #28, PR #36* |
| PSP-17 | Unique `agent_id` | An `agent_id` MUST name exactly one logical agent within its trust domain. A shared platform identity, such as an execution role, service account, or namespace that several agents can use, MUST NOT serve as `agent_id`. The Agent Registration Record lists the workload identities that resolve to it (`workload_identities`, Section 3.4). Resolution that yields more than one active record MUST fail closed. This replaces "or agent class" in §1.3. | Core | §1.3, §6.1, CC-02 · *Proposed #6* |
| PSP-18 | Governed registration | An authenticated human administrator, or a pre-approved workflow attributable to an accountable owner, MUST authorize the creation of each Agent Registration Record. An agent MAY request a credential only for its existing active registration, and MUST NOT create or expand its own registration. | Core | CC-05 |
| PSP-19 | Authoritative record | Each Agent Registration Record MUST have one authoritative `record_issuer` within its trust domain, and every resolver MUST apply the §6.1 resolution rule. Deployments MAY distribute, replicate, or cache records by any means, central or decentralized, provided resolution meets that rule. | Core | L1-06, §6.1 · *Proposed #17* |
| PSP-20 | Digest contract | Every `record_digest` in `registration_record_ref` MUST identify its algorithm, for example `sha256:<hex>`. By default the digest covers the record's integrity-protected payload octets exactly as issued; a verifier MUST NOT parse and re-serialize them before hashing. A profile that uses a canonical form instead MUST name the canonicalization algorithm, its version, and any preprocessing. An unknown or ambiguous digest profile MUST fail closed. | Core | §6.1, §6.2 · *Proposed #22* |

#### 2.1.5 Credential

| ID | Title | Requirement | Profile | Ref |
|---|---|---|---|---|
| PSP-21 | Holder key | The Agent Runtime Credential MUST be a proof-of-possession credential bound to a holder key; an identifier, directory object, or shared secret alone MUST NOT authenticate an instance. The holder key MUST be generated and held outside the model-visible process. That process MAY ask an authorized presenter to construct a proof (L2-13); it MUST NOT read or export the key. | Core | L1-09, L2-12, L2-13 · *Proposed #19* |
| PSP-22 | One instance | Each credential MUST be bound to one runtime instance and MUST NOT be used by any other. `runtime_instance_id` MUST identify that instance; a binding profile MAY derive it, for example from the holder-key thumbprint, when the carrier has no instance field. The `agent_id` and its record persist across instances and credentials. | Core | L1-05, L1-09, RTR-04 · *Agreed #16; Proposed PR #36* |
| PSP-23 | Lifetime | Credential lifetime MUST be finite and MUST NOT exceed the declared `maximum_agent_runtime_credential_lifetime_seconds`. `expires_at` MUST be later than `issued_at` and MUST NOT outlive the earliest expiry or maximum age of the evidence it rests on. Deployments SHOULD set lifetimes in minutes, not hours. Credentials MUST rotate automatically before expiry. | Core | L1-05 |
| PSP-24 | Credential contents | The credential MUST carry the fields in Section 3.2 and SHOULD carry no more than the Bridge needs to verify the instance and issue its own token (RTR-07). Detail on how the appraiser reached a result belongs in agent runtime evidence, reachable through `evidence_refs`. | Core | §6.2, §6.4, RTR-07 · *New; Proposed #27* |
| PSP-25 | Audience | Where the carrier binds an audience into the credential, `audiences` MUST be set. Where the audience belongs to each presentation proof instead, as with DPoP or a workload proof token, the verifier MUST check the audience in that proof and `audiences` MAY be omitted. | Core | §6.2 · *Proposed #27* |

#### 2.1.6 Change and revocation

A credential records the state at issuance. These requirements set when later changes take effect: routine changes at renewal, urgent ones through revocation.

| ID | Title | Requirement | Profile | Ref |
|---|---|---|---|---|
| PSP-26 | Registration changes | A credential whose `registration_record_ref` names a superseded record version MAY be accepted until its `expires_at` only if the current version is active and the evidence behind the credential still satisfies the current version, including that `software_hash` is still approved. The resolver MUST resolve the current version, and the Bridge MUST apply L2-01 and L2-14 against it. Renewal MUST reference the current version. Otherwise the verifier MUST reject the credential; work already admitted MAY drain under L1-10 when the change is administrative. | Core | L1-10, L2-14, §6.1 · *Agreed #16* |
| PSP-27 | Change timing | Routine changes, such as approving new software, MAY take effect at the next renewal and MUST take effect within one credential lifetime. Urgent changes, such as suspension, compromise, or removal of an approval an instance depends on, MUST propagate as revocation events within the declared revocation latency. | Core | L1-05, L3-04, RTR-39 · *Proposed #33* |
| PSP-28 | De-provisioning | The system MUST support automated provisioning and de-provisioning of Agent Registration Records. A de-provisioned `agent_id` and its record remain identifiable for audit and MUST NOT authorize new credentials. Every agent MUST have an accountable sponsor or service owner; a change of owner MUST trigger re-verification, transfer, or de-provisioning, subject to L1-10 drain rules. | Core | L1-06, L1-10 · *Agreed #16* |
| PSP-29 | Credential revocation | Revoking an Agent Runtime Credential MUST also revoke tokens derived from it (RTR-07). Revocation events MUST identify their subject by `credential_id`, `runtime_instance_id`, or `agent_id`. Holder keys are per instance and expire with the credential, so de-provisioning does not require revoking keys in a separate key registry. Revocation events MUST reach other trust domains that accepted the credential within their declared propagation bound. | Core | L3-04, L3-05, RTR-07 · *Proposed #17* |
| PSP-30 | Risk signals | Implementations SHOULD consume current risk or compromise signals for active credentials. A confirmed compromise signal (§1.4) MUST cause the credential to be revoked, MUST invalidate derived credentials, and MUST require re-attestation before reissue. The conformance declaration MUST list each signal source the issuer relies on with its `maximum_signal_age_seconds`. A source with no signal inside that bound is indeterminate, and the issuer MUST NOT issue or renew a credential while a declared source is indeterminate. | Core | L1-12 · *Proposed #30* |

### 2.2 Optional

#### 2.2.1 Cross-domain trust

| ID | Title | Requirement | Profile | Ref |
|---|---|---|---|---|
| PSP-31 | Federated acceptance | A trust domain MAY accept Agent Runtime Credentials issued in another. Accepting another issuer's results MUST be an explicit, configured trust decision naming that issuer. The receiving organization's Bridge checks the incoming credential and issues its own token (RTR-09). | Extended | L1-07 |
| PSP-32 | Independent re-appraisal | A relying party that chooses to appraise evidence itself, instead of accepting the issuer's results, MUST obtain the evidence through `evidence_refs` and the collateral its evidence profile requires (`collateral`, Section 3.1). Embedded certificate chains do not supply the relying party's trust anchors or replace its freshness, revocation, and appraisal-policy checks. If required collateral is unavailable or a check cannot complete, the relying party MUST fail closed on that path. | Extended | L1-07, L1-11 · *Proposed #20* |

## 3. Schema definitions

Field names are provisional. Status notes follow the convention in Section 2. This section replaces §6.2 with two models: agent runtime evidence (3.1), the Passport's input, and the Agent Runtime Credential (3.2), its output.

### 3.1 Agent runtime evidence

One object per piece of evidence. Fields with no status are the evidence-object fields §6.2 already requires inside `attestation_evidence`.

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Kind of evidence, such as an image signature, provenance statement, workload attestation document, or hardware quote |
| `issuer` | Yes | Component that produced the evidence |
| `subject` | Yes | What the evidence describes: an instance, an artifact, or a key |
| `issued_at` | Yes | Time the evidence was produced |
| `expires_at` or `maximum_age` | Yes | How long the evidence remains valid |
| `proof` | Yes | Embedded proof, or an authenticated reference to it |
| `integrity` | Yes | Integrity metadata for the object |
| `supports` | Yes | Relationships the evidence supports: `software_provenance`, `instance_to_software`, `instance_to_key`, `platform_state` (*Proposed #21*) |
| `profile` | Yes | URI of the evidence profile that defines what this evidence proves for each relationship it supports (*Proposed #21*) |
| `source_position` | Yes | Where the producer sits relative to the agent's host: `host-platform`, `independent-observer`, or `hardware` (*Proposed #15*) |
| `verification_method` | Yes | `public_jwks`, `configured_trust_bundle`, `mtls_client_certificate`, or `platform_attestor_api` (*Proposed #5*) |
| `verification_ref` | Conditional | JWKS URI or trust-bundle reference from an authoritative source (PSP-07); required for the first two methods (*Proposed #5*) |
| `federatable` | Recommended | `true` if another trust domain can verify the evidence using only the declared method (*Proposed #5*) |
| `collateral` | Recommended | `embedded` or `retrievable`: whether the evidence includes the verification material its profile requires (*Proposed #20*) |

### 3.2 Agent Runtime Credential

The credential carries appraisal results bound to the holder key. Compared with §6.2, `attestation_evidence` moves to Section 3.1 and is replaced by `assurance` and `evidence_refs`.

| Field | Required | Description |
|---|---|---|
| `credential_id` | Yes | Collision-resistant identifier for this credential |
| `format_version` | Yes | Version of the descriptor or carrier profile |
| `issuer` | Yes | Credential issuer |
| `issuer_key_ref` | Yes | Reference to the key that protects the credential |
| `holder_key_ref` | Yes | Confirmation data for the proof-of-possession key |
| `runtime_instance_id` | Yes | The one running instance the credential is bound to; a binding profile MAY derive it (PSP-22) (*Proposed PR #36*) |
| `software_hash` | Yes | Digest of the verified software artifact as packaged (PSP-12) (*Agreed #16*) |
| `assurance` | Yes | Appraisal results for each relationship and for holder-key protection (Section 3.3) (*Proposed #15, #21*) |
| `registration_check` | Yes | `issuance` or `lookup`: which route performed the registration check (PSP-15) (*Proposed #33*) |
| `agent_id` | Conditional | Copied from the resolved record; MUST under `issuance`, MUST be absent under `lookup` (PSP-16) (*Proposed #28, PR #36*) |
| `registration_record_ref` | Conditional | `record_issuer`, `record_id`, `record_version`, and `record_digest` (PSP-20) of the record version current at issuance; same condition as `agent_id` (*Proposed #28, #22*) |
| `trust_domain` | Yes | Organizational trust boundary |
| `issued_at`, `expires_at` | Yes | Issue and expiry times (PSP-23) |
| `audiences` | Conditional | Intended relying parties, where the carrier binds them (PSP-25) (*Proposed #27*) |
| `supply_chain_ref` | Recommended | Reference to the artifact's origin evidence: signing authority, provenance statement, or the governed approval entry in `approved_software_refs` (*Proposed #18*) |
| `evidence_refs` | Recommended | Authenticated references to the evidence the results rest on (PSP-04) (*New*) |

### 3.3 Assurance results

`assurance` records what the appraisal established for each relationship, not what kind of evidence was submitted. Levels are ordered from lowest to highest.

| Level | Meaning |
|---|---|
| `host-platform` | Reported by a component on the agent's host, such as a node agent, kubelet, or container runtime. Trusts the host. Core minimum. |
| `independent-observer` | Reported by a component the agent's host does not control, such as an out-of-host monitor. |
| `hardware` | Rooted in hardware, such as a TEE quote or TPM measurement, under an evidence profile that defines the claim. |

| Field | Description |
|---|---|
| `instance_to_software` | Level at which the appraisal established that the instance runs `software_hash` |
| `instance_to_key` | Level at which the appraisal established that the instance holds the key in `holder_key_ref` |
| `holder_key_protection` | Where the holder key is kept, using the §8.2 `key_custody` values |

Key protection has its own field because it varies independently of the other two: a hardware security module can protect the key of an instance whose software only the host attested.

### 3.4 Registration record fields the Passport reads

This document adds one field to §6.1 and otherwise reads existing fields. PR #38 governs the Agent Manifest additions to §6.1.

| Field | Use by the Passport |
|---|---|
| `agent_id` | Copied into the credential under registration-aware issuance (PSP-16) |
| `lifecycle_state` | No credential for a record that is not `active` (PSP-28) |
| `approved_runtime_issuers` | Issuers the Bridge accepts for this agent |
| `approved_software_refs` | Matched under PSP-09; strings, or typed entries if PR #38 lands |
| `evidence_requirements` | Composition evidence the record requires (PSP-12), if PR #38 lands (*PR #38*) |
| `workload_identities` | Workload identities, such as SPIFFE IDs, that resolve to this record; required for registration lookup (PSP-17) (*Proposed #6, #33*) |
| `trust_domain`, `record_version`, `record_issuer` | Resolution and the digest contract (PSP-19, PSP-20) |

### 3.5 Conformance declaration fields

Additions to §8.2. `attestation_level` is replaced by `minimum_assurance`.

| Field | Values |
|---|---|
| `software_evidence_method` | `digest`, `signature`, or `provenance` (*Agreed #26*) |
| `registration_check` | `issuance` or `lookup` (*Proposed #33*) |
| `minimum_assurance` | Lowest accepted level for `instance_to_software` and for `instance_to_key` (*Proposed #15*) |
| `passport_isolation` | For each Passport component, the mechanism that separates it from the agent (*Proposed #32*) |
| `risk_signal_sources` | For each source: issuer and `maximum_signal_age_seconds` (*Proposed #30*) |

## 4. Examples

### 4.1 Issuance

A finance team registers an invoice-reconciliation agent. Its Agent Registration Record, version 7, names `agents/invoice-reconciler`, lists the approved container image digest, and lists the SPIFFE ID the platform assigns to its workloads. This is the agent the Router document follows through a payment call.

1. **Collect.** The agent starts in a Kubernetes pod. The node agent observes the process, the pod, and the image digest the container runtime reports, and records the public key the instance generated in an isolated signer.
2. **Appraise.** The appraiser authenticates the node agent and confirms it is authorized for `example.com`. The reported digest matches the artifact whose signature the appraiser verified. Both relationships reach `host-platform`.
3. **Check registration.** The issuer reads record version 7. It is active, the digest appears in `approved_software_refs`, and the issuer is in `approved_runtime_issuers`.
4. **Issue.** The issuer signs a 30-minute credential bound to the instance's key ([Section 4.2](#42-credential)). The raw evidence stays with the appraiser.

The agent then requests delegated authority for Alice's task. The Bridge verifies the credential, resolves the current record under L2-14, and issues its own token carrying the Passport's results (RTR-07).

### 4.2 Credential

```json
{
  "credential_id": "arc_3e91c0",
  "format_version": "1",
  "issuer": "https://passport.example.com",
  "issuer_key_ref": "https://passport.example.com/keys/2026-10",
  "holder_key_ref": { "jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" },
  "runtime_instance_id": "ri_04d1",
  "software_hash": "sha256:4f7a1c9e2b6d8f03a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1",
  "assurance": {
    "instance_to_software": "host-platform",
    "instance_to_key": "host-platform",
    "holder_key_protection": "isolated-component"
  },
  "registration_check": "issuance",
  "agent_id": "agents/invoice-reconciler",
  "registration_record_ref": {
    "record_issuer": "https://registry.example.com",
    "record_id": "reg_19",
    "record_version": 7,
    "record_digest": "sha256:9b2e4d6f8a0c2e4f6a8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4f6a8b0d2f"
  },
  "trust_domain": "example.com",
  "issued_at": "2026-09-30T14:00:00Z",
  "expires_at": "2026-09-30T14:30:00Z",
  "supply_chain_ref": "https://registry.example.com/reg_19@7#approved_software_refs/0",
  "evidence_refs": ["https://passport.example.com/evidence/ev_51a8", "https://passport.example.com/evidence/ev_51a9"]
}
```

The credential carries no evidence, only the results and `evidence_refs`, which point to the evidence.

### 4.3 Registration lookup

In another deployment, a SPIRE server issues the agent's credentials. It attests the pod and checks the image signature, but cannot read registration records. Its credential carries `runtime_instance_id`, `software_hash`, and `assurance`, sets `registration_check` to `lookup`, and carries no `agent_id` or `registration_record_ref` (PSP-16).

The Bridge finds the record whose `workload_identities` lists the credential's SPIFFE ID, confirms it is the only active match (PSP-17), matches `software_hash` against `approved_software_refs` (PSP-09), and only then issues delegated authority. The Router receives the same facts in the Bridge token either way.

### 4.4 Registration change

The team approves a new image digest and the record moves to version 8. Credentials naming version 7 stay valid: their evidence still satisfies version 8, and renewals reference version 8 (PSP-26). Later the team removes the old digest. A credential for an instance still running it fails its next L2-14 check and cannot be renewed. If the old image had a known vulnerability, the team revokes affected credentials directly (PSP-27).

### 4.5 Variations

- The instance reads a service-account token from its own filesystem and presents it as its credential. The Bridge rejects it (PSP-08).
- The image is approved but the pod runs a different digest. Appraisal fails and no credential is issued (PSP-11).
- A TEE quote commits to the holder key. `instance_to_key` reaches `hardware`; `instance_to_software` stays at the level the other evidence supports (PSP-13).
- The risk-signal feed stops reporting. Once its declared maximum age passes, renewal stops until the feed recovers (PSP-30).
- Ten agents share one cloud execution role. The role cannot serve as `agent_id`; each agent needs its own registration and workload identity (PSP-17).

## 5. Open questions

References identify the affected requirements or ODIS issues.

- **Sandbox identity:** Should a sandbox and the agents or sub-agents it hosts have separate identities, and which one does `runtime_instance_id` name? This affects PSP-22 and the Router's caller verification (RTR-04). (New issue)
- **Binding profiles:** How do the fields in Section 3.2 map onto X.509 SVIDs, workload identity tokens, and JWTs, including where `runtime_instance_id` comes from when a carrier has no instance field? (PSP-22, PSP-25; #27)
- **Evidence profiles:** Who defines and publishes the evidence profiles that PSP-13 depends on, especially for hardware claims? (#21)
- **Composition evidence:** Which formats can satisfy `evidence_requirements`, and how does an appraiser show an instance matches an approved composition? Depends on PR #38. (PSP-12; #16, #21)
- **Revocation subjects:** Shared Signals and other event standards lack identifiers for agents, credentials, and runtime instances. ODIS should define them once for both this document and the Router. (PSP-29; #25)
- **Deployment patterns:** Where should the endpoint pattern and other worked patterns live? (#13)
- **Profile tags:** The profile tags in Section 2 are provisional. Which requirements belong in Core, Extended, and Safety?

## Glossary

**Agent Registration Record.** An organization's governed record of a logical agent: its owner, sponsor, lifecycle state, approved software, approved issuers, and the workload identities that resolve to it ([ODIS §6.1](../ODIS.md#61-agent-registration-record)).

**Agent runtime evidence.** Raw data about a running instance, its software, or its holder key, such as a workload attestation document, image signature, or hardware quote. Input to appraisal; never required by later layers (Section 3.1).

**Agent Runtime Credential.** The short-lived, holder-bound credential the Passport issues to one running instance, carrying appraisal results (Section 3.2). The Router document calls it the Passport credential.

**Appraiser.** The Passport component that checks agent runtime evidence and produces assurance results.

**Assurance result.** The level at which appraisal established a relationship, such as instance to software (Section 3.3).

**Authorized presenter.** A component outside the model-visible process that constructs proofs with the holder key on the agent's behalf ([ODIS §1.4](../ODIS.md#14-normative-terminology)).

**Evidence collector.** A component outside the agent that gathers agent runtime evidence, such as a node agent or endpoint security agent.

**Evidence profile.** A published definition of what a type of evidence proves for each relationship it supports.

**Holder key.** The private key a credential is bound to. Proof of possession shows the presenter controls it.

**Model-visible process.** Any execution context the model can read or influence, including the agent process and anything its tools can reach ([ODIS §1.4](../ODIS.md#14-normative-terminology)). This document uses it for the boundary ODIS.md also calls "agent-visible" and "agent application process" (#14).

**Registration-aware issuance.** The route in which the credential issuer checks the Agent Registration Record before issuing (PSP-15).

**Registration lookup.** The route in which the Bridge checks the Agent Registration Record because the issuer cannot (PSP-15).

**Runtime instance.** One running copy of an agent, identified by `runtime_instance_id`.

**Trust domain.** Systems under one administrative authority that trust the same issuers.

**Workload identity system.** A system that identifies running processes and the keys they hold, such as SPIFFE/SPIRE or a cloud workload identity service.
