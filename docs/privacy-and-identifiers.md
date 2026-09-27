# Identity, disclosure, and domain information

Status: design discussion, 2026-09-10. Based on SDK `0.2.0-alpha.1`; not a change to the wire protocol and not a delivered privacy profile.

Update 2026-09-13: the [identifier/disclosure policy](../spec/identifier-disclosure-policy-v0.1.md)
records the chosen direction and production gates. The experimental
[local domain-exchange helper](domain-exchange.md) now implements explicit requests,
withholding and domain-validator hooks. It does **not** implement confidential
messaging, scoped credential lifecycles or unlinkability. `verifyStatement` alone
continues to perform only the generic checks described below. The helper is included
in `v0.2.0-alpha.2` (2026-09-27); its security boundary remains local-test-only.

## Three different identifiers

| Identifier | Purpose | Current baseline |
| --- | --- | --- |
| Internal asset/serial number | Operator or manufacturer's durable record of a physical machine | Not a required RIP field. It can remain in an operator's private inventory. RIP does not prove its physical binding. |
| Credential/key identifier | Name the key whose possession is being authenticated | Mandatory `peerKeyId`, derived from the public key. Reusing a key gives the same identifier. It is available to the peer's resolver and report. |
| Discovery/session handle | Route an encounter or distinguish sessions | Discovery is adapter-owned; session connection IDs are fresh. Changing them does not make a reused authentication key unlinkable. |

An operator may require a permanent inventory identity internally without requiring every external counterpart to learn it. Whether a global physical-asset identifier is required at all is a deployment question, not a cryptographic prerequisite.

When a counterpart genuinely needs a serial, a separate issuer-signed statement can associate that serial with the authenticated key. That verifies the issuer's association; software-key possession alone still does not prove that a particular physical chassis is present or that the key has not been copied. A hardware-backed enrollment and physical-association design would be separate evidence, not an implicit effect of carrying the serial as an attribute.

## Not broadcasting is not the same as not revealing

The baseline does not put a permanent serial into discovery. Discovery itself is not implemented as a real radio adapter. A deployment can accidentally disclose identifiers through its advertisements, addresses, logs, and attributes.

EDHOC protects the initiator's credential identity against active attacks and the responder's against passive attacks; an active initiator can elicit the responder credential identifier before the responder authenticates it. Choose roles with that asymmetry in mind, not as a promise of anonymity. [RFC 9528, section 9.1](https://www.rfc-editor.org/rfc/rfc9528.html#section-9.1).

The current RIP responder resolver reports a stable key ID. An authenticated counterpart can correlate repeated use of that key, and share logs with others. For a responder, an active requester may obtain the credential ID even without completing authentication. Neither omitting a serial field nor hashing a stable identifier removes this correlation.

The [local article fixture](articles/examples/bakery-2035.mjs) reproduces both observations using only synthetic peers: repeated fresh sessions with one credential return the same ID; an untrusted initiator can capture a responder's key ID in its resolver before sending message_3. These are local checks of documented boundaries, not tests against any external robot or service.

## Proposed direction, not implemented privacy assurance

1. Keep the durable physical-asset identifier and the asset-to-credential mapping in the operator's private inventory. Do not include them in ordinary advertisements, signed domain statements, or shared diagnostics by default.
2. For relationships that do not require global continuity, evaluate separately issued, audience/domain-specific or short-lived authentication keys and credentials. A random display alias over the same public key is insufficient: the baseline derives and validates the key ID.
3. Provision those credentials through an independently trusted process. Key rotation requires new trust material, subject-bound claims, status/expiry handling, recovery, and abuse controls; it is not solved by generating arbitrary new keys on each encounter.
4. Define encrypted post-authentication application exchange and minimal statement selection before sending sensitive attributes. The current SDK signs COSE objects but provides no confidential application messaging. Selecting among separately issued small statements is possible application composition; removing a field from an existing signed statement breaks verification and is not cryptographic selective disclosure.
5. Evaluate observers separately: passive radio listeners, active unauthenticated peers, authenticated peers, credential issuers, and colluding operators. Include radio addresses, location trajectories, signature bytes, and distinctive attribute combinations. Credential changes alone do not guarantee unlinkability or one-physical-machine uniqueness.

The SDK has no pseudonym provisioning/rotation lifecycle, unlinkable proof system, zero-knowledge attribute predicates, or protected audit-opening mechanism. These need explicit design and independent review. Do not advertise a universal authority decryption key or assume a police credential should automatically reveal all data.

Identifier and signature correlation are established privacy concerns; the [W3C VC privacy discussion](https://www.w3.org/TR/vc-data-model-2.0/#privacy-considerations) is useful background, not a claim that RIP implements W3C credentials. For road systems, the [USDOT SCMS primer](https://www.its.dot.gov/pcb/documents/SCMS_Primer.pdf) describes pseudonym credentials and lifecycle infrastructure. Reuse applicable sector standards where possible; RIP currently has no SCMS/IEEE 1609.2 interoperability claim.

## Vehicle information: separate assertions, not a universal robot schema

These are illustrative schema-design questions, not road-tested fields or advice to base driving decisions on this alpha SDK.

| Requested information | What the domain must define | Disclosure and trust concern |
| --- | --- | --- |
| Human occupant present | `present`, `absent`, `unknown`; sensor provenance, observation time, coverage and maximum age | Avoid passenger identities, video, or occupancy data without a justified recipient/purpose. A failed sensor is not evidence of absence. |
| Weight | Rated maximum versus measured total/current load; units, estimate bounds, sensor and observation time | A manufacturer can attest a rating; it cannot establish today's actual load through a static certificate. |
| Braking distance | Current estimate versus certified test result; speed, road/tyre conditions, grade, load, uncertainty, timestamp | There is no context-free guaranteed braking-distance number. Authentication does not validate the model or safety outcome. |
| Hazardous cargo | Applicable classification, who asserts the loading record, time and unknown state | A minimized hazard category may be sufficient; full manifests/routes can expose sensitive operations. |
| Emergency vehicle | Authorized issuer for vehicle/service role; separately, whether an emergency mission is currently active and its validity | Self-declaration is not authority. A verified role is not an instruction to yield or a permission to control signals. |

Each domain owns its vocabulary, validators, accepted issuer roles, precision, freshness, confidentiality and disclosure rules. These are not globally required RIP fields. A claim's `subject` must match the authenticated credential identity; carrying unrelated optional JSON is insufficient.

## Current checks versus application checks

`verifyStatement` checks the COSE signature, schema-specific issuer trust, subject binding, and the statement's issue/expiry interval. It does **not** validate domain `content`, enforce a maximum age on a nested sensor observation, check live revocation, prove a physical body, or decide an action.

For example, a trusted issuer's correctly signed `nominalPayloadKg: -12` passes the generic signature checks. The domain validator must reject that value. An expired or missing observation must not silently become `false`, zero, safe, or allowed.

High-rate, many-to-many road telemetry may need signed broadcast messages under existing V2X profiles rather than a new pairwise handshake per neighbor or per sensor update. RIP's current pairwise demo does not establish suitability for that workload. No new core messages or crypto are proposed here.

## Concrete next design gate

Choose a threat model and one domain before claiming privacy: which counterpart needs which fact; whether repeat visits should be linkable; who manages private asset mappings; how scoped credentials are issued/refreshed/revoked offline; and how sensitive statements are transported. Test cross-domain credential reuse, active identity probing, stale measurements, copied subject claims, issuer overreach, and multi-credential/Sybil abuse. Authentication, disclosure policy, physical correlation, and operation decisions must remain visibly separate.
