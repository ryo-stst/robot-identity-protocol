# RIP EDHOC baseline 0.2

Status: experimental application profile, SDK `0.2.0-alpha.1`. Not a registered standard or independent interoperability claim. Supersedes v0.1 for new integrations.

## Purpose

Two endpoints authenticate each other's key using locally installed trust. Access decisions and control are out of scope. A key does not necessarily identify a legal organization or unique physical body. No global directory is required.

Normative dependencies: [RFC 9528 (EDHOC)](https://www.rfc-editor.org/rfc/rfc9528.html), [RFC 9052 (COSE)](https://www.rfc-editor.org/rfc/rfc9052.html), [RFC 8949 (CBOR)](https://www.rfc-editor.org/rfc/rfc8949.html), [RFC 8747 (confirmation claim)](https://www.rfc-editor.org/rfc/rfc8747.html).

## Fixed interoperability choices

| Item | This profile |
| --- | --- |
| Profile ID | `rip-edhoc-ccs-0.2` (application-local identifier) |
| Method / suite | EDHOC 0 / 0: both sign; X25519, Ed25519, SHA-256, AES-CCM per RFC 9528 |
| Handshake | Raw EDHOC message_1, message_2, message_3 |
| Connection ID | Fresh 8-byte CBOR bstr each session |
| Identity key | Public Ed25519 JWK with only `crv`, `kty`, `x` |
| Key ID / ID_CRED kid | UTF-8 bstr of `urn:rip:key:sha256:` + unpadded base64url SHA-256 of UTF-8 `{"crv":"Ed25519","kty":"OKP","x":"…"}` |
| CRED / CCS | Deterministic CBOR `{2: keyId, 8: {1: {1: 1, -1: 6, -2: publicKeyBytes}}}` |
| EAD | None; reject any received EAD |
| Frames | 1–4096 bytes, one complete message per receive |
| Lifetime | Default 30 s, configurable 1–120000 ms, checked before/after operations |

No silent downgrade to legacy. A bearer profile must define service ID, selection/demultiplexing, fragmentation, retransmission, admission and concurrency bounds. IPC is an example, not a radio profile.

Discovery is outside EDHOC. An untrusted advertisement can expose a rotating handle and endpoint. Selection does not authenticate its name, position, features or advertised profile list. Only the subsequent credential/key proof is authenticated.

## State and completion

Initiator: `new → start/send m1 → wait-2 → receive m2 → send-3 → respond/send m3 → complete`.
Responder: `new → receive m1 → send-2 → respond/send m2 → wait-3 → receive m3 → complete`.

Out-of-order/repeated calls fail with `UNEXPECTED_MESSAGE_OR_REPLAY`. Concurrent operations are rejected. Cryptographic/parse/trust failure closes the session; use fresh ephemeral keys for a new session. Cross-session transcript replay fails cryptographic checks; replaying discovery/m1 can still consume resources, requiring adapter admission limits.

Local codes include `FRAME_SIZE`, `UNSUPPORTED_PROFILE_OR_MESSAGE`, `MALFORMED_MESSAGE`, `UNSUPPORTED_EXTENSION`, `SESSION_EXPIRED`, `UNKNOWN_PEER`, `CREDENTIAL_KEY_MISMATCH`, `ISSUER_NOT_TRUSTED_FOR_SCHEMA`, `AUTHENTICATION_FAILED`. They are SDK diagnostics, not assigned EDHOC wire errors. Do not disclose detailed trust-resolution failures to an unauthenticated remote peer.

No optional message_4/application acknowledgement is exposed. A report describes local verification only; `peerAcceptanceConfirmed` is false. `exchangeId` is base64url SHA-256 of the CBOR array of three raw frame bstrs: diagnostic identifier, not transferable proof or exported secret.

## Local trust

`pinnedCredentials` uses independently provisioned peer keys. `issuerCredentials` resolves a key ID to a locally supplied COSE-signed identity statement and checks issuer, identity schema, subject, public key and validity before returning CCS. Distribution is out of band (e.g. an offline fleet bundle), not radio trust-on-first-use. No implicit URL fetch occurs.

The integrating organization controls trust roots. Trust for `urn:rip:identity:0.2` does not grant trust for payload/status schemas. The implementation uses exportable software keys and Node-compatible cryptography; hardware identity-key handles and complete X.509 path validation remain future work. Reports explicitly say `revocation: not-checked`.

## Domain-owned statements

Separate tagged COSE_Sign1 (tag 18), protected headers `{1: -8, 4: issuerKeyIdBytes}`, empty unprotected map and embedded deterministic-CBOR payload. Verify the received payload bytes; no JSON reserialization. No other headers accepted. Maximum 16384 bytes, bounded CBOR depth, duplicate-map-key rejection.

Payload: `{id, schema, subject, issuer, issuedAt, expiresAt, content}`, all required, no extra top-level fields. IDs/schema/subject/issuer are nonempty strings up to 512 characters. Time: safe-integer Unix milliseconds, `issuedAt <= now < expiresAt`. `content` is a domain-owned map. Use a schema namespace you control; example.com is illustrative, not a required service.

Verify against the authenticated subject, exact requested schema and an issuer locally accepted for that schema. A verified claim is an issuer assertion, not proof of physical truth. Certified nominal capacity and live measured load require distinct schema/freshness semantics.

These objects are signed, **not encrypted**. Transfer and disclosure selection are separate from the handshake. They are not put into unauthenticated EAD. Confidential application traffic needs an independently specified OSCORE or other authenticated-encryption profile; not implemented here.

## Offline status and rotation

`verifyStatusSnapshot`: statement schema `urn:rip:credential-status:0.2`, subject = credential statement ID, content = `{status: "good" | "revoked"}`, trusted status issuer supplied locally. Invalid, future, expired, missing or too-old knowledge yields `unknown`, never good. `asOf` is signed issue time. Integrators must associate the status authority with the credential issuer and securely refresh bundles. Status is not automatically folded into authentication.

Rotation means issuing a credential for a new key and updating material. Recovery, secure time, persistent status and distribution require production integration design. Whether an application accepts unknown status is outside RIP operation decisions.

## Optional optical experiment

After the three-message local exchange, derive 32 bytes with EDHOC_Exporter label **40001**, an [experimental private-use label](https://www.iana.org/assignments/edhoc), not a global registration. HMAC-SHA-256 over deterministic CBOR `[profileId, "optical-v0.2", targetKeyId, challengeBytes]` using a fresh 32-byte challenge. Never return/log the secret.

Compare an independently acquired local sensor response: one matching track = correlated; several = ambiguous; unequal = mismatch. The helper does not prove sensor authenticity, capture freshness, distance, exclusive visibility or relay resistance. Web/CLI observations are simulated. A production profile must define one-time challenge consumption, deadlines, calibration, relay handling, ambiguity and privacy. The old public-input v0.1 hash is not a secure optical challenge.

## Evidence

See [readiness gates](../docs/readiness.md) and [executable case catalog](../test-vectors/baseline-cases.json). Local tests are not independent EDHOC interoperability, hardware testing or an audit. Standard security properties do not automatically certify this integration.
