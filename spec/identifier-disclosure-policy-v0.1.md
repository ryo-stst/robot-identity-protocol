# Identifier and disclosure policy 0.1

Status: accepted direction for local experiments; production credential and
confidential-channel profiles remain design gates. 2026-09-13. This document does
not change the EDHOC method, suite, CCS format, three-message sequence or EAD rule.

## Decisions now

1. **No mandatory public physical-asset number.** Operators may maintain a durable
   serial internally. Core authentication names a credential key, not a chassis.
   Private operator-owned asset-to-credential mappings need no central world DB.
2. **No automatic attribute release.** The domain-exchange helper has no default
   providers or full schema catalog. Only explicitly requested, locally selected,
   separately signed minimal statements can be returned. A provider may withhold
   an entire statement. Signed-field deletion is not supported selective disclosure.
3. **No anonymity claim for the existing credential.** Same public key means the
   same `peerKeyId`. Session/discovery aliases do not hide that relationship.
   Default logs should show per-run labels and results, not serials or complete
   credentials; the core API still exposes the key ID for legitimate verification.
4. **No private radio payload before channel protection.** The current extension
   envelope and its availability statuses are unsigned, and COSE statements are
   not encrypted. The helper explicitly requires local-test mode. A successful
   handshake alone is not an encrypted application channel.
5. **No authorization/control additions.** Choosing what information to disclose
   is distinct from commanding a robot, granting an operation, or declaring safety.

These are common protocol boundaries, not industry attribute definitions. A
domain chooses whether occupancy, cargo class, calibration or some other fact is
needed, and defines issuer authority, precision, observation age and unknown states.

## Threat model and what is actually addressed

| Observer | Current evidence / limitation | Next production requirement |
| --- | --- | --- |
| Passive local-radio observer | No real radio adapter tested; extension envelopes provide no secrecy | Reviewed encrypted application binding; consider addresses, traffic timing and movement metadata |
| Active unauthenticated peer | Local regression confirms EDHOC initiator can learn responder key ID before message_3 | Deliberate role/credential design; do not claim symmetric active identity privacy |
| Authenticated counterpart | Learns key ID, can link repeated use; selected attributes can also identify a machine | Minimized attributes and separately provisioned scoped/short-lived credentials where justified |
| Colluding counterparts | Can combine keys, statement IDs/signatures and distinctive attributes | Cross-context privacy evaluation, not merely rotating the advertisement handle |
| Issuer / inventory operator | Can associate credentials with asset records | Restricted operator-owned records, retention/audit policy and explicit recovery rules |
| Key copier / Sybil participant | Software key possession does not prove one physical machine | Enrollment/issuance abuse controls, secure storage and optional hardware/physical evidence |

EDHOC role asymmetry comes from [RFC 9528 section 9.1](https://www.rfc-editor.org/rfc/rfc9528.html#section-9.1),
not a newly discovered RIP vulnerability. Tests exercise synthetic local peers
only. Neither a hidden serial nor a new random display name removes this boundary.

## Scoped credentials: concrete future design, not shipped assurance

A candidate deployment profile should use this separation:

- `internalAssetId`: retained in operator inventory; never required by core.
- A real new key and issuer-signed identity credential for a chosen relationship
  or time window, with locally enforced audience, validity and issuer constraints.
- Minimal domain statements whose `subject` is that scoped key, not the internal
  serial or a reused global public key. Refresh/reissue statements when changing keys.
- Private inventory records linking active credentials to assets for recovery and
  abuse management; no mandatory shared directory and no universal decryption key.

Current `issuerCredentials` checks the public key and identity statement validity;
it does **not** enforce arbitrary `audience` fields in `content`. Merely adding
`audience: "delivery"` would therefore not implement scoped authentication. A
future profile must specify the vocabulary, trusted enrollment, actual resolver
checks, allowed key reuse and downgrade behavior, then test them independently.

Credential duration is a deployment/threat-model parameter, not an invented
universal lifetime. Offline renewal, revocation freshness/unknown states,
retirement, loss/recovery, simultaneous credentials, issuer compromise and Sybil
controls must be specified before calling rotation production-ready. Fresh keys
with no trusted provisioning do not replace trusted identity.

## Completion gates

1. **Now, local evidence:** cross-domain extension framing, exact schema matching,
   explicit providers/validators, unknown/withheld/failure separation, repeated-key
   tracking and active-responder-probing regressions. Implemented in SDK
   `v0.2.0-alpha.2`. No confidential information used.
2. **Protected application binding:** choose and review an existing standard
   integration; prove peer/session binding, confidentiality and anti-replay with
   loss/reordering and negative tests. Define adapter MTU and reassembly bounds.
3. **Scoped credential pilot:** identify one concrete observer/relationship that
   needs unlinkability, provision real distinct credentials with audience checks,
   and measure leakage across key IDs, signed objects and radio metadata. Do not
   invent a global industry taxonomy to do this.
4. **External evidence:** independent implementation interoperability, security
   review and real bearer testing before production/privacy claims.

See [privacy discussion and vehicle examples](../docs/privacy-and-identifiers.md)
for supporting context. Source-derived boundaries and locally tested facts are
distinct from the proposed deployment design above.
