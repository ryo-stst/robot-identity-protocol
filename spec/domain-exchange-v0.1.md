# Optional domain information exchange 0.1

Status: experimental local-test contract in SDK `v0.2.0-alpha.2`, 2026-09-27. Used after the
[EDHOC baseline](edhoc-baseline-v0.2.md), not an EDHOC change, EAD extension, radio
profile, or production application-security profile.

## The small promise

Two peers can authenticate without sharing a business domain. They still need a
compatible bearer, authentication profile and independently configured trust.
After authentication, a peer can request a small set of versioned domain schemas.
Unknown schemas are not guessed, downloaded, or treated as verified. The result
of endpoint authentication stays separate from every extension result.

RIP defines the exchange envelope, not an industry vocabulary. Domain authors own
schema meanings, validators, units, observation-age rules, trusted issuer roles,
and disclosure policy. A URI is an identifier, never an instruction to fetch code.
Use an exact versioned identifier, such as `https://example.com/cargo/v1`.
`/v2` is a different schema: no substring match, implicit downgrade, or inferred
compatibility. The existing signed statement's `schema` field carries this
identifier; no extra `version` field is added to the statement.

## Security boundary — read before connecting a transport

The SDK requires `mode: "local-test-only"`. Its new envelopes are **not signed or
encrypted**. COSE objects inside a `provided` entry retain their existing issuer
signatures, but that does not authenticate the envelope, request, availability
report, sender, or delivery time. Request IDs and `exchangeId` prevent accidental
mix-ups and some local replays; both are public correlation values, not MACs or
proofs of session binding. An attacker who observes them can forge an
`unsupported` response or substitute another still-valid statement for the same
subject/schema. These are not guarantees of current availability or latest state.

Only use this version with synthetic data in a trusted local harness. A future
production binding must provide confidentiality, integrity, peer/session binding,
ordering, anti-replay, bounded reassembly, and lifecycle management through an
independently specified and reviewed application-security profile (e.g. an
appropriate OSCORE integration). No such adapter is shipped. Do not send private
attributes over a radio merely because EDHOC completed beforehand.

## Local state and minimal disclosure

`DomainExtensionSession` is constructed from a completed `AuthenticationSession`.
It snapshots the authenticated peer key ID and diagnostic exchange ID. It does
not change the core session or its report, including `peerAcceptanceConfirmed`.

- Default provider and validator lists are empty. No automatic identity/serial
  statement or full supported-schema catalog is sent.
- Only explicitly requested schemas invoke a locally installed provider. The
  provider gets the authenticated peer key ID for **information disclosure**
  policy, not for robot operation authorization. It returns one already signed
  minimal statement, or `undefined` to withhold it. Providers are trusted local
  callbacks, not remotely supplied code. Do not strip fields from a signed object.
- No provider: `unsupported`. No permitted/current statement or provider failure:
  `unavailable`. The latter does not reveal whether data is absent or withheld.
  The distinction from `unsupported` still leaks limited schema-support metadata;
  use protected transport before enabling remote queries.
- One outgoing request can be pending. Receiving a response consumes that request
  even on failure. A duplicate incoming request is rejected. Both directions have
  a limit of 32 requests per helper instance. State is local and not persistent.
- Default helper lifetime is 30 seconds, configurable from 1 to 120000 ms, checked
  before and after asynchronous work; an observed backward clock step is rejected.
  Integrators still need trustworthy time. A timed-out result is not returned. Local
  callbacks must terminate; this is not a sandbox or cancellation of hung code.
- Invalid frames close that request, not the authenticated core. Further requests
  within the limits may proceed. The adapter must own retry/admission policy;
  restarting helpers is not persistent replay protection.

## Framing contract

One bounded CBOR array per frame, encoded deterministically by this SDK. The
decoder accepts structurally equivalent CBOR, rejects trailing objects, and
limits nesting. No arbitrary top-level keys or unrecognized message types.

```text
request  = ["rip-domain-exchange-0.1", 0, exchangeId, requestId, schemas]
response = ["rip-domain-exchange-0.1", 1, exchangeId, requestId, entries]

schemas = [schema, ...]
entry   = [schema, "provided", coseSign1Bytes]
        / [schema, "unsupported"]
        / [schema, "unavailable"]
```

`exchangeId` is the baseline report's 43-character base64url diagnostic hash.
`requestId` is a fresh random 16-byte bstr. Each schema is a nonempty string of at
most 512 UTF-16 code units (the baseline SDK string bound). Requests contain 1–8
unique schemas. Responses contain exactly one entry per requested schema, in the
same order; duplicates, omissions, extra/unrequested schemas and wrong request or
exchange IDs are rejected before any domain validator runs. Unknown status values
are malformed, not a fallback success.

Maximum envelope: 150000 bytes, decode depth 6. Each embedded COSE object is 1–16384
bytes, subsequently checked by the baseline's bounded COSE parser. These are
application frames, **not** the core's 4096-byte EDHOC frames; a future radio adapter
must define separately bounded fragmentation/reassembly. No production performance
or MTU claim is made.

## Receiver results

The SDK returns `items` separately from the unchanged authentication report. Each
item has `schema`, `status`, `reason`, `source`, `revocation: "not-checked"` and,
**only for a verified item**, the signed `statement`.

| Status | Meaning |
| --- | --- |
| `verified` | Exact-schema issuer trust, signature, authenticated subject and statement validity passed, and the explicitly installed local domain validator returned `true` |
| `unsupported` | Remote envelope reports no provider, or the receiver has no exact-schema validator; no meaning inferred |
| `unavailable` | Remote envelope reports no disclosed statement; not proof the attribute does not exist |
| `unresolved` | COSE verification cannot establish locally accepted schema-scoped issuer trust |
| `failed` | Invalid signature, wrong subject/schema, invalid time interval, malformed object, or rejected/throwing domain validator |

`source: "envelope-report"` denotes the unauthenticated remote status; it is not a
signed fact. `source: "local-check"` denotes a local verification/interpretation
result. Every exchange result declares `envelopeAuthentication: "not-provided"`
and `confidentiality: "not-provided"`. A `provided` object with no local validator
is bounded but not decoded or accepted; the result is `unsupported`.

For recognized schemas, validate COSE first, then pass a detached copy to the
domain validator with the evaluation time. `true` means the installed validator
accepted the assertion's structure/semantics, not that sensors or issuers tell the
truth. It must check nested observation age/units/unknown states when relevant.
Validation never executes a URL, untrusted script, or operational action.

This profile deliberately has no `allowed`, `safe`, or `permission` result and no
wire `required` flag that could overwrite core authentication. Applications may
need particular facts before doing their own work, entirely outside RIP.

## Evidence and next gate

Run `npm run example:domains` and `npm test` from this source checkout. The example
uses two synthetic domains in one process: both authenticate, each reports the
other domain as unsupported, and an explicitly added validator/issuer trust makes
one known extension verifiable. Negative tests cover copied subjects, tampering,
expiry, schema-version mismatch, validator rejection, framing and local replay.
These are same-SDK checks, not independent interoperability or radio testing.

Before production: specify and independently test a protected application binding,
real transport limits, secure credential lifecycle, domain observation validators,
and the observer-specific [privacy plan](../docs/privacy-and-identifiers.md).

References: [CBOR security considerations](https://www.rfc-editor.org/rfc/rfc8949.html#section-10),
[EDHOC security and identity protection](https://www.rfc-editor.org/rfc/rfc9528.html#section-9.1).
Reviewed against primary sources on 2026-09-13; the extension format is RIP's own
experimental application contract, not an IETF-assigned format.
