# Changelog

## 0.2.0-alpha.1 — 2026-09-05

- Introduce the three-message EDHOC mutual-authentication baseline.
- Breaking: default export/example use the baseline; historical JSON teaching APIs move to `/legacy`, without automatic fallback.
- Add issuer-signed COSE statements, schema-scoped trust, subject/time checks and an offline status-snapshot helper.
- Add bounded state/message handling, negative case catalog and two-process offline example.
- New optical experiment derives a response from a session secret and reports correlation, not body or anti-relay proof.
- Document quickstart, integration choices and remaining interoperability/production gates.


All notable changes to this project will be documented here.

## 0.1.0-alpha.4 - 2026-09-01

- Add a progressive 10-minute Quickstart that begins with one endpoint-authentication exchange.
- Add optional multi-candidate physical-binding and domain-attribute examples.
- Add a fixed successful JSON test vector and tampering coverage.
- Add GitHub Discussions and a structured public use-case form.

## 0.1.0-alpha.3 - 2026-08-23

- Rename the project and SDK to Robot Identity Protocol (RIP).
- Add an experimental optional physical-binding profile and generic SDK helpers.
- Add signed session-response and verifier-local observation tests.
- Preserve endpoint authentication as RIP core; physical-body correlation remains separate evidence.

## 0.1.0-alpha.2 - 2026-08-08

- Accept runtime JWK objects whose optional members are present with `undefined` values by omitting those members from the alpha JSON mapping.
- Preserve rejection of unsupported top-level values and `undefined` array members.

## 0.1.0-alpha.1 - 2026-08-08

Initial public experimental release:

- transport-independent authentication data model;
- Ed25519 proof of possession over the complete session transcript;
- local trusted-key verification;
- advertisement/session binding, expiry checks, and in-memory replay guard;
- explicit `endpoint-only` physical-binding result;
- English experimental specification, tests, and two-endpoint example;
- Apache-2.0 licensing, DCO contribution policy, and security policy.
