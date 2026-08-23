# Changelog

All notable changes to this project will be documented here.

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
