# Robot Identity Protocol (RIP)

Authenticate another robot's communication endpoint and inspect who issued its additional information. Application authorization and physical control stay outside the protocol.

**Start here: [run your first exchange](QUICKSTART.md)** · [interactive walkthrough](https://robot-identity-field-lab.sato-kit111.chatgpt.site/) · [discuss a use case](https://github.com/ryo-stst/robot-identity-protocol/discussions)

## What runs today

`v0.2.0-alpha.1` introduces an experimental EDHOC-based mutual-authentication profile. Both participants verify locally; no central database or SaaS request is part of the exchange.

- Fixed EDHOC method 0 / suite 0 / CCS credentials, using the `edhoc` library.
- Locally pinned keys or locally resolved issuer-signed identity credentials.
- Standard COSE_Sign1 objects for custom attributes, with separate issuer, schema, subject and expiry checks.
- Signed offline status snapshots distinguishing good-as-of, revoked and unknown/stale; not automatically included in authentication.
- Two-process offline example and negative tests.
- Optional simulated optical correlation using a session-secret-derived response, not proof of unique physical-body identity.

This is a **reference SDK and draft application profile**, not a new IETF standard, completed hardware implementation, security audit, or production-ready service. The handshake currently has three messages. A report is a local result, not confirmation that the remote application accepted it.

## Keep the results separate

| Evidence | Meaning | Not established |
| --- | --- | --- |
| Endpoint authentication | Peer controls the key in a locally accepted credential | Location or visible body |
| Domain claim | An accepted issuer signed this value for this subject/schema within its validity window | Measurement accuracy or permission to act |
| Optional sensor correlation | A local observation matched the session's optical response | Relay resistance, distance or body uniqueness |

## Integrate incrementally

1. [Run the example](QUICKSTART.md) before picking hardware.
2. Add a bounded message transport and secure credential bootstrap.
3. Add a schema only when your domain needs it. RIP does not define industry taxonomies.

See the [baseline specification](spec/edhoc-baseline-v0.2.md), [integration guide](docs/integration.md) and [readiness gates](docs/readiness.md).
BLE, Wi-Fi, UWB, ROS 2, OSCORE application traffic, hardware-backed keys and independent C/TS interoperability are **not yet implemented or verified by this SDK**.

## Compatibility, rights and governance

The v0.1 JSON-signature experiment is a [legacy teaching profile](spec/authentication-protocol-v0.1.md), available from the explicit `/legacy` export. It is not wire-compatible with EDHOC and is not an automatic fallback.

Code and repository documentation are under [Apache-2.0](LICENSE); dependencies retain their own licenses ([notices](THIRD_PARTY.md)). Commercial use and compatible independent implementations are welcome under the applicable licenses. The license does not grant trademark rights or imply certification. See [TRADEMARKS.md](TRADEMARKS.md), [licensing](docs/licensing.md), [CONTRIBUTING.md](CONTRIBUTING.md) and [security reporting](SECURITY.md).
We do not sell runtime authentication or require the demo website to use the OSS.
