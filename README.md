# Robot Identity Protocol (RIP)

Experimental, transport-independent authentication protocol for robots and other Physical AI endpoints.

This public repository contains an open specification draft and a minimal TypeScript reference SDK. The SDK proves that the same authentication transcript can be carried by an in-memory link today and by BLE, local Wi-Fi, UWB-assisted, vehicle, or other bearer profiles later.

**[Launch RIP Field Lab →](https://robot-identity-field-lab.sato-kit111.chatgpt.site/)**

The public browser demo uses the released RIP SDK to simulate three discovery candidates, an isolated authentication session, hostile scenarios, an optional physical-binding profile, and the resulting payloads. Runs use temporary in-memory data and are not saved.

> **Alpha warning:** this project has not received an independent security review. It is not a production security claim, certification program, safety controller, or interoperability standard.

## What this project does

- discovers an authentication-capable endpoint through an abstract bearer;
- creates a fresh challenge and session transcript;
- proves possession of an identity key;
- binds the proof to the advertisement and session;
- verifies the proof against locally supplied trust material;
- returns `verified`, `failed`, or `unresolved` evidence.

It deliberately does **not** authorize actions, issue robot commands, decide safety, define industry-specific attributes, or require a global registry or hosted service.

The SDK is used on **both sides** of an exchange. Presenter endpoints use its discovery and signing functions; verifier endpoints use its challenge, trust, replay, verification, and report functions. The same package exposes both role surfaces in this alpha. An independently implemented verifier is possible only if it follows the wire model and passes compatibility tests.

```mermaid
sequenceDiagram
    participant A as Verifier A
    participant B as Presenter B
    participant T as Local trust material

    B-->>A: DiscoveryAdvertisement (abstract bearer)
    A->>B: AuthenticationInitiation (session + nonce)
    B->>A: AuthenticationPresentation (key + signed transcript)
    A->>T: Resolve trusted key locally
    A-->>A: VerificationReport
```

## Repository contents

- `spec/`: experimental protocol specification;
- `src/`: transport-independent TypeScript reference SDK;
- `test/`: positive, tampering, expiry, unknown-trust, and replay tests;
- `examples/`: a two-endpoint offline example;
- `docs/licensing.md`: plain-language rights summary.

The core protocol authenticates an endpoint. Optional profiles can add domain-specific evidence without making one sensor method mandatory. [`RIP Physical Binding Profile v0.1`](spec/physical-binding-profile-v0.1.md) demonstrates how a signed session response can be correlated with a verifier-local camera, ranging, direction, acoustic, or multi-modal observation.

Multiple presenters may advertise at once. A verifier keeps them as separate untrusted candidates, selects one advertisement, and creates an isolated authentication session for that target. Authentication proves the selected communication endpoint; physical-body selection remains a separate binding problem.

## Try it in the browser

Open **[RIP Field Lab](https://robot-identity-field-lab.sato-kit111.chatgpt.site/)**, select one of the three Presenter candidates, choose a success or attack scenario, optionally enable the simulated optical-binding profile, and run the protocol. The lab separates RIP core data from optional domain-extension data and links each verifier-local candidate to its discovery handle, session, presented peer key, and optional physical observation.

The Field Lab is an educational alpha, not a hosted trust registry, certification service, safety controller, or production-security claim. Its web source remains separate from this Apache-2.0 repository; the protocol, SDK, examples, and tests in this repository remain the portable open-source core.

## Try it locally

Requirements: Node.js 22 or later.

```bash
npm install
npm test
npm run example
```

The current alpha uses JSON and Ed25519 to exercise the data model. Those choices are an implementation profile, not a final wire-format commitment. BLE pairing is not required and BLE identity is not treated as robot identity.

## Implementation status

| Capability | Status |
| --- | --- |
| One-way proof of key possession | Implemented |
| Local trusted-key verification | Implemented |
| Advertisement/session binding | Implemented |
| Expiry and in-memory replay guard | Implemented |
| Arbitrary attribute envelope model | Model only; issuer proof verification pending |
| Mutual authentication | Specification direction; implementation pending |
| BLE, Wi-Fi, UWB, and vehicle adapters | Interfaces/profiles pending |
| Optional physical-binding profile helpers | Experimental; simulated optical example, no production sensor claim |

## License and rights

The specification, SDK source, examples, and tests are licensed under the [Apache License 2.0](LICENSE). In summary, commercial use, modification, redistribution, private use, and patent use are permitted subject to the license conditions. Preserve the license and notices, and state significant changes when redistributing modified work.

The license provides no warranty, liability commitment, certification, endorsement, or trademark permission. See [Licensing and rights](docs/licensing.md) and [Trademarks](TRADEMARKS.md). This summary is informational; the license text controls.

## Contributing and security

Contributions are welcome under the same Apache-2.0 license and use Developer Certificate of Origin sign-off. See [CONTRIBUTING.md](CONTRIBUTING.md).

Please do not file public issues for suspected vulnerabilities. Follow [SECURITY.md](SECURITY.md).
