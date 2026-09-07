# Which Robot Did I Authenticate? Simulating Physical Binding with Robot Identity Protocol (RIP)

![Robot Identity Protocol and Field Lab illustration](https://robot-identity-field-lab.sato-kit111.chatgpt.site/og.png)

*Updated September 7, 2026 for SDK `0.2.0-alpha.1` and the current Field Lab. The authentication baseline now uses EDHOC; the older v0.1 JSON exchange is legacy, with no automatic fallback. The illustration above is not a screenshot of the current interface.*

Robots are moving out of fenced, single-vendor environments.

Imagine a world in which Physical AI is part of ordinary life: delivery robots arrive at stores, autonomous vehicles share roads, drones enter managed airspace, service robots move through hospitals, and machines from different manufacturers meet for a few seconds to exchange goods or information.

In that world, a shared backend cannot always answer every trust question. Two machines may be operated by different companies. They may meet for the first time. Connectivity may be intermittent. A warehouse, vehicle, or robot still needs to answer a smaller and more immediate question:

> Who is the endpoint speaking to me right now, and what authenticated information is attached to that identity?

I started **Robot Identity Protocol (RIP)** as an experimental, vendor-neutral protocol for that interaction. The design does not require a global robot database or a mandatory SaaS call during authentication. It is transport-independent, local-first, and intentionally limited to authentication and authenticated information—not authorization, robot control, or business decisions.

This post explores a deceptively difficult case: when three robots are nearby, does authenticating a radio endpoint tell us which physical robot we are looking at?

Short answer: **no**. Endpoint authentication, issuer-signed business information, and a local sensor's physical correlation are three different kinds of evidence. The demo keeps them separate.

If you want to see the idea first, open [RIP Field Lab](https://robot-identity-field-lab.sato-kit111.chatgpt.site/) and press **Run demo**. It runs on the same page. Start with two peers; add more candidates and optional information after that first exchange.

## The scenario: three nearby robots, one authentication target

The Field Lab starts with A and B1. Under **Go further**, enable **Show three candidates** to add B2 and B3, then select one candidate. These labels identify objects in the demonstration; they are not authenticated robot names or measured physical positions.

Discovery is outside the authentication handshake. In a real deployment, a bearer adapter would discover endpoints through an appropriate local link. The current demo simulates candidate discovery: it does not scan Bluetooth, Wi-Fi, or a camera. Seeing an advertisement does not authenticate its claimed name, location, or capabilities.

Suppose A selects B3. The current baseline uses [EDHOC (RFC 9528)](https://www.rfc-editor.org/rfc/rfc9528.html), an existing authenticated key-exchange protocol, instead of inventing a new signature transcript. RIP fixes a small application profile: method 0, cipher suite 0, CCS credentials, and three messages.

Here is the exchange, followed by local results—not a broadcast authentication of all three candidates:

```text
A discovers candidates B1, B2, B3 (simulated; not authenticated)
A selects B3; B1 and B2 remain outside this exchange

A (initiator) ── EDHOC message_1 ──> B3 (responder)
A             <── EDHOC message_2 ── B3
A locally verifies B3's credential and key proof
A             ── EDHOC message_3 ──> B3
                                    B3 locally verifies A

A has a local report about B3; B3 has a local report about A
```

This is mutual authentication: **both peers use the SDK**, or would need a compatible implementation. Initiator and responder are exchange roles, not different kinds of machine. Independent-implementation interoperability is still unverified.

The peers must already have trustworthy local material: pinned peer keys or issuer-signed identity credentials with locally configured issuer trust. Receiving a new key over discovery is not enough to trust it. No global directory lookup is required.

An excerpt from A's local report looks like this; the shortened key ID is illustrative:

```json
{
  "profile": "rip-edhoc-ccs-0.2",
  "role": "initiator",
  "peerKeyId": "urn:rip:key:sha256:...",
  "identity": "verified",
  "trust": "locally-resolved-credential",
  "physicalBinding": "not-evaluated",
  "authorization": "outside-protocol",
  "revocation": "not-checked",
  "peerAcceptanceConfirmed": false
}
```

The full `peerKeyId` distinguishes the authenticated keys behind B1, B2, or B3 in this run. It does not by itself establish a legal organization, a manufacturer-certified serial number, or a unique physical body.

`physicalBinding: "not-evaluated"` is an honest boundary, not an error. A camera track and an authenticated endpoint still need an independently justified association. `peerAcceptanceConfirmed: false` matters too: this SDK does not expose EDHOC message_4 or an application acknowledgement. A's local success report does not prove that B3 received and accepted the final message.

## Adding physical binding without hard-coding one sensor

Warehouses, road vehicles, drones, and home robots do not share one universal sensor or threat model. Making a camera, QR code, UWB radio, or any other single mechanism mandatory would reduce the protocol's usefulness.

Instead, RIP keeps physical correlation outside the authentication core. The current optical experiment runs **after** the EDHOC exchange; it is not an extra field inserted into an unauthenticated advertisement.

1. Complete the local authenticated exchange.
2. Create a fresh 32-byte optical challenge.
3. Derive a response using an EDHOC-exported session secret and HMAC-SHA-256 over the profile, target key ID, and challenge. Both authenticated peers can derive the matching response; the secret is not returned or logged.
4. Compare that expected response with a local sensor observation and its candidate tracks. The demo supplies a simulated observation, not a camera measurement.
5. Report `correlated`, `ambiguous`, or `mismatch` separately from core authentication.

This replaces the old v0.1 public-input hash experiment. A hash calculated only from public values is not a secure optical challenge-response. The new [experimental profile](https://github.com/ryo-stst/robot-identity-protocol/blob/main/spec/edhoc-baseline-v0.2.md#optional-optical-experiment) uses a private-use EDHOC exporter label, not a registered global extension.

For a single matching simulated track, the optional result is:

```json
{
  "status": "correlated",
  "localTrackId": "simulated-track-3",
  "assurance": "sensor-correlation-only",
  "relayResistance": "not-established",
  "physicalIdentityProven": false
}
```

`simulated-track-3` is a local observation label, not a global identity. Even a matching secret-derived response does not prevent someone from relaying the optical signal, compromising a sensor, or creating an ambiguous observation. The core report still says physical binding was not evaluated by the authentication core.

A production sensor profile would need authenticated observations, one-time challenge consumption, capture deadlines, calibration, ambiguity handling, privacy rules, and explicit relay defenses. Those are **not implemented** by this helper. Ranging, direction, acoustic, or multi-modal profiles are possible future integrations, not current hardware support.

## Business-specific information is also extensible

Authentication answers who controls the endpoint key. Real operations usually need additional facts.

RIP does not standardize every warehouse, road, aviation, healthcare, or industrial field. A domain defines and versions its own schema in a namespace it controls. No central RIP approval is required.

The baseline now implements **issuer-signed COSE_Sign1 statements**. A statement has `id`, `schema`, `subject`, `issuer`, `issuedAt`, `expiresAt`, and domain-owned `content`. Times are Unix milliseconds. A logistics statement could use schema `https://example.com/robot/payload/v1` with content:

```json
{
  "nominalPayloadKg": 80
}
```

This is only the content inside a signed statement, not an authentication message or a complete wire payload. `example.com` is illustrative; it is not a required service.

The verifier checks the signature, whether the issuer is locally trusted for that exact schema, the validity interval, and whether the statement's subject matches the **authenticated peer key**. Trusting an issuer for identity does not automatically trust it to certify payload capacity.

The domain still defines units, meaning, freshness requirements, and which issuers are appropriate. An 80 kg *nominal capacity* assertion is not a live measurement of remaining capacity. A signature authenticates the issuer's assertion; it does not prove that the physical claim is true.

These statements are separate from the EDHOC handshake and bound to its authenticated subject, not automatically to one specific session or a fresh sensor reading. They are signed, **not encrypted**. Confidential transfer and selective disclosure need separate application design; the current SDK does not implement them.

Here are several possible scenarios.

### 1. Warehouse and delivery handoff

A warehouse receives pickup robots operated by multiple delivery companies. After authenticating a robot endpoint, the warehouse may request a logistics schema containing:

- nominal payload capacity;
- cargo-bay dimensions;
- temperature-control capability;
- hazardous-goods compatibility;
- most recent inspection status;
- the delivery operator or service class.

The warehouse's own application—not RIP—decides whether to release or load a parcel.

### 2. Store and restaurant pickup

A store may need to authenticate a pickup endpoint and then associate it with a nearby machine. Endpoint authentication alone does not solve a copied visual code or relay attack. A commerce-specific schema could include:

- order pickup role;
- operator reference;
- cargo compartment type;
- short-lived pickup entitlement reference;
- supported handoff mechanism.

The actual order authorization remains a separate business decision.

### 3. Mixed autonomous traffic

Vehicles from different manufacturers may exchange authenticated information useful to cooperative planning, such as:

- vehicle mass class;
- braking-performance class;
- automation mode;
- dimensions or maneuverability class;
- hazardous or oversized load indicators;
- emergency-vehicle role.

Some data might be public and some restricted. Disclosure and policy rules belong to the relevant vehicle or regulatory profile, not the RIP core, and selective disclosure is not implemented here. These are potential inputs to a separately validated driving system, not a demonstrated improvement in braking, safety, or congestion.

### 4. Drones and managed airspace

A drone or local airspace Verifier could use a jurisdiction-specific schema for:

- operator credential references;
- vehicle class;
- permitted flight category;
- remote identification compatibility;
- inspection or maintenance status;
- emergency capability.

RIP should connect to applicable aviation standards rather than inventing a replacement for them.

### 5. Hospitals and care facilities

Service robots moving between organizations may need to present information such as:

- device class;
- maintenance and calibration status;
- cleaning or sterile-handling status;
- approved operating-area class;
- responsible operator reference.

Patient data and the decision to enter a restricted zone remain outside the authentication protocol.

### 6. Construction, factories, and mines

Temporary interaction between machines from different vendors could require authenticated attributes including:

- rated load;
- tool or attachment class;
- inspection status;
- hazardous-area compatibility;
- emergency-stop interface profile;
- site-specific training or operator credential references.

Again, a site's safety controller consumes the evidence and decides what is permitted. RIP does not issue the command.

These examples are intentionally not core schemas. A trade group, regulator, customer consortium, or open-source community can define and version them independently.

Unlike the earlier article version, issuer signature, schema-specific trust, subject binding, and validity checks are now implemented. Domain-content validation, production issuer onboarding, and certification are not supplied by that generic verifier.

## Why no global robot database?

A global registry may be useful in some deployments, but making it mandatory creates a central availability, governance, privacy, and market-control dependency.

RIP instead lets each verifier use locally provisioned trust material. A separate offline status helper can check signed status snapshots, but it cannot discover a revocation newer than its local knowledge. Authentication reports still say `revocation: "not-checked"`; the helper is not automatically part of the handshake.

A future SaaS product could distribute credentials, status bundles, scenarios, or compatibility reports. Those are product directions, not capabilities already delivered by the Field Lab. Two endpoints should not need to contact one specific global service every time they authenticate.

This also keeps the open protocol useful to competing vendors. The business opportunity can exist around management, testing, compatibility, reporting, and lifecycle tooling without placing the authentication exchange behind one company's API.

## What RIP deliberately does not decide

RIP does not answer:

- Should this robot receive the package?
- May this vehicle enter the lane?
- Is this machine safe enough for the task?
- May this robot open the door?
- Should an autonomous system trust the claimed payload capacity?

It produces authentication evidence and attached information. Authorization, operational policy, safety logic, and control remain separate systems.

That separation is essential. A valid identity is not the same thing as permission, safety, or suitability.

## Try the experiment

Start with the browser walkthrough:

1. Open [RIP Field Lab](https://robot-identity-field-lab.sato-kit111.chatgpt.site/) and press **Run demo**. It stays on the same page.
2. Follow the three messages between A and B1. **Pause** the walkthrough or open a step to inspect its payload and local verification result. **Show all results** skips the playback.
3. Only then open **Go further**. Choose **Show three candidates**, select B3, and press **Run a new demo**. B1 and B2 remain outside that exchange.
4. Try **Add an issuer-signed domain claim** or **Add simulated optical correlation**, one at a time. Run a new demo and compare the optional evidence with the core result.
5. Try a failure case and inspect where verification stops.

The demo executes real EDHOC cryptography with simulated peers in one server process. The on-screen playback is deliberately slowed down for explanation; it is not a measurement of radio latency. **Replay demo** replays the same result, while **Run a new demo** creates a fresh run. No radio, camera, physical robot, or user-supplied implementation is connected. This is a learning walkthrough, not yet a hosted hardware or custom-code testbed.

To run your own local experiment, install Node.js 22 or later, then:

```sh
git clone https://github.com/ryo-stst/robot-identity-protocol.git
cd robot-identity-protocol
npm ci
npm run example
```

Internet is needed to download the repository and dependencies, not to run the local exchange. Expect two local reports with different `peerKeyId` values and the same `exchangeId`. That exchange ID is a diagnostic transcript identifier, not a transferable authentication proof.

Choose just one next command:

- `npm run example:claims` — verify an issuer-signed domain statement.
- `npm run example:optical` — multiple candidates and simulated optical correlation.
- `npm run example:processes` — two local Node processes, each keeping its own private key. The trusted demo harness provisions public keys; this is IPC, not a radio adapter or independent implementation.

The open specification and TypeScript reference SDK are available in the [Robot Identity Protocol repository](https://github.com/ryo-stst/robot-identity-protocol) under Apache-2.0. The alpha package is distributed through GitHub Releases, not the npm registry. See the [quickstart](https://github.com/ryo-stst/robot-identity-protocol/blob/main/QUICKSTART.md), [current profile](https://github.com/ryo-stst/robot-identity-protocol/blob/main/spec/edhoc-baseline-v0.2.md), and [integration guide](https://github.com/ryo-stst/robot-identity-protocol/blob/main/docs/integration.md) for install instructions and extension boundaries.

RIP is an experimental alpha, not an adopted standard. Independent EDHOC interoperability, real radio adapters, hardware-backed identity keys, confidential application messaging, and an independent security review remain [readiness gates](https://github.com/ryo-stst/robot-identity-protocol/blob/main/docs/readiness.md). Using an existing standard does not certify this integration. RIP is not a certification program, safety controller, or replacement for applicable regulation.

The most useful feedback now is concrete:

- Which real robot-to-robot or robot-to-infrastructure interaction needs this separation between endpoint identity and physical body?
- Which binding method—optical, ranging, direction, acoustic, or multi-modal—could be deployed in your environment?
- Which domain attributes must be authenticated, and who should define their schemas and issuer policies?

If these questions match a system you are building, please open an issue in the repository and describe the interaction and threat model without including sensitive deployment details.
