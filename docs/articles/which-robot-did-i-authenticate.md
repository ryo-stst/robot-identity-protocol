# Which Robot Did I Authenticate? Simulating Physical Binding with Robot Identity Protocol (RIP)

![RIP Field Lab showing one selected robot among multiple candidates](https://robot-identity-field-lab.sato-kit111.chatgpt.site/og.png)

Robots are moving out of fenced, single-vendor environments.

Imagine a world in which Physical AI is part of ordinary life: delivery robots arrive at stores, autonomous vehicles share roads, drones enter managed airspace, service robots move through hospitals, and machines from different manufacturers meet for a few seconds to exchange goods or information.

In that world, a shared backend cannot always answer every trust question. Two machines may be operated by different companies. They may meet for the first time. Connectivity may be intermittent. A warehouse, vehicle, or robot still needs to answer a smaller and more immediate question:

> Who is the endpoint speaking to me right now, and what authenticated information is attached to that identity?

I started **Robot Identity Protocol (RIP)** as an experimental, vendor-neutral protocol for that interaction. The design does not require a global robot database or a mandatory SaaS call during authentication. It is transport-independent, local-first, and intentionally limited to authentication and authenticated information—not authorization, robot control, or business decisions.

This post explores a deceptively difficult case: when three robots are nearby, does authenticating a radio endpoint tell us which physical robot we are looking at?

Short answer: **no**. That requires a second, explicit result.

## The scenario: three nearby robots, one authentication target

The public [RIP Field Lab](https://robot-identity-field-lab.sato-kit111.chatgpt.site/) places one Verifier and three Presenter candidates—B1, B2, and B3—in the same simulated field.

Each Presenter advertises independently. There are no permanent lines connecting the Verifier to every robot, because observing an advertisement does not mean that an authenticated relationship already exists.

The simplified flow is:

```text
Presenter B1 ── DiscoveryAdvertisement ──┐
Presenter B2 ── DiscoveryAdvertisement ──┼─> Verifier candidate set
Presenter B3 ── DiscoveryAdvertisement ──┘

Verifier selects B3
Verifier ── AuthenticationInitiation(session + fresh nonce) ──> B3
Verifier <── AuthenticationPresentation(signed transcript) ─── B3
Verifier ── local verification ──> VerificationReport
```

The Verifier keeps the advertisements as separate, untrusted candidates. When it selects B3, RIP creates a fresh session for that candidate only. B1 and B2 do not silently become part of that session.

The signed presentation can prove that the selected communication endpoint controls a particular key and that the proof is fresh and bound to the selected advertisement and session.

But consider a camera view containing all three robot bodies. The cryptographic proof alone does not prove that the radio endpoint belongs to the object labeled `track-03` by the local camera system. A relay, a mistaken local association, or simply two nearby radios can break that assumption.

RIP therefore reports the core result as:

```json
{
  "authentication": "verified",
  "physicalBinding": "endpoint-only"
}
```

`endpoint-only` is not an error. It is an honest boundary: the endpoint was authenticated, but the visible physical body was not proven.

## Adding physical binding without hard-coding one sensor

Warehouses, road vehicles, drones, and home robots do not share one universal sensor or threat model. Making a camera, QR code, UWB radio, or any other single mechanism mandatory would reduce the protocol's usefulness.

Instead, RIP keeps physical binding outside the authentication core and composes it as an optional profile.

The experimental optical flow works like this:

1. The Verifier places a fresh physical-binding request in `AuthenticationInitiation.extensions`.
2. The request specifies a method, challenge nonce, and validity window.
3. The Presenter commits to the response inside an Attribute Envelope covered by the normal RIP presentation signature.
4. A Verifier-local sensor adapter records which local track produced the matching response.
5. The profile verifier compares the signed response, session ID, nonce, method, time window, and local observation.
6. RIP core and the optional profile return separate results.

A minimal request looks like this:

```json
{
  "profile": "org.robot-identity.physical-binding",
  "version": "0.1",
  "method": "optical-challenge",
  "challengeNonce": "fresh-random-value",
  "issuedAt": "2026-08-25T00:00:00Z",
  "expiresAt": "2026-08-25T00:00:30Z"
}
```

The Verifier's observation remains local:

```json
{
  "sessionId": "rip-session-id",
  "localTrackId": "camera-track-03",
  "method": "optical-challenge",
  "challengeHash": "session-bound-challenge-hash",
  "observedAt": "2026-08-25T00:00:01Z",
  "sensorReference": "camera-01",
  "confidence": 0.99
}
```

`camera-track-03` is not a global robot identity. It is a label meaningful to that Verifier in that observation window.

If the simulated response matches, the Field Lab displays two independent outcomes:

```json
{
  "ripCore": "endpoint-only",
  "optionalPhysicalBindingProfile": "verified",
  "method": "optical-challenge",
  "localTrackId": "track-03",
  "productionBodyProof": false
}
```

That last field matters. The current browser demonstration simulates the observation. It demonstrates profile composition, payload boundaries, and failure reporting; it does **not** claim production-grade optical liveness, secure ranging, calibration, or relay resistance.

The same session-binding pattern can support other domain-selected methods:

- secure ranging;
- direction or angle-of-arrival evidence;
- acoustic challenge-response;
- short-lived visual patterns;
- multi-modal correlation combining several observations.

Each profile must define its own sensor security, timing rules, thresholds, privacy behavior, and negative tests. It must not redefine the meaning of RIP core authentication.

## Business-specific information is also extensible

Authentication answers who controls the endpoint key. Real operations usually need additional facts.

RIP does not attempt to standardize the meaning of every warehouse, road, aviation, healthcare, or industrial field. Instead, a domain can define an Attribute Schema and carry the resulting information in a common Attribute Envelope. The envelope provides fields for the schema identifier, subject, issuer, issuance and expiry times, content or a content reference, proof, and status reference.

The domain owns the schema semantics. RIP supplies a way to attach that information to the authenticated session without turning those fields into universal robot identity claims.

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

A store may need to distinguish a legitimate pickup robot from a nearby machine or a copied visual code. A commerce-specific schema could include:

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

Some data may be public, some selectively disclosed, and some available only to authorized authorities. Those disclosure and policy rules belong to the relevant vehicle or regulatory profile—not the RIP core.

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

The current alpha contains the generic Attribute Envelope model, but issuer-proof verification for arbitrary attributes is still pending. The project labels that boundary explicitly rather than presenting the data model as a completed certification system.

## Why no global robot database?

A global registry may be useful in some deployments, but making it mandatory creates a central availability, governance, privacy, and market-control dependency.

RIP instead lets a Verifier use locally available trust material and status information. A SaaS product may distribute credentials, status bundles, scenarios, or conformance results, but two endpoints should not need to contact one specific global service every time they authenticate.

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

1. Open [RIP Field Lab](https://robot-identity-field-lab.sato-kit111.chatgpt.site/).
2. Select Presenter B1, B2, or B3.
3. Choose a success or hostile scenario.
4. Set the optional profile to `OPTICAL`.
5. Run the protocol.
6. Inspect the core payload, domain-extension payload, session result, and Verifier-local track correlation separately.

The open specification and TypeScript reference SDK are available in the [Robot Identity Protocol repository](https://github.com/ryo-stst/robot-identity-protocol) under Apache-2.0. The optional profile is documented in [RIP Physical Binding Profile v0.1](https://github.com/ryo-stst/robot-identity-protocol/blob/main/spec/physical-binding-profile-v0.1.md).

RIP is an experimental alpha. It has not received an independent security review and is not a production interoperability standard, certification program, safety controller, or replacement for applicable regulation.

The most useful feedback now is concrete:

- Which real robot-to-robot or robot-to-infrastructure interaction needs this separation between endpoint identity and physical body?
- Which binding method—optical, ranging, direction, acoustic, or multi-modal—could be deployed in your environment?
- Which domain attributes must be authenticated, and who should define their schemas and issuer policies?

If these questions match a system you are building, please open an issue in the repository and describe the interaction and threat model without including sensitive deployment details.
