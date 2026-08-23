# RIP Physical Binding Profile v0.1

Status: **Experimental optional profile**. This is not a production sensor-security claim or a mandatory part of Robot Identity Protocol (RIP).

## Purpose

RIP core authenticates a communication endpoint. It cannot determine which camera, LiDAR, or human-visible body corresponds to that endpoint. This optional profile correlates one verifier-local physical track with one verified RIP session.

## Composition with RIP core

1. The verifier selects one discovery candidate and creates a normal `AuthenticationInitiation`.
2. The initiation carries a `PhysicalBindingRequest` in its non-critical `extensions` map.
3. The request identifies a domain-selected method such as optical challenge, secure ranging, direction, acoustic challenge, or a multi-modal procedure.
4. The Presenter produces a physical response derived from the fresh request and returns a `physical-binding-response` Attribute Envelope. The normal RIP presentation signature covers that envelope and the initiation.
5. A verifier-local adapter records which sensor track emitted the matching response.
6. The optional profile verifier compares the signed response, local observation, session ID, verifier nonce, method, and validity window.
7. The profile returns a separate result. It does not alter the core authentication result and does not authorize an action.

## Why it is optional

Warehouses, vehicles, drones, and consumer robots use different sensors and threat models. RIP therefore standardizes how a profile binds its result to a session, while domain owners define the observation method and acceptance thresholds.

## Minimal request

```json
{
  "profile": "org.robot-identity.physical-binding",
  "version": "0.1",
  "method": "optical-challenge",
  "challengeNonce": "fresh-random-value",
  "issuedAt": "2026-08-23T00:00:00Z",
  "expiresAt": "2026-08-23T00:00:30Z"
}
```

## Verifier-local observation

```json
{
  "sessionId": "rip-session-id",
  "localTrackId": "camera-track-02",
  "method": "optical-challenge",
  "challengeHash": "session-bound-challenge-hash",
  "observedAt": "2026-08-23T00:00:01Z",
  "sensorReference": "camera-01",
  "confidence": 0.99
}
```

`localTrackId` is local state, not a portable robot identity. A production profile must define sensor authenticity, relay resistance, timing bounds, calibration, confidence semantics, privacy, failure behavior, and negative test vectors.

## Adding another method

1. Choose a stable method identifier and document the physical signal or ranging procedure.
2. Reuse the RIP session ID and verifier nonce when deriving the challenge hash.
3. Put the signed response commitment in the presentation Attribute Envelope.
4. Record the observation under a verifier-local track ID.
5. Verify the profile separately from RIP core and return `verified`, `failed`, or `unresolved` evidence.
6. Publish relay, ambiguity, stale-observation, and wrong-track tests.

The alpha SDK exports generic request, response, observation, and verification helpers. The Field Lab demonstrates `optical-challenge` with simulated camera observations only.
