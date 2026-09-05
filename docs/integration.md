# Integrate without adopting a whole platform

## Start locally

Run the [quickstart](../QUICKSTART.md), then `npm run example:processes`. Both peers carry an implementation; no central service is required.

`AuthenticationSession` emits/consumes complete byte frames. `ByteTransport.send(frame)` and `receive(signal)` connect it to an adapter; `authenticateOverTransport` drives three messages. The adapter provides discovery/selection, boundaries, timeouts, bounded queues and admission. BLE GATT, local Wi-Fi and ROS 2 adapters are not shipped yet. Different radios still need compatible hardware.

Never trust a public key just because a radio peer supplied it. Use independently provisioned pins or `issuerCredentials` with locally trusted issuers and signed identity objects. The browser's demonstration issuer is not a real-world trust authority.

## Add one domain schema

You own the schema. No industry registration or RIP-maintainer approval is needed.

```ts
import { issueStatement, verifyStatement } from "@robot-identity-protocol/sdk";
const schema = "https://example.com/robot/payload/v1"; // use your own namespace
const bytes = await issueStatement(fleetIssuer, {
  schema, subject: authenticatedPeerKeyId,
  issuedAt: Date.now(), expiresAt: Date.now() + 60_000,
  content: { nominalPayloadKg: 80 },
});
const claim = await verifyStatement(bytes, {
  schema, subject: session.report().peerKeyId,
  issuers: [{ keyId: fleetIssuer.keyId, publicKey: fleetIssuer.publicKey, schemas: [schema] }],
});
```

Use `claim.statement` only when `claim.status === "verified"`. Keep unknown/failure reasons separate from core identity. Choose issuer trust independently; do not accept a trust list sent by the same untrusted peer.

Examples, not mandatory vocabularies:

- Delivery: certified nominal payload; live remaining payload is a different timed assertion.
- Maintenance: installed tool type and calibration-valid-until.
- Agriculture: tank capacity, chemical ID and measurement time.
- Laboratory automation: end-effector type, calibration reference and environmental limits.
- Healthcare logistics: compartment temperature, sensor ID and observed time, without patient data.

Each schema specifies units, fields, who may assert them, freshness and privacy. Domain policy decides what action to take; a signature neither measures capacity nor permits an operation.

## Optional physical correlation

`npm run example:optical` uses a session-secret-derived response and simulated sensor tracks. It does not implement a driver, time-of-flight proof or anti-relay system. Add a sensor method as its own versioned profile with negative tests, not new core handshake messages.

## Before deployment

Read the [readiness gates](readiness.md). Keep alpha software in evaluation environments; independent review and relevant hardware/operational validation are still required.
