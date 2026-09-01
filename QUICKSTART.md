# RIP Quickstart

Run one local endpoint-authentication exchange in about 10 minutes. Nothing is sent to a hosted service.

## 1. Run the smallest example

Requirements: Node.js 22 or later and Git.

```bash
git clone https://github.com/ryo-stst/robot-identity-protocol.git
cd robot-identity-protocol
npm install
npm run example
```

Look for these three results:

```json
{
  "authentication": "verified",
  "physicalBinding": "endpoint-only",
  "authorizationDecision": "outside-this-protocol"
}
```

- `verified`: the Presenter controlled the expected identity key and the signed session was fresh.
- `endpoint-only`: the cryptographic endpoint was authenticated; no claim was made about which visible robot body it belongs to.
- `outside-this-protocol`: RIP returns identity evidence. Another application decides what action, if any, is allowed.

That is the complete first exercise.

## 2. Choose one next example

You do not need to run both.

### Multiple nearby candidates and simulated physical binding

```bash
npm run example:field
```

This keeps three advertisements separate, selects `Presenter B2`, authenticates only that endpoint, and correlates it with verifier-local `camera-track-02`. The sensor event is simulated and is not a production body-binding claim.

### A domain-specific attribute

```bash
npm run example:attribute
```

This attaches a logistics-owned Attribute Envelope with values such as `nominalPayloadKg`. RIP carries and signs the envelope without defining its business meaning. Issuer-proof verification is still unresolved in this alpha.

## 3. Add the SDK to another Node.js project

The alpha is distributed as a GitHub release asset rather than through the npm registry:

```bash
npm install https://github.com/ryo-stst/robot-identity-protocol/releases/download/v0.1.0-alpha.4/robot-identity-protocol-sdk-0.1.0-alpha.4.tgz
```

Both roles use the same package: the Presenter creates advertisements and signed presentations; the Verifier creates challenges and verifies reports.

When you need exact payloads, use [`test-vectors/one-way-success.json`](test-vectors/one-way-success.json). For protocol details, continue to the [core specification](spec/authentication-protocol-v0.1.md) or the [optional physical-binding profile](spec/physical-binding-profile-v0.1.md).
