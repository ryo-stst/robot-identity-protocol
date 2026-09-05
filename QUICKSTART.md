# Your first RIP exchange

Start with two peers. No robot, account, cloud registry or radio is needed.
Use Node.js 22 or later. Internet is needed to download dependencies, not to run the exchange.

## 1. Install and run

```sh
git clone https://github.com/ryo-stst/robot-identity-protocol.git
cd robot-identity-protocol
npm ci
npm run example
```

Expected: `status: "verified"`, two different `peerKeyId` values and the same `exchangeId`.
Each report says its local peer verified the other peer's credential and key proof.
It does **not** identify a physical robot, check live revocation or allow an action.
The example controls both peers and a demonstration issuer; this is not an independent-implementation test.

## 2. See the three messages

```ts
import {
  AuthenticationSession, generateIdentityKeyPair, pinnedCredentials,
} from "@robot-identity-protocol/sdk";

const a = generateIdentityKeyPair();
const b = generateIdentityKeyPair();
// Demo bootstrap only. Provision production trust through your own secure process.
const resolvePeer = pinnedCredentials([a, b].map(peer => ({
  subject: peer.keyId, publicKey: peer.publicKey,
})));
const initiator = new AuthenticationSession({ role: "initiator", identity: a, resolvePeer });
const responder = new AuthenticationSession({ role: "responder", identity: b, resolvePeer });
await responder.receive(await initiator.start());       // EDHOC message_1
await initiator.receive(await responder.respond());     // EDHOC message_2
await responder.receive(await initiator.respond());     // EDHOC message_3
console.log(initiator.report(), responder.report());
```

Both peers use the SDK or another compatible implementation. Initiator/responder are exchange roles, not different kinds of robot.

## 3. Choose just one next experiment

| Learn about | Run |
| --- | --- |
| Two processes, each keeping its own private key | `npm run example:processes` |
| An issuer-signed, subject-bound custom claim | `npm run example:claims` |
| Multiple candidates and simulated optical correlation | `npm run example:optical` |
| Success and rejection tests | `npm test` |

The two-process example uses local IPC, not a radio, and provisions public keys through its trusted harness. Do not copy that bootstrap onto an untrusted transport.
The optical example uses a session-secret-derived response; its observation is simulated and does not prove anti-relay protection.

## Use the packaged SDK

```sh
npm install https://github.com/ryo-stst/robot-identity-protocol/releases/download/v0.2.0-alpha.1/robot-identity-protocol-sdk-0.2.0-alpha.1.tgz
```

Distribution is through GitHub Releases; npm registry publication is not implied.

Next: [baseline profile](spec/edhoc-baseline-v0.2.md), [integration and extensions](docs/integration.md), [browser walkthrough](https://robot-identity-field-lab.sato-kit111.chatgpt.site/) or [security limits](SECURITY.md).

Upgrading from alpha.4? Default exports and example now use EDHOC. Old JSON teaching APIs are available through `@robot-identity-protocol/sdk/legacy`, with no automatic fallback.
