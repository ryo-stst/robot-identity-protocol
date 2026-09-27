# Try two different domains

Status: experimental local-test example in `v0.2.0-alpha.2`, 2026-09-27.
Use synthetic data only; release availability does not imply production readiness.

## 1. Run it

From this checkout, with Node.js 22 or later:

```sh
npm ci
npm run example:domains
```

The example runs a delivery endpoint and an inspection endpoint in one local
process. They use real EDHOC and COSE cryptography, but no robot, radio, Internet
request, account, or encrypted application channel.

## 2. Read the three outcomes

| Step | Endpoint authentication | Additional information |
| --- | --- | --- |
| The two different domains meet | Both verified using preinstalled trust | Nothing automatically disclosed |
| Each asks for its own domain's information | Still verified | Other endpoint reports `unsupported` |
| Delivery software explicitly adds the inspection validator and issuer trust | Same authentication, unchanged | Inspection statement verifies and its content is available |

`unsupported` is not an identity failure. It means a particular piece of domain
information cannot be supplied or understood under the requested exact schema.
It does not mean that the robot is bad, unsafe, or prohibited from operating.

## 3. Add your domain

Start with the [runnable command](../examples/cross-domain.ts) and its
[shared implementation](https://github.com/ryo-stst/robot-identity-protocol/blob/main/src/baseline/domain-demo.ts). The
smallest new configuration has three independently owned parts:

1. A versioned schema ID and local validator for your meanings, units, valid values
   and observation-age limits. Do not fetch executable validators from peer URLs.
2. A provider that returns an issuer-signed statement **only when explicitly
   requested and appropriate to disclose**. Return `undefined` to withhold it.
3. Independently installed issuer trust scoped to that exact schema. Being trusted
   for identity does not automatically make an issuer trusted for measurements.

After both core sessions complete, the exchange looks like this:

```ts
// requester/responder are DomainExtensionSession instances configured with
// mode: "local-test-only", a completed AuthenticationSession, and local callbacks.
const request = requester.request(["https://example.com/inspection/tool/v1"]);
const response = await responder.respond(request); // local byte-frame handoff only
const result = await requester.verify(response);

const item = result.items[0];
if (item?.status === "verified") {
  console.log(item.statement?.content); // assertion accepted by the configured checks
}
```

No protocol-maintainer approval or global schema registry is required. Sharing a
schema is an agreement among its users; unknown versions remain unsupported until
an explicit validator is installed. RIP does not infer what `weight: 12` means.

## Boundaries worth knowing

- `verified` includes signature, schema-specific issuer trust, subject and validity
  checks **plus your installed validator**. It still does not measure physical truth,
  check live revocation, bind a visible body, or authorize an operation.
- `unavailable` intentionally does not distinguish absent data from withheld data.
  `unresolved` means local issuer trust could not be established. `failed` means
  supplied evidence or domain validation failed. Only verified items expose a
  `statement` in the result.
- The wrapper request/response is **not encrypted or authenticated** by this helper.
  In particular, `source: "envelope-report"` is not signed proof of unsupported or
  unavailable information. Results explicitly declare both protections absent.
  Public request/session IDs do not fix that limitation.
- No serial is automatically sent, but reused credential keys remain linkable.
  A signature is not secrecy and a display alias is not anonymous authentication.

Before connecting external peers, a reviewed protected application transport is
required; none is delivered here. See the [precise framing and state contract](../spec/domain-exchange-v0.1.md)
and [identifier/disclosure policy](../spec/identifier-disclosure-policy-v0.1.md).
The [Field Lab](https://robot-identity-field-lab.sato-kit111.chatgpt.site/#domains)
also exposes this fixture under an optional cross-domain experiment. Its synthetic
peers exchange data inside one server process; HTTPS to your browser is not a
delivered robot-to-robot encrypted application transport. The bakery article has a
separate [CLI fixture](articles/examples/bakery-2035.mjs).
