# Three Robots Arrive at a Bakery. Which One Gets the Package?

<!-- Publication source, 2026-09-27. Fiction and executable evidence are explicitly separated. -->

![Friendly robots meeting in an everyday neighborhood](assets/robot-introductions-cover-v1.png)

*A short story from an imagined 2035, followed by a small experiment with Robot Identity Protocol. The date is a setting, not a forecast. The cover is an AI-generated conceptual illustration.*

## The morning the bakery met three strangers

At 5:47 a.m., the first robot politely asked Mara's bakery for twelve boxes of pastries.

At 5:48, the second asked for exactly the same thing.

At 5:49, the third arrived and waited without speaking.

Mara was still upstairs. Downstairs, the ovens were cooling, the streetlights were switching off, and the pickup hatch had a problem that no amount of computer vision could make disappear.

It could see three machines. It did not yet know which claims belonged to which conversation.

The smallest machine had immaculate wheels. The largest had a photograph of an inspection certificate on its display. The quiet one had a dent on its side.

None of those details answered the hatch's question.

In this imagined city, delivery companies no longer owned every part of a journey. A neighborhood cooperative could borrow a vehicle from another fleet. A repair company could substitute a machine overnight. Stores bought their own pickup equipment. There was no single vendor account shared by everyone on the street.

That flexibility made the city useful. It also meant that machines would meet strangers every morning.

The hatch asked each robot to establish a fresh authenticated conversation. Separately—not by drawing one reassuring green line around the whole group.

The first robot's credential checked out. It controlled a key the hatch was configured to trust. But it supplied no statement about a suitable cargo compartment. Its suitability was still unanswered.

The second robot also controlled a legitimate key. The inspection statement it presented was genuinely signed. There was just one inconvenient detail: the statement was about the third robot's credential, not its own.

The third robot proved control of its key and supplied an inspection statement bound to that same key. The statement described a dry-food compartment, a nominal twelve-kilogram payload, and forty-two liters of cargo space.

The hatch had learned something useful. It had not learned everything.

Was this the vehicle assigned to today's order? Was its compartment actually empty? Was the radio endpoint really the dented machine waiting in front of the hatch? Those still belonged to the bakery's order system, sensors, and handoff controller.

In the story, those separate checks also passed. The controller opened the hatch for the quiet robot.

Mara came downstairs just as the last box disappeared.

"Did you get its serial number?" she asked.

"I did not need its entire life story," the hatch replied.

That last sentence is the future I want to explore. It is also where the current software still has work to do.

## What would make this future possible?

If independently operated machines routinely meet, they need a way to check the source of a message and connect relevant information to the endpoint speaking now. They also need shared trust arrangements, compatible communication links, and domain-specific meanings for the information they exchange.

That is a prerequisite for this particular multi-operator scenario—not a claim that RIP itself must become mandatory, or that a global fleet database is always the wrong architecture.

RIP is an experimental attempt at a small part of the problem: local endpoint authentication and independently defined, authenticated information. It builds its current exchange on EDHOC, rather than requiring every integrator to design a new handshake. Authorization, safety decisions, and robot control remain outside it.

## A smaller experiment you can actually run

The accompanying [local example](examples/bakery-2035.mjs) implements only the cryptographic part of the story. It uses SDK `0.2.0-alpha.2`, real key exchange and signatures, synthetic issuers, and three separate sessions in one Node process. There is no radio, camera, door, order backend, or physical robot.

The fixture provisions issuer trust locally before the robots meet. It does not trust a key merely because a stranger advertises it.

The results are intentionally less dramatic than the story:

| Candidate | Endpoint authentication | Cargo statement | Package handoff |
| --- | --- | --- | --- |
| B1 | Verified | Not provided | Not decided by this example |
| B2 | Verified | Failed: the signed subject belongs to B3 | Not decided by this example |
| B3 | Verified | Verified for B3's authenticated key | Not decided by this example |

All three endpoints authenticate. Only one supplies a matching cargo statement. Neither result commands the hatch to open.

To reproduce the example, use Node.js 22 or later:

```sh
git clone https://github.com/ryo-stst/robot-identity-protocol.git
cd robot-identity-protocol
git checkout v0.2.0-alpha.2
npm ci
npm run example:bakery
```

The source and runnable fixture are included in the [alpha release](https://github.com/ryo-stst/robot-identity-protocol/releases/tag/v0.2.0-alpha.2). Prefer clicking first? The [Field Lab](https://robot-identity-field-lab.sato-kit111.chatgpt.site/) offers a simpler two-peer walkthrough and an optional cross-domain experiment. The bakery scenario itself runs locally with the command above.

## Customization is a statement, not a new handshake

The bakery example chooses a fictional schema namespace:

`https://example.com/bakery/cargo-capability/v1`

Its domain content is deliberately small:

```json
{
  "nominalPayloadKg": 12,
  "cargoBayVolumeL": 42,
  "compartmentClass": "dry-food"
}
```

The SDK places that content inside a COSE-signed statement with an issuer, subject key, schema, and issue/expiry times. The receiving application verifies the signature, whether it trusts that issuer for this schema, the time interval, and whether the subject matches the authenticated peer key.

No RIP maintainer has to approve a universal bakery vocabulary. A domain defines its own schema and validators. An identity issuer is not automatically a trusted cargo inspector.

There is an important catch: a signature proves what the issuer asserted, not that the assertion is sensible or physically true. The example also signs a negative payload capacity. Generic signature verification accepts it; a domain validator must reject it. Nominal capacity is not today's remaining capacity, and an unexpired certificate is not a fresh load measurement.

A separate [cross-domain experiment](../domain-exchange.md) makes that distinction executable: it authenticates
delivery and inspection endpoints, reports unknown domain requests as unsupported,
and verifies known statements only after an explicitly installed validator and
schema-scoped issuer trust. It changes no core handshake messages. Its wrapper
exchange is local-test-only and does not yet provide encrypted or authenticated
application transport. This is separate from the bakery fixture above; the Field
Lab runs the cross-domain fixture with synthetic peers inside one server process.

## The bakery should not become a tracking service

A fleet may need a permanent internal asset number for repairs, ownership, or recovery. The bakery may only need to authenticate a credential and check a narrowly scoped assertion. Those are different requirements.

Current RIP does **not** require a manufacturer serial or a global physical-robot number. It **does** expose the authenticated key identifier to its counterpart. Reusing that key makes visits linkable. The example runs B3 twice and asserts exactly that: new exchange, same key identifier.

So the hatch's line about not needing a life story is a design goal, not a claim that this SDK already prevents tracking.

Possible future integrations could keep durable asset records private and use separately provisioned, scoped or short-lived credentials externally. But relabeling one unchanged key is not privacy. Rotation, issuer trust, offline status, misuse prevention, and information leaked by radio addresses or movement all need design. The current SDK does not implement that lifecycle or cryptographic selective disclosure.

The optional statements are signed, not encrypted. A protected application channel is still needed for confidential transfer. Putting a serial, route, or passenger record into an "optional" field does not make it private. See the [identifier and disclosure design note](../privacy-and-identifiers.md) for the current boundaries.

## The next street over

Imagine the same morning from a different machine's point of view.

A small autonomous shuttle approaches a wet intersection. It might benefit from trustworthy, timely information about another vehicle. It does not automatically need that vehicle's VIN, passenger names, or journey history.

A vehicle domain could define occupancy state, measured mass, a condition-dependent braking estimate, hazard category, or an emergency-service credential. But each needs an appropriate source, freshness rules, an unknown state, and a reason for disclosure. A certified emergency-service role and "responding to an emergency right now" are different assertions. None is a steering command.

This is not an empty standards landscape: [USDOT describes SCMS](https://www.its.dot.gov/research-areas/Interoperable-Connectivity-Spectrum/) as credential infrastructure for trusted V2X communication with privacy. RIP is not a replacement for those systems or a demonstrated road-safety solution. High-rate road broadcasts may need a very different integration from a one-to-one bakery encounter.

Now imagine a hospital borrowing delivery robots during a busy week. Its corridor system may need a maintenance or cleaning assertion, not the patient's name carried in the next parcel. That is another story—and another domain profile—not a reason to put every industry's vocabulary into the authentication core.

## A useful machine does not have to tell you everything

The interesting future is not one in which every robot broadcasts a permanent name and its entire file to everyone nearby.

It is one in which a machine can establish an appropriately trusted conversation, share the information needed for that encounter, and let the surrounding application make its own decisions.

RIP can already demonstrate a small part of that conversation. Physical association, privacy-preserving credential management, and deployment-specific safety remain work to be done. It is an experimental alpha, without independent interoperability or security certification.

If you operate robots, the most useful question is not "Would you adopt another protocol?"

It is: **What is the smallest fact a stranger's machine needs to prove to yours—and what should it never learn?**
