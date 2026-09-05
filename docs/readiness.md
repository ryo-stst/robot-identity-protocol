# Readiness and adoption gates

Updated 2026-09-05. Experimental baseline, not production assurance.

| Area | Implemented | Remaining gate |
| --- | --- | --- |
| Authentication | EDHOC integration, fixed method/suite/CCS, local mutual verification | RFC byte-vector coverage; independent C ↔ TypeScript interop |
| Transport | Byte interface, two-process offline IPC | One real bearer; loss, fragmentation, DoS, concurrency tests |
| Trust | Local pins, issuer-signed identity lookup, schema scope | Secure provisioning, persistent rotation/recovery |
| Attributes | COSE, subject/schema/issuer/time checks | Domain validators, confidential exchange |
| Offline status | Signed fresh/stale/revoked snapshot helper | Distribution and deployment-policy integration |
| Physical evidence | Secret-derived optical response, simulated correlation/ambiguity | Real sensor timing and relay experiments |
| SDK | Node.js reference, bounded frames/state | Embedded implementation, hardware key handles, independent runtime verification |
| Security | Negative tests, COSE Sig_structure cross-check | Independent review and fuzzing |

No optional EDHOC message_4, OSCORE transport or generic encrypted application messaging is exposed. Do not infer these from upstream APIs.

## Adoption path

1. Reach one successful exchange without an account.
2. Reproduce success/rejection locally, then connect one real bearer.
3. Two independent organizations/implementations reproduce the same cases.
4. Measure integration effort saved against the existing approach and publish a reproducible example.
5. Broaden adapters and propose a stable profile with community governance.

Measure completed external quickstarts, independent reproduction and integration effort saved, not just page views/stars. Broad adoption and willingness to pay remain unvalidated. Local authentication and compatibility tests stay OSS; potential paid team/CI/history tools must not become an interoperability toll.
