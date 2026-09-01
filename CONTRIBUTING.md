# Contributing

Thank you for helping build interoperable, transport-independent robot authentication.

## Before opening a change

- Keep authorization, action policy, robot commands, and safety decisions outside the core.
- Do not add a mandatory hosted dependency or global database.
- Separate endpoint authentication from physical-entity binding.
- Add tests for positive and negative behavior.
- Do not include confidential, personal, export-controlled, or third-party material you cannot license.

For an open-ended robot interaction or adoption idea, start in [GitHub Discussions](https://github.com/ryo-stst/robot-identity-protocol/discussions/new?category=ideas). Use an issue for a concrete defect or scoped protocol change. For substantial protocol changes, open an issue before implementation so the compatibility and security impact can be discussed.

## Developer Certificate of Origin

Every commit must include a `Signed-off-by` line. Use:

```bash
git commit -s -m "Describe the change"
```

The sign-off certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/). By contributing, you agree that your contribution is licensed under Apache License 2.0 under the repository's existing terms.

## Pull requests

- Keep each pull request focused.
- Explain protocol and privacy consequences.
- Run `npm test`.
- State whether wire data, public API, security claims, or compatibility changed.
