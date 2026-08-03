# Security policy

## Supported versions

Blindport is pre-1.0 software. Only the latest published release receives
security updates.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/blindport/blindport/security/advisories/new)
or email `admin@blindport.com` if private reporting is unavailable. Include the
affected version, deployment mode, reproduction steps, impact, and any proposed
mitigation. Do not include live bearer tokens, wallet credentials, macaroons,
private keys, database contents, or user traffic in a report.

The Blindport release signing key is committed at
[`maintainers/blindport-release-key.asc`](maintainers/blindport-release-key.asc).
Verify its fingerprint before use:

```text
18ED E472 6C14 1484 4923 D6FF 14EA BFF7 39C1 6205
```

GitHub Actions also creates artifact attestations for released images and agent
binaries. See [the self-hosting guide](docs/self-hosting.md) for verification.
