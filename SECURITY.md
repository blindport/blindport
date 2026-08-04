# Security policy

## Supported versions

Blindport is pre-1.0 software. Only the latest published release receives
security updates.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Blindport accepts
vulnerability reports only by email at `security@blindport.com`. Encrypt the
report with the [Blindport public key](https://blindport.com/release-key.asc)
before sending it. Verify the primary release-signing key fingerprint:

```text
18ED E472 6C14 1484 4923 D6FF 14EA BFF7 39C1 6205
```

Include the affected version, deployment mode, reproduction steps, impact, and
any proposed mitigation. Do not include live bearer tokens, wallet credentials,
macaroons, private keys, database contents, or user traffic.

Unencrypted reports and reports sent through other channels are not accepted.

The GPG signature authenticates release source history. GitHub Actions builds
convenience images and binaries but is not an independent verifier of those
artifacts. See [the self-hosting guide](docs/self-hosting.md) for the two trust
models.
