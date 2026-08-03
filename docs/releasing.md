# Releasing Blindport

Releases are built only from signed, annotated SemVer tags. The release workflow
runs the complete CI suite, publishes multi-architecture images to GHCR, creates
SBOM and provenance records, smoke-tests each exact image digest, generates
GitHub artifact attestations, promotes stable aliases, and creates a GitHub
Release with agent binaries and digest-pinned image references.

## Repository setup

1. Create the public repository at `https://github.com/blindport/blindport`.
2. Add the Blindport public signing key to the GitHub account. Its fingerprint is
   `18EDE4726C1414844923D6FF14EABFF739C16205`.
3. Protect the `v*` tag namespace with a repository ruleset. Limit tag creation,
   update, and deletion to release maintainers, and prevent force updates.
4. Enable GitHub Actions and allow workflows to create packages and attestations.
5. Enable private vulnerability reporting in the repository security settings.
6. After the first successful release, set the three linked GHCR packages to
   public visibility if they did not inherit public visibility from the repository.
7. Protect `master` and require the `ci / e2e` result plus the other CI jobs used
   by the repository's merge policy.

## Create a release

Use a version newer than the latest stable release and a new version for every
attempt. The workflow treats exact image tags as write-once and rejects a tag
before publishing when any matching exact image tag already exists. Digest
references, not tags, are the immutable image identity. Restrict package write
access to the release workflow and release maintainers.

```sh
git status --short
git tag -s v0.2.0 -u 18EDE4726C1414844923D6FF14EABFF739C16205 \
  -m "Blindport v0.2.0"
git verify-tag v0.2.0
git push origin v0.2.0
```

Prereleases such as `v0.2.0-rc.1` publish only their exact image tags. Stable
releases also promote `vMAJOR.MINOR` and `latest`; versions beginning with `v1`
or later also promote `vMAJOR`.

The workflow authenticates to GHCR with the repository-scoped `GITHUB_TOKEN`.
No registry password or personal access token should be added as a repository
secret.
