# sBTC: Release Process

## Executive summary

This release process targets the following goals:

1. Ensure there exists a provable chain of trust connecting the source code to
   the corresponding artifacts.
1. Ensure there exists a clear _separation of duties_ between those who _write_
   the code and those who _release_ it (and announce its release).
1. Ensure that, under no circumstances, a single individual or entity is a
   single point of (security) failure or otherwise can single-handedly
   compromise the security of the sBTC protocol or its projects.

It implements (1) by leveraging GitHub rulesets for branch/tag protection and
attestation for artifacts, (2) through the announcement process (described
below), (3) through the 4-eyes processes (described below) and the
decentralised, threshold-based set of sBTC signers.

## [sBTC Core developers] Creating a new release

An sBTC release is a tagged commit on the `main` branch.

Any commit to `main` MUST require at least two reviews through a GitHub pull
request. Before merging the pull request, all tests MUST pass. Any new push to
the branch being reviewed WILL invalidate previous reviews.

Tags MUST be named according to [semantic versioning][0].

[GitHub rulesets][1] ensure that only a subset of sBTC core developers can
create a `git tag`. Creating a tag SHOULD require 4-eyes (as of February 2025,
this is not yet possible).

Once a tag is created, a [GitHub deployment environment][2] MUST build and
publish any corresponding artifacts. The deployment environment MUST require a
review from a subset of sBTC core developers before executing (again, enforcing
4-eyes). The use of deployment environment ensures that the process of
publishing artifacts (and all credentials required for it) is gated behind the
review process. Where possible, short-lived credentials SHOULD be preferred to
long-lived secrets: [^GHCR]

[^GHCR]:
    Since April 2025, sBTC Docker images are now available in GitHub
    [Container registry][3], as it allows authenticating through OIDC instead of
    hardcoded credentials (as required in DockerHub).

All artifacts MUST be [attested][4] so that their build provenance can be
established. This way, downstream users (e.g., sBTC signers) will be able to
cryptographically verify that an artifact (e.g., a Docker release) has been
built and published through GitHub actions.

All artifacts MUST be addressed through their cryptographic digest (e.g., `git
commit` or Docker image digest), in addition to their label (e.g., the `git
tag`).

To improve quality of life, the release notes MUST include breaking changes (if
any), upgrade migrations (if any), and a link to the relevant artifacts (e.g.,
Docker container images and their cryptographic hash).

## [sBTC Comms] Announcing a new release

After a new release has been created, the sBTC Comms team will inform the sBTC
signers and provide the appropriate update instructions.

All members of the sBTC Comms team MUST NOT be participating in sBTC development
(that is, they MUST NOT be part of the Core developers team). This ensures clear
separation of duties and prevents a rogue core developer from "convincing" the
sBTC signers of deploying a tampered release.

At all times, there MUST be at least two members of the sBTC Comms team in any
communications channel including an sBTC signer (similarly to the 4-eyes process
for releases).

## [sBTC Signers] Deploying a new release

Once sBTC Signers receive a release announcement from the sBTC Comms team, they
MUST:

1. Ensure the communication comes from a member of the sBTC Comms team.
1. Carefully read the corresponding upgrade instructions.
1. Verify the attestation of the attached artifacts.
1. Execute the upgrade.
1. Confirm the execution.

The `gh` executable can quickly [verify attestations][5]:

```bash
> gh attestation verify oci://index.docker.io/blockstack/sbtc:signer-0.0.9-rc6 -R stacks-network/sbtc
Loaded digest sha256:3bba86a5c2dfdbda61209dc728ab208406a909c8b5affba45da5bb4ccb27ad0d for oci://index.docker.io/blockstack/sbtc:signer-0.0.9-rc6
Loaded 1 attestation from GitHub API

The following policy criteria will be enforced:
- OIDC Issuer must match:................... https://token.actions.githubusercontent.com
- Source Repository Owner URI must match:... https://github.com/stacks-network
- Source Repository URI must match:......... https://github.com/stacks-network/sbtc
- Predicate type must match:................ https://slsa.dev/provenance/v1
- Subject Alternative Name must match regex: (?i)^https://github.com/stacks-network/sbtc/

✓ Verification succeeded!

sha256:3bba86a5c2dfdbda61209dc728ab208406a909c8b5affba45da5bb4ccb27ad0d was attested by:
REPO                 PREDICATE_TYPE                  WORKFLOW
stacks-network/sbtc  https://slsa.dev/provenance/v1  .github/workflows/image-build.yaml@refs/tags/0.0.9-rc6
```

## References

[0]: https://semver.org
[1]: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
[2]: https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment
[3]: https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry
[4]: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
[5]: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds#verifying-artifact-attestations-with-the-github-cli
