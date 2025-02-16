# sBTC: Release Process

## Executive summary

This release process targets the following goals:

1. Ensure there exists a provable chain of trust connecting the source code to
   the corresponding artifacts.
1. Ensure there exists a clear _separation of duties_ between those who _write_
   the code and those who _release_ it (and announce its release).

It implements (1) by leveraging GitHub rulesets for branch/tag protection and
attestation for artifacts and (2) through the announcement process (described
below).

## [sBTC Core developers] Creating a new release

An sBTC release is a tagged commit on the `main` branch.

Any commit to `main` MUST require at least one review through a GitHub pull
request. Before merging the pull request, all tests MUST pass.

Tags MUST be named according to [semantic versioning][0].

[GitHub rulesets][1] ensure that only a subset of sBTC core developers can
create a `git tag`. Creating a tag SHOULD require 4-eyes (as of February 2025,
this is not yet possible).

Once a tag is created, a [GitHub deployment environment][2] will build and
publish any corresponding artifacts. The deployment environment MUST require a
review from a subset of sBTC core developers before executing. The use of
deployment environment ensures that all credentials that are required to publish artifacts
are gated behind the review process (e.g., Docker Hub credentials, until [OIDC
identities are supported][4]).

All artifacts MUST be [attested][3] so that their build provenance can be
established. This way, downstream users (e.g., sBTC signers) will be able to
cryptographically verify that an artifact (e.g., a Docker release) has been
built and published through GitHub actions.

All artifacts MUST be addressed through their cryptographic digest (e.g., `git
commit` or Docker image digest), in addition to their label (e.g., the `git
tag`).

To improve quality of life, the release notes MUST include breaking changes (if
any), upgrade migrations (if any), and a link to the relevant artifacts (e.g.,
Docker images).

## [sBTC Comms] Announcing a new release

After a new release has been created, the sBTC Comms team will inform the sBTC
signers and provide the appropriate update instructions.

All members of the sBTC Comms team MUST NOT be participating to sBTC development
(that is, they MUST NOT be part of the Core developers team). This ensures clear
separation of duties and, for instance, prevents a rogue core developer from
"convincing" the sBTC signers of deploying a tampered release.

At all times, there MUST be at least two members of the sBTC Comms team in any
communications channel including an sBTC signer (similarly to the 4-eyes process for releases).

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

[0]: https://semver.org
[1]: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
[2]: https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment
[3]: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
[4]: https://github.com/docker/roadmap/issues/314#issuecomment-2605945137
[5]: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds#verifying-artifact-attestations-with-the-github-cli
