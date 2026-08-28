# Release promotions

This directory contains reviewed promotion manifests named for the release tag,
for example `v0.1.0.json`. A promotion manifest is external to the Provider
candidate and binds all four candidate targets to their content-addressed live
evidence files.

Generate one only from the attested `candidate-manifest.json` downloaded from a
successful `Release candidate` run and the four architecture-specific evidence
sets:

```text
node npm/scripts/candidate-manifest.js promote \
  candidate-manifest.json \
  compatibility-evidence/promotions/v0.1.0.json \
  compatibility-evidence/<evidence-sha256>.json ...
```

The command rejects evidence produced by another source commit, workflow run,
Provider/helper digest, platform, or architecture. The signed release workflow
also requires the candidate source commit to be an ancestor of the release tag
and permits only `compatibility-evidence/**` changes after that candidate.

Never create a promotion from a locally rebuilt binary, an unattested artifact,
or a digest copied from a different workflow run. The final signed prerelease is
still a different build and must be revalidated on clean machines before manual
promotion to a final GitHub/npm release.
