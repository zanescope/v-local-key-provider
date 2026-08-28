# Compatibility evidence

Only redacted, authorized, successful live-regression evidence belongs here.
Each JSON file is named `<sha256-of-file>.json`. Its digest appears in a reviewed
[`promotions/<release-tag>.json`](promotions/README.md) manifest rather than in
the compiled compatibility registry. Signed release builders verify the file
digest, target binary/signing identity, architecture, validated cipher profiles,
complete coverage, registry-selected route, exact live-tested Provider/helper
candidate set, candidate source commit, workflow run, and GitHub attestation
workflow before building. The signed release job independently downloads that
run again and verifies each required asset with both `--signer-workflow` and
`--source-digest`; a committed `candidate_attestation_verified=true` field is
not sufficient by itself.

Schema v1 release evidence must request both `database` and `media`, report both
coverage states as `complete`, and explicitly record that secrets, paths, account
identity, and chat content are absent. Runner-local account and database paths are
loaded only from the platform-protected private config described in `RELEASING.md`;
they must never be supplied through GitHub workflow inputs, Secrets, or artifacts.

An uploaded CI artifact alone is not release authorization. The live workflow
must download the immutable `Release candidate` artifact by run id, verify every
asset against `candidate-manifest.json`, and run `gh attestation verify` against
the pinned candidate workflow before it may write evidence.

Registry entries contain only the exact target identity, architecture, profiles,
and bounded route recipe known before candidate validation. Promotion manifests
are not compiled into that candidate, which removes the former
`binary -> evidence -> binary` self-reference. Release builders validate the
external manifest and inject only its SHA-256 into the final signed build; a
missing, stale, partial, or mismatched promotion fails closed.
