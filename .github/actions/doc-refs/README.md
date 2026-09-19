# doc-refs — verified commit citations in docs

Docs that pin claims to commits (audit remediations, provenance records) rot
silently: a rebase, a typo, or a wishful citation leaves a hash that resolves
to nothing. This action turns that into a CI failure.

## The contract

1. `docs/refs.yml` (repo root) lists every doc whose commit citations CI
   verifies, relative to the repository root:

   ```yaml
   docs:
     - path: AUDIT-E2.md
   ```

2. Citations are backtick-quoted 7..40-char lowercase hex strings —
   `` `25206a2` `` — anywhere in the listed doc.

3. Each citation must resolve via `git rev-parse --verify <ref>^{commit}` in
   THIS repository, so CI needs `fetch-depth: 0` (a shallow clone would
   report everything missing). Ambiguous short hashes fail: lengthen them.

4. A line containing `no-verify-hash` is exempt, for hex that is not a commit
   of this repo: illustrative examples, key IDs, and cross-repo pins. A
   cross-repo pin should say WHERE it is enforced (the owning repo's
   doc-refs job, a Dockerfile `git checkout`, ...), so every pin is checked
   somewhere.

5. A listed doc containing zero citations passes with a WARN — a drift
   signal worth a look, not a failure. A listed doc that does not exist, or
   a manifest that lists nothing, is a hard failure.

## Usage

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: ./.github/actions/doc-refs
```

Pass `manifest:` to override the default `docs/refs.yml`. Locally, run the
script directly from the repository root:

```sh
./.github/actions/doc-refs/verify_doc_refs.sh
```

## Vendoring rules

This directory is vendored verbatim (`action.yml`, `verify_doc_refs.sh`,
`README.md`) into every repository that uses it: the repos that run it do
not share a commit history, so byte-identical vendoring at commit time is
the sync mechanism. When updating it here, copy the same bytes into the
other repos' `.github/actions/doc-refs/` in the same commit (`cmp` the
files), keep the exec bit set on the script
(`git update-index --chmod=+x`), and note the vendored blob hash in the
commit message.
