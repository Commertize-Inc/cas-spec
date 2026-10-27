# Contributing

Contributions are accepted under the licence of the files they change: Apache-2.0 for code, vectors and scripts, CC-BY-4.0 for specification text and documentation. Every commit must carry a `Signed-off-by:` line certifying the Developer Certificate of Origin 1.1 (https://developercertificate.org). By contributing you confirm you have the right to submit the work under those licences. Do not include material you do not have the right to contribute, or anything your employer owns, without its permission.

Add the line with `git commit -s`. The `dco` CI job refuses a pull request that has a commit without it.

Before opening a pull request, run:

```bash
npm run check:wording
npm run typecheck
npm test
npm run vectors:check
```

`conformance/vectors/cas-1.0.json` is generated output. Change `packages/verify-ts/test/vectors.ts`, run `npm run vectors`, and commit the regenerated file in its own commit. CI regenerates it from the fixed seed and fails on any byte difference.

Conduct: see `CODE_OF_CONDUCT.md`. Security reports: see `SECURITY.md`, never a public issue.
