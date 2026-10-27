# CAS-1 conformance

Suite version: `cas-1.0-verifier`, pinned to spec version `cas-1.0`. Draft until the spec is tagged.

## Verifier vectors

`vectors/cas-1.0.json` is a list of cases. Each case gives the inputs of `verify` (section 6 of the spec) and the expected `{ valid, reason, step }`, plus `revokeReason` where one applies. The state each case reads is an offline snapshot (spec section 6.4), so any implementation can run the file with no network. The reference suite runs every case twice: once from the snapshot, and once live, with the same state served by a fake provider that answers the way a credential contract does.

A case may instead carry `modes: ["live"]` and `liveReads`: values the contract's `isValid` and `paused` (booleans) and `status` (a number) reads return instead of what the snapshot state implies, each encoded as one 32-byte word. Such a case runs live only, because a snapshot cannot disagree with itself. `credential-inconsistent-state` uses it: `isValid` answers false for an issued credential on an unpaused contract, and the expected result is `INCONSISTENT_STATE`.

The cases cover: a valid credential, valid mandates, each revocation reason (for a credential and for a mandate anchor), unlinked, not found, paused, revoked-while-paused, untrusted and missing issuers, wrong subject, wrong kind, wrong chain, wrong signer, a tampered message, the high-s signature form, wrong domain chain and contract, an unsupported type or schema, a non-zero spend cap, the window bounds, scope denials (task, asset, counterparty, amount, empty lists), a credential mismatch, and an unanchored mandate.

Two behaviours have named vectors:

- **Pause is not revocation.** `credential-paused`, `mandate-anchor-paused` and `mandate-anchor-revoked-while-paused` expect `PAUSED` with no revocation reason. `credential-paused-revoked` expects `REVOKED`, because a credential revoked before or during a pause still reads as revoked.
- **Revoke by digest.** A mandate is revoked by revoking its anchor: the `TASK_MANDATE` credential at `idFor(agent, 1, digest)` whose `ref` is the mandate digest (spec section 4.4). `mandate-revoked-mandate-ended`, `mandate-revoked-kya-lapsed`, `mandate-revoked-misuse`, `mandate-revoked-error`, `mandate-revoked-holder-request` and `mandate-revoked-legal-order` cover each reason and expect `MANDATE_REVOKED` at step `anchor`.

**How the signatures were made.** The generator (`packages/verify-ts/test/generate-vectors.ts`) derives secp256k1 keys and signing nonces from a fixed public seed (`packages/verify-ts/test/vector-file.ts`), signs each mandate, and writes only addresses and signatures. Because the seed is public, the keys are public by construction: they are test keys, were never funded and must never hold anything. Anyone can regenerate the file byte for byte with `npm run vectors`; `npm run vectors:check` (also a CI job) fails on any byte difference. The test suite also builds a fresh set with new random keys on every run, so the vectors do not depend on any one key.

An implementation is a conformant verifier for `cas-1.0` when it produces the expected result for every case in the file at that suite version.

## Issuer conformance

A credential contract conforms when it exposes the read interface and events of spec section 3.3, writes only as in section 3.2, and is not transferable. This directory contains no issuer suite. An issuer mark cannot be shown until one exists at a pinned suite version.

## Badge rule

The marks are **"CAS-1 Conformant (verifier)"** and **"CAS-1 Conformant (issuer)"**.

- A project may show a mark only while it links to a passing run, in a public CI system, of this suite at a pinned suite version, run against the project's own released code.
- The badge names the suite version. It shows no counts or percentages.
- The badge text MUST read 'CAS-1 Conformant (verifier) · cas-1.0-verifier' or the issuer equivalent, and MUST NOT include 'certified', 'approved', 'verified by Commertize' or the Commertize logo.
- The mark is self-declared. It means the project's own CI ran this suite at that version and passed. Commertize does not test, review, certify or endorse any project, operator or agent, and is not responsible for a project's use of the mark.
- If a newer suite version is published, the mark stays tied to the version it links to.

## Licence

The vectors and the generator are Apache-2.0. This README is CC-BY-4.0.
