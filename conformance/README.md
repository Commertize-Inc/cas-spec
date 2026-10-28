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

## Receipt signature vectors (secp256k1)

`vectors/cas-1.0-receipt-secp256k1.json` (suite `cas-1.0-receipt-secp256k1`) covers spec section 5.1.1. Each case gives the receipt `hash` (the signed message is `"CAS-v0.1\n"` followed by it), the EIP-191 `digest`, the signature entry `{ alg, key_id, sig }` (and the same 65 bytes as `sigHex`), the agent's key state (`agentKeys`, `anchor`, `paused`, see "Key state" below), and the expected `{ valid, reason, signer }`.

- Valid cases from six throwaway keys: keys in force (including a zero hash and a second receipt under the same key), an old key's receipt anchored before its rotation, the new key after the rotation, an anchor log earlier than the revoke log in the same block, and a key held under two credentials (anchored under either, including exactly at the second issue).
- Invalid cases:
  - signature: the high-`s` twin, `v = 29`, `v` written as `0`/`1`, a stale hash, and a `key_id` naming another address;
  - key state: an agent that is not the signer, a new key anchored before its credential, and revoked or unlinked keys anchored before their credential was issued (all `SUBJECT_MISMATCH`); an old key anchored at or after its rotation or not anchored, a revoked key not anchored, an unlinked key anchored after the unlink, an anchor log after the revoke log in the same block, an anchor between an unlink and a later revoke (the earliest end counts), an anchor between two credentials of one address, and a receipt with no anchor for a key with one revoked and one later credential (all `KEY_REVOKED`); a key in force on a paused contract (`PAUSED`) and a revoked key on a paused contract (`KEY_REVOKED`);
  - malformed entries: a 64-byte signature, a non-canonical base64url string, a checksummed `key_id`, an uppercase hash, and a wrong `alg`.

**Throwaway test keys.** The file carries no private key. Each valid case names its signer by `keyIndex`, the position of a throwaway test key in a stream anyone can derive from the public seed `cas-1.0-receipt-secp256k1/conformance-vectors/seed-1`:
- block `i` (from 0) is `keccak256(utf8(seed) || uint32_be(i))`;
- each block, read as a big-endian integer `d`, is the next key when `1 <= d < n` (the secp256k1 order), and is skipped otherwise;
- `keyIndex` 0 is the first key, 1 the second, and so on.

This is the same derivation as `packages/verify-ts/test/helpers.ts` (`withSeed`, `throwawayKey`).

**Addresses that must never be registered.** Anyone can derive these keys, so an issuer MUST refuse to issue a credential to any of these addresses (spec section 5.1.1):

- `0x52021b20D8B401Cab955FD94937dC9dA0f819A5C` (keyIndex 0)
- `0x1f86889f263a34A688C1B22C1059A76AccAaFf87` (keyIndex 1)
- `0x2744a427a349ca57B44c9e721ead157758E8A27d` (keyIndex 2)
- `0x020E04D4deAD79ad49bb8d81b073843F63Cf5377` (keyIndex 3)
- `0xA3440d6eF34d830442903311E1614FAC295F3EBf` (keyIndex 4)
- `0x07d8C96BC18F4d7Aa5f9373E63249c34Ab3220Ec` (keyIndex 5)

**Key state.** Each case carries `agentKeys` (the agent's `KYA_REGISTERED` credentials as a verifier would read them: address, `ISSUED`/`REVOKED`/`UNLINKED`, `issued`, the position of the `Issued` event, and `ended`, the position of the earliest `Unlinked` or `Revoked` event), `anchor` (the position of the receipt's anchor log on the credential contract's chain, or null: an anchor on any other chain, or a log that is not a `CasAnchor` event from a trusted anchoring contract, is null) and `paused`. A position is `{ block, logIndex }`, ordered by block number and then log index. The rotation cases revoke keyIndex 0 and issue keyIndex 1 in one block (block 2000, log indexes 0 and 1); the old key's receipts stay `VALID` only when anchored strictly before the revoke log, and are `KEY_REVOKED` otherwise. Keys derived from a public seed are public by construction: they were never funded and must never be used for anything else. Invalid cases carry no `keyIndex`. The signatures use RFC 6979 deterministic nonces, so any RFC 6979 signer produces the same bytes. `npm run vectors` regenerates the file byte for byte and `npm run vectors:check` fails on any difference.

## Issuer conformance

A credential contract conforms when it exposes the read interface and events of spec section 3.3, writes only as in section 3.2, and is not transferable. This directory contains no issuer suite. An issuer mark cannot be shown until one exists at a pinned suite version.

Issuer cases that a future suite MUST include, and that any issuer implementation SHOULD test now:

- **I-1, no re-issue to a revoked subject (spec section 3.2).**
  1. Issue `KYA_REGISTERED` to subject `S` with ref `r1`.
  2. Revoke it.
  3. Call `issue(S, 0, r2, contentHash)` with a different ref `r2`. It MUST revert, and no `Issued` event is emitted.

  The receipt vector `two-credentials-anchored-at-reissue` models the state this rule forbids. It exists so that verifiers agree on a result if a non-conforming issuer ever produces that state.
- **I-2, conformance keys are never registered (spec section 5.1.1).** `issue()` to any address under "Addresses that must never be registered" MUST be refused by the issuer.
- **I-3, no privileged credential to a revoked subject (spec section 3.2).**
  1. Revoke a `KYA_REGISTERED` credential of subject `S`.
  2. For each of `KYA_REGISTERED`, `TASK_MANDATE`, `WORK_ACCEPTED` and `ATTESTATION`, `issue(S, kind, ref, contentHash)` with a fresh `ref` MUST revert, and no `Issued` event is emitted.
  3. `STATUS_REINSTATED` is refused through `issue` for any subject: `issue(S, STATUS_REINSTATED, ref, contentHash)` MUST revert.
- **I-4, status kinds are allowed only where the spec places them (spec section 3.2).**
  1. For the same revoked `S`, `issue(S, STATUS_REVOKED, ref, contentHash)` succeeds; for a subject `T` that is not revoked it MUST revert.
  2. `reinstate(S, N, contentHash)` for a fresh address `N` succeeds and issues `STATUS_REINSTATED` to `N` with `ref = word(S)`; `reinstate(S, S, ...)`, `reinstate(T, N, ...)` with `T` not revoked, and `reinstate(S, R, ...)` with `R` revoked MUST revert.
  3. Verifying either status record as a credential gives `NOT_A_CREDENTIAL`, never `VALID` (vectors `credential-status-revoked`, `credential-status-reinstated`), and a `verify` of `S` for `KYA_REGISTERED` is still not `VALID`.

## Badge rule

The marks are **"CAS-1 Conformant (verifier)"** and **"CAS-1 Conformant (issuer)"**.

- A project may show a mark only while it links to a passing run, in a public CI system, of this suite at a pinned suite version, run against the project's own released code.
- The badge names the suite version. It shows no counts or percentages.
- The badge text MUST read 'CAS-1 Conformant (verifier) · cas-1.0-verifier' or the issuer equivalent, and MUST NOT include 'certified', 'approved', 'verified by Commertize' or the Commertize logo.
- The mark is self-declared. It means the project's own CI ran this suite at that version and passed. Commertize does not test, review, certify or endorse any project, operator or agent, and is not responsible for a project's use of the mark.
- If a newer suite version is published, the mark stays tied to the version it links to.

## Licence

The vectors and the generator are Apache-2.0. This README is CC-BY-4.0.
