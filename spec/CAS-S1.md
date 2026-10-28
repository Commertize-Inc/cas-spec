# CAS-1: Commertize Agent Standard, version 1 (draft)

Status: **draft for public review**, spec version `cas-1.0`. Nothing in this document is final until it is tagged `cas-1.0` in this repository. Editor: Commertize, Inc. Licence: CC-BY-4.0 (see `spec/LICENSE`).

Networks: the examples and conformance vectors in this draft use Base Sepolia (chain id 84532), a test network. No mainnet credential contract exists, and this repository publishes no contract address.

The key words MUST, MUST NOT, SHOULD and MAY are used as described in RFC 2119 and RFC 8174.

## 1. Purpose and scope

CAS is what a software agent shows before it acts on a real asset or on someone else's behalf. It answers three questions:

1. **Who stands behind this agent?** A *credential*: a non-transferable on-chain record about an agent wallet, written by an issuer under checks the issuer itself describes.
2. **What may it do?** A *mandate*: a scope that a human principal signed (EIP-712 typed data) and that can be revoked.
3. **What did it do?** A *receipt*: a signed, hash-linked record of one action taken under a mandate.

An *attestation* is the issuer's public statement of the checks behind a credential class.

Verification is open to anyone. It needs no key and no account, and it can run without contacting the issuer: the result is a deterministic function of chain state plus the mandate body. A hosted verification endpoint, where one exists, is a convenience and never the authority.

Out of scope: agent identity and discovery (CAS reads existing registries and agent cards and does not replace them), payment rails, custody of any asset or key, and any judgement about an agent's quality. A VALID result means only that the checks in section 6 passed at the block read. It is not an endorsement of the agent, the principal or any action.

## 2. Terms

| Term | Meaning |
|---|---|
| Subject | The agent wallet address a credential is about. CAS keys on this address. |
| Issuer | An address holding the issuer role on a credential contract. CAS-1.0 has no built-in issuer: every verifier supplies its own trusted-issuer set (section 6.1). |
| Principal | The human or organisation that signs a mandate for an agent. |
| Credential contract | A contract that implements the read interface in section 3.3. |
| Relying party | Whoever runs the verification before letting the agent act. |
| KYA | "Know your agent": the checks an issuer states, in its attestation (section 5.2), that it ran before issuing a credential. CAS defines no minimum checks. A credential says only that the issuer recorded it; it is not identity verification performed for, or on behalf of, any relying party. |

## 3. Credential

### 3.1 Record

A credential is a record in a credential contract, addressed by a 256-bit id:

| Field | Type | Meaning |
|---|---|---|
| `subject` | address | The agent wallet. Never zero. |
| `kind` | uint8 enum | `0 KYA_REGISTERED`, `1 TASK_MANDATE`, `2 WORK_ACCEPTED`, `3 ATTESTATION`, `4 STATUS_REVOKED`, `5 STATUS_REINSTATED`. Kinds 4 and 5 record a status and confer nothing (section 3.2). |
| `status` | uint8 enum | `0 NONE`, `1 ISSUED`, `2 REVOKED`, `3 UNLINKED`. |
| `reason` | uint8 enum | Revocation reason (section 3.4). Meaningful only when `status` is `REVOKED`. |
| `issuedAt` | uint64 | Block timestamp at issue. |
| `issuer` | address | The address that issued it. |
| `ref` | bytes32 | The issuer's reference. For `TASK_MANDATE` it is the mandate digest (section 4.4). Never zero. |
| `contentHash` | bytes32 | A keyed hash binding the credential to off-chain records of the principal. It carries no personal data and a verifier cannot open it. Never zero. |

The id is deterministic: `id = uint256(keccak256(word(subject) || word(kind) || ref))`, where `word` left-pads to 32 bytes (the standard Solidity argument encoding of `(address, uint8, bytes32)`, 96 bytes in all). One `(subject, kind, ref)` can be issued once; a second issue of the same triple MUST fail.

A credential is not transferable. There is no transfer function, no approval and no balance. The only writes are issue, revoke, unlink and pause (section 3.2).

### 3.2 Writes

| Write | Who | Effect |
|---|---|---|
| `issue(subject, kind, ref, contentHash)` | issuer role, only while not paused | `NONE` to `ISSUED`; emits `Issued`. |
| `reinstate(oldSubject, newSubject, contentHash)` | issuer role, only while not paused | Issues `STATUS_REINSTATED` to `newSubject` with the opaque `ref = keccak256(enc("CAS-REINSTATE", oldSubject, contentHash))`, where `enc` is the standard Solidity argument encoding of `(string, address, bytes32)` (a 0x60 offset word, the address word, the content hash, then the string length word and its bytes right-padded to 32); `NONE` to `ISSUED`; emits `Issued` and `Reinstated`. Reverts with `StatusKindMisuse` unless `oldSubject` is revoked, `newSubject` is not revoked, and the two differ; with `ReinstatedAlready` if `oldSubject` was reinstated before (once per old address); with `SuccessorNotRegistered` unless `newSubject` already holds an `ISSUED` `KYA_REGISTERED` credential. |
| `revoke(id, reason)` | issuer role, also while paused | `ISSUED` or `UNLINKED` to `REVOKED`; emits `Revoked`. Final. |
| `unlink(id)` | the subject only, also while paused | `ISSUED` to `UNLINKED`; emits `Unlinked`. The holder can always walk away. |
| `pause()` / `unpause()` | admin role | While paused no credential verifies as VALID and nothing can be issued. Revocation and unlinking still work and still read. |

**Revoked subjects.** A subject is *revoked* when any of its `KYA_REGISTERED` credentials is `REVOKED`. Because revocation is final, this flag is monotone: once revoked, an address stays revoked.
- A revoked subject receives no credential that confers standing, permission or reputation: no `KYA_REGISTERED`, `TASK_MANDATE`, `WORK_ACCEPTED`, or `ATTESTATION` (or any later kind that vouches for, grades or credits the subject).
- Every issuer MUST read the subject's revoked flag (`kyaRevoked(subject)`, section 3.3) before any issue.
- The credential contract MUST enforce this on chain: `issue(subject, kind, ref, contentHash)` MUST revert for a revoked subject and any of these kinds, whatever the `ref`.
- The status kinds record the revocation and its outcome and confer nothing:
  - `STATUS_REVOKED` (kind 4) is the only kind issuable to a revoked subject, and it is issuable only to one: `issue(subject, 4, ref, contentHash)` MUST revert unless `subject` is revoked.
  - `STATUS_REINSTATED` (kind 5) is issued only by `reinstate(oldSubject, newSubject, contentHash)`, to the new address. Its `ref` is an opaque hash of the old address and the content hash, so the record itself does not name the old address; the `Reinstated` event links the two addresses (section 3.3). An old address is reinstated at most once, and the new address MUST already hold an `ISSUED` `KYA_REGISTERED` credential: it registers through the normal flow first. `issue(subject, 5, ...)` MUST revert with `StatusKindMisuse`, as MUST `issue(subject, 4, ...)` for a subject that is not revoked.
  - Neither is a credential for section 5 or section 6: a verifier MUST NOT treat either as standing, a permission or a vouch, and the result of `verify` is never `VALID` for one. Read as a credential, a status record gives `NOT_A_CREDENTIAL` (section 6.2), whatever kind was asked for. Read as a status, it is reported as a status record.
- Reinstating an agent means rotation: the new address first receives its own `KYA_REGISTERED` credential, then `reinstate(revoked, new, contentHash)` records `STATUS_REINSTATED` on the new address and emits `Reinstated` linking it to the revoked one. The revoked address is never registered again. This also governs renewal: renewing a revoked agent is a rotation.
- Work already in flight settles under its escrow terms, but no `WORK_ACCEPTED` credential is issued to a revoked subject. The rule is what stops a receipt signed while a key was revoked, and anchored after a re-issue, from reading as `VALID` (section 5.1.1, "Several credentials for one address"); the verifier alone cannot tell such a receipt apart. (Verifiers still handle a subject with several credentials deterministically, section 5.1.1; laundering is possible only in the state this rule forbids.)

CAS-1.0 credentials carry no expiry field. A credential whose underlying checks lapse is revoked with `KYA_LAPSED`. Time limits on what an agent may do live in the mandate window (section 4).

### 3.3 Read interface

A credential contract MUST expose these view functions (Solidity signatures; selectors are the first four bytes of the keccak-256 of the canonical signature):

```
function status(uint256 id) view returns (uint8)
function isValid(uint256 id) view returns (bool)          // true iff not paused, status == ISSUED, and kind is not 4 or 5
function kyaRevoked(address subject) view returns (bool)  // true iff any KYA_REGISTERED credential of subject is REVOKED (section 3.2)
function paused() view returns (bool)
function credential(uint256 id) view returns ((address subject, uint8 kind, uint8 status, uint8 reason,
                                                uint64 issuedAt, address issuer, bytes32 ref, bytes32 contentHash))
function idFor(address subject, uint8 kind, bytes32 ref) pure returns (uint256)
```

And these events:

```
event Issued(uint256 indexed id, address indexed subject, uint8 indexed kind, bytes32 ref, bytes32 contentHash, address issuer)
event Revoked(uint256 indexed id, address indexed subject, uint8 reason, address by)
event Unlinked(uint256 indexed id, address indexed subject)
event Reinstated(uint256 indexed id, address indexed newSubject, address indexed oldSubject)
```

The `Reinstated` event carries addresses and the id only, never a reason or any data about the principal.

And these errors, among others (the remaining errors are implementation-defined):

```
error StatusKindMisuse(address subject, uint8 kind)   // a status kind outside the rules of section 3.2
error ReinstatedAlready(address oldSubject)           // oldSubject was already reinstated
error SuccessorNotRegistered(address newSubject)      // newSubject holds no ISSUED KYA_REGISTERED credential
```

`isValid` is the single source of truth for validity. It is false for a status record (kinds 4 and 5) even when issued, so `isValid(id) && subject == caller` never admits a revoked agent through its own `STATUS_REVOKED` record. That check still accepts any kind 0 to 3: a consumer that needs KYA standing MUST also check that the record's kind is `KYA_REGISTERED` (0). `kyaRevoked(subject)` is the revoked flag of section 3.2, the read every issuer makes before an issue. The other reads exist so a verifier can explain a failure and can detect a contract whose reads disagree (section 6.2, `INCONSISTENT_STATE`).

### 3.4 Revocation reasons

A fixed enum. New reasons need a new minor version (section 8).

| Value | Name | Use |
|---|---|---|
| 0 | `MANDATE_ENDED` | The work or relationship the credential covered has ended. |
| 1 | `KYA_LAPSED` | The checks behind the credential are out of date. |
| 2 | `MISUSE` | Used outside its terms. |
| 3 | `ERROR` | Issued by mistake. |
| 4 | `HOLDER_REQUEST` | The subject or principal asked for it. |
| 5 | `LEGAL_ORDER` | Required by law or a competent authority. |

A reason is a category, not a finding about any person. User-facing text SHOULD show the name and nothing stronger.

## 4. Mandate

A mandate is a scope a principal grants to one agent. The body is EIP-712 typed data, signed by the principal and kept off-chain by the parties. Its digest is anchored on-chain as a `TASK_MANDATE` credential (section 4.4), which is also how it is revoked.

### 4.1 Domain

```
EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
name              = "CAS Mandate"
version           = "1"
chainId           = the chain of the credential contract
verifyingContract = the credential contract that anchors the mandate
```

The domain MUST have exactly these four fields. A `salt` or any other field makes the mandate invalid (`WRONG_DOMAIN`).

### 4.2 Type

```
Mandate(string schema,address principal,address agent,uint256 credentialId,string[] taskClasses,
        string[] assetClasses,address[] counterparties,uint256 spendCap,uint64 validAfter,
        uint64 validBefore,bytes32 nonce)
```

| Field | Rule |
|---|---|
| `schema` | `"cas-1.0"` for this version. A verifier MUST refuse a major version it does not implement. |
| `principal` | The signer. Non-zero. |
| `agent` | The subject the mandate is for. Non-zero. |
| `credentialId` | The agent's `KYA_REGISTERED` credential id (decimal string in JSON). |
| `taskClasses` | 1 to 64 distinct class names, lower case `[a-z0-9][a-z0-9._:-]{0,63}`. |
| `assetClasses` | 0 to 64 distinct class names, same syntax. |
| `counterparties` | 0 to 64 distinct addresses the agent may deal with. |
| `spendCap` | Base units, decimal string in JSON. **MUST be `0` in CAS-1.0**: a CAS-1.0 mandate authorises no movement of value. |
| `validAfter`, `validBefore` | Unix seconds. `validAfter <= t < validBefore`. `validBefore` MUST be greater than `validAfter`. |
| `nonce` | 32 random bytes, so two otherwise equal mandates have different digests. |

The type is fixed. A typed-data object whose `Mandate` type differs in any field name, type or order is refused (`UNSUPPORTED_VERSION`), and so is one that declares any type other than `EIP712Domain` and `Mandate`.

Class vocabularies (which task and asset class names exist) are published separately and versioned on their own. The scope check below compares names exactly and does not interpret them.

### 4.3 Signature

A 65-byte `r || s || v` secp256k1 signature over `keccak256(0x19 0x01 || domainSeparator || hashStruct(message))`. `v` is 27 or 28 (0 or 1 is accepted). A verifier MUST refuse `s > n/2` (the malleable form), `r` or `s` outside `[1, n-1]`, and any other `v`. The recovered address MUST equal `principal`. Signatures from contract wallets (ERC-1271) are out of scope for CAS-1.0.

### 4.4 Anchor and revocation

The issuer anchors an accepted mandate by issuing a credential with `subject = agent`, `kind = TASK_MANDATE`, `ref = digest`. Its id is therefore `idFor(agent, 1, digest)`, which any verifier can compute from the mandate alone.

- An unanchored mandate is not in force (`MANDATE_NOT_ANCHORED`), however well signed.
- Revoking the anchor ends the mandate (`MANDATE_REVOKED`, with the reason). The principal asks the issuer to revoke; the agent can end it itself with `unlink`.
- Issuing the anchor is the issuer's statement that the signer is the principal bound to the agent's credential. A verifier does not need to see that binding.

### 4.5 Scope check

`allows(mandate, action)` is true only if every element the action names is granted:

1. `action.taskClass` is in `taskClasses`.
2. If `action.assetClass` is present, it is in `assetClasses`.
3. If `action.counterparty` is present, it is a valid address and is in `counterparties` (case-insensitive).
4. `action.amount` (default `0`, decimal integer string) is at most `spendCap`, compared as integers.

Empty lists grant nothing: an action that names an asset class or a counterparty is denied when the list is empty. Anything malformed is denied.

## 5. Receipt and attestation

### 5.1 Receipt

A receipt is a signed, hash-linked record of one action under a mandate. CAS-1.0 adopts the CAS v0.1 receipt format published in `Commertize-Inc/commertize-agents` (`spec/cas/schemas/receipt.schema.json`): JCS-canonical JSON, a SHA-256 record hash, one or more signatures, and a `prev_hash` chain per mandate. For a CAS-1 mandate, `mandate_id` MUST be the mandate digest (`0x`-prefixed hex). A receipt MAY reference a payment proof or a venue's own signature in `evidence.refs`.

A receipt is evidence of what the agent recorded. It is not a statement by the issuer.

#### 5.1.1 Receipt signatures with secp256k1

This section fixes the `secp256k1` suite of the receipt format (CAS v0.1, C-2) for CAS-1. It keeps the C-2 signed message unchanged and adds the byte encoding, the verification rules and the binding to the agent.

**Message.** `m` is the UTF-8 encoding of the string `"CAS-v0.1\n"` followed by the receipt's `hash` (`"sha256:"` and 64 lowercase hex digits). `m` is exactly 80 bytes. A `hash` in any other form is malformed.

**Digest.** `d = keccak256(0x19 || "Ethereum Signed Message:\n80" || m)`: the EIP-191 personal message digest (version `0x45`) of `m`. This is the digest an EVM wallet produces when asked to sign `m` as a personal message, so an agent can sign a receipt with the same key and the same tools it already uses for its address, including hardware and remote signers that refuse to sign a raw digest. The `CAS-v0.1\n` prefix inside `m` keeps CAS signatures apart from any other message the same key signs.

**Signature bytes.** A 65-byte `r || s || v`: `r` and `s` are 32-byte big-endian integers and `v` is one byte, `27` or `28`. A signer MUST produce the low-`s` form (`s <= n/2`). The `sig` field is the base64url encoding of these 65 bytes, unpadded and canonical as C-2 requires (87 characters).

**key_id.** For this suite `key_id` MUST be the signer's address: `"0x"` and 40 lowercase hex digits. A mixed-case (checksummed) or uppercase `key_id` is malformed, so that one key has exactly one `key_id` string.

**Verification.** A verifier MUST, in order:

1. Recompute the receipt `hash` (C-1). It uses only a hash it computed itself.
2. Check the entry: `alg` is `"secp256k1"`, `key_id` has the form above, `sig` is canonical base64url of exactly 65 bytes. Otherwise the result is `MALFORMED`.
3. Refuse `v` other than `27` or `28`, `r` or `s` outside `[1, n-1]`, a high `s` (`s > n/2`), and an `r` that is not the x-coordinate of a curve point: `BAD_SIGNATURE`. Unlike a mandate signature (section 4.3), a receipt signature does not accept `v` as `0` or `1`: the `sig` string of a receipt is canonical, so one signature has one encoding.
4. Recover the signer address from `d` and the signature. If it is not `key_id`, the result is `BAD_SIGNATURE`.
5. Judge the signing key by the credential that registered it, at a position on chain the agent cannot choose:
   - **Which credentials.** The applicable credentials are the agent's `KYA_REGISTERED` credentials whose `subject` is the recovered address, read from the credential contract or an offline snapshot of it (section 6.4). An agent that rotates its key gets a new address and a new credential; the verifier attributes each credential to the agent from its own trusted source, never from an address carried in the receipt (`key_id` included). If there is none, the result is `SUBJECT_MISMATCH`.
   - **Positions, not timestamps.** Every comparison in this step is between positions on the credential contract's own chain: block number first, then log index within the block. `I` is the position of a credential's `Issued` event. `E` is the position of its earliest end event: `Unlinked` or `Revoked`, whichever came first (a credential can be unlinked and later revoked).
   - **Which anchor.** `A` is the position of the receipt's anchor log. That log is a `CasAnchor(bytes32 indexed headHash)` event (topic 0 = `keccak256("CasAnchor(bytes32)")`) in the receipt's `anchor.tx` (CAS v0.1 R-3), emitted by an anchoring contract whose address the verifier names as trusted, with `headHash` equal to the 32 bytes of `anchor.head_hash`. `head_hash` is this receipt's `hash` or the `hash` of a later receipt in the same `prev_hash` chain. Any other log, or a log from an emitter the verifier has not named, does not count. `A` exists only if that transaction is confirmed on the credential contract's own chain. The receipt names `anchor.chain_id` itself, so an anchor on any other chain gives no `A`: the receipt is treated as unanchored. The receipt's own `occurred_at` is chosen by the agent and is never used.
   - **No anchor.** If there is no `A`, nothing places the signature in time. The result is `KEY_REVOKED` if any applicable credential is `REVOKED` or `UNLINKED`, and `VALID` only if every applicable credential is `ISSUED`. A credential issued later never makes such a receipt `VALID`: a key's revocation invalidates every receipt it signed that was not anchored on chain before it.
   - **Anchored: each credential, in this order.**
     1. If `A` is before `I`, the key was not yet the agent's under this credential: `SUBJECT_MISMATCH`, whatever the credential's status.
     2. `ISSUED`: the key is in force at `A`: `VALID`.
     3. `REVOKED` or `UNLINKED`: `VALID` only if `A` is before `E`, otherwise `KEY_REVOKED`.
   - **Several credentials for one address.** Section 3.2 forbids issuing again to a revoked subject, but a verifier still decides deterministically: an anchored receipt is `VALID` if any applicable credential gives `VALID` (so it is `VALID` under a later credential only if `A` is at or after that credential's `I`), otherwise `KEY_REVOKED` if any gives `KEY_REVOKED`, otherwise `SUBJECT_MISMATCH`. Every verifier reading the same state reaches the same result.
   - **Paused contract.** If the result would be `VALID` and the verifier reads the contract as paused, the result is `PAUSED` instead (section 3.2). `KEY_REVOKED` and `SUBJECT_MISMATCH` are reported while paused, as revocation is in section 6.

Only when all five steps pass is the signature `VALID`. The result codes of this section, in precedence order, are `MALFORMED` (step 2), `BAD_SIGNATURE` (steps 3 and 4), then `SUBJECT_MISMATCH`, `KEY_REVOKED`, `PAUSED` and `VALID` (step 5). Each also appears in the list of section 6.5. A receipt signed under several suites follows the C-2 policy rule: a verifier MAY require each suite it names.

**Binding.** The `secp256k1` suite proves that the holder of the agent's own key signed the receipt. The key is the one whose address is the subject of the agent's `KYA_REGISTERED` credential. A receipt signed by any other key, including a key of the principal or of the issuer, is not a `VALID` agent signature under this section.

**Signing may default to off.** An implementation that holds an agent key MAY ship with receipt signing disabled until the principal enables it on that machine, and MAY offer a local stop (for example a kill file) that blocks signing and writes. Such a local stop is cooperative: it binds that implementation only. The authoritative stop for an agent is on chain or at the issuer: revoking its credential or its mandate (sections 3.2 and 4.4).

**Conformance keys are never agents.** The keys behind every published conformance vector are derived from public seeds, so anyone holds them. An issuer MUST refuse to issue a credential whose `subject` is one of the addresses listed under "Addresses that must never be registered" in `conformance/README.md`, and a verifier SHOULD treat a signature by one of them as test data only.

**Vectors.** `conformance/vectors/cas-1.0-receipt-secp256k1.json` holds valid and invalid cases with their expected results, including a rotated key, a revoked key and an unlinked key. The signatures in it use RFC 6979 deterministic nonces, so a conforming signer reproduces each valid case byte for byte. Its keys are throwaway test keys derived from a public seed: never funded, and never to be used for anything else.

### 5.2 Attestation

An attestation is a credential of kind `ATTESTATION` whose `subject` is the issuer and whose `ref` is the keccak-256 of a public policy document. The document states, for one credential class, which checks are run, by whom, and under which policy version. Changing the policy means a new document and a new attestation. The reference verifier does not evaluate attestations in this version.

## 6. Verify semantics (normative)

`verify(subject, credentialId, mandate?, action?, at?)` evaluates to `VALID` only if every step passes. Otherwise it gives the first failing reason code and the step that produced it.

### 6.1 Inputs

- The relying party MUST supply its trusted-issuer set. An empty set fails closed (`NO_TRUSTED_ISSUER`). There is no default.
- Live mode reads through a provider the relying party chooses. Offline mode reads a state snapshot the relying party supplies (section 6.4).
- An `action` without a `mandate` is `MALFORMED`.

### 6.2 Steps

1. **Chain.** The provider's chain id MUST equal the expected chain (`WRONG_CHAIN`), and the contract MUST have code (`NO_CONTRACT`). Every read in one verification uses one pinned block number.
2. **Credential.** Read `credential(id)`, `paused()`, `isValid(id)` and `status(id)`. If they disagree, or any word is out of range, the result is `INCONSISTENT_STATE`. Then, in order: `NONE` gives `NOT_FOUND`; a record whose `idFor(subject, kind, ref)` is not the id it was read under gives `INVALID_ID`; a record of a status kind (`STATUS_REVOKED`, `STATUS_REINSTATED`) gives `NOT_A_CREDENTIAL`, before revocation, trust, subject and kind are judged, so a status record is never `VALID` and never reads as a revoked credential; `REVOKED` gives `REVOKED` with the reason; `UNLINKED` gives `UNLINKED`; an issuer outside the trusted set gives `UNTRUSTED_ISSUER`; another subject gives `SUBJECT_MISMATCH`; a kind other than `KYA_REGISTERED` gives `WRONG_KIND`; a paused contract gives `PAUSED`. Revocation is reported even while paused. `PAUSED` is its own result and is never reported as `REVOKED`: a pause is an incident on the contract, a revocation is a decision about one credential, and an integrator MUST be able to tell them apart. A pause carries no revocation reason.
3. **Mandate** (if given): type and schema (`UNSUPPORTED_VERSION`), shape (`MALFORMED`), domain (`WRONG_DOMAIN`), signature (`BAD_SIGNATURE`, `PRINCIPAL_MISMATCH`), `agent` equals the subject (`SUBJECT_MISMATCH`), `spendCap` is 0 (`UNSUPPORTED_SPEND_CAP`), window (`NOT_YET_VALID`, `EXPIRED`), scope (`SCOPE_DENIED`), and `credentialId` equals the credential verified in step 2 (`CREDENTIAL_MISMATCH`).
4. **Anchor** (if a mandate is given): verify `idFor(agent, 1, digest)` as in step 2, with kind `TASK_MANDATE`. `NOT_FOUND` gives `MANDATE_NOT_ANCHORED`; `REVOKED` or `UNLINKED` gives `MANDATE_REVOKED`; other failures pass through. The anchor's `ref` MUST equal the digest.

Any provider error is `PROVIDER_ERROR`. No failure path may produce `VALID`.

### 6.3 Freshness

The live status read is the truth. A relying party MUST NOT cache a `VALID` result for longer than one block before letting an agent act on it, and MUST re-verify after any `Revoked` or `Unlinked` event for the ids involved.

### 6.4 Offline mode

A snapshot is `{ spec, chainId, contract, blockNumber, paused, credentials }`, where `credentials` maps decimal ids to records with enum names. Offline results carry `source: "snapshot"` and the snapshot's block number. A snapshot is only as current as its block, and only as trustworthy as whoever produced it; it suits audits, tests and air-gapped review, not a decision to act.

### 6.5 Reason codes

`VALID`, `MALFORMED`, `NO_TRUSTED_ISSUER`, `PROVIDER_ERROR`, `WRONG_CHAIN`, `NO_CONTRACT`, `INCONSISTENT_STATE`, `NOT_FOUND`, `REVOKED`, `UNLINKED`, `UNTRUSTED_ISSUER`, `SUBJECT_MISMATCH`, `WRONG_KIND`, `PAUSED`, `INVALID_ID`, `UNSUPPORTED_VERSION`, `WRONG_DOMAIN`, `BAD_SIGNATURE`, `PRINCIPAL_MISMATCH`, `UNSUPPORTED_SPEND_CAP`, `NOT_YET_VALID`, `EXPIRED`, `SCOPE_DENIED`, `CREDENTIAL_MISMATCH`, `MANDATE_NOT_ANCHORED`, `MANDATE_REVOKED`, `KEY_REVOKED` (receipt signatures, section 5.1.1), `NOT_A_CREDENTIAL` (a status record read as a credential, sections 3.2 and 6.2).

## 7. Compatibility with agent registries and agent cards (informative)

CAS reads identity and discovery layers and does not duplicate them. This section describes the mapping to ERC-8004-style agent registries (a draft Ethereum standard: an identity registry, a registration file per agent, and optional reputation and validation registries). This mapping follows the draft text of that standard as read on 2026-10-26 and may change if the final text differs.

1. **CAS keys on the agent wallet.** The subject of record is always the wallet address. A registry identity `(registry, agentId)` is an optional alias: a verifier MAY resolve it to the identity's agent wallet at the same pinned block and then verify that wallet. The registry id is never stored as the identity of record.
2. **Registration file.** An agent that holds a CAS credential MAY list `"cas-1"` in the registration file's `supportedTrust` array and add a `cas` entry:

   ```json
   "cas": {
     "spec": "cas-1.0",
     "chainId": 84532,
     "contract": "0x<credential contract>",
     "subject": "0x<agent wallet>",
     "credentialId": "<decimal id>"
   }
   ```

3. **Agent cards.** An agent card MAY carry the same object as `extensions.cas`. A hosted verification URL MAY be added as `verifyUrl`; it is a convenience only (section 1).
4. **A transferred identity breaks the link, by design.** Registry identities can change hands; CAS credentials cannot. When a registry identity is transferred or its agent wallet changes, the alias resolves to a different wallet, which holds no credential of its own (`NOT_FOUND` or `SUBJECT_MISMATCH`). Mandates do not carry over. The new holder must obtain its own credential and its own mandate.
5. **Receipts as evidence.** With the principal's consent, a receipt (section 5.1) MAY be cited as an evidence link in a registry's feedback record. CAS publishes no feedback of its own.
6. **Fields CAS does not touch:** names, endpoints, descriptions and any transferable registry entry.

## 8. Versioning

- The spec is semver-tagged in this repository: `cas-1.0`, `cas-1.1`, and so on.
- Minor versions are additive only (a new reason, a new optional field read by new verifiers, a new class vocabulary). A verifier for `cas-1.x` MUST accept every `cas-1.y` mandate with `y <= x` and refuse other majors.
- A major version means a new credential contract, with a migration that reads both and writes only the new one.
- A conformance suite version is pinned to a spec version (see `conformance/README.md`).

## 9. Security considerations

- **Fail closed.** Missing trusted issuers, provider errors, inconsistent reads and malformed input never verify.
- **Replay across chains or contracts** is blocked by the domain (`chainId`, `verifyingContract`). Replay of the same mandate on the same contract is harmless: the anchor is one record.
- **Signature malleability** is blocked by refusing high-s signatures.
- **Snapshot trust.** Offline mode trusts the snapshot producer; prefer live reads before an agent acts.
- **Issuer compromise.** A relying party controls its own trusted-issuer set and can drop an issuer at once. Credentials an issuer wrote stay readable on-chain after that.
- **Privacy.** No personal data is on-chain. `contentHash` is keyed so it cannot be reversed by guessing.

## 10. Reference implementation

`packages/verify-ts` (`@commertize/cas-verify`, Apache-2.0) implements sections 3 to 6 with no runtime dependencies. `conformance/` holds the verifier test vectors.
