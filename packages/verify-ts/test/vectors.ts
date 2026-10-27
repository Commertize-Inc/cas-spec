// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// Builds the CAS-1 verifier conformance vectors with fresh throwaway keys.
// Used by the tests (fresh keys every run) and by generate-vectors.ts (the committed file).

import { mandateAnchorId, type Action, type Mandate } from "../src/mandate.ts";
import { typedDataDigest, type TypedData } from "../src/eip712.ts";
import { bigToBytes32, bytesToHex, concat, hexToBytes, type Hex } from "../src/hex.ts";
import { keccak256 } from "../src/keccak.ts";
import { REVOKE_REASONS, type CredentialRecord, type Snapshot, type VerifyReason } from "../src/credential.ts";
import { highS, mandateTypedData, randomHash, signTyped, throwawayKey } from "./helpers.ts";

export interface Vector {
	name: string;
	description: string;
	input: {
		chainId: number;
		contract: string;
		trustedIssuers: string[];
		subject: string;
		credentialId: string;
		mandate?: { typedData: unknown; signature: string };
		action?: Action;
		at: number;
		snapshot: Snapshot;
		/** Live-only: values the contract's isValid/paused/status reads return instead of what the snapshot state implies. */
		liveReads?: { isValid?: boolean; paused?: boolean; status?: number };
	};
	/** Modes the case runs in. Absent means both. A case with liveReads runs live only: a snapshot cannot disagree with itself. */
	modes?: ("snapshot" | "live")[];
	expect: { valid: boolean; reason: VerifyReason; step: string; revokeReason?: string };
}

const CHAIN = 84532; // a public test network id; vectors are network-agnostic
const AT = 1_800_000_000;
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** idFor(subject, kind, ref) = uint256(keccak256(word(subject) || word(kind) || ref)), for any kind (spec 3.1). */
export function idFor(agent: string, kind: number, ref: Hex): string {
	return BigInt(bytesToHex(keccak256(concat(new Uint8Array(12), hexToBytes(agent), bigToBytes32(BigInt(kind)), hexToBytes(ref))))).toString();
}
const id = idFor;

export function buildVectors(): Vector[] {
	const contract = throwawayKey().address; // any address; the snapshot names it
	const issuer = throwawayKey().address;
	const otherIssuer = throwawayKey().address;
	const agent = throwawayKey();
	const principal = throwawayKey();
	const stranger = throwawayKey();
	const counterparty = throwawayKey().address;

	const kyaRef = randomHash();
	const credentialId = id(agent.address, 0, kyaRef);
	const kya: CredentialRecord = { subject: agent.address, kind: "KYA_REGISTERED", status: "ISSUED", reason: "MANDATE_ENDED", issuedAt: AT - 86_400, issuer, ref: kyaRef, contentHash: randomHash() };

	const mandate: Mandate = {
		schema: "cas-1.0",
		principal: principal.address,
		agent: agent.address,
		credentialId,
		taskClasses: ["read", "draft"],
		assetClasses: ["real-estate"],
		counterparties: [counterparty],
		spendCap: "0",
		validAfter: AT - 3600,
		validBefore: AT + 3600,
		nonce: randomHash(),
	};
	const action: Action = { taskClass: "draft", assetClass: "real-estate", counterparty };

	const signed = (m: Mandate, key = principal, mutate?: (td: TypedData) => void) => {
		const td = mandateTypedData(CHAIN, contract, m);
		mutate?.(td);
		return { td, sig: signTyped(td, key), digest: bytesToHex(typedDataDigest(td)) };
	};
	const anchorOf = (digest: Hex, over: Partial<CredentialRecord> = {}): [string, CredentialRecord] => [
		mandateAnchorId(agent.address, digest),
		{ subject: agent.address, kind: "TASK_MANDATE", status: "ISSUED", reason: "MANDATE_ENDED", issuedAt: AT - 3000, issuer, ref: digest, contentHash: randomHash(), ...over },
	];
	const snap = (creds: Record<string, CredentialRecord>, paused = false): Snapshot => ({ spec: "cas-1.0", chainId: CHAIN, contract, blockNumber: 1234, paused, credentials: creds });

	const good = signed(mandate);
	const [goodAnchorId, goodAnchor] = anchorOf(good.digest);
	const baseSnap = snap({ [credentialId]: kya, [goodAnchorId]: goodAnchor });
	const base = { chainId: CHAIN, contract, trustedIssuers: [issuer], subject: agent.address, credentialId, at: AT, snapshot: baseSnap };
	const withMandate = (s = good, a: Action | undefined = action, snapshot = baseSnap) => ({ ...base, mandate: { typedData: s.td, signature: s.sig }, ...(a ? { action: a } : {}), snapshot });
	const V = (name: string, description: string, input: Vector["input"], expect: Vector["expect"]): Vector => ({ name, description, input: clone(input), expect });

	const out: Vector[] = [
		V("credential-valid", "issued KYA_REGISTERED credential, trusted issuer, not paused", base, { valid: true, reason: "VALID", step: "done" }),
		V("mandate-valid", "valid credential plus an anchored mandate whose scope allows the action", withMandate(), { valid: true, reason: "VALID", step: "done" }),
		V("mandate-valid-no-action", "a mandate without an action checks signature, window and anchor only", withMandate(good, undefined), { valid: true, reason: "VALID", step: "done" }),
		V("credential-invalid-id", "the record under the id was issued for another ref: the id does not derive from it", { ...base, snapshot: snap({ [credentialId]: { ...kya, ref: randomHash() } }) }, { valid: false, reason: "INVALID_ID", step: "credential" }),
		{
			...V("credential-inconsistent-state", "live only: the contract's isValid answers false for an issued credential on an unpaused contract; the reads disagree", { ...base, liveReads: { isValid: false } }, { valid: false, reason: "INCONSISTENT_STATE", step: "credential" }),
			modes: ["live"],
		},
		V("credential-not-found", "no record at the id", { ...base, snapshot: snap({}) }, { valid: false, reason: "NOT_FOUND", step: "credential" }),
		V("credential-unlinked", "the subject unlinked its credential", { ...base, snapshot: snap({ [credentialId]: { ...kya, status: "UNLINKED" } }) }, { valid: false, reason: "UNLINKED", step: "credential" }),
		V("credential-paused", "the contract is paused: nothing is valid", { ...base, snapshot: snap({ [credentialId]: kya }, true) }, { valid: false, reason: "PAUSED", step: "credential" }),
		V("credential-paused-revoked", "revocation still reads while paused", { ...base, snapshot: snap({ [credentialId]: { ...kya, status: "REVOKED", reason: "MISUSE" } }, true) }, { valid: false, reason: "REVOKED", step: "credential", revokeReason: "MISUSE" }),
		V("credential-untrusted-issuer", "issued by an address the verifier does not trust", { ...base, snapshot: snap({ [credentialId]: { ...kya, issuer: otherIssuer } }) }, { valid: false, reason: "UNTRUSTED_ISSUER", step: "credential" }),
		V("credential-no-trusted-issuers", "an empty trusted-issuer list fails closed", { ...base, trustedIssuers: [] }, { valid: false, reason: "NO_TRUSTED_ISSUER", step: "credential" }),
		V("credential-subject-mismatch", "the record belongs to another subject", { ...base, subject: stranger.address }, { valid: false, reason: "SUBJECT_MISMATCH", step: "credential" }),
		V("credential-wrong-kind", "credentialId names a TASK_MANDATE record", { ...base, credentialId: goodAnchorId }, { valid: false, reason: "WRONG_KIND", step: "credential" }),
		V("credential-wrong-chain", "snapshot taken on another chain", { ...base, snapshot: { ...baseSnap, chainId: 1 } }, { valid: false, reason: "WRONG_CHAIN", step: "credential" }),
		V("mandate-wrong-signer", "signed by a key that is not the principal", withMandate(signed(mandate, stranger)), { valid: false, reason: "PRINCIPAL_MISMATCH", step: "mandate" }),
		V("mandate-high-s", "the malleable high-s form of a valid signature is refused", { ...withMandate(), mandate: { typedData: good.td, signature: highS(good.sig) } }, { valid: false, reason: "BAD_SIGNATURE", step: "mandate" }),
		V("mandate-tampered", "message changed after signing (task class added)", { ...withMandate(), mandate: { typedData: { ...good.td, message: { ...mandate, taskClasses: ["read", "draft", "file"] } }, signature: good.sig } }, { valid: false, reason: "PRINCIPAL_MISMATCH", step: "mandate" }),
		V("mandate-wrong-domain-chain", "signed for another chain id", withMandate(signed(mandate, principal, (td) => (td.domain.chainId = 1))), { valid: false, reason: "WRONG_DOMAIN", step: "mandate" }),
		V("mandate-wrong-domain-contract", "signed for another verifying contract", withMandate(signed(mandate, principal, (td) => (td.domain.verifyingContract = otherIssuer))), { valid: false, reason: "WRONG_DOMAIN", step: "mandate" }),
		V("mandate-unsupported-type", "a Mandate type that is not the CAS-1 type", withMandate(signed(mandate, principal, (td) => {
			td.types.Mandate = td.types.Mandate!.filter((f) => f.name !== "counterparties");
			const { counterparties: _c, ...rest } = td.message;
			td.message = rest;
		})), { valid: false, reason: "UNSUPPORTED_VERSION", step: "mandate" }),
		V("mandate-unsupported-schema", "schema string of another major version", withMandate(signed({ ...mandate, schema: "cas-2.0" })), { valid: false, reason: "UNSUPPORTED_VERSION", step: "mandate" }),
		V("mandate-spend-cap", "CAS-1.0 mandates carry spendCap 0", withMandate(signed({ ...mandate, spendCap: "1" })), { valid: false, reason: "UNSUPPORTED_SPEND_CAP", step: "mandate" }),
		V("mandate-not-yet-valid", "before validAfter", { ...withMandate(), at: AT - 3601 }, { valid: false, reason: "NOT_YET_VALID", step: "mandate" }),
		V("mandate-expired-at-bound", "validBefore is exclusive", { ...withMandate(), at: AT + 3600 }, { valid: false, reason: "EXPIRED", step: "mandate" }),
		V("mandate-last-second", "one second before validBefore is inside the window", { ...withMandate(), at: AT + 3599 }, { valid: true, reason: "VALID", step: "done" }),
		V("scope-task-denied", "task class not granted", withMandate(good, { ...action, taskClass: "file" }), { valid: false, reason: "SCOPE_DENIED", step: "mandate" }),
		V("scope-asset-denied", "asset class not granted", withMandate(good, { ...action, assetClass: "compute" }), { valid: false, reason: "SCOPE_DENIED", step: "mandate" }),
		V("scope-counterparty-denied", "counterparty not on the allowlist", withMandate(good, { ...action, counterparty: stranger.address }), { valid: false, reason: "SCOPE_DENIED", step: "mandate" }),
		V("scope-amount-denied", "any amount above the cap (0) is denied", withMandate(good, { ...action, amount: "1" }), { valid: false, reason: "SCOPE_DENIED", step: "mandate" }),
		V("scope-empty-lists-grant-nothing", "a mandate with no asset classes or counterparties denies an action that names one", (() => {
			const s = signed({ ...mandate, assetClasses: [], counterparties: [] });
			const [aid, a] = anchorOf(s.digest);
			return withMandate(s, { taskClass: "draft", assetClass: "real-estate" }, snap({ [credentialId]: kya, [aid]: a }));
		})(), { valid: false, reason: "SCOPE_DENIED", step: "mandate" }),
		V("mandate-credential-mismatch", "mandate names another credential id", (() => {
			const s = signed({ ...mandate, credentialId: "1" });
			const [aid, a] = anchorOf(s.digest);
			return withMandate(s, action, snap({ [credentialId]: kya, [aid]: a }));
		})(), { valid: false, reason: "CREDENTIAL_MISMATCH", step: "mandate" }),
		V("mandate-not-anchored", "signed and in scope but no anchor credential", withMandate(good, action, snap({ [credentialId]: kya })), { valid: false, reason: "MANDATE_NOT_ANCHORED", step: "anchor" }),
		V("mandate-anchor-untrusted", "anchor issued by an untrusted issuer", withMandate(good, action, snap({ [credentialId]: kya, [goodAnchorId]: { ...goodAnchor, issuer: otherIssuer } })), { valid: false, reason: "UNTRUSTED_ISSUER", step: "anchor" }),
		V("mandate-anchor-wrong-kind", "the record at the anchor id is not a TASK_MANDATE, so the id is not idFor(subject, kind, ref)", withMandate(good, action, snap({ [credentialId]: kya, [goodAnchorId]: { ...goodAnchor, kind: "WORK_ACCEPTED" } })), { valid: false, reason: "INVALID_ID", step: "anchor" }),
		V("mandate-anchor-ref-mismatch", "the record at the anchor id carries another ref", withMandate(good, action, snap({ [credentialId]: kya, [goodAnchorId]: { ...goodAnchor, ref: randomHash() } })), { valid: false, reason: "INVALID_ID", step: "anchor" }),
		V("mandate-anchor-paused", "a paused contract stops the mandate too", withMandate(good, action, snap({ [credentialId]: kya, [goodAnchorId]: goodAnchor }, true)), { valid: false, reason: "PAUSED", step: "credential" }),
		V("mandate-anchor-revoked-while-paused", "a pause is reported as PAUSED, not as the anchor's revocation: the credential step decides first", withMandate(good, action, snap({ [credentialId]: kya, [goodAnchorId]: { ...goodAnchor, status: "REVOKED", reason: "MANDATE_ENDED" } }, true)), { valid: false, reason: "PAUSED", step: "credential" }),
		V("mandate-anchor-unlinked", "the agent unlinked the mandate anchor", withMandate(good, action, snap({ [credentialId]: kya, [goodAnchorId]: { ...goodAnchor, status: "UNLINKED" } })), { valid: false, reason: "MANDATE_REVOKED", step: "anchor" }),
		V("mandate-other-agent", "a mandate for another agent, even with an anchor at the subject's id", (() => {
			const s = signed({ ...mandate, agent: stranger.address });
			const [aid, a] = anchorOf(s.digest);
			return withMandate(s, action, snap({ [credentialId]: kya, [aid]: a }));
		})(), { valid: false, reason: "SUBJECT_MISMATCH", step: "mandate" }),
		V("action-without-mandate", "an action needs a mandate", { ...base, action }, { valid: false, reason: "MALFORMED", step: "input" }),
	];
	for (const reason of REVOKE_REASONS) {
		out.push(V(`credential-revoked-${reason.toLowerCase().replace(/_/g, "-")}`, `credential revoked with ${reason}`, { ...base, snapshot: snap({ [credentialId]: { ...kya, status: "REVOKED", reason } }) }, { valid: false, reason: "REVOKED", step: "credential", revokeReason: reason }));
		out.push(V(`mandate-revoked-${reason.toLowerCase().replace(/_/g, "-")}`, `mandate anchor revoked with ${reason}`, withMandate(good, action, snap({ [credentialId]: kya, [goodAnchorId]: { ...goodAnchor, status: "REVOKED", reason } })), { valid: false, reason: "MANDATE_REVOKED", step: "anchor", revokeReason: reason }));
	}
	return out;
}
