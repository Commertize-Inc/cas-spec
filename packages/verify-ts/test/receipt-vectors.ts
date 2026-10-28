// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// Receipt signature vectors for the secp256k1 suite (spec section 5.1.1).
//
// Signatures use RFC 6979 deterministic nonces (HMAC-SHA256), low s, v in {27, 28}: the same
// bytes any RFC 6979 signer produces for an EIP-191 personal message, so a signing
// implementation can reproduce every positive vector byte for byte.
//
// The keys come from a fixed public seed. They are THROWAWAY TEST KEYS: public by construction,
// never funded, and they must never be used for anything else.

import { createHmac } from "node:crypto";
import { bigToBytes32, bytesToBig, bytesToHex, hexToBytes, type Hex } from "../src/hex.ts";
import { G, HALF_N, mul, N, powMod } from "../src/secp256k1.ts";
import { base64urlEncode, receiptDigest, type AgentKeyCredential, type ChainPosition } from "../src/receipt.ts";
import { randomHash, throwawayKey, type Key } from "./helpers.ts";

const hmac = (key: Uint8Array, ...parts: Uint8Array[]): Uint8Array => {
	const h = createHmac("sha256", key);
	for (const p of parts) h.update(p);
	return new Uint8Array(h.digest());
};

/** RFC 6979 section 3.2 with HMAC-SHA256 over a 32-byte digest; low s (EIP-2); v in {27, 28}. */
export function signRfc6979(digest: Uint8Array, priv: bigint): Uint8Array {
	const x = bigToBytes32(priv);
	const h1 = bigToBytes32(bytesToBig(digest) % N); // bits2octets
	let V: Uint8Array = new Uint8Array(32).fill(1);
	let K: Uint8Array = new Uint8Array(32).fill(0);
	K = hmac(K, V, Uint8Array.of(0), x, h1);
	V = hmac(K, V);
	K = hmac(K, V, Uint8Array.of(1), x, h1);
	V = hmac(K, V);
	const e = bytesToBig(digest) % N;
	for (;;) {
		V = hmac(K, V);
		const k = bytesToBig(V);
		if (k >= 1n && k < N) {
			const R = mul(G, k)!;
			const r = R.x % N;
			let s = (powMod(k, N - 2n, N) * ((e + r * priv) % N)) % N;
			if (r !== 0n && s !== 0n && R.x < N) {
				let v = Number(R.y & 1n);
				if (s > HALF_N) {
					s = N - s;
					v ^= 1;
				}
				const sig = new Uint8Array(65);
				sig.set(bigToBytes32(r), 0);
				sig.set(bigToBytes32(s), 32);
				sig[64] = 27 + v;
				return sig;
			}
		}
		K = hmac(K, V, Uint8Array.of(0));
		V = hmac(K, V);
	}
}

export interface ReceiptVector {
	name: string;
	/**
	 * Valid cases: which throwaway test key signed (0-5), the n-th key derived from the public seed
	 * (conformance/README.md). The file carries no private key.
	 */
	keyIndex?: number;
	hash: string;
	/** null when the hash is malformed: no digest is defined for it. */
	digest: Hex | null;
	signature: { alg: string; key_id: string; sig: string };
	sigHex: Hex | null;
	/** The agent's KYA_REGISTERED credentials as the verifier read them (spec 5.1.1 step 5). */
	agentKeys: AgentKeyCredential[];
	/** Position of the receipt's anchor log on the credential contract's chain; null when not anchored there. */
	anchor: ChainPosition | null;
	/** The credential contract's paused() as the verifier read it. */
	paused: boolean;
	expected: { valid: boolean; reason: string; signer?: string };
}

const lower = (a: string) => a.toLowerCase();

/** Fixed positions (block number, log index) on the credential contract's chain for the key-state cases. */
const P_ISSUE: ChainPosition = { block: 1000, logIndex: 0 };
const P_ROTATE: ChainPosition = { block: 2000, logIndex: 0 }; // old key revoked
const P_NEW_ISSUE: ChainPosition = { block: 2000, logIndex: 1 }; // new key issued in the same block, next log
const BEFORE_ROTATION: ChainPosition = { block: 1500, logIndex: 3 };
const AFTER_ROTATION: ChainPosition = { block: 2500, logIndex: 0 };

function positive(name: string, key: Key, keyIndex: number, hash: string): ReceiptVector {
	const digest = receiptDigest(hash);
	const sig = signRfc6979(digest, key.priv);
	return {
		name,
		keyIndex,
		hash,
		digest: bytesToHex(digest),
		signature: { alg: "secp256k1", key_id: lower(key.address), sig: base64urlEncode(sig) },
		sigHex: bytesToHex(sig),
		agentKeys: [{ address: key.address, status: "ISSUED", issued: P_ISSUE, ended: null }],
		anchor: null,
		paused: false,
		expected: { valid: true, reason: "VALID", signer: lower(key.address) },
	};
}

/** Derives a variant of a positive vector: new signature bytes or fields, and the expected result. */
function variant(base: ReceiptVector, name: string, change: Partial<ReceiptVector> & { sigBytes?: Uint8Array }, expected: ReceiptVector["expected"]): ReceiptVector {
	const { sigBytes, ...rest } = change;
	const v: ReceiptVector = { ...base, ...rest, name, expected };
	if (sigBytes) {
		v.signature = { ...v.signature, sig: base64urlEncode(sigBytes) };
		v.sigHex = bytesToHex(sigBytes);
	}
	if (change.signature && change.signature.sig !== base.signature.sig) v.sigHex = null; // not a decodable canonical string
	return v;
}

export function buildReceiptVectors(): ReceiptVector[] {
	const keys = Array.from({ length: 6 }, () => throwawayKey());
	const hashes = keys.map(() => "sha256:" + randomHash().slice(2));
	const out: ReceiptVector[] = keys.map((k, i) => positive(`valid-${i + 1}`, k, i, hashes[i]!));
	out.push(positive("valid-zero-hash", keys[0]!, 0, "sha256:" + "0".repeat(64)));
	out.push(positive("valid-same-key-second-receipt", keys[0]!, 0, hashes[1]!));

	const base = out[0]!;
	const sig = hexToBytes(base.sigHex!);
	const s = bytesToBig(sig.slice(32, 64));
	const highS = new Uint8Array(sig);
	highS.set(bigToBytes32(N - s), 32);
	highS[64] = sig[64] === 27 ? 28 : 27;
	const v29 = new Uint8Array(sig);
	v29[64] = 29;
	const v01 = new Uint8Array(sig);
	v01[64] = sig[64]! - 27;
	const short = sig.slice(0, 64);
	const other = keys[1]!;
	// 65 bytes = 520 bits = 86 full characters + 4 bits, so the last character carries 2 unused low bits.
	// Setting the lowest one keeps the decoded bytes and makes the string non-canonical.
	const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const enc = base.signature.sig;
	if (enc.length !== 87) throw new Error("a 65-byte signature encodes to 87 characters");
	const nonCanonical = enc.slice(0, -1) + ALPHABET[ALPHABET.indexOf(enc.at(-1)!) ^ 1]!;
	if (keys[0]!.address === lower(keys[0]!.address)) throw new Error("seed gave an all-lowercase checksum address; pick another seed");

	out.push(
		variant(base, "invalid-high-s", { sigBytes: highS }, { valid: false, reason: "BAD_SIGNATURE" }),
		variant(base, "invalid-v-29", { sigBytes: v29 }, { valid: false, reason: "BAD_SIGNATURE" }),
		variant(base, "invalid-v-0-or-1-form", { sigBytes: v01 }, { valid: false, reason: "BAD_SIGNATURE" }),
		variant(base, "invalid-stale-hash", { hash: hashes[2]!, digest: bytesToHex(receiptDigest(hashes[2]!)) }, { valid: false, reason: "BAD_SIGNATURE" }),
		variant(base, "invalid-key-id-other-address", { signature: { ...base.signature, key_id: lower(other.address) } }, { valid: false, reason: "BAD_SIGNATURE" }),
		variant(base, "invalid-agent-not-the-signer", { agentKeys: [{ address: other.address, status: "ISSUED", issued: P_ISSUE, ended: null }] }, { valid: false, reason: "SUBJECT_MISMATCH", signer: lower(base.signature.key_id) }),
		variant(base, "malformed-short-signature", { sigBytes: short }, { valid: false, reason: "MALFORMED" }),
		variant(base, "malformed-non-canonical-base64url", { signature: { ...base.signature, sig: nonCanonical } }, { valid: false, reason: "MALFORMED" }),
		variant(base, "malformed-key-id-checksum-case", { signature: { ...base.signature, key_id: keys[0]!.address } }, { valid: false, reason: "MALFORMED" }),
		variant(base, "malformed-hash-uppercase", { hash: base.hash.toUpperCase().replace("SHA256:", "sha256:"), digest: null }, { valid: false, reason: "MALFORMED" }),
		variant(base, "malformed-wrong-alg", { signature: { ...base.signature, alg: "ed25519" } }, { valid: false, reason: "MALFORMED" })
	);

	// Key rotation: the agent moved from key 0 (old) to key 1 (new). Rotating revokes the old key's
	// credential and issues one for the new key (positions on the credential chain, never occurred_at).
	const oldKey = keys[0]!;
	const newKey = keys[1]!;
	const rotated: AgentKeyCredential[] = [
		{ address: oldKey.address, status: "REVOKED", issued: P_ISSUE, ended: P_ROTATE },
		{ address: newKey.address, status: "ISSUED", issued: P_NEW_ISSUE, ended: null },
	];
	const signedByNew = out[1]!; // valid-2, signed with key 1
	const keep = (v: ReceiptVector) => ({ keyIndex: v.keyIndex });
	out.push(
		variant(base, "rotated-old-key-anchored-before-revocation", { ...keep(base), agentKeys: rotated, anchor: BEFORE_ROTATION }, { valid: true, reason: "VALID", signer: lower(oldKey.address) }),
		variant(base, "rotated-old-key-anchored-at-revocation-time", { agentKeys: rotated, anchor: P_ROTATE }, { valid: false, reason: "KEY_REVOKED", signer: lower(oldKey.address) }),
		variant(base, "rotated-old-key-anchored-after-revocation", { agentKeys: rotated, anchor: AFTER_ROTATION }, { valid: false, reason: "KEY_REVOKED", signer: lower(oldKey.address) }),
		variant(base, "rotated-old-key-not-anchored", { agentKeys: rotated, anchor: null }, { valid: false, reason: "KEY_REVOKED", signer: lower(oldKey.address) }),
		variant(signedByNew, "rotated-new-key", { ...keep(signedByNew), agentKeys: rotated, anchor: AFTER_ROTATION }, { valid: true, reason: "VALID", signer: lower(newKey.address) }),
		variant(signedByNew, "rotated-new-key-anchored-before-its-credential", { agentKeys: rotated, anchor: BEFORE_ROTATION }, { valid: false, reason: "SUBJECT_MISMATCH", signer: lower(newKey.address) }),
		// Revocation without rotation (for example KYA_LAPSED), and a holder who unlinked.
		variant(base, "revoked-key-not-anchored", { agentKeys: [{ address: oldKey.address, status: "REVOKED", issued: P_ISSUE, ended: P_ROTATE }], anchor: null }, { valid: false, reason: "KEY_REVOKED", signer: lower(oldKey.address) }),
		// Anchored before the credential was issued: not yet the agent's key, whatever its status now.
		variant(base, "revoked-key-anchored-before-issue", { agentKeys: [{ address: oldKey.address, status: "REVOKED", issued: P_ISSUE, ended: P_ROTATE }], anchor: { block: 500, logIndex: 0 } }, { valid: false, reason: "SUBJECT_MISMATCH", signer: lower(oldKey.address) }),
		variant(base, "unlinked-key-anchored-before-issue", { agentKeys: [{ address: oldKey.address, status: "UNLINKED", issued: P_ISSUE, ended: P_ROTATE }], anchor: { block: 500, logIndex: 0 } }, { valid: false, reason: "SUBJECT_MISMATCH", signer: lower(oldKey.address) }),
		// Same block: the log index decides.
		variant(base, "revoked-key-anchor-log-before-revoke-log-same-block", { ...keep(base), agentKeys: [{ address: oldKey.address, status: "REVOKED", issued: P_ISSUE, ended: { block: 2000, logIndex: 5 } }], anchor: { block: 2000, logIndex: 4 } }, { valid: true, reason: "VALID", signer: lower(oldKey.address) }),
		variant(base, "revoked-key-anchor-log-after-revoke-log-same-block", { agentKeys: [{ address: oldKey.address, status: "REVOKED", issued: P_ISSUE, ended: { block: 2000, logIndex: 5 } }], anchor: { block: 2000, logIndex: 6 } }, { valid: false, reason: "KEY_REVOKED", signer: lower(oldKey.address) }),
		// Unlinked first (block 1800), revoked later (block 2000): ended is the EARLIEST end event, so an anchor at 1900 is too late.
		variant(base, "unlinked-then-revoked-earliest-end-counts", { agentKeys: [{ address: oldKey.address, status: "REVOKED", issued: P_ISSUE, ended: { block: 1800, logIndex: 0 } }], anchor: { block: 1900, logIndex: 0 } }, { valid: false, reason: "KEY_REVOKED", signer: lower(oldKey.address) }),
		// Two credentials for one address: revoked at 2000, issued again at 3000. VALID if any credential is in force at the anchor.
		...[
			["two-credentials-anchor-under-first", { block: 1500, logIndex: 0 }, { valid: true, reason: "VALID" }],
			["two-credentials-anchor-in-the-gap", { block: 2500, logIndex: 0 }, { valid: false, reason: "KEY_REVOKED" }],
			["two-credentials-anchor-under-second", { block: 3500, logIndex: 0 }, { valid: true, reason: "VALID" }],
			// No anchor and one credential ended: the receipt may have been signed while revoked; the later credential does not launder it.
			["two-credentials-not-anchored", null, { valid: false, reason: "KEY_REVOKED" }],
			["two-credentials-anchored-at-reissue", { block: 3000, logIndex: 0 }, { valid: true, reason: "VALID" }],
		].map(([name, anchor, exp]) =>
			variant(
				base,
				name as string,
				{
					...((exp as { valid: boolean }).valid ? keep(base) : {}),
					agentKeys: [
						{ address: oldKey.address, status: "REVOKED", issued: P_ISSUE, ended: P_ROTATE },
						{ address: oldKey.address, status: "ISSUED", issued: { block: 3000, logIndex: 0 }, ended: null },
					],
					anchor: anchor as ChainPosition | null,
				},
				{ ...(exp as { valid: boolean; reason: string }), signer: lower(oldKey.address) }
			)
		),
		// Paused contract: never VALID; a revoked key is still reported as revoked.
		variant(base, "paused-key-in-force", { paused: true }, { valid: false, reason: "PAUSED", signer: lower(oldKey.address) }),
		variant(base, "paused-revoked-key-not-anchored", { paused: true, agentKeys: [{ address: oldKey.address, status: "REVOKED", issued: P_ISSUE, ended: P_ROTATE }], anchor: null }, { valid: false, reason: "KEY_REVOKED", signer: lower(oldKey.address) }),
		variant(base, "unlinked-key-anchored-after-unlink", { agentKeys: [{ address: oldKey.address, status: "UNLINKED", issued: P_ISSUE, ended: P_ROTATE }], anchor: AFTER_ROTATION }, { valid: false, reason: "KEY_REVOKED", signer: lower(oldKey.address) })
	);
	for (const v of out) if (!v.expected.valid) delete v.keyIndex;
	return out;
}
