// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

/**
 * Receipt signatures with the secp256k1 suite (spec section 5.1.1).
 *
 *   message  m = UTF-8 bytes of "CAS-v0.1\n" followed by the receipt `hash`
 *              ("sha256:" + 64 lowercase hex), 80 bytes
 *   digest   d = keccak256(0x19 || "Ethereum Signed Message:\n80" || m)   (EIP-191, version 0x45)
 *   sig      base64url (unpadded, canonical) of the 65 bytes r || s || v, v in {27, 28}
 *   key_id   the signer's address, "0x" + 40 lowercase hex
 *
 * The caller passes a hash it recomputed itself (C-1): a valid signature over a
 * stale hash is a failure, and this function cannot see the record.
 */

import { keccak256 } from "./keccak.ts";
import { concat, sameAddress, utf8, type Hex } from "./hex.ts";
import { recoverAddress } from "./secp256k1.ts";

export const RECEIPT_SIGNING_PREFIX = "CAS-v0.1\n";
const HASH = /^sha256:[0-9a-f]{64}$/;
const KEY_ID = /^0x[0-9a-f]{40}$/;
const B64U = /^[A-Za-z0-9_-]+$/;

export type ReceiptSignatureReason = "VALID" | "MALFORMED" | "BAD_SIGNATURE" | "SUBJECT_MISMATCH" | "KEY_REVOKED" | "PAUSED";

export interface ReceiptSignature {
	alg: string;
	key_id: string;
	sig: string;
}

/** The 80 signed bytes for a receipt hash. Throws on a hash that is not "sha256:" + 64 lowercase hex. */
export function receiptMessage(hash: string): Uint8Array {
	if (!HASH.test(hash)) throw new Error('hash must be "sha256:" + 64 lowercase hex');
	return utf8(RECEIPT_SIGNING_PREFIX + hash);
}

/** The EIP-191 (personal message) digest the secp256k1 signature covers. */
export function receiptDigest(hash: string): Uint8Array {
	const m = receiptMessage(hash);
	return keccak256(concat(utf8(`\x19Ethereum Signed Message:\n${m.length}`), m));
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** base64url without padding (RFC 4648 section 5). */
export function base64urlEncode(b: Uint8Array): string {
	let out = "";
	for (let i = 0; i < b.length; i += 3) {
		const n = (b[i]! << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
		const chars = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63].map((c) => ALPHABET[c]!);
		out += chars.slice(0, i + 2 < b.length ? 4 : i + 1 < b.length ? 3 : 2).join("");
	}
	return out;
}

/** Strict base64url: unpadded and canonical (re-encoding gives the same string), as C-2 requires. */
function decodeSig(s: string): Uint8Array | null {
	if (!B64U.test(s) || s.length % 4 === 1) return null;
	const out: number[] = [];
	let acc = 0;
	let bits = 0;
	for (const ch of s) {
		acc = (acc << 6) | ALPHABET.indexOf(ch);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push((acc >> bits) & 0xff);
		}
		acc &= (1 << bits) - 1;
	}
	const b = new Uint8Array(out);
	return base64urlEncode(b) === s ? b : null; // leftover non-zero bits make the string non-canonical
}

/**
 * A position on the credential contract's own chain: block number, then log index within the block.
 * Every ordering in step 5 uses positions, never timestamps.
 */
export interface ChainPosition {
	block: number;
	logIndex: number;
}

/** True when a is strictly earlier than b (block number first, then log index). */
export const before = (a: ChainPosition, b: ChainPosition): boolean => a.block < b.block || (a.block === b.block && a.logIndex < b.logIndex);

/**
 * One KYA_REGISTERED credential of the agent, as the verifier read it from the credential contract (or
 * an offline snapshot): never from the receipt. An agent that rotates its key has one entry per subject
 * address; an address may also appear in more than one credential (section 5.1.1, "Several credentials").
 */
export interface AgentKeyCredential {
	/** The credential's subject: the signing address. */
	address: string;
	status: "ISSUED" | "REVOKED" | "UNLINKED";
	/** Position of the credential's Issued event. */
	issued: ChainPosition;
	/** Position of its EARLIEST end event (Unlinked or Revoked, whichever came first); null while ISSUED. */
	ended: ChainPosition | null;
}

/**
 * Checks one secp256k1 receipt signature (spec section 5.1.1).
 *
 * `anchor` is the position of the receipt's anchor log on the credential contract's own chain, as the
 * verifier read it: a `CasAnchor(bytes32 indexed headHash)` log, emitted by an anchoring contract the
 * verifier names as trusted, in the receipt's `anchor.tx`, whose headHash is the receipt's `anchor.head_hash`
 * (section 5.1.1). null when the receipt is not anchored, the anchor is not confirmed, or no such log exists
 * on that chain. The receipt's own `occurred_at` is never used.
 *
 * `paused` is the credential contract's paused() as the verifier read it. It is required: a caller that
 * does not pass it cannot get VALID by omission.
 */
export function verifyReceiptSecp256k1(
	hash: string,
	signature: ReceiptSignature,
	agentKeys: readonly AgentKeyCredential[],
	anchor: ChainPosition | null,
	paused: boolean
): { valid: boolean; reason: ReceiptSignatureReason; signer?: Hex } {
	if (signature?.alg !== "secp256k1" || typeof signature.key_id !== "string" || !KEY_ID.test(signature.key_id) || typeof signature.sig !== "string")
		return { valid: false, reason: "MALFORMED" };
	let digest: Uint8Array;
	try {
		digest = receiptDigest(hash);
	} catch {
		return { valid: false, reason: "MALFORMED" };
	}
	const bytes = decodeSig(signature.sig);
	if (!bytes || bytes.length !== 65) return { valid: false, reason: "MALFORMED" };
	if (bytes[64] !== 27 && bytes[64] !== 28) return { valid: false, reason: "BAD_SIGNATURE" };
	let signer: Hex;
	try {
		signer = recoverAddress(digest, bytes);
	} catch {
		return { valid: false, reason: "BAD_SIGNATURE" };
	}
	if (!sameAddress(signer, signature.key_id)) return { valid: false, reason: "BAD_SIGNATURE", signer };
	// Step 5: every KYA_REGISTERED credential whose subject is the signer.
	const creds = agentKeys.filter((k) => sameAddress(k.address, signer));
	let reason: ReceiptSignatureReason;
	if (creds.length === 0) reason = "SUBJECT_MISMATCH";
	else if (anchor === null)
		// Unanchored: nothing places the signature in time, so any ended credential for this key means it may
		// have been signed while the key was revoked. A later credential never launders such a receipt.
		reason = creds.some((k) => k.status !== "ISSUED") ? "KEY_REVOKED" : "VALID";
	else {
		// Anchored: VALID under a credential only when the anchor is at or after its issue and before its end.
		const results = creds.map((k) => keyResult(k, anchor));
		reason = results.includes("VALID") ? "VALID" : results.includes("KEY_REVOKED") ? "KEY_REVOKED" : "SUBJECT_MISMATCH";
	}
	// A paused contract never gives VALID; a revoked key is still reported as revoked while paused (as in section 6).
	if (reason === "VALID" && paused) return { valid: false, reason: "PAUSED", signer };
	return { valid: reason === "VALID", reason, signer };
}

/** One credential at an anchor position: before its issue, the key was not yet the agent's, whatever its status now. */
function keyResult(k: AgentKeyCredential, anchor: ChainPosition): "VALID" | "KEY_REVOKED" | "SUBJECT_MISMATCH" {
	if (before(anchor, k.issued)) return "SUBJECT_MISMATCH";
	if (k.status === "ISSUED") return "VALID";
	// Revoked or unlinked: valid only for a receipt anchored strictly before the earliest end event.
	return k.ended !== null && before(anchor, k.ended) ? "VALID" : "KEY_REVOKED";
}
