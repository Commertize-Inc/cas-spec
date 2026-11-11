// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.
// Receipt signatures with the secp256k1 suite (spec section 5.1.1): the reference check. The vector file and its tests come with the generator.
import { test } from "node:test";
import assert from "node:assert/strict";
import { bigToBytes32, concat, hexToBytes, utf8 } from "../src/hex.ts";
import { base64urlEncode, receiptDigest, receiptMessage, RECEIPT_SIGNING_PREFIX, verifyReceiptSecp256k1, type AgentKeyCredential } from "../src/receipt.ts";
import { randomHash, signDigest, throwawayKey } from "./helpers.ts";
import { keccak256 } from "../src/keccak.ts";


test("receipt signatures with fresh random keys and nonces on every run", () => {
	for (let i = 0; i < 8; i++) {
		const k = throwawayKey();
		const hash = "sha256:" + randomHash().slice(2);
		const sig = hexToBytes(signDigest(receiptDigest(hash), k));
		const s = { alg: "secp256k1", key_id: k.address.toLowerCase(), sig: base64urlEncode(sig) };
		assert.deepEqual(verifyReceiptSecp256k1(hash, s, issued(k.address), null, false), { valid: true, reason: "VALID", signer: k.address.toLowerCase() });
		const other = "sha256:" + randomHash().slice(2);
		assert.equal(verifyReceiptSecp256k1(other, s, issued(k.address), null, false).reason, "BAD_SIGNATURE", "a signature over another hash fails");
	}
});

test("receiptMessage: only sha256 + 64 lowercase hex; the message is the prefix and the hash, 80 bytes", () => {
	const h = "sha256:" + "ab".repeat(32);
	assert.equal(new TextDecoder().decode(receiptMessage(h)), "CAS-v0.1\n" + h);
	for (const bad of ["sha256:" + "AB".repeat(32), "sha256:" + "ab".repeat(31), "sha512:" + "ab".repeat(32), "ab".repeat(32), ""]) assert.throws(() => receiptMessage(bad), bad);
});

test("base64urlEncode matches the platform encoder; decoding is strict", () => {
	for (let n = 0; n < 70; n++) {
		const b = new Uint8Array(n).map((_, i) => (i * 37 + n) & 0xff);
		assert.equal(base64urlEncode(b), Buffer.from(b).toString("base64url"), String(n));
	}
	const k = throwawayKey();
	const hash = "sha256:" + randomHash().slice(2);
	const sig = base64urlEncode(hexToBytes(signDigest(receiptDigest(hash), k)));
	for (const bad of [sig + "=", sig.replace(/^./, "+"), sig.slice(0, -1), sig + "A"])
		assert.equal(verifyReceiptSecp256k1(hash, { alg: "secp256k1", key_id: k.address.toLowerCase(), sig: bad }, issued(k.address), null, false).reason, "MALFORMED", bad);
	assert.equal(bigToBytes32(1n).length, 32);
});

const issued = (address: string): AgentKeyCredential[] => [{ address, status: "ISSUED", issued: { block: 0, logIndex: 0 }, ended: null }];

test("key state (step 5): a revoked or unlinked key's receipt is VALID only when anchored on chain strictly before the credential ended", () => {
	const k = throwawayKey();
	const hash = "sha256:" + randomHash().slice(2);
	const s = { alg: "secp256k1", key_id: k.address.toLowerCase(), sig: base64urlEncode(hexToBytes(signDigest(receiptDigest(hash), k))) };
	const ended = (status: "REVOKED" | "UNLINKED"): AgentKeyCredential[] => [{ address: k.address, status, issued: at(100), ended: at(200) }];
	for (const st of ["REVOKED", "UNLINKED"] as const) {
		assert.equal(verifyReceiptSecp256k1(hash, s, ended(st), at(199), false).reason, "VALID", st);
		assert.equal(verifyReceiptSecp256k1(hash, s, ended(st), at(200), false).reason, "KEY_REVOKED", `${st} at the end time`);
		assert.equal(verifyReceiptSecp256k1(hash, s, ended(st), at(201), false).reason, "KEY_REVOKED", st);
		assert.equal(verifyReceiptSecp256k1(hash, s, ended(st), null, false).reason, "KEY_REVOKED", `${st} unanchored`);
		assert.equal(verifyReceiptSecp256k1(hash, s, ended(st), at(99), false).reason, "SUBJECT_MISMATCH", `${st} anchored before issue`);
	}
	assert.equal(verifyReceiptSecp256k1(hash, s, [{ address: k.address, status: "ISSUED", issued: at(100), ended: null }], at(99), false).reason, "SUBJECT_MISMATCH");
	assert.equal(verifyReceiptSecp256k1(hash, s, [{ address: k.address, status: "ISSUED", issued: at(100), ended: null }], null, false).reason, "VALID");
	assert.equal(verifyReceiptSecp256k1(hash, s, [], null, false).reason, "SUBJECT_MISMATCH");
});

const at = (block: number, logIndex = 0) => ({ block, logIndex });

test("key state: positions order by block then log index; earliest end counts; any credential in force wins; paused never VALID", () => {
	const k = throwawayKey();
	const hash = "sha256:" + randomHash().slice(2);
	const s = { alg: "secp256k1", key_id: k.address.toLowerCase(), sig: base64urlEncode(hexToBytes(signDigest(receiptDigest(hash), k))) };
	const revoked: AgentKeyCredential[] = [{ address: k.address, status: "REVOKED", issued: at(10), ended: at(20, 5) }];
	assert.equal(verifyReceiptSecp256k1(hash, s, revoked, at(20, 4), false).reason, "VALID", "same block, earlier log");
	assert.equal(verifyReceiptSecp256k1(hash, s, revoked, at(20, 5), false).reason, "KEY_REVOKED", "same log position");
	assert.equal(verifyReceiptSecp256k1(hash, s, revoked, at(20, 6), false).reason, "KEY_REVOKED");
	assert.equal(verifyReceiptSecp256k1(hash, s, [{ address: k.address, status: "ISSUED", issued: at(10, 3), ended: null }], at(10, 2), false).reason, "SUBJECT_MISMATCH");
	const two: AgentKeyCredential[] = [revoked[0]!, { address: k.address, status: "ISSUED", issued: at(30), ended: null }];
	assert.equal(verifyReceiptSecp256k1(hash, s, two, at(15), false).reason, "VALID");
	assert.equal(verifyReceiptSecp256k1(hash, s, two, at(25), false).reason, "KEY_REVOKED", "in the gap: one revoked, one not yet issued");
	assert.equal(verifyReceiptSecp256k1(hash, s, two, at(35), false).reason, "VALID");
	assert.equal(verifyReceiptSecp256k1(hash, s, two, at(5), false).reason, "SUBJECT_MISMATCH", "before both");
	// No laundering: unanchored with any ended credential is KEY_REVOKED, even if a later credential is in force.
	assert.equal(verifyReceiptSecp256k1(hash, s, two, null, false).reason, "KEY_REVOKED");
	assert.equal(verifyReceiptSecp256k1(hash, s, two, at(30), false).reason, "VALID", "anchored exactly at the re-issue position");
	assert.equal(verifyReceiptSecp256k1(hash, s, two, at(29, 9), false).reason, "KEY_REVOKED", "one log before the re-issue");
	assert.equal(verifyReceiptSecp256k1(hash, s, issued(k.address), null, true).reason, "PAUSED");
	assert.equal(verifyReceiptSecp256k1(hash, s, revoked, null, true).reason, "KEY_REVOKED", "revocation is reported while paused");
	assert.equal(verifyReceiptSecp256k1(hash, s, [], null, true).reason, "SUBJECT_MISMATCH");
});

// Encoding rules pinned without the vector file (the generator PR adds the conformance vectors).
test("encoding: the digest is EIP-191 over the 80-byte message, built independently here", () => {
	const hash = "sha256:" + "0".repeat(64);
	const m = utf8(RECEIPT_SIGNING_PREFIX + hash);
	assert.equal(m.length, 80);
	const expected = keccak256(concat(utf8("\x19Ethereum Signed Message:\n80"), m));
	assert.deepEqual(receiptDigest(hash), expected);
});

test("encoding: alg, lowercase key_id, v 27/28 only and canonical base64url are enforced", () => {
	const k = throwawayKey();
	const hash = "sha256:" + randomHash().slice(2);
	const raw = hexToBytes(signDigest(receiptDigest(hash), k));
	const keys = [{ address: k.address, status: "ISSUED" as const, issued: { block: 0, logIndex: 0 }, ended: null }];
	const good = { alg: "secp256k1", key_id: k.address.toLowerCase(), sig: base64urlEncode(raw) };
	assert.equal(verifyReceiptSecp256k1(hash, good, keys, null, false).reason, "VALID");
	assert.equal(verifyReceiptSecp256k1(hash, { ...good, alg: "ed25519" }, keys, null, false).reason, "MALFORMED");
	const upper = "0x" + k.address.slice(2).toUpperCase();
	assert.equal(verifyReceiptSecp256k1(hash, { ...good, key_id: upper }, keys, null, false).reason, "MALFORMED");
	const v0 = new Uint8Array(raw);
	v0[64] = raw[64]! - 27;
	assert.equal(verifyReceiptSecp256k1(hash, { ...good, sig: base64urlEncode(v0) }, keys, null, false).reason, "BAD_SIGNATURE", "v as 0/1 is refused");
	const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const nonCanonical = good.sig.slice(0, -1) + ALPHABET[ALPHABET.indexOf(good.sig.at(-1)!) ^ 1]!;
	assert.equal(verifyReceiptSecp256k1(hash, { ...good, sig: nonCanonical }, keys, null, false).reason, "MALFORMED");
});
