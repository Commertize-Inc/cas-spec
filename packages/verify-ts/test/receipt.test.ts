// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.
// Receipt signatures with the secp256k1 suite (spec section 5.1.1).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { bigToBytes32, bytesToHex, hexToBytes } from "../src/hex.ts";
import { addressOf, G, mul } from "../src/secp256k1.ts";
import { base64urlEncode, receiptDigest, receiptMessage, RECEIPT_SIGNING_PREFIX, verifyReceiptSecp256k1, type AgentKeyCredential } from "../src/receipt.ts";
import { randomHash, signDigest, throwawayKey, withSeed } from "./helpers.ts";
import { signRfc6979, type ReceiptVector } from "./receipt-vectors.ts";
import { RECEIPT_VECTOR_FILE, RECEIPT_VECTOR_SEED, renderReceiptVectorFile } from "./vector-file.ts";

const file = JSON.parse(readFileSync(RECEIPT_VECTOR_FILE, "utf8")) as { suite: string; note: string; vectors: ReceiptVector[] };

test("receipt vectors: the committed file is a byte-identical regeneration from the public seed", () => {
	assert.equal(readFileSync(RECEIPT_VECTOR_FILE, "utf8"), renderReceiptVectorFile());
	assert.equal(file.suite, "cas-1.0-receipt-secp256k1");
	assert.match(file.note, /throwaway test keys/);
});

test("receipt vectors: every case gives its expected result", () => {
	for (const v of file.vectors) {
		const r = verifyReceiptSecp256k1(v.hash, v.signature, v.agentKeys, v.anchor, v.paused);
		assert.equal(r.valid, v.expected.valid, v.name);
		assert.equal(r.reason, v.expected.reason, v.name);
		if (v.expected.signer) assert.equal(r.signer, v.expected.signer, v.name);
	}
});

test("receipt vectors: at least six valid vectors from distinct throwaway keys; each reproduces byte for byte (RFC 6979)", () => {
	const valid = file.vectors.filter((v) => v.expected.valid);
	assert.ok(valid.length >= 6);
	assert.ok(new Set(valid.map((v) => v.keyIndex)).size >= 6);
	// The keys are re-derived from the public seed: the n-th throwaway key of the seeded stream. The file holds none.
	const keys = withSeed(RECEIPT_VECTOR_SEED, () => Array.from({ length: 6 }, () => throwawayKey()));
	for (const v of valid) {
		const priv = keys[v.keyIndex!]!.priv;
		assert.equal(addressOf(mul(G, priv)), v.signature.key_id, v.name);
		const message = new TextDecoder().decode(receiptMessage(v.hash));
		assert.equal(message, RECEIPT_SIGNING_PREFIX + v.hash);
		assert.equal(new TextEncoder().encode(message).length, 80);
		assert.equal(bytesToHex(receiptDigest(v.hash)), v.digest);
		const sig = signRfc6979(receiptDigest(v.hash), priv);
		assert.equal(bytesToHex(sig), v.sigHex, v.name);
		assert.equal(base64urlEncode(sig), v.signature.sig, v.name);
		assert.equal(v.signature.sig.length, 87);
	}
	assert.ok(file.vectors.every((v) => !("throwawayTestPrivateKey" in v) && !/"priv/i.test(JSON.stringify(v))), "the file carries no private key");
	assert.ok(file.vectors.filter((v) => !v.expected.valid).every((v) => v.keyIndex === undefined));
});

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
	const sig = base64urlEncode(signRfc6979(receiptDigest(hash), k.priv));
	for (const bad of [sig + "=", sig.replace(/^./, "+"), sig.slice(0, -1), sig + "A"])
		assert.equal(verifyReceiptSecp256k1(hash, { alg: "secp256k1", key_id: k.address.toLowerCase(), sig: bad }, issued(k.address), null, false).reason, "MALFORMED", bad);
	assert.equal(bigToBytes32(1n).length, 32);
});

const issued = (address: string): AgentKeyCredential[] => [{ address, status: "ISSUED", issued: { block: 0, logIndex: 0 }, ended: null }];

test("key state (step 5): a revoked or unlinked key's receipt is VALID only when anchored on chain strictly before the credential ended", () => {
	const k = throwawayKey();
	const hash = "sha256:" + randomHash().slice(2);
	const s = { alg: "secp256k1", key_id: k.address.toLowerCase(), sig: base64urlEncode(signRfc6979(receiptDigest(hash), k.priv)) };
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

test("receipt vectors: rotation and revocation cases are present", () => {
	const names = new Set(file.vectors.map((v) => v.name));
	for (const n of ["rotated-old-key-anchored-before-revocation", "rotated-old-key-anchored-after-revocation", "rotated-old-key-not-anchored", "rotated-new-key", "revoked-key-not-anchored", "unlinked-key-anchored-after-unlink"])
		assert.ok(names.has(n), n);
	assert.ok(file.vectors.some((v) => v.expected.reason === "KEY_REVOKED"));
});

const at = (block: number, logIndex = 0) => ({ block, logIndex });

test("key state: positions order by block then log index; earliest end counts; any credential in force wins; paused never VALID", () => {
	const k = throwawayKey();
	const hash = "sha256:" + randomHash().slice(2);
	const s = { alg: "secp256k1", key_id: k.address.toLowerCase(), sig: base64urlEncode(signRfc6979(receiptDigest(hash), k.priv)) };
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
