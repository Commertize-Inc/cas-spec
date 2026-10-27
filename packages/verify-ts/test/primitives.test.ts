// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// Pins the hand-written primitives to values published elsewhere, and to node:crypto.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createECDH, createPublicKey, createHash, verify as nodeVerify } from "node:crypto";
import { keccak256 } from "../src/keccak.ts";
import { bytesToHex, hexToBytes, isAddress, toChecksumAddress, utf8, bigToBytes32, bytesToBig } from "../src/hex.ts";
import { domainSeparator, encodeType, hashStruct, typedDataDigest, type TypedData } from "../src/eip712.ts";
import { addressOf, G, mul, recoverAddress } from "../src/secp256k1.ts";
import { SELECTORS } from "../src/credential.ts";
import { highS, signDigest, throwawayKey } from "./helpers.ts";

const k = (s: string) => bytesToHex(keccak256(utf8(s)));

test("keccak256 matches published values (empty, abc, and across the 136-byte block boundary)", () => {
	assert.equal(k(""), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	assert.equal(k("abc"), "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
	assert.equal(k("transfer(address,uint256)").slice(0, 10), "0xa9059cbb");
	assert.equal(SELECTORS.paused, "0x5c975abb");
	// 135, 136 and 137 bytes exercise the padding boundary; the digests must all differ and be stable.
	const d = [135, 136, 137, 272].map((n) => k("a".repeat(n)));
	assert.equal(new Set(d).size, 4);
	assert.equal(k("a".repeat(136)), k("a".repeat(136)));
});

test("EIP-712 Mail example from the EIP text: type, domain, struct, digest and signer", () => {
	const td: TypedData = {
		types: {
			EIP712Domain: [
				{ name: "name", type: "string" },
				{ name: "version", type: "string" },
				{ name: "chainId", type: "uint256" },
				{ name: "verifyingContract", type: "address" },
			],
			Person: [
				{ name: "name", type: "string" },
				{ name: "wallet", type: "address" },
			],
			Mail: [
				{ name: "from", type: "Person" },
				{ name: "to", type: "Person" },
				{ name: "contents", type: "string" },
			],
		},
		primaryType: "Mail",
		domain: { name: "Ether Mail", version: "1", chainId: 1, verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC" },
		message: {
			from: { name: "Cow", wallet: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
			to: { name: "Bob", wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
			contents: "Hello, Bob!",
		},
	};
	assert.equal(encodeType(td.types, "Mail"), "Mail(Person from,Person to,string contents)Person(string name,address wallet)");
	assert.equal(bytesToHex(domainSeparator(td.domain)), "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
	assert.equal(bytesToHex(hashStruct(td.types, "Mail", td.message)), "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e");
	const digest = typedDataDigest(td);
	assert.equal(bytesToHex(digest), "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
	const sig = hexToBytes(
		"0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c",
	);
	assert.equal(recoverAddress(digest, sig), "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826");
	// The EIP's private key is keccak256("cow").
	assert.equal(toChecksumAddress(addressOf(mul(G, bytesToBig(keccak256(utf8("cow")))))), "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826");
});

test("address derivation agrees with node:crypto ECDH on fresh keys; private key 1 is the known address", () => {
	assert.equal(toChecksumAddress(addressOf(mul(G, 1n))), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
	for (let i = 0; i < 5; i++) {
		const key = throwawayKey();
		const ecdh = createECDH("secp256k1");
		ecdh.setPrivateKey(Buffer.from(bigToBytes32(key.priv)));
		const pub = ecdh.getPublicKey();
		assert.equal(bytesToHex(keccak256(pub.subarray(1))).slice(26), key.address.slice(2).toLowerCase());
	}
});

test("the test signer's ECDSA output verifies under node:crypto (independent of our recovery code)", () => {
	const key = throwawayKey();
	const ecdh = createECDH("secp256k1");
	ecdh.setPrivateKey(Buffer.from(bigToBytes32(key.priv)));
	const pub = ecdh.getPublicKey();
	const jwk = { kty: "EC", crv: "secp256k1", x: pub.subarray(1, 33).toString("base64url"), y: pub.subarray(33).toString("base64url") };
	const pk = createPublicKey({ key: jwk, format: "jwk" });
	const msg = Buffer.from("cas conformance");
	const digest = createHash("sha256").update(msg).digest();
	const sig = hexToBytes(signDigest(digest, key));
	assert.ok(nodeVerify("sha256", msg, { key: pk, dsaEncoding: "ieee-p1363" }, sig.slice(0, 64)));
	assert.equal(recoverAddress(digest, sig), key.address.toLowerCase());
});

test("recovery refuses malformed and malleable signatures", () => {
	const key = throwawayKey();
	const digest = keccak256(utf8("x"));
	const good = signDigest(digest, key);
	assert.equal(recoverAddress(digest, hexToBytes(good)), key.address.toLowerCase());
	assert.throws(() => recoverAddress(digest, hexToBytes(highS(good))), /high s/);
	const b = hexToBytes(good);
	assert.throws(() => recoverAddress(digest, b.slice(0, 64)), /65 bytes/);
	assert.throws(() => recoverAddress(digest.slice(1), b), /32 bytes/);
	for (const v of [2, 3, 26, 29]) {
		const badV = b.slice();
		badV[64] = v;
		assert.throws(() => recoverAddress(digest, badV), /recovery id/, `v=${v}`);
	}
	const zeroR = b.slice();
	zeroR.fill(0, 0, 32);
	assert.throws(() => recoverAddress(digest, zeroR), /r out of range/);
	const zeroS = b.slice();
	zeroS.fill(0, 32, 64);
	assert.throws(() => recoverAddress(digest, zeroS), /s out of range/);
	// v 0/1 is accepted as well as 27/28, and flipping v changes the signer.
	const v01 = b.slice();
	v01[64] = b[64]! - 27;
	assert.equal(recoverAddress(digest, v01), key.address.toLowerCase());
	const flipped = b.slice();
	flipped[64] = b[64] === 27 ? 28 : 27;
	assert.notEqual(recoverAddress(digest, flipped), key.address.toLowerCase());
});

test("encodeType sorts dependencies by name; hashStruct refuses unknown and missing fields", () => {
	const types = {
		Top: [
			{ name: "z", type: "Zed" },
			{ name: "a", type: "Alpha[]" },
		],
		Zed: [{ name: "v", type: "uint8" }],
		Alpha: [{ name: "w", type: "bool" }],
	};
	assert.equal(encodeType(types, "Top"), "Top(Zed z,Alpha[] a)Alpha(bool w)Zed(uint8 v)");
	const msg = { z: { v: 1 }, a: [{ w: true }] };
	hashStruct(types, "Top", msg);
	assert.throws(() => hashStruct(types, "Top", { ...msg, extra: 1 }), /unknown field extra/);
	assert.throws(() => hashStruct(types, "Top", { z: { v: 1 } }), /missing field a/);
});

test("utf8() matches TextEncoder, including astral and lone surrogates", () => {
	for (const s of ["", "abc", "é", "€", "\u{1F600}", "a\uD800b", "\uDC00", "x\uD83D"])
		assert.deepEqual(utf8(s), new TextEncoder().encode(s), JSON.stringify(s));
});

test("addresses: EIP-55 checksum is enforced for mixed case", () => {
	assert.ok(isAddress("0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826"));
	assert.ok(isAddress("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"));
	assert.ok(!isAddress("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD827"));
	assert.ok(!isAddress("0xCd2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"));
	assert.ok(!isAddress("0xcd2a3d9f938e13cd947ec05abc7fe734df8dd8"));
});
