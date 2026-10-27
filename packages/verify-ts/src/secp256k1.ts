// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// Public-key recovery on secp256k1 (verification only: this module never signs and holds no key).

import { bytesToBig, bytesToHex, type Hex } from "./hex.ts";
import { keccak256 } from "./keccak.ts";

export const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const HALF_N = N >> 1n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

export type Point = { x: bigint; y: bigint } | null; // null = point at infinity

const mod = (a: bigint, m: bigint): bigint => {
	const r = a % m;
	return r < 0n ? r + m : r;
};

export function powMod(b: bigint, e: bigint, m: bigint): bigint {
	let r = 1n;
	b = mod(b, m);
	while (e > 0n) {
		if (e & 1n) r = (r * b) % m;
		b = (b * b) % m;
		e >>= 1n;
	}
	return r;
}

const inv = (a: bigint, m: bigint): bigint => powMod(a, m - 2n, m); // m is prime

export const G: Point = { x: GX, y: GY };

export function add(a: Point, b: Point): Point {
	if (a === null) return b;
	if (b === null) return a;
	if (a.x === b.x) {
		if (mod(a.y + b.y, P) === 0n) return null;
		const l = mod(3n * a.x * a.x * inv(2n * a.y, P), P);
		const x = mod(l * l - 2n * a.x, P);
		return { x, y: mod(l * (a.x - x) - a.y, P) };
	}
	const l = mod((b.y - a.y) * inv(b.x - a.x, P), P);
	const x = mod(l * l - a.x - b.x, P);
	return { x, y: mod(l * (a.x - x) - a.y, P) };
}

export function mul(p: Point, k: bigint): Point {
	let r: Point = null;
	let q = p;
	k = mod(k, N);
	while (k > 0n) {
		if (k & 1n) r = add(r, q);
		q = add(q, q);
		k >>= 1n;
	}
	return r;
}

export function addressOf(pub: Point): Hex {
	if (pub === null) throw new Error("point at infinity");
	const raw = new Uint8Array(64);
	let x = pub.x;
	let y = pub.y;
	for (let i = 31; i >= 0; i--) {
		raw[i] = Number(x & 0xffn);
		raw[32 + i] = Number(y & 0xffn);
		x >>= 8n;
		y >>= 8n;
	}
	return bytesToHex(keccak256(raw).slice(12));
}

/**
 * Recovers the signer address of a 65-byte r||s||v signature over a 32-byte digest.
 * Refuses (throws) on: wrong lengths, r or s outside [1, n-1], high s (EIP-2), v not in {0,1,27,28},
 * and an r that is not the x of a curve point. Only r < n is accepted as x (the r >= n case is not used).
 */
export function recoverAddress(digest: Uint8Array, sig: Uint8Array): Hex {
	if (digest.length !== 32) throw new Error("digest must be 32 bytes");
	if (sig.length !== 65) throw new Error("signature must be 65 bytes");
	const r = bytesToBig(sig.slice(0, 32));
	const s = bytesToBig(sig.slice(32, 64));
	let v = sig[64]!;
	if (v === 27 || v === 28) v -= 27;
	if (v !== 0 && v !== 1) throw new Error("bad recovery id");
	if (r <= 0n || r >= N) throw new Error("r out of range");
	if (s <= 0n || s >= N) throw new Error("s out of range");
	if (s > HALF_N) throw new Error("high s (malleable signature)");
	const ySq = mod(r * r * r + 7n, P);
	let y = powMod(ySq, (P + 1n) / 4n, P);
	if (mod(y * y, P) !== ySq) throw new Error("r is not on the curve");
	if ((y & 1n) !== BigInt(v)) y = P - y;
	const R: Point = { x: r, y };
	const e = mod(bytesToBig(digest), N);
	const rInv = inv(r, N);
	// Q = r^-1 (sR - eG)
	const Q = add(mul(R, mod(s * rInv, N)), mul(G, mod(-e * rInv, N)));
	return addressOf(Q);
}
