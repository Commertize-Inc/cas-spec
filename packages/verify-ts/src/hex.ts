// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

import { keccak256 } from "./keccak.ts";

export type Hex = `0x${string}`;

const HEX = /^0x([0-9a-fA-F]{2})*$/;

export function isHex(v: unknown): v is Hex {
	return typeof v === "string" && HEX.test(v);
}

export function hexToBytes(h: string): Uint8Array {
	if (!isHex(h)) throw new Error("not even-length 0x hex");
	const out = new Uint8Array((h.length - 2) / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 + i * 2, 4 + i * 2), 16);
	return out;
}

export function bytesToHex(b: Uint8Array): Hex {
	let s = "0x";
	for (const x of b) s += x.toString(16).padStart(2, "0");
	return s as Hex;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

export function bigToBytes32(v: bigint): Uint8Array {
	if (v < 0n || v >= 1n << 256n) throw new Error("out of uint256 range");
	const out = new Uint8Array(32);
	for (let i = 31; i >= 0; i--) {
		out[i] = Number(v & 0xffn);
		v >>= 8n;
	}
	return out;
}

export function bytesToBig(b: Uint8Array): bigint {
	let v = 0n;
	for (const x of b) v = (v << 8n) | BigInt(x);
	return v;
}

/** UTF-8 bytes of a string (lone surrogates become U+FFFD, as TextEncoder does). Written out to avoid any platform global. */
export function utf8(s: string): Uint8Array {
	const out: number[] = [];
	for (let i = 0; i < s.length; i++) {
		let c = s.charCodeAt(i);
		if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
			const d = s.charCodeAt(i + 1);
			if (d >= 0xdc00 && d <= 0xdfff) {
				c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
				i++;
			}
		}
		if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
		if (c < 0x80) out.push(c);
		else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
		else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
		else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
	}
	return Uint8Array.from(out);
}

export const keccakHex = (b: Uint8Array): Hex => bytesToHex(keccak256(b));

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** True for a 20-byte 0x address. Mixed case must carry a valid EIP-55 checksum. */
export function isAddress(v: unknown): v is Hex {
	if (typeof v !== "string" || !ADDRESS.test(v)) return false;
	const body = v.slice(2);
	if (body === body.toLowerCase() || body === body.toUpperCase()) return true;
	return toChecksumAddress(v) === v;
}

export function toChecksumAddress(a: string): Hex {
	if (!ADDRESS.test(a)) throw new Error("not an address");
	const lower = a.slice(2).toLowerCase();
	const h = bytesToHex(keccak256(utf8(lower))).slice(2);
	let out = "0x";
	for (let i = 0; i < 40; i++) out += parseInt(h[i]!, 16) >= 8 ? lower[i]!.toUpperCase() : lower[i]!;
	return out as Hex;
}

export const sameAddress = (a: string, b: string): boolean =>
	isAddress(a) && isAddress(b) && a.toLowerCase() === b.toLowerCase();
