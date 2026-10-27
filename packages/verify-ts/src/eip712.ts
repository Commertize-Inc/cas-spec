// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// EIP-712 typed-data hashing (encodeType, hashStruct, the 0x1901 digest).
// Supports the types CAS uses: address, bool, string, bytes, bytesN, uintN, intN, structs and dynamic arrays.

import { bigToBytes32, concat, hexToBytes, isAddress, isHex, utf8, type Hex } from "./hex.ts";
import { keccak256 } from "./keccak.ts";

export interface TypedField {
	name: string;
	type: string;
}
export type Types = Record<string, TypedField[]>;
export interface TypedData {
	types: Types;
	primaryType: string;
	domain: Record<string, unknown>;
	message: Record<string, unknown>;
}

const DOMAIN_FIELDS: TypedField[] = [
	{ name: "name", type: "string" },
	{ name: "version", type: "string" },
	{ name: "chainId", type: "uint256" },
	{ name: "verifyingContract", type: "address" },
	{ name: "salt", type: "bytes32" },
];

/** The EIP712Domain type for the fields actually present, in canonical order. */
export function domainType(domain: Record<string, unknown>): TypedField[] {
	return DOMAIN_FIELDS.filter((f) => domain[f.name] !== undefined);
}

const baseOf = (t: string): string => t.replace(/\[\d*\]$/, "");

function deps(types: Types, primary: string, found: Set<string> = new Set()): Set<string> {
	const base = baseOf(primary);
	if (found.has(base) || types[base] === undefined) return found;
	found.add(base);
	for (const f of types[base]!) deps(types, f.type, found);
	return found;
}

export function encodeType(types: Types, primary: string): string {
	const all = [...deps(types, primary)];
	const rest = all.filter((t) => t !== primary).sort();
	return [primary, ...rest].map((t) => `${t}(${types[t]!.map((f) => `${f.type} ${f.name}`).join(",")})`).join("");
}

export const typeHash = (types: Types, primary: string): Uint8Array => keccak256(utf8(encodeType(types, primary)));

function toBigInt(v: unknown): bigint {
	if (typeof v === "bigint") return v;
	if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
	if (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v)) return BigInt(v);
	if (typeof v === "string" && /^0x[0-9a-fA-F]+$/.test(v)) return BigInt(v);
	throw new Error("not an integer");
}

function encodeValue(types: Types, type: string, value: unknown): Uint8Array {
	if (types[type] !== undefined) return hashStruct(types, type, value);
	const arr = /^(.*)\[(\d*)\]$/.exec(type);
	if (arr) {
		if (!Array.isArray(value)) throw new Error(`${type}: not an array`);
		if (arr[2] !== "" && value.length !== Number(arr[2])) throw new Error(`${type}: wrong length`);
		return keccak256(concat(...value.map((v) => encodeValue(types, arr[1]!, v))));
	}
	if (type === "string") {
		if (typeof value !== "string") throw new Error("string: not a string");
		return keccak256(utf8(value));
	}
	if (type === "bytes") {
		if (!isHex(value)) throw new Error("bytes: not hex");
		return keccak256(hexToBytes(value));
	}
	if (type === "address") {
		if (!isAddress(value)) throw new Error("address: not an address");
		return concat(new Uint8Array(12), hexToBytes(value));
	}
	if (type === "bool") {
		if (typeof value !== "boolean") throw new Error("bool: not a boolean");
		return bigToBytes32(value ? 1n : 0n);
	}
	const bn = /^bytes([1-9]|[12][0-9]|3[0-2])$/.exec(type);
	if (bn) {
		if (!isHex(value) || hexToBytes(value).length !== Number(bn[1])) throw new Error(`${type}: wrong length`);
		const out = new Uint8Array(32);
		out.set(hexToBytes(value));
		return out;
	}
	const un = /^(u?)int(\d+)$/.exec(type);
	if (un) {
		const bits = BigInt(un[2]!);
		if (bits < 8n || bits > 256n || bits % 8n !== 0n) throw new Error(`${type}: bad width`);
		const v = toBigInt(value);
		if (un[1] === "u") {
			if (v < 0n || v >= 1n << bits) throw new Error(`${type}: out of range`);
			return bigToBytes32(v);
		}
		const lim = 1n << (bits - 1n);
		if (v < -lim || v >= lim) throw new Error(`${type}: out of range`);
		return bigToBytes32(v < 0n ? (1n << 256n) + v : v);
	}
	throw new Error(`unsupported type ${type}`);
}

export function hashStruct(types: Types, primary: string, value: unknown): Uint8Array {
	const fields = types[primary];
	if (fields === undefined) throw new Error(`unknown type ${primary}`);
	if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${primary}: not an object`);
	const obj = value as Record<string, unknown>;
	const names = new Set(fields.map((f) => f.name));
	for (const k of Object.keys(obj)) if (!names.has(k)) throw new Error(`${primary}: unknown field ${k}`);
	const parts = [typeHash(types, primary)];
	for (const f of fields) {
		if (obj[f.name] === undefined) throw new Error(`${primary}: missing field ${f.name}`);
		parts.push(encodeValue(types, f.type, obj[f.name]));
	}
	return keccak256(concat(...parts));
}

export function domainSeparator(domain: Record<string, unknown>): Uint8Array {
	return hashStruct({ EIP712Domain: domainType(domain) }, "EIP712Domain", domain);
}

/** keccak256(0x19 0x01 || domainSeparator || hashStruct(message)). */
export function typedDataDigest(td: TypedData): Uint8Array {
	const types = { ...td.types };
	delete types.EIP712Domain;
	return keccak256(concat(new Uint8Array([0x19, 0x01]), domainSeparator(td.domain), hashStruct(types, td.primaryType, td.message)));
}

export type { Hex };
