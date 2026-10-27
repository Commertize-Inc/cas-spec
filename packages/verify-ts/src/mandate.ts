// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// CAS-1 signed mandate: the canonical EIP-712 types, signature recovery and the scope check.
// Pure functions. No network, no key, no clock unless you omit `at`.

import { typedDataDigest, type TypedData, type TypedField } from "./eip712.ts";
import { bigToBytes32, bytesToHex, concat, hexToBytes, isAddress, isHex, sameAddress, type Hex } from "./hex.ts";
import { keccak256 } from "./keccak.ts";
import { recoverAddress } from "./secp256k1.ts";

export const SPEC_VERSION = "cas-1.0" as const;
export const MANDATE_DOMAIN_NAME = "CAS Mandate" as const;
export const MANDATE_DOMAIN_VERSION = "1" as const;

/** The CAS-1 Mandate type, field for field. A typed-data object whose Mandate type differs is refused. */
export const MANDATE_TYPE: readonly TypedField[] = Object.freeze([
	{ name: "schema", type: "string" },
	{ name: "principal", type: "address" },
	{ name: "agent", type: "address" },
	{ name: "credentialId", type: "uint256" },
	{ name: "taskClasses", type: "string[]" },
	{ name: "assetClasses", type: "string[]" },
	{ name: "counterparties", type: "address[]" },
	{ name: "spendCap", type: "uint256" },
	{ name: "validAfter", type: "uint64" },
	{ name: "validBefore", type: "uint64" },
	{ name: "nonce", type: "bytes32" },
]);

export interface Mandate {
	schema: string;
	principal: Hex;
	agent: Hex;
	credentialId: string;
	taskClasses: string[];
	assetClasses: string[];
	counterparties: Hex[];
	spendCap: string;
	validAfter: number | string;
	validBefore: number | string;
	nonce: Hex;
}

export interface Action {
	taskClass: string;
	assetClass?: string;
	counterparty?: string;
	/** Base units, decimal integer string. Absent means 0. */
	amount?: string;
}

export type MandateReason =
	| "VALID"
	| "MALFORMED"
	| "UNSUPPORTED_VERSION"
	| "WRONG_DOMAIN"
	| "BAD_SIGNATURE"
	| "PRINCIPAL_MISMATCH"
	| "SUBJECT_MISMATCH"
	| "UNSUPPORTED_SPEND_CAP"
	| "NOT_YET_VALID"
	| "EXPIRED"
	| "SCOPE_DENIED";

export interface MandateResult {
	valid: boolean;
	reason: MandateReason;
	detail?: string;
	signer?: Hex;
	/** The EIP-712 digest the principal signed. Also the `ref` of the mandate's anchor credential. */
	digest?: Hex;
}

export interface MandateOptions {
	/** Required domain chain id. */
	chainId: number | bigint;
	/** Required domain verifyingContract: the credential contract the mandate is anchored in. */
	contract: string;
	/** If given, the mandate must name this agent. */
	agent?: string;
	/** If given, the scope check runs for this action. */
	action?: Action;
	/** Unix seconds for the window check. Default: now. */
	at?: number;
}

const DEC = /^(0|[1-9][0-9]{0,77})$/;
const MAX_LIST = 64;
const CLASS = /^[a-z0-9][a-z0-9._:-]{0,63}$/;

const fail = (reason: MandateReason, detail?: string, extra: Partial<MandateResult> = {}): MandateResult => ({
	valid: false,
	reason,
	...(detail ? { detail } : {}),
	...extra,
});

function sameType(a: readonly TypedField[] | undefined, b: readonly TypedField[]): boolean {
	return Array.isArray(a) && a.length === b.length && a.every((f, i) => f.name === b[i]!.name && f.type === b[i]!.type);
}

const asSeconds = (v: unknown): bigint | null => {
	if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
	if (typeof v === "string" && DEC.test(v)) return BigInt(v);
	return null;
};

/** Structural checks on the message beyond what EIP-712 hashing enforces. Returns a detail string or null. */
function shapeProblem(m: Record<string, unknown>): string | null {
	if (!isAddress(m.principal) || !isAddress(m.agent)) return "principal and agent must be addresses";
	if (/^0x0{40}$/i.test(m.principal) || /^0x0{40}$/i.test(m.agent)) return "zero address";
	if (typeof m.credentialId !== "string" || !DEC.test(m.credentialId)) return "credentialId must be a decimal string";
	for (const k of ["taskClasses", "assetClasses"] as const) {
		const l = m[k];
		if (!Array.isArray(l) || l.length > MAX_LIST || l.some((x) => typeof x !== "string" || !CLASS.test(x))) return `${k}: up to ${MAX_LIST} lower-case class names`;
		if (new Set(l).size !== l.length) return `${k}: duplicate entry`;
	}
	if ((m.taskClasses as unknown[]).length === 0) return "taskClasses must not be empty";
	const c = m.counterparties;
	if (!Array.isArray(c) || c.length > MAX_LIST || c.some((x) => !isAddress(x))) return `counterparties: up to ${MAX_LIST} addresses`;
	if (new Set(c.map((x: string) => x.toLowerCase())).size !== c.length) return "counterparties: duplicate entry";
	if (typeof m.spendCap !== "string" || !DEC.test(m.spendCap)) return "spendCap must be a decimal string";
	const a = asSeconds(m.validAfter);
	const b = asSeconds(m.validBefore);
	if (a === null || b === null || b >= 1n << 64n) return "validAfter/validBefore must be uint64 seconds";
	if (b <= a) return "validBefore must be after validAfter";
	if (!isHex(m.nonce) || hexToBytes(m.nonce).length !== 32) return "nonce must be bytes32";
	return null;
}

/**
 * The scope check. True only if every requested element is inside the mandate.
 * Empty lists grant nothing: an action naming an asset class or counterparty needs it listed.
 */
export function allows(m: Mandate, action: Action): { ok: true } | { ok: false; detail: string } {
	if (typeof action !== "object" || action === null) return { ok: false, detail: "no action" };
	if (typeof action.taskClass !== "string" || !m.taskClasses.includes(action.taskClass)) return { ok: false, detail: "taskClass not granted" };
	if (action.assetClass !== undefined && (typeof action.assetClass !== "string" || !m.assetClasses.includes(action.assetClass)))
		return { ok: false, detail: "assetClass not granted" };
	if (action.counterparty !== undefined) {
		if (!isAddress(action.counterparty)) return { ok: false, detail: "counterparty is not an address" };
		if (!m.counterparties.some((c) => sameAddress(c, action.counterparty!))) return { ok: false, detail: "counterparty not granted" };
	}
	const amount = action.amount ?? "0";
	if (typeof amount !== "string" || !DEC.test(amount)) return { ok: false, detail: "amount must be a decimal string" };
	if (BigInt(amount) > BigInt(m.spendCap)) return { ok: false, detail: "amount over spendCap" };
	return { ok: true };
}

/** The id of the TASK_MANDATE credential that anchors this mandate: idFor(agent, TASK_MANDATE, digest). */
export function mandateAnchorId(agent: string, digest: Hex): string {
	if (!isAddress(agent)) throw new Error("agent is not an address");
	const enc = concat(new Uint8Array(12), hexToBytes(agent), bigToBytes32(1n), hexToBytes(digest));
	return BigInt(bytesToHex(keccak256(enc))).toString();
}

/**
 * Verifies a CAS-1 mandate offline: canonical types, domain, signature by `principal`, window,
 * the v1 spend-cap rule, and (if `opts.action` is given) the scope check.
 * It does NOT read the chain: anchoring and revocation are checked by `verify`.
 */
export function verifyMandate(typedData: unknown, signature: string, opts: MandateOptions): MandateResult {
	if (typeof typedData !== "object" || typedData === null) return fail("MALFORMED", "typed data is not an object");
	const td = typedData as TypedData;
	if (td.primaryType !== "Mandate" || typeof td.types !== "object" || td.types === null) return fail("MALFORMED", "primaryType must be Mandate");
	if (Object.keys(td.types).some((k) => k !== "Mandate" && k !== "EIP712Domain")) return fail("MALFORMED", "unexpected types");
	if (!sameType(td.types.Mandate, MANDATE_TYPE)) return fail("UNSUPPORTED_VERSION", "Mandate type is not the CAS-1 type");
	const m = td.message as Record<string, unknown>;
	if (typeof m !== "object" || m === null) return fail("MALFORMED", "message is not an object");
	if (typeof m.schema !== "string" || !m.schema.startsWith("cas-1.")) return fail("UNSUPPORTED_VERSION", "schema must be cas-1.x");
	const shape = shapeProblem(m);
	if (shape) return fail("MALFORMED", shape);

	const d = td.domain as Record<string, unknown>;
	if (typeof d !== "object" || d === null) return fail("WRONG_DOMAIN", "no domain");
	const dKeys = Object.keys(d).sort().join(",");
	if (dKeys !== "chainId,name,verifyingContract,version") return fail("WRONG_DOMAIN", "domain must have exactly name, version, chainId, verifyingContract");
	if (d.name !== MANDATE_DOMAIN_NAME || d.version !== MANDATE_DOMAIN_VERSION) return fail("WRONG_DOMAIN", "domain name/version");
	let chainOk = false;
	try {
		chainOk = BigInt(d.chainId as string | number) === BigInt(opts.chainId);
	} catch {
		chainOk = false;
	}
	if (!chainOk) return fail("WRONG_DOMAIN", "chainId");
	if (typeof d.verifyingContract !== "string" || !sameAddress(d.verifyingContract, opts.contract)) return fail("WRONG_DOMAIN", "verifyingContract");

	let digest: Hex;
	let signer: Hex;
	try {
		digest = bytesToHex(typedDataDigest(td));
	} catch (e) {
		return fail("MALFORMED", (e as Error).message);
	}
	try {
		if (!isHex(signature)) throw new Error("signature is not hex");
		signer = recoverAddress(hexToBytes(digest), hexToBytes(signature));
	} catch (e) {
		return fail("BAD_SIGNATURE", (e as Error).message, { digest });
	}
	const mandate = m as unknown as Mandate;
	if (!sameAddress(signer, mandate.principal)) return fail("PRINCIPAL_MISMATCH", "signer is not the principal", { digest, signer });
	if (opts.agent !== undefined && !sameAddress(opts.agent, mandate.agent)) return fail("SUBJECT_MISMATCH", "mandate names another agent", { digest, signer });
	if (BigInt(mandate.spendCap) !== 0n) return fail("UNSUPPORTED_SPEND_CAP", "CAS-1.0 mandates carry spendCap 0", { digest, signer });

	const at = BigInt(opts.at ?? Math.floor(Date.now() / 1000));
	if (at < asSeconds(mandate.validAfter)!) return fail("NOT_YET_VALID", undefined, { digest, signer });
	if (at >= asSeconds(mandate.validBefore)!) return fail("EXPIRED", undefined, { digest, signer });

	if (opts.action !== undefined) {
		const s = allows(mandate, opts.action);
		if (!s.ok) return fail("SCOPE_DENIED", s.detail, { digest, signer });
	}
	return { valid: true, reason: "VALID", digest, signer };
}
