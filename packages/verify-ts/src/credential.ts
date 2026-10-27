// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// CAS-1 credential verification: a live read of a CASCredential-shaped contract through a provider
// you supply, or an offline read of a state snapshot you supply. Read-only: no key, no transaction.

import { bigToBytes32, bytesToBig, bytesToHex, concat, hexToBytes, isAddress, isHex, sameAddress, toChecksumAddress, utf8, type Hex } from "./hex.ts";
import { keccak256 } from "./keccak.ts";
import { mandateAnchorId, verifyMandate, type Action, type Mandate, type MandateReason } from "./mandate.ts";

/** Any EIP-1193-style provider: `{ request({ method, params }) }`. Only eth_chainId, eth_blockNumber, eth_getCode and eth_call are used. */
export interface Provider {
	request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export const KINDS = ["KYA_REGISTERED", "TASK_MANDATE", "WORK_ACCEPTED", "ATTESTATION"] as const;
export const STATUSES = ["NONE", "ISSUED", "REVOKED", "UNLINKED"] as const;
export const REVOKE_REASONS = ["MANDATE_ENDED", "KYA_LAPSED", "MISUSE", "ERROR", "HOLDER_REQUEST", "LEGAL_ORDER"] as const;
export type Kind = (typeof KINDS)[number];
export type Status = (typeof STATUSES)[number];
export type RevokeReason = (typeof REVOKE_REASONS)[number];

/** The read-only interface fragment this verifier calls (human-readable signatures). */
export const CREDENTIAL_INTERFACE = Object.freeze([
	"function status(uint256 id) view returns (uint8)",
	"function isValid(uint256 id) view returns (bool)",
	"function paused() view returns (bool)",
	"function credential(uint256 id) view returns ((address subject, uint8 kind, uint8 status, uint8 reason, uint64 issuedAt, address issuer, bytes32 ref, bytes32 contentHash))",
	"function idFor(address subject, uint8 kind, bytes32 ref) pure returns (uint256)",
]);

const selector = (sig: string): Uint8Array => keccak256(utf8(sig)).slice(0, 4);
export const SELECTORS = Object.freeze({
	status: bytesToHex(selector("status(uint256)")),
	isValid: bytesToHex(selector("isValid(uint256)")),
	paused: bytesToHex(selector("paused()")),
	credential: bytesToHex(selector("credential(uint256)")),
});

export interface CredentialRecord {
	subject: Hex;
	kind: Kind;
	status: Status;
	/** Meaningful only when status is REVOKED. */
	reason: RevokeReason;
	issuedAt: number;
	issuer: Hex;
	ref: Hex;
	contentHash: Hex;
}

/** An offline state snapshot. Every field is checked; anything unexpected is refused. */
export interface Snapshot {
	spec: "cas-1.0";
	chainId: number;
	contract: string;
	blockNumber: number;
	paused: boolean;
	credentials: Record<string, CredentialRecord>;
}

export type CredentialReason =
	| "VALID"
	| "MALFORMED"
	| "NO_TRUSTED_ISSUER"
	| "PROVIDER_ERROR"
	| "WRONG_CHAIN"
	| "NO_CONTRACT"
	| "INCONSISTENT_STATE"
	| "NOT_FOUND"
	| "REVOKED"
	| "UNLINKED"
	| "UNTRUSTED_ISSUER"
	| "SUBJECT_MISMATCH"
	| "WRONG_KIND"
	| "PAUSED"
	| "INVALID_ID";

export interface CredentialResult {
	valid: boolean;
	reason: CredentialReason;
	detail?: string;
	revokeReason?: RevokeReason;
	credential?: CredentialRecord;
	source: "live" | "snapshot";
	blockNumber?: number;
}

export interface CredentialOptions {
	/** Issuer addresses you accept. Required and non-empty: there is no default issuer. */
	trustedIssuers: readonly string[];
	/** Exactly one of provider (live read) or snapshot (offline). */
	provider?: Provider;
	snapshot?: Snapshot;
	/** If given, the credential must belong to this subject. */
	subject?: string;
	/** If given, the credential must be of this kind. */
	kind?: Kind;
	/** Live mode: read at this block number. Default: the latest block at call time, pinned for every read. */
	blockNumber?: number;
}

const HASH32 = /^0x[0-9a-fA-F]{64}$/;

/** idFor(subject, kind, ref) = uint256(keccak256(word(subject) || word(kind) || ref)) (spec 3.1). */
export function idFor(subject: string, kind: Kind | number, ref: string): bigint {
	const k = typeof kind === "number" ? kind : (KINDS as readonly string[]).indexOf(kind);
	if (!isAddress(subject)) throw new Error("subject is not an address");
	if (!Number.isInteger(k) || k < 0 || k >= KINDS.length) throw new Error("unknown kind");
	if (!HASH32.test(ref)) throw new Error("ref is not 32 bytes");
	return bytesToBig(keccak256(concat(new Uint8Array(12), hexToBytes(subject), bigToBytes32(BigInt(k)), hexToBytes(ref))));
}

const DEC = /^(0|[1-9][0-9]{0,77})$/;
const MAX_UINT = (1n << 256n) - 1n;

const parseId = (id: unknown): bigint | null => {
	if (typeof id === "bigint") return id >= 0n && id <= MAX_UINT ? id : null;
	if (typeof id === "string" && DEC.test(id)) {
		const v = BigInt(id);
		return v <= MAX_UINT ? v : null;
	}
	return null;
};

const res = (source: "live" | "snapshot", reason: CredentialReason, extra: Partial<CredentialResult> = {}): CredentialResult => ({
	valid: reason === "VALID",
	reason,
	source,
	...extra,
});

function words(h: unknown, n: number): bigint[] {
	if (!isHex(h)) throw new Error("eth_call result is not hex");
	const b = hexToBytes(h);
	if (b.length !== n * 32) throw new Error(`expected ${n} words, got ${b.length} bytes`);
	return Array.from({ length: n }, (_, i) => bytesToBig(b.slice(i * 32, i * 32 + 32)));
}

const asAddress = (w: bigint): Hex => {
	if (w >> 160n !== 0n) throw new Error("dirty address word");
	return toChecksumAddress(bytesToHex(bigToBytes32(w).slice(12)));
};
const asEnum = <T extends readonly string[]>(w: bigint, list: T): T[number] => {
	if (w >= BigInt(list.length)) throw new Error("enum out of range");
	return list[Number(w)]!;
};
const asBool = (w: bigint): boolean => {
	if (w > 1n) throw new Error("dirty bool word");
	return w === 1n;
};

function decodeCredential(h: unknown): CredentialRecord {
	const w = words(h, 8);
	if (w[4]! >= 1n << 64n) throw new Error("issuedAt out of range");
	return {
		subject: asAddress(w[0]!),
		kind: asEnum(w[1]!, KINDS),
		status: asEnum(w[2]!, STATUSES),
		reason: asEnum(w[3]!, REVOKE_REASONS),
		issuedAt: Number(w[4]!),
		issuer: asAddress(w[5]!),
		ref: bytesToHex(bigToBytes32(w[6]!)),
		contentHash: bytesToHex(bigToBytes32(w[7]!)),
	};
}

const toQuantity = (n: number): string => `0x${n.toString(16)}`;
const fromQuantity = (q: unknown): number => {
	if (typeof q !== "string" || !/^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(q)) throw new Error("not a quantity");
	const v = BigInt(q);
	if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("quantity too large");
	return Number(v);
};

interface State {
	record: CredentialRecord;
	paused: boolean;
	isValid: boolean;
	statusRead: Status;
	blockNumber: number;
}

async function readLive(p: Provider, chainId: number, contract: string, id: bigint, block: number | undefined): Promise<State | CredentialResult> {
	const live = (r: CredentialReason, detail?: string): CredentialResult => res("live", r, detail ? { detail } : {});
	let got: number;
	try {
		got = fromQuantity(await p.request({ method: "eth_chainId" }));
	} catch (e) {
		return live("PROVIDER_ERROR", (e as Error).message);
	}
	if (got !== chainId) return live("WRONG_CHAIN", `provider is on chain ${got}`);
	let blockNumber: number;
	try {
		blockNumber = block ?? fromQuantity(await p.request({ method: "eth_blockNumber" }));
	} catch (e) {
		return live("PROVIDER_ERROR", (e as Error).message);
	}
	const tag = toQuantity(blockNumber);
	try {
		const code = await p.request({ method: "eth_getCode", params: [contract, tag] });
		if (!isHex(code) || code === "0x") return { ...live("NO_CONTRACT"), blockNumber };
	} catch (e) {
		return live("PROVIDER_ERROR", (e as Error).message);
	}
	const call = (sel: Hex, arg?: bigint) =>
		p.request({ method: "eth_call", params: [{ to: contract, data: bytesToHex(concat(hexToBytes(sel), ...(arg === undefined ? [] : [bigToBytes32(arg)]))) }, tag] });
	let raw: unknown[];
	try {
		raw = await Promise.all([call(SELECTORS.credential, id), call(SELECTORS.paused), call(SELECTORS.isValid, id), call(SELECTORS.status, id)]);
	} catch (e) {
		return { ...live("PROVIDER_ERROR", (e as Error).message), blockNumber };
	}
	try {
		return {
			record: decodeCredential(raw[0]),
			paused: asBool(words(raw[1], 1)[0]!),
			isValid: asBool(words(raw[2], 1)[0]!),
			statusRead: asEnum(words(raw[3], 1)[0]!, STATUSES),
			blockNumber,
		};
	} catch (e) {
		return { ...live("INCONSISTENT_STATE", (e as Error).message), blockNumber };
	}
}

function readSnapshot(s: Snapshot, chainId: number, contract: string, id: bigint): State | CredentialResult {
	const snap = (r: CredentialReason, detail?: string): CredentialResult => res("snapshot", r, detail ? { detail } : {});
	if (typeof s !== "object" || s === null || s.spec !== "cas-1.0") return snap("MALFORMED", "snapshot spec must be cas-1.0");
	if (s.chainId !== chainId) return snap("WRONG_CHAIN", `snapshot is for chain ${String(s.chainId)}`);
	if (typeof s.contract !== "string" || !sameAddress(s.contract, contract)) return snap("MALFORMED", "snapshot is for another contract");
	if (!Number.isSafeInteger(s.blockNumber) || s.blockNumber < 0 || typeof s.paused !== "boolean") return snap("MALFORMED", "snapshot blockNumber/paused");
	if (typeof s.credentials !== "object" || s.credentials === null) return snap("MALFORMED", "snapshot credentials");
	const blockNumber = s.blockNumber;
	const c = Object.hasOwn(s.credentials, id.toString()) ? s.credentials[id.toString()] : undefined;
	if (c === undefined) return { ...snap("NOT_FOUND"), blockNumber };
	const ok =
		typeof c === "object" &&
		c !== null &&
		isAddress(c.subject) &&
		isAddress(c.issuer) &&
		(KINDS as readonly string[]).includes(c.kind) &&
		(STATUSES as readonly string[]).includes(c.status) &&
		(REVOKE_REASONS as readonly string[]).includes(c.reason) &&
		Number.isSafeInteger(c.issuedAt) &&
		typeof c.ref === "string" &&
		HASH32.test(c.ref) &&
		typeof c.contentHash === "string" &&
		HASH32.test(c.contentHash);
	if (!ok) return { ...snap("MALFORMED", "snapshot credential record"), blockNumber };
	return { record: c, paused: s.paused, isValid: !s.paused && c.status === "ISSUED", statusRead: c.status, blockNumber };
}

/**
 * Verifies one credential. VALID only when: the record exists and is ISSUED, the contract is not paused,
 * the issuer is in `trustedIssuers`, the optional subject/kind match, and (live) every read agrees.
 * Revocation is reported even while paused. Any read failure is a failure, never VALID.
 */
export async function verifyCredential(chainId: number, contract: string, id: string | bigint, opts: CredentialOptions): Promise<CredentialResult> {
	const source: "live" | "snapshot" = opts?.snapshot !== undefined && opts?.provider === undefined ? "snapshot" : "live";
	if (!Number.isSafeInteger(chainId) || chainId <= 0) return res(source, "MALFORMED", { detail: "chainId" });
	if (!isAddress(contract)) return res(source, "MALFORMED", { detail: "contract is not an address" });
	const nid = parseId(id);
	if (nid === null) return res(source, "MALFORMED", { detail: "id must be a uint256 decimal string or bigint" });
	if (opts.subject !== undefined && !isAddress(opts.subject)) return res(source, "MALFORMED", { detail: "subject is not an address" });
	if (opts.kind !== undefined && !(KINDS as readonly string[]).includes(opts.kind)) return res(source, "MALFORMED", { detail: "unknown kind" });
	const trusted = opts.trustedIssuers;
	if (!Array.isArray(trusted) || trusted.length === 0) return res(source, "NO_TRUSTED_ISSUER", { detail: "trustedIssuers is required" });
	if (trusted.some((t) => !isAddress(t))) return res(source, "MALFORMED", { detail: "trustedIssuers must be addresses" });
	if ((opts.provider === undefined) === (opts.snapshot === undefined)) return res(source, "MALFORMED", { detail: "pass exactly one of provider or snapshot" });

	const st = opts.provider !== undefined ? await readLive(opts.provider, chainId, contract, nid, opts.blockNumber) : readSnapshot(opts.snapshot!, chainId, contract, nid);
	if (!("record" in st)) return st;
	const { record, paused, isValid, statusRead, blockNumber } = st;
	const out = (r: CredentialReason, extra: Partial<CredentialResult> = {}) => res(source, r, { credential: record, blockNumber, ...extra });

	if (statusRead !== record.status || isValid !== (!paused && record.status === "ISSUED"))
		return out("INCONSISTENT_STATE", { detail: "status/isValid/paused reads disagree" });
	if (record.status === "NONE") return res(source, "NOT_FOUND", { blockNumber });
	// The record must be the one its id names. A conforming contract cannot fail this; a snapshot can.
	if (idFor(record.subject, record.kind, record.ref) !== nid) return out("INVALID_ID", { detail: "id is not idFor(subject, kind, ref) of the record" });
	if (record.status === "REVOKED") return out("REVOKED", { revokeReason: record.reason });
	if (record.status === "UNLINKED") return out("UNLINKED");
	if (!trusted.some((t) => sameAddress(t, record.issuer))) return out("UNTRUSTED_ISSUER");
	if (opts.subject !== undefined && !sameAddress(opts.subject, record.subject)) return out("SUBJECT_MISMATCH");
	if (opts.kind !== undefined && opts.kind !== record.kind) return out("WRONG_KIND");
	if (paused) return out("PAUSED");
	if (!isValid) return out("INCONSISTENT_STATE", { detail: "isValid is false for an issued credential" });
	return out("VALID");
}

export type VerifyReason = CredentialReason | MandateReason | "CREDENTIAL_MISMATCH" | "MANDATE_NOT_ANCHORED" | "MANDATE_REVOKED";

export interface VerifyOptions extends Omit<CredentialOptions, "subject" | "kind"> {
	chainId: number;
	contract: string;
	/** The agent wallet address. CAS keys on this address. */
	subject: string;
	/** The subject's KYA_REGISTERED credential id. */
	credentialId: string | bigint;
	/** A signed CAS-1 mandate. Required when `action` is given. */
	mandate?: { typedData: unknown; signature: string };
	action?: Action;
	/** Unix seconds for the mandate window. Default: now. */
	at?: number;
}

export interface VerifyResult {
	valid: boolean;
	reason: VerifyReason;
	/** Which step decided the result. */
	step: "input" | "credential" | "mandate" | "anchor" | "done";
	detail?: string;
	revokeReason?: RevokeReason;
	source: "live" | "snapshot";
	blockNumber?: number;
	mandateDigest?: Hex;
	anchorId?: string;
}

/**
 * The CAS-1 verify procedure (spec section 6): credential, then (if given) mandate signature, window and scope,
 * then the mandate's anchor credential. Every chain read uses one pinned block.
 */
export async function verify(o: VerifyOptions): Promise<VerifyResult> {
	const source: "live" | "snapshot" = o?.snapshot !== undefined && o?.provider === undefined ? "snapshot" : "live";
	if (o.action !== undefined && o.mandate === undefined) return { valid: false, reason: "MALFORMED", step: "input", detail: "an action needs a mandate", source };
	let blockNumber = o.blockNumber;
	if (o.provider !== undefined && blockNumber === undefined) {
		try {
			blockNumber = fromQuantity(await o.provider.request({ method: "eth_blockNumber" }));
		} catch (e) {
			return { valid: false, reason: "PROVIDER_ERROR", step: "input", detail: (e as Error).message, source };
		}
	}
	const base: CredentialOptions = { trustedIssuers: o.trustedIssuers, provider: o.provider, snapshot: o.snapshot, blockNumber, subject: o.subject };
	const c = await verifyCredential(o.chainId, o.contract, o.credentialId, { ...base, kind: "KYA_REGISTERED" });
	if (!c.valid) return { valid: false, reason: c.reason, step: "credential", detail: c.detail, revokeReason: c.revokeReason, source, blockNumber: c.blockNumber };
	if (o.mandate === undefined) return { valid: true, reason: "VALID", step: "done", source, blockNumber: c.blockNumber };

	const m = verifyMandate(o.mandate.typedData, o.mandate.signature, { chainId: o.chainId, contract: o.contract, agent: o.subject, action: o.action, at: o.at });
	if (!m.valid) return { valid: false, reason: m.reason, step: "mandate", detail: m.detail, source, blockNumber: c.blockNumber, mandateDigest: m.digest };
	const msg = (o.mandate.typedData as { message: Mandate }).message;
	if (BigInt(msg.credentialId) !== parseId(o.credentialId)) return { valid: false, reason: "CREDENTIAL_MISMATCH", step: "mandate", source, blockNumber: c.blockNumber, mandateDigest: m.digest };

	const anchorId = mandateAnchorId(o.subject, m.digest!);
	const a = await verifyCredential(o.chainId, o.contract, anchorId, { ...base, kind: "TASK_MANDATE" });
	const at = { step: "anchor" as const, source, blockNumber: a.blockNumber, mandateDigest: m.digest, anchorId };
	if (a.reason === "NOT_FOUND") return { valid: false, reason: "MANDATE_NOT_ANCHORED", ...at };
	if (a.reason === "REVOKED" || a.reason === "UNLINKED") return { valid: false, reason: "MANDATE_REVOKED", revokeReason: a.revokeReason, ...at };
	if (!a.valid) return { valid: false, reason: a.reason, detail: a.detail, ...at };
	if (a.credential?.ref.toLowerCase() !== m.digest!.toLowerCase()) return { valid: false, reason: "INCONSISTENT_STATE", detail: "anchor ref is not the mandate digest", ...at };
	return { valid: true, reason: "VALID", ...at, step: "done" };
}
