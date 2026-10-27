// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// verifyMandate and allows: shape, domain and scope corner cases with real signatures from throwaway keys.

import { test } from "node:test";
import assert from "node:assert/strict";
import { allows, mandateAnchorId, verifyMandate, type Mandate } from "../src/mandate.ts";
import { typedDataDigest } from "../src/eip712.ts";
import { bytesToHex } from "../src/hex.ts";
import { mandateTypedData, randomHash, signTyped, throwawayKey } from "./helpers.ts";
import { idFor } from "./vectors.ts";

const CHAIN = 84532;
const contract = throwawayKey().address;
const principal = throwawayKey();
const agent = throwawayKey().address;
const cp = throwawayKey().address;
const AT = 1_800_000_000;
const M = (over: Partial<Mandate> = {}): Mandate => ({
	schema: "cas-1.0",
	principal: principal.address,
	agent,
	credentialId: "7",
	taskClasses: ["read"],
	assetClasses: ["real-estate"],
	counterparties: [cp],
	spendCap: "0",
	validAfter: AT - 10,
	validBefore: AT + 10,
	nonce: randomHash(),
	...over,
});
const check = (m: Mandate, opts: Partial<Parameters<typeof verifyMandate>[2]> = {}, mutate?: (td: ReturnType<typeof mandateTypedData>) => void) => {
	const td = mandateTypedData(CHAIN, contract, m);
	const sig = signTyped(td, principal);
	mutate?.(td);
	return verifyMandate(td, sig, { chainId: CHAIN, contract, at: AT, ...opts });
};

test("valid mandate: signer, digest, and the anchor id equals idFor(agent, TASK_MANDATE, digest)", () => {
	const m = M();
	const r = check(m, { agent, action: { taskClass: "read" } });
	assert.deepEqual([r.valid, r.reason], [true, "VALID"]);
	assert.equal(r.signer, principal.address.toLowerCase());
	assert.equal(r.digest, bytesToHex(typedDataDigest(mandateTypedData(CHAIN, contract, m))));
	assert.equal(mandateAnchorId(agent, r.digest!), idFor(agent, 1, r.digest!));
	assert.notEqual(mandateAnchorId(agent, r.digest!), idFor(agent, 0, r.digest!));
	// chainId as a decimal string in the domain hashes the same and passes
	assert.equal(check(m, {}, (td) => (td.domain.chainId = String(CHAIN))).reason, "VALID");
});

test("malformed shapes are refused before any signature work", () => {
	const bad: [Partial<Mandate>, RegExp][] = [
		[{ taskClasses: [] }, /taskClasses must not be empty/],
		[{ taskClasses: ["Read"] }, /class names/],
		[{ taskClasses: ["read", "read"] }, /duplicate/],
		[{ counterparties: [cp, cp.toLowerCase() as never] }, /duplicate/],
		[{ credentialId: "07" }, /credentialId/],
		[{ spendCap: "-1" }, /spendCap/],
		[{ validBefore: AT - 10 }, /after validAfter/],
		[{ validAfter: -1 }, /uint64/],
		[{ validBefore: (1n << 64n).toString() }, /uint64/],
		[{ agent: "0x0000000000000000000000000000000000000000" }, /zero address/],
	];
	for (const [over, re] of bad) {
		const td = mandateTypedData(CHAIN, contract, M(over));
		const r = verifyMandate(td, `0x${"11".repeat(65)}`, { chainId: CHAIN, contract, at: AT });
		assert.equal(r.reason, "MALFORMED", JSON.stringify(over));
		assert.match(r.detail ?? "", re);
	}
	const extra = mandateTypedData(CHAIN, contract, { ...M(), note: "x" } as never);
	assert.equal(verifyMandate(extra, `0x${"11".repeat(65)}`, { chainId: CHAIN, contract, at: AT }).reason, "MALFORMED");
	assert.equal(verifyMandate(null, "0x", { chainId: CHAIN, contract }).reason, "MALFORMED");
	const td = mandateTypedData(CHAIN, contract, M());
	assert.equal(verifyMandate({ ...td, primaryType: "Mail" }, "0x", { chainId: CHAIN, contract }).reason, "MALFORMED");
	assert.equal(verifyMandate({ ...td, types: { ...td.types, Extra: [] } }, "0x", { chainId: CHAIN, contract }).reason, "MALFORMED");
});

test("domain must be exactly the CAS Mandate domain for this chain and contract", () => {
	assert.equal(check(M(), {}, (td) => (td.domain.name = "Other")).reason, "WRONG_DOMAIN");
	assert.equal(check(M(), {}, (td) => (td.domain.version = "2")).reason, "WRONG_DOMAIN");
	assert.equal(check(M(), {}, (td) => (td.domain.salt = randomHash())).reason, "WRONG_DOMAIN");
	assert.equal(check(M(), {}, (td) => delete td.domain.verifyingContract).reason, "WRONG_DOMAIN");
	assert.equal(check(M(), { chainId: 1 }).reason, "WRONG_DOMAIN");
	assert.equal(check(M(), { contract: cp }).reason, "WRONG_DOMAIN");
	assert.equal(check(M(), {}, (td) => (td.domain.chainId = "abc")).reason, "WRONG_DOMAIN");
});

test("signature failures", () => {
	assert.equal(check(M(), {}, () => undefined).reason, "VALID");
	const td = mandateTypedData(CHAIN, contract, M());
	assert.equal(verifyMandate(td, "nothex", { chainId: CHAIN, contract, at: AT }).reason, "BAD_SIGNATURE");
	assert.equal(verifyMandate(td, `0x${"00".repeat(65)}`, { chainId: CHAIN, contract, at: AT }).reason, "BAD_SIGNATURE");
	const other = throwawayKey();
	assert.equal(verifyMandate(td, signTyped(td, other), { chainId: CHAIN, contract, at: AT }).reason, "PRINCIPAL_MISMATCH");
	assert.equal(check(M(), { agent: cp }).reason, "SUBJECT_MISMATCH");
});

test("window bounds: validAfter inclusive, validBefore exclusive", () => {
	assert.equal(check(M(), { at: AT - 11 }).reason, "NOT_YET_VALID");
	assert.equal(check(M(), { at: AT - 10 }).reason, "VALID");
	assert.equal(check(M(), { at: AT + 9 }).reason, "VALID");
	assert.equal(check(M(), { at: AT + 10 }).reason, "EXPIRED");
});

test("spend cap: v1 refuses any non-zero cap; amount above cap is denied", () => {
	assert.equal(check(M({ spendCap: "1" })).reason, "UNSUPPORTED_SPEND_CAP");
	assert.equal(check(M(), { action: { taskClass: "read", amount: "0" } }).reason, "VALID");
	assert.equal(check(M(), { action: { taskClass: "read", amount: "1" } }).reason, "SCOPE_DENIED");
	// allows() itself compares integers, not strings ("10" > "9")
	const m = M({ spendCap: "9" });
	assert.deepEqual(allows(m, { taskClass: "read", amount: "9" }), { ok: true });
	assert.equal(allows(m, { taskClass: "read", amount: "10" }).ok, false);
	assert.equal(allows(m, { taskClass: "read", amount: "1.5" }).ok, false);
	assert.equal(allows(m, { taskClass: "read", amount: "-1" }).ok, false);
});

test("allows(): every element must be granted; empty lists grant nothing", () => {
	const m = M({ taskClasses: ["read", "draft"] });
	assert.equal(allows(m, { taskClass: "draft", assetClass: "real-estate", counterparty: cp.toLowerCase() }).ok, true);
	assert.equal(allows(m, { taskClass: "file" }).ok, false);
	assert.equal(allows(m, { taskClass: "draft", assetClass: "compute" }).ok, false);
	assert.equal(allows(m, { taskClass: "draft", counterparty: agent }).ok, false);
	assert.equal(allows(m, { taskClass: "draft", counterparty: "0x12" }).ok, false);
	const empty = M({ assetClasses: [], counterparties: [] });
	assert.equal(allows(empty, { taskClass: "read" }).ok, true);
	assert.equal(allows(empty, { taskClass: "read", assetClass: "real-estate" }).ok, false);
	assert.equal(allows(empty, { taskClass: "read", counterparty: cp }).ok, false);
	assert.equal(allows(m, null as never).ok, false);
	assert.equal(allows(m, { taskClass: 1 as never }).ok, false);
});
