// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// Live-read and input corner cases for verifyCredential: every failure path is a failure, never VALID.

import { test } from "node:test";
import assert from "node:assert/strict";
import { idFor, SELECTORS, verifyCredential, type Snapshot } from "../src/credential.ts";
import { mandateAnchorId } from "../src/mandate.ts";
import { fakeProvider, randomHash, throwawayKey } from "./helpers.ts";
import { idFor as idForTest } from "./vectors.ts";

const contract = throwawayKey().address;
const issuer = throwawayKey().address;
const subject = throwawayKey().address;
const ref = randomHash();
const id = idForTest(subject, 0, ref);
const snap = (over: Partial<Snapshot> = {}): Snapshot => ({
	spec: "cas-1.0",
	chainId: 84532,
	contract,
	blockNumber: 77,
	paused: false,
	credentials: { [id]: { subject, kind: "KYA_REGISTERED", status: "ISSUED", reason: "MANDATE_ENDED", issuedAt: 1, issuer, ref, contentHash: randomHash() } },
	...over,
});
const W = (n: bigint) => `0x${n.toString(16).padStart(64, "0")}`;
const live = (over: Parameters<typeof fakeProvider>[1] = {}, calls: string[] = []) =>
	verifyCredential(84532, contract, id, { trustedIssuers: [issuer], provider: fakeProvider(snap(), over, calls) });

test("baseline: live and snapshot both VALID, with the block number", async () => {
	const a = await live();
	assert.deepEqual([a.valid, a.reason, a.source, a.blockNumber], [true, "VALID", "live", 77]);
	const b = await verifyCredential(84532, contract, id, { trustedIssuers: [issuer], snapshot: snap() });
	assert.deepEqual([b.valid, b.reason, b.source, b.blockNumber], [true, "VALID", "snapshot", 77]);
	assert.equal(a.credential?.subject, subject);
});

test("every read is pinned to one block number", async () => {
	const tags: unknown[] = [];
	const p = fakeProvider(snap());
	const spy = { request: async (a: { method: string; params?: unknown[] }) => (a.params && tags.push(a.params[a.params.length - 1]), p.request(a)) };
	const r = await verifyCredential(84532, contract, id, { trustedIssuers: [issuer], provider: spy, blockNumber: 70 });
	assert.equal(r.reason, "VALID");
	assert.equal(r.blockNumber, 70);
	assert.equal(tags.length, 5);
	assert.ok(tags.every((t) => t === "0x46"), `tags ${JSON.stringify(tags)}`);
});

test("wrong chain, missing contract, provider errors", async () => {
	assert.equal((await live({ chainId: "0x1" })).reason, "WRONG_CHAIN");
	assert.equal((await live({ chainId: "84532" })).reason, "PROVIDER_ERROR");
	assert.equal((await live({ code: "0x" })).reason, "NO_CONTRACT");
	assert.equal((await live({ code: null })).reason, "NO_CONTRACT");
	assert.equal((await live({ block: "latest" })).reason, "PROVIDER_ERROR");
	const thrower = { request: async () => { throw new Error("rpc down"); } };
	const r = await verifyCredential(84532, contract, id, { trustedIssuers: [issuer], provider: thrower });
	assert.deepEqual([r.valid, r.reason, r.detail], [false, "PROVIDER_ERROR", "rpc down"]);
});

test("reads that disagree or are malformed are INCONSISTENT_STATE, never VALID", async () => {
	assert.equal((await live({ isValid: W(0n) })).reason, "INCONSISTENT_STATE");
	assert.equal((await live({ status: W(2n) })).reason, "INCONSISTENT_STATE");
	assert.equal((await live({ paused: W(2n) })).reason, "INCONSISTENT_STATE");
	assert.equal((await live({ isValid: "0x01" })).reason, "INCONSISTENT_STATE");
	assert.equal((await live({ status: W(4n) })).reason, "INCONSISTENT_STATE");
	assert.equal((await live({ credential: "0x" })).reason, "INCONSISTENT_STATE");
	// a record whose status word disagrees with isValid
	const lying = fakeProvider(snap({ paused: false }), { isValid: W(1n) });
	const s2 = snap();
	s2.credentials[id]!.status = "REVOKED";
	assert.equal((await verifyCredential(84532, contract, id, { trustedIssuers: [issuer], provider: fakeProvider(s2, { isValid: W(1n) }) })).reason, "INCONSISTENT_STATE");
	assert.equal((await verifyCredential(84532, contract, id, { trustedIssuers: [issuer], provider: lying })).reason, "VALID");
	// paused but isValid says true
	assert.equal((await verifyCredential(84532, contract, id, { trustedIssuers: [issuer], provider: fakeProvider(snap({ paused: true }), { isValid: W(1n) }) })).reason, "INCONSISTENT_STATE");
});

test("dirty words in the credential tuple are refused", async () => {
	const base = (await fakeProvider(snap()).request({
		method: "eth_call",
		params: [{ to: contract, data: `${SELECTORS.credential}${BigInt(id).toString(16).padStart(64, "0")}` }, "0x1"],
	})) as string;
	assert.equal((await live({ credential: base })).reason, "VALID"); // control: the untouched tuple passes
	const word = (i: number, v: string) => `0x${base.slice(2, 2 + i * 64)}${v}${base.slice(2 + (i + 1) * 64)}`;
	assert.equal((await live({ credential: word(0, `01${base.slice(4, 66)}`) })).reason, "INCONSISTENT_STATE"); // dirty address
	assert.equal((await live({ credential: word(1, W(4n).slice(2)) })).reason, "INCONSISTENT_STATE"); // kind out of range
	assert.equal((await live({ credential: word(2, W(4n).slice(2)) })).reason, "INCONSISTENT_STATE"); // status out of range
	assert.equal((await live({ credential: word(3, W(6n).slice(2)) })).reason, "INCONSISTENT_STATE"); // reason out of range
	assert.equal((await live({ credential: word(4, W(1n << 64n).slice(2)) })).reason, "INCONSISTENT_STATE"); // issuedAt > uint64
	assert.equal((await live({ credential: `${base}00` })).reason, "INCONSISTENT_STATE"); // trailing byte
});

test("input validation fails closed", async () => {
	const o = { trustedIssuers: [issuer], snapshot: snap() };
	assert.equal((await verifyCredential(84532, "0x1234", id, o)).reason, "MALFORMED");
	assert.equal((await verifyCredential(0, contract, id, o)).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, "-1", o)).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, "0x10", o)).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, (1n << 256n).toString(), o)).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, 1n << 256n, o)).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, id, { ...o, trustedIssuers: [] })).reason, "NO_TRUSTED_ISSUER");
	assert.equal((await verifyCredential(84532, contract, id, { ...o, trustedIssuers: ["nope"] })).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, id, { trustedIssuers: [issuer] })).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, id, { ...o, provider: fakeProvider(snap()) })).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, id, { ...o, subject: "x" })).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, id, { ...o, kind: "OTHER" as never })).reason, "MALFORMED");
	assert.equal((await verifyCredential(84532, contract, BigInt(id), o)).reason, "VALID");
});

test("snapshot validation: wrong contract, bad records, inherited keys", async () => {
	const v = (s: unknown) => verifyCredential(84532, contract, id, { trustedIssuers: [issuer], snapshot: s as Snapshot });
	assert.equal((await v({ ...snap(), spec: "cas-2.0" })).reason, "MALFORMED");
	assert.equal((await v({ ...snap(), contract: issuer })).reason, "MALFORMED");
	assert.equal((await v({ ...snap(), blockNumber: -1 })).reason, "MALFORMED");
	assert.equal((await v({ ...snap(), paused: "no" })).reason, "MALFORMED");
	assert.equal((await v({ ...snap(), credentials: null })).reason, "MALFORMED");
	assert.equal((await v({ ...snap(), credentials: { [id]: null } })).reason, "MALFORMED");
	const bad = snap();
	bad.credentials[id]!.status = "ACTIVE" as never;
	assert.equal((await v(bad)).reason, "MALFORMED");
	const bad2 = snap();
	bad2.credentials[id]!.ref = "0x12";
	assert.equal((await v(bad2)).reason, "MALFORMED");
	// a key on the prototype is not a record
	const proto = Object.create({ [id]: snap().credentials[id] });
	assert.equal((await v({ ...snap(), credentials: proto })).reason, "NOT_FOUND");
});

test("checksum-insensitive issuer and subject match; wrong subject and kind refused", async () => {
	const o = { trustedIssuers: [issuer.toLowerCase()], snapshot: snap() };
	assert.equal((await verifyCredential(84532, contract.toLowerCase(), id, { ...o, subject: subject.toUpperCase().replace("0X", "0x") })).reason, "VALID");
	assert.equal((await verifyCredential(84532, contract, id, { ...o, subject: issuer })).reason, "SUBJECT_MISMATCH");
	assert.equal((await verifyCredential(84532, contract, id, { ...o, kind: "TASK_MANDATE" })).reason, "WRONG_KIND");
});

test("a paused contract gives PAUSED, never REVOKED, with no revoke reason", async () => {
	for (const opts of [{ snapshot: snap({ paused: true }) }, { provider: fakeProvider(snap({ paused: true })) }]) {
		const r = await verifyCredential(84532, contract, id, { trustedIssuers: [issuer], ...opts });
		assert.deepEqual([r.valid, r.reason, r.revokeReason], [false, "PAUSED", undefined]);
		assert.equal(r.credential?.status, "ISSUED", "the record itself is untouched by the pause");
	}
});

test("a record that does not derive to its id is INVALID_ID, never VALID", async () => {
	const rec = snap().credentials[id]!;
	const other = throwawayKey().address;
	for (const bad of [{ ref: randomHash() }, { subject: other }, { kind: "ATTESTATION" as const }]) {
		const s = snap({ credentials: { [id]: { ...rec, ...bad } } });
		for (const opts of [{ snapshot: s }, { provider: fakeProvider(s) }]) {
			const r = await verifyCredential(84532, contract, id, { trustedIssuers: [issuer], ...opts });
			assert.deepEqual([r.valid, r.reason], [false, "INVALID_ID"], JSON.stringify(bad));
		}
	}
	// It is checked before revocation: a revoked record under the wrong id is still the wrong record.
	const rv = snap({ credentials: { [id]: { ...rec, ref: randomHash(), status: "REVOKED", reason: "MISUSE" } } });
	assert.equal((await verifyCredential(84532, contract, id, { trustedIssuers: [issuer], snapshot: rv })).reason, "INVALID_ID");
});

test("idFor matches the test derivation and mandateAnchorId, and checksum case does not matter", () => {
	assert.equal(idFor(subject, 0, ref), BigInt(id));
	assert.equal(idFor(subject.toLowerCase(), "KYA_REGISTERED", ref), BigInt(id));
	const digest = randomHash();
	assert.equal(idFor(subject, "TASK_MANDATE", digest).toString(), mandateAnchorId(subject, digest));
	assert.notEqual(idFor(subject, 1, ref), idFor(subject, 0, ref));
	assert.throws(() => idFor(subject, 4, ref));
	assert.throws(() => idFor("0x1", 0, ref));
	assert.throws(() => idFor(subject, 0, "0x00"));
});
