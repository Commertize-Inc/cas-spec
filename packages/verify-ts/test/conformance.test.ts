// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// The CAS-1 verifier conformance suite: every vector, offline (snapshot) and live (the same state behind a fake provider).
// Runs the committed file and a freshly generated set with new throwaway keys.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verify } from "../src/credential.ts";
import { buildVectors, type Vector } from "./vectors.ts";
import { fakeProvider } from "./helpers.ts";
import { renderVectorFile, VECTOR_FILE } from "./vector-file.ts";

const committed = JSON.parse(readFileSync(new URL("../../../conformance/vectors/cas-1.0.json", import.meta.url), "utf8")) as { suite: string; spec: string; vectors: Vector[] };

async function run(v: Vector, mode: "snapshot" | "live") {
	const { snapshot, liveReads, ...rest } = v.input;
	// liveReads values are returned encoded as one uint256 word (bool as 0/1), as the contract would.
	const w = (n: number) => `0x${n.toString(16).padStart(64, "0")}`;
	const reads = Object.fromEntries(Object.entries(liveReads ?? {}).map(([k, v]) => [k, w(typeof v === "boolean" ? Number(v) : v)]));
	const r = await verify(mode === "snapshot" ? { ...rest, snapshot } : { ...rest, provider: fakeProvider(snapshot, reads) });
	const got = { valid: r.valid, reason: r.reason, step: r.step, ...(r.revokeReason ? { revokeReason: r.revokeReason } : {}) };
	assert.deepEqual(got, v.expect, `${v.name} (${mode}): ${r.detail ?? ""}`);
	assert.equal(r.source, mode);
}

test("committed vector file: header and coverage", () => {
	assert.equal(committed.suite, "cas-1.0-verifier");
	assert.equal(committed.spec, "cas-1.0");
	const names = committed.vectors.map((v) => v.name);
	assert.equal(new Set(names).size, names.length, "vector names are unique");
	const reasons = new Set(committed.vectors.map((v) => v.expect.reason));
	for (const r of ["VALID", "NOT_FOUND", "REVOKED", "UNLINKED", "PAUSED", "INVALID_ID", "UNTRUSTED_ISSUER", "NO_TRUSTED_ISSUER", "SUBJECT_MISMATCH", "WRONG_KIND", "WRONG_CHAIN", "PRINCIPAL_MISMATCH", "BAD_SIGNATURE", "WRONG_DOMAIN", "UNSUPPORTED_VERSION", "UNSUPPORTED_SPEND_CAP", "NOT_YET_VALID", "EXPIRED", "SCOPE_DENIED", "CREDENTIAL_MISMATCH", "MANDATE_NOT_ANCHORED", "MANDATE_REVOKED", "MALFORMED", "INCONSISTENT_STATE", "NOT_A_CREDENTIAL"])
		assert.ok(reasons.has(r as never), `a vector expects ${r}`);
	assert.ok(!JSON.stringify(committed).match(/priv/i), "no private key material in the file");
	// A pause is its own result: every PAUSED vector carries no revoke reason.
	const paused = committed.vectors.filter((v) => v.expect.reason === "PAUSED");
	assert.ok(paused.length >= 3, "paused credential, paused mandate, revoked anchor while paused");
	for (const v of paused) assert.equal(v.expect.revokeReason, undefined, v.name);
	// Revoke-by-digest: a TASK_MANDATE at idFor(agent, 1, digest) revoked with each reason.
	const byDigest = committed.vectors.filter((v) => v.name.startsWith("mandate-revoked-"));
	assert.equal(byDigest.length, 6, "one revoke-by-digest vector per revocation reason");
	for (const v of byDigest) assert.deepEqual([v.expect.reason, v.expect.step], ["MANDATE_REVOKED", "anchor"], v.name);
	// liveReads only ever appear on live-only cases (a snapshot cannot disagree with itself).
	for (const v of committed.vectors) if (v.input.liveReads) assert.deepEqual(v.modes, ["live"], v.name);
	// The generator and the committed file name the same vectors.
	assert.deepEqual(names, buildVectors().map((v) => v.name));
});

test("committed vector file is byte-identical to a regeneration from the fixed seed", () => {
	assert.equal(readFileSync(VECTOR_FILE, "utf8"), renderVectorFile());
	// And the seed is what makes it reproducible: two renders agree, a fresh random build does not.
	assert.equal(renderVectorFile(), renderVectorFile());
	assert.notDeepEqual(buildVectors()[0]!.input.contract, JSON.parse(renderVectorFile()).vectors[0].input.contract);
});

for (const v of committed.vectors) {
	for (const mode of v.modes ?? (["snapshot", "live"] as const)) test(`vector ${v.name} (${mode})`, () => run(v, mode));
}

test("fresh vectors with new throwaway keys pass in every listed mode", async () => {
	for (const v of buildVectors()) for (const mode of v.modes ?? (["snapshot", "live"] as const)) await run(v, mode);
});
