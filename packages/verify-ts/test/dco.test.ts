// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.
// scripts/check-dco.mjs against fixture repositories built in a temp dir.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

type Check = (repoDir: string, base?: string) => { ok: boolean; errors: string[]; count: number };
const scriptUrl = new URL("../../../scripts/check-dco.mjs", import.meta.url).href;
const { checkDco } = (await import(scriptUrl)) as { checkDco: Check };

const ALICE = { name: "Alice Example", email: "alice@example.com" };
const MALLORY = { name: "Mallory Example", email: "mallory@example.com" };

function repo() {
	const dir = mkdtempSync(join(tmpdir(), "cas-dco-"));
	const git = (...a: string[]) => execFileSync("git", ["-C", dir, ...a], { encoding: "utf8" }).trim();
	git("init", "-q", "-b", "main");
	git("-c", `user.name=${ALICE.name}`, "-c", `user.email=${ALICE.email}`, "commit", "-q", "--allow-empty", "-m", "base", "-m", `Signed-off-by: ${ALICE.name} <${ALICE.email}>`);
	const base = git("rev-parse", "HEAD");
	return { dir, base, git };
}
function commitMsg(r: ReturnType<typeof repo>, who: { name: string; email: string }, msg: string): string {
	execFileSync("git", ["-C", r.dir, "-c", `user.name=${who.name}`, "-c", `user.email=${who.email}`, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-F", "-"], { input: msg });
	return r.git("rev-parse", "HEAD");
}
const sob = (w: { name: string; email: string }) => `Signed-off-by: ${w.name} <${w.email}>`;
const grant = (w: { name: string; email: string }, sha: string) => `I, ${w.name} <${w.email}>, hereby add my Signed-off-by to this commit: ${sha}`;
const remediation = (w: { name: string; email: string }, shas: string[]) =>
	`DCO Remediation Commit for ${w.name} <${w.email}>\n\n${shas.map((s) => grant(w, s)).join("\n")}\n\n${sob(w)}\n`;

test("signed-off commits pass", () => {
	const r = repo();
	commitMsg(r, ALICE, `one\n\n${sob(ALICE)}\n`);
	assert.deepEqual(checkDco(r.dir, r.base), { ok: true, errors: [], count: 1 });
});

test("an unsigned commit with no remediation fails", () => {
	const r = repo();
	const u = commitMsg(r, ALICE, "unsigned\n");
	const res = checkDco(r.dir, r.base);
	assert.equal(res.ok, false);
	assert.match(res.errors.join("\n"), new RegExp(u.slice(0, 12)));
});

test("a remediation naming every unsigned sha, by the same author and signed off, passes", () => {
	const r = repo();
	const u1 = commitMsg(r, ALICE, "unsigned one\n");
	const u2 = commitMsg(r, ALICE, "unsigned two\n");
	commitMsg(r, ALICE, remediation(ALICE, [u1, u2]));
	assert.equal(checkDco(r.dir, r.base).ok, true);
});

test("a partial remediation fails on the sha it leaves out", () => {
	const r = repo();
	const u1 = commitMsg(r, ALICE, "unsigned one\n");
	const u2 = commitMsg(r, ALICE, "unsigned two\n");
	commitMsg(r, ALICE, remediation(ALICE, [u1]));
	const res = checkDco(r.dir, r.base);
	assert.equal(res.ok, false);
	assert.equal(res.errors.length, 1);
	assert.match(res.errors[0]!, new RegExp(u2.slice(0, 12)));
});

test("a remediation by a different author fails, even when it names the right person", () => {
	const r = repo();
	const u = commitMsg(r, ALICE, "unsigned\n");
	commitMsg(r, MALLORY, `DCO Remediation Commit\n\n${grant(ALICE, u)}\n\n${sob(MALLORY)}\n`);
	assert.equal(checkDco(r.dir, r.base).ok, false);
	const r2 = repo();
	const u2 = commitMsg(r2, ALICE, "unsigned\n");
	commitMsg(r2, MALLORY, remediation(MALLORY, [u2])); // names Mallory, not the commit's author
	assert.equal(checkDco(r2.dir, r2.base).ok, false);
});

test("a remediation that is not itself signed off fails; a short sha does not count", () => {
	const r = repo();
	const u = commitMsg(r, ALICE, "unsigned\n");
	commitMsg(r, ALICE, `DCO Remediation Commit\n\n${grant(ALICE, u)}\n`);
	assert.equal(checkDco(r.dir, r.base).ok, false, "unsigned remediation");
	const r2 = repo();
	const u2 = commitMsg(r2, ALICE, "unsigned\n");
	commitMsg(r2, ALICE, `DCO Remediation Commit\n\n${grant(ALICE, u2.slice(0, 12))}\n\n${sob(ALICE)}\n`);
	assert.equal(checkDco(r2.dir, r2.base).ok, false, "short sha");
});
