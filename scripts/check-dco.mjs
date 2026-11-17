// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// DCO check: every commit in the range must carry a Signed-off-by line that names its author, or be
// named by a remediation commit in the same range.
// Usage: node scripts/check-dco.mjs <base-ref>   (checks <base-ref>..HEAD; with no argument, every commit)
//
// Remediation (no history rewrite). A commit that is itself signed off by its author may add the
// author's sign-off to earlier commits, one line per commit, in this exact form:
//   I, <Name> <<email>>, hereby add my Signed-off-by to this commit: <full 40-hex sha>
// A line counts only when <Name> <<email>> is exactly the unsigned commit's author, the remediation
// commit's author email equals that email, and the named commit is in the checked range. Every
// unsigned commit must be covered, or the check fails.
import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

export function checkDco(repoDir, base) {
	const range = base ? [`${base}..HEAD`] : ["HEAD"];
	const out = execFileSync("git", ["-C", repoDir, "log", "--format=%H%x00%an <%ae>%x00%ae%x00%B%x01", ...range], { encoding: "utf8" });
	const commits = out
		.split("\x01")
		.map((c) => c.trim())
		.filter(Boolean)
		.map((c) => {
			const [sha, author, email, body] = c.split("\x00");
			return { sha, author, email, lines: (body ?? "").split("\n").map((l) => l.trim()) };
		});
	if (commits.length === 0) return { ok: false, errors: ["check-dco: no commits in range"], count: 0 };
	const signed = (c) => c.lines.includes(`Signed-off-by: ${c.author}`);
	// Remediation grants: sha -> set of "Name <email>" that a signed-off commit by that email vouched for.
	const granted = new Map();
	const RX = /^I, (.+ <[^<>\s]+>), hereby add my Signed-off-by to this commit: ([0-9a-f]{40})$/;
	for (const r of commits) {
		if (!signed(r)) continue;
		for (const l of r.lines) {
			const m = RX.exec(l);
			if (!m) continue;
			const who = m[1];
			if (!who.endsWith(`<${r.email}>`)) continue; // only the same author email may remediate
			if (!granted.has(m[2])) granted.set(m[2], new Set());
			granted.get(m[2]).add(who);
		}
	}
	const errors = [];
	for (const c of commits) {
		if (signed(c)) continue;
		if (granted.get(c.sha)?.has(c.author)) continue;
		errors.push(`${c.sha.slice(0, 12)} ${c.author}: no "Signed-off-by: ${c.author}" line and no matching remediation`);
	}
	return { ok: errors.length === 0, errors, count: commits.length };
}

// Resolve symlinks and percent-encode (spaces) before comparing, so the guard never silently skips.
const isMain = (() => {
	try {
		return !!process.argv[1] && pathToFileURL(realpathSync(process.argv[1])).href === pathToFileURL(realpathSync(fileURLToPath(import.meta.url))).href;
	} catch {
		return false;
	}
})();
if (isMain) {
	const r = checkDco(process.cwd(), process.argv[2]);
	if (!r.ok) {
		console.error(r.errors.join("\n"));
		if (r.count) console.error(`check-dco: ${r.errors.length} of ${r.count} commit(s) not signed off (git commit -s, or a DCO remediation commit)`);
		process.exit(1);
	}
	console.log(`check-dco: ok (${r.count} commits)`);
}
