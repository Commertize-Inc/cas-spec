// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// DCO check: every commit in the range must carry a Signed-off-by line that names its author.
// Usage: node scripts/check-dco.mjs <base-ref>   (checks <base-ref>..HEAD; with no argument, every commit)
import { execFileSync } from "node:child_process";

const base = process.argv[2];
const range = base ? [`${base}..HEAD`] : ["HEAD"];
const out = execFileSync("git", ["log", "--format=%H%x00%an <%ae>%x00%B%x01", ...range], { encoding: "utf8" });
const commits = out.split("\x01").map((c) => c.trim()).filter(Boolean);
if (commits.length === 0) {
	console.error("check-dco: no commits in range");
	process.exit(1);
}
const bad = [];
for (const c of commits) {
	const [sha, author, body] = c.split("\x00");
	const lines = (body ?? "").split("\n").map((l) => l.trim());
	if (!lines.includes(`Signed-off-by: ${author}`)) bad.push(`${sha.slice(0, 12)} ${author}: no "Signed-off-by: ${author}" line`);
}
if (bad.length) {
	console.error(bad.join("\n"));
	console.error(`check-dco: ${bad.length} of ${commits.length} commit(s) not signed off (git commit -s)`);
	process.exit(1);
}
console.log(`check-dco: ok (${commits.length} commits)`);
