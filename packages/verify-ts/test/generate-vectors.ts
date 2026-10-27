// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// Writes (or, with --check, compares) conformance/vectors/cas-1.0.json.
// The file is generated from a fixed public seed, so anyone can regenerate it byte for byte. Keys derived
// from a public seed are public by construction: they are test keys, never funded, and must never hold
// anything. The file itself holds addresses and signatures only, never a private key.
// Usage (from the repository root):
//   node --experimental-strip-types packages/verify-ts/test/generate-vectors.ts          write the file
//   node --experimental-strip-types packages/verify-ts/test/generate-vectors.ts --check  exit 1 on any byte difference

import { readFileSync, writeFileSync } from "node:fs";
import { renderVectorFile, VECTOR_FILE } from "./vector-file.ts";

const want = renderVectorFile();
if (process.argv.includes("--check")) {
	let have: string;
	try {
		have = readFileSync(VECTOR_FILE, "utf8");
	} catch (e) {
		console.error(`vectors:check: cannot read the committed file: ${(e as Error).message}`);
		process.exit(1);
	}
	if (have !== want) {
		const a = have.split("\n");
		const b = want.split("\n");
		let i = 0;
		while (i < a.length && i < b.length && a[i] === b[i]) i++;
		console.error(`vectors:check: committed file differs from a fresh regeneration at line ${i + 1}`);
		console.error(`  committed:   ${(a[i] ?? "<end of file>").slice(0, 160)}`);
		console.error(`  regenerated: ${(b[i] ?? "<end of file>").slice(0, 160)}`);
		console.error("Run `npm run vectors` and commit the result in its own commit.");
		process.exit(1);
	}
	console.log(`vectors:check: ok (${Buffer.byteLength(want)} bytes, byte-identical)`);
} else {
	writeFileSync(VECTOR_FILE, want);
	console.log(`wrote ${JSON.parse(want).vectors.length} vectors`);
}
