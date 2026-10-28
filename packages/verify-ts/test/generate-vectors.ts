// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// Writes (or, with --check, compares) the committed vector files:
//   conformance/vectors/cas-1.0.json                    verifier vectors (addresses and signatures only)
//   conformance/vectors/cas-1.0-receipt-secp256k1.json  receipt signature vectors (section 5.1.1)
// Each file is generated from a fixed public seed, so anyone can regenerate it byte for byte. Keys derived
// from a public seed are public by construction: they are test keys, never funded, and must never hold
// anything. Neither file holds a private key: the receipt file names each signer by its index in the
// seeded key stream (conformance/README.md says how to derive it).
// Usage (from the repository root):
//   node --experimental-strip-types packages/verify-ts/test/generate-vectors.ts          write the files
//   node --experimental-strip-types packages/verify-ts/test/generate-vectors.ts --check  exit 1 on any byte difference

import { readFileSync, writeFileSync } from "node:fs";
import { renderReceiptVectorFile, renderVectorFile, RECEIPT_VECTOR_FILE, VECTOR_FILE } from "./vector-file.ts";

const files: [URL, string][] = [
	[VECTOR_FILE, renderVectorFile()],
	[RECEIPT_VECTOR_FILE, renderReceiptVectorFile()],
];
let failed = false;
for (const [file, want] of files) {
	const name = file.pathname.split("/").slice(-2).join("/");
	if (process.argv.includes("--check")) {
		let have: string;
		try {
			have = readFileSync(file, "utf8");
		} catch (e) {
			console.error(`vectors:check: cannot read ${name}: ${(e as Error).message}`);
			failed = true;
			continue;
		}
		if (have !== want) {
			const a = have.split("\n");
			const b = want.split("\n");
			let i = 0;
			while (i < a.length && i < b.length && a[i] === b[i]) i++;
			console.error(`vectors:check: ${name} differs from a fresh regeneration at line ${i + 1}`);
			console.error(`  committed:   ${(a[i] ?? "<end of file>").slice(0, 160)}`);
			console.error(`  regenerated: ${(b[i] ?? "<end of file>").slice(0, 160)}`);
			console.error("Run `npm run vectors` and commit the result in its own commit.");
			failed = true;
			continue;
		}
		console.log(`vectors:check: ${name} ok (${Buffer.byteLength(want)} bytes, byte-identical)`);
	} else {
		writeFileSync(file, want);
		console.log(`wrote ${name}: ${JSON.parse(want).vectors.length} vectors`);
	}
}
if (failed) process.exit(1);
