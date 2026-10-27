// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

// The committed vector file, as a pure function of a fixed public seed.

import { buildVectors } from "./vectors.ts";
import { withSeed } from "./helpers.ts";

/** Fixed public seed for the committed file. Changing it changes every key, address and signature in the file. */
export const VECTOR_SEED = "cas-1.0-verifier/conformance-vectors/seed-1";
export const VECTOR_FILE = new URL("../../../conformance/vectors/cas-1.0.json", import.meta.url);

export function renderVectorFile(): string {
	const file = {
		suite: "cas-1.0-verifier",
		spec: "cas-1.0",
		note: `Generated from the fixed public seed "${VECTOR_SEED}" (packages/verify-ts/test/vector-file.ts). The keys are public by construction, test-only and never funded. Addresses and signatures only.`,
		vectors: withSeed(VECTOR_SEED, buildVectors),
	};
	return `${JSON.stringify(file, null, "\t")}\n`;
}
