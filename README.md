# CAS: Commertize Agent Standard

> **DRAFT v0.** This is a working draft. Its text, data formats and verifier behaviour may change before a stable version; do not rely on it for production decisions.

CAS is what a software agent shows before it acts on a real asset or on someone else's behalf: a **credential** (who stands behind this agent), a signed **mandate** (what it may do) and **receipts** (what it did). Anyone can verify a credential and a mandate, with no key and no account, from chain state.

This repository holds the draft specification, a reference verifier and the conformance suite. Status: **DRAFT v0** (first draft release label: `v0.1.0-draft`). This repository publishes no credential contract address.

| Path | What it is | Licence |
|---|---|---|
| `spec/CAS-S1.md` | CAS-1 draft: credential, mandate (EIP-712), receipt, attestation, verify semantics, versioning, registry compatibility | CC-BY-4.0 (`spec/LICENSE`) |
| `packages/verify-ts` | `@commertize/cas-verify`, a TypeScript reference verifier. No runtime dependencies, no key, read-only | Apache-2.0 |
| `conformance/` | Verifier test vectors, receipt signature (secp256k1) vectors, and the badge rule | vectors Apache-2.0, README CC-BY-4.0 |

The specification and code are provided as is, without warranty (see the licences). A relying party decides for itself whom to trust and what to allow; CAS results are inputs to that decision, not advice.

## Quick look

```ts
import { verify } from "@commertize/cas-verify";

const result = await verify({
	chainId: 84532,                // Base Sepolia (testnet); no mainnet deployment exists
	contract: "0x...",             // the credential contract
	trustedIssuers: ["0x..."],     // you choose; there is no default
	provider,                      // any EIP-1193 provider you trust
	subject: "0x...",              // the agent wallet
	credentialId: "123...",
	mandate: { typedData, signature },
	action: { taskClass: "draft" },
});
// { valid: true, reason: "VALID", step: "done", ... } or the first failing reason
```

Use the package from a clone (see `packages/verify-ts/README.md`).

## Develop

Node 22.6 or later. No runtime dependencies; TypeScript and Node types are dev-only.

```bash
npm ci --ignore-scripts
npm run check:wording
npm run typecheck
npm test
```

## Contributing and security

Issues and pull requests are welcome; see `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`. Report vulnerabilities privately as described in `SECURITY.md`.

"Commertize", "Commertize Agent Standard" and the "CAS-1 Conformant" marks are trademarks of Commertize, Inc. No registration is claimed. See `NOTICE`.
