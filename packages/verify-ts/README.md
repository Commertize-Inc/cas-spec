# @commertize/cas-verify

Reference verifier for CAS-1 (Commertize Agent Standard, draft `cas-1.0`). It checks a credential's live status, and a principal-signed EIP-712 mandate's signature, window, scope and on-chain anchor.

- **Read-only.** It never signs, holds no key and sends no transaction. The only RPC methods it calls are `eth_chainId`, `eth_blockNumber`, `eth_getCode` and `eth_call`.
- **Your provider, your issuers.** You pass any EIP-1193 provider and your own trusted-issuer list. It calls no Commertize service.
- **No runtime dependencies.** Keccak-256, secp256k1 recovery and EIP-712 hashing are written out in `src/` and pinned by tests to published values and to `node:crypto`.
- **Fail closed.** Every error path gives a reason code, never `VALID`.

## API

| Function | What it does |
|---|---|
| `verify(options)` | The full procedure of spec section 6: credential, then mandate, then the mandate's anchor, all at one pinned block |
| `verifyCredential(chainId, contract, id, { trustedIssuers, provider \| snapshot, subject?, kind?, blockNumber? })` | One credential, live or from a snapshot |
| `verifyMandate(typedData, signature, { chainId, contract, agent?, action?, at? })` | Offline mandate checks: type, domain, signer, window, spend cap, scope. Does not read the chain |
| `allows(mandate, action)` | The scope check alone |
| `mandateAnchorId(agent, digest)` | The id of the anchor credential, `idFor(agent, TASK_MANDATE, digest)` |
| `CREDENTIAL_INTERFACE`, `SELECTORS` | The read interface this package calls |

Offline mode: pass `snapshot` instead of `provider` (shape in spec section 6.4). The result says `source: "snapshot"` and carries the snapshot's block number.

## From a clone

```bash
node --experimental-strip-types --conditions=source your-script.ts
```

with `import { verify } from "./packages/verify-ts/src/index.ts"`.

## What it does not do

It does not resolve registry aliases to wallets, evaluate attestations, validate receipts or verify contract-wallet (ERC-1271) signatures. Those are listed in the spec as later work or as out of scope.
