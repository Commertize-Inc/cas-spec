// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Commertize, Inc.

export {
	verify,
	verifyCredential,
	CREDENTIAL_INTERFACE,
	SELECTORS,
	KINDS,
	STATUSES,
	REVOKE_REASONS,
	type Provider,
	type Snapshot,
	type CredentialRecord,
	type CredentialOptions,
	type CredentialResult,
	type CredentialReason,
	type VerifyOptions,
	type VerifyResult,
	type VerifyReason,
	idFor,
	type Kind,
	type Status,
	type RevokeReason,
} from "./credential.ts";
export {
	verifyMandate,
	allows,
	mandateAnchorId,
	MANDATE_TYPE,
	MANDATE_DOMAIN_NAME,
	MANDATE_DOMAIN_VERSION,
	SPEC_VERSION,
	type Mandate,
	type Action,
	type MandateOptions,
	type MandateResult,
	type MandateReason,
} from "./mandate.ts";
export { typedDataDigest, hashStruct, encodeType, type TypedData } from "./eip712.ts";
export { recoverAddress } from "./secp256k1.ts";
export {
	verifyReceiptSecp256k1,
	receiptMessage,
	receiptDigest,
	base64urlEncode,
	RECEIPT_SIGNING_PREFIX,
	type ReceiptSignature,
	type ReceiptSignatureReason,
	type AgentKeyCredential,
	type ChainPosition,
} from "./receipt.ts";
export { keccak256 } from "./keccak.ts";
export { toChecksumAddress, isAddress } from "./hex.ts";
