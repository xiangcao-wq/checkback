import type { KeyObject } from "node:crypto";
import { z } from "zod";
import { LiveDispatchIntentSchema } from "../live-shadow/contracts.ts";
import {
  publicKeyId,
  sha256Canonical,
  signCanonicalEd25519,
  verifyCanonicalEd25519,
} from "../live-shadow/crypto.ts";

const Hex64Schema = z.string().regex(/^[a-f0-9]{64}$/);
const Base64SignatureSchema = z
  .string()
  .regex(/^[A-Za-z0-9+/]{86}==$/)
  .superRefine((value, context) => {
    const decoded = Buffer.from(value, "base64");
    try {
      if (decoded.byteLength !== 64 || decoded.toString("base64") !== value) {
        context.addIssue({
          code: "custom",
          message: "Ed25519 signature must use canonical Base64",
        });
      }
    } finally {
      decoded.fill(0);
    }
  });
const DecimalStringSchema = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,17})$/);
const SafeIdentifierSchema = z
  .string()
  .min(1)
  .max(96)
  .regex(/^[A-Za-z0-9._-]+$/);
const HighEntropyIdentifierSchema = (prefix: string) =>
  z.string().regex(new RegExp(`^${prefix}_[a-f0-9]{64}$`));

export const REMOTE_ANCHOR_OPERATIONS = Object.freeze([
  "register_registry",
  "get_checkpoint",
  "acquire_session",
  "renew_session",
  "claim_authorization",
  "consume_slot",
  "release_session",
] as const);

export const RemoteAnchorOperationSchema = z.enum(REMOTE_ANCHOR_OPERATIONS);
export type RemoteAnchorOperation = z.infer<
  typeof RemoteAnchorOperationSchema
>;

export const RemoteAnchorServiceProfileSchema = z.enum([
  "offline_simulator",
  "production_external",
]);

export const RemoteAnchorCheckpointSchema = z
  .object({
    registry_sequence: DecimalStringSchema,
    registry_head_sha256: Hex64Schema,
    active_session_id: HighEntropyIdentifierSchema("session").nullable(),
    fencing_token: DecimalStringSchema,
    session_lease_expires_at_ms: DecimalStringSchema.nullable(),
  })
  .strict();

export type RemoteAnchorCheckpoint = z.infer<
  typeof RemoteAnchorCheckpointSchema
>;

const RemoteAnchorExecutionClaimSchema = z
  .object({
    execution_id: HighEntropyIdentifierSchema("exec"),
    media_scope_id: HighEntropyIdentifierSchema("scope"),
    pair_commitment_hmac_sha256: Hex64Schema,
  })
  .strict();

const RegisterRegistryBodySchema = z
  .object({
    operation: z.literal("register_registry"),
    enrollment_id: HighEntropyIdentifierSchema("enrollment"),
  })
  .strict();

const GetCheckpointBodySchema = z
  .object({
    operation: z.literal("get_checkpoint"),
  })
  .strict();

const AcquireSessionBodySchema = z
  .object({
    operation: z.literal("acquire_session"),
    session_id: HighEntropyIdentifierSchema("session"),
    requested_lease_ms: DecimalStringSchema,
  })
  .strict();

const RenewSessionBodySchema = z
  .object({
    operation: z.literal("renew_session"),
    session_id: HighEntropyIdentifierSchema("session"),
    fencing_token: DecimalStringSchema,
    requested_lease_ms: DecimalStringSchema,
  })
  .strict();

const ClaimAuthorizationBodySchema = z
  .object({
    operation: z.literal("claim_authorization"),
    session_id: HighEntropyIdentifierSchema("session"),
    fencing_token: DecimalStringSchema,
    authorization_id: HighEntropyIdentifierSchema("auth"),
    authorization_fingerprint_sha256: Hex64Schema,
    signed_consent_sha256: Hex64Schema,
    runtime_manifest_sha256: Hex64Schema,
    expires_at_ms: DecimalStringSchema,
    executions: z
      .array(RemoteAnchorExecutionClaimSchema)
      .min(1)
      .max(1_000)
      .readonly(),
  })
  .strict();

const ConsumeSlotBodySchema = z
  .object({
    operation: z.literal("consume_slot"),
    session_id: HighEntropyIdentifierSchema("session"),
    fencing_token: DecimalStringSchema,
    intent: LiveDispatchIntentSchema,
  })
  .strict();

const ReleaseSessionBodySchema = z
  .object({
    operation: z.literal("release_session"),
    session_id: HighEntropyIdentifierSchema("session"),
    fencing_token: DecimalStringSchema,
  })
  .strict();

export const RemoteAnchorOperationBodySchema = z.discriminatedUnion(
  "operation",
  [
    RegisterRegistryBodySchema,
    GetCheckpointBodySchema,
    AcquireSessionBodySchema,
    RenewSessionBodySchema,
    ClaimAuthorizationBodySchema,
    ConsumeSlotBodySchema,
    ReleaseSessionBodySchema,
  ],
);

export type RemoteAnchorOperationBody = z.infer<
  typeof RemoteAnchorOperationBodySchema
>;

export const RemoteAnchorRequestPayloadSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow.remote-anchor-request.v1",
    ),
    anchor_realm_id: HighEntropyIdentifierSchema("realm"),
    expected_service_profile: RemoteAnchorServiceProfileSchema,
    authority_registry_id: HighEntropyIdentifierSchema("registry"),
    authority_key_id: Hex64Schema,
    request_id: HighEntropyIdentifierSchema("anchorreq"),
    idempotency_key: HighEntropyIdentifierSchema("anchorop"),
    request_nonce_hex: Hex64Schema,
    operation: RemoteAnchorOperationSchema,
    issued_at_ms: DecimalStringSchema,
    expires_at_ms: DecimalStringSchema,
    expected_checkpoint: RemoteAnchorCheckpointSchema.nullable(),
    body: RemoteAnchorOperationBodySchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (value.operation !== value.body.operation) {
      context.addIssue({
        code: "custom",
        path: ["body", "operation"],
        message: "operation/body mismatch",
      });
    }
    const issuedAt = BigInt(value.issued_at_ms);
    const expiresAt = BigInt(value.expires_at_ms);
    if (expiresAt <= issuedAt || expiresAt - issuedAt > BigInt(60_000)) {
      context.addIssue({
        code: "custom",
        path: ["expires_at_ms"],
        message: "remote anchor request ttl invalid",
      });
    }
    if (
      value.operation === "register_registry" &&
      value.expected_checkpoint !== null
    ) {
      context.addIssue({
        code: "custom",
        path: ["expected_checkpoint"],
        message: "registration checkpoint must be null",
      });
    }
    if (
      value.operation !== "register_registry" &&
      value.operation !== "get_checkpoint" &&
      value.expected_checkpoint === null
    ) {
      context.addIssue({
        code: "custom",
        path: ["expected_checkpoint"],
        message: "mutation checkpoint required",
      });
    }
  });

export type RemoteAnchorRequestPayload = z.infer<
  typeof RemoteAnchorRequestPayloadSchema
>;

export const SignedRemoteAnchorRequestSchema = z
  .object({
    payload: RemoteAnchorRequestPayloadSchema,
    signature_algorithm: z.literal("Ed25519"),
    signature_base64: Base64SignatureSchema,
  })
  .strict();

export type SignedRemoteAnchorRequest = z.infer<
  typeof SignedRemoteAnchorRequestSchema
>;

export const RemoteAnchorTimeSchema = z
  .object({
    unix_ms: DecimalStringSchema,
    source_id: SafeIdentifierSchema,
    epoch_id: HighEntropyIdentifierSchema("timeepoch"),
    max_error_ms: DecimalStringSchema,
  })
  .strict();

export type RemoteAnchorTime = z.infer<typeof RemoteAnchorTimeSchema>;

export type RemoteAnchorRequestTimeStatus = "active" | "future" | "expired";

/**
 * The anchor makes decisions against the conservative upper edge of its
 * signed time interval. Every verifier must use this exact rule.
 */
export function remoteAnchorRequestTimeStatus(
  request: RemoteAnchorRequestPayload,
  anchorTime: RemoteAnchorTime,
): RemoteAnchorRequestTimeStatus {
  const issuedAt = BigInt(request.issued_at_ms);
  const expiresAt = BigInt(request.expires_at_ms);
  const upperBound =
    BigInt(anchorTime.unix_ms) + BigInt(anchorTime.max_error_ms);
  if (issuedAt > upperBound) return "future";
  if (expiresAt <= upperBound) return "expired";
  return "active";
}

export const RemoteAnchorReceiptPayloadSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow.remote-anchor-receipt.v1",
    ),
    anchor_mode: z.literal("remote_service"),
    service_profile: RemoteAnchorServiceProfileSchema,
    anchor_realm_id: HighEntropyIdentifierSchema("realm"),
    anchor_epoch_id: HighEntropyIdentifierSchema("anchorepoch"),
    anchor_key_id: Hex64Schema,
    authority_registry_id: HighEntropyIdentifierSchema("registry"),
    authority_key_id: Hex64Schema,
    request_id: HighEntropyIdentifierSchema("anchorreq"),
    idempotency_key: HighEntropyIdentifierSchema("anchorop"),
    request_nonce_sha256: Hex64Schema,
    signed_request_sha256: Hex64Schema,
    operation: RemoteAnchorOperationSchema,
    decision: z.enum(["committed", "observed", "rejected"]),
    error_code: SafeIdentifierSchema.nullable(),
    anchor_time: RemoteAnchorTimeSchema,
    global_sequence: DecimalStringSchema.nullable(),
    previous_registry_head_sha256: Hex64Schema.nullable(),
    registry_head_sha256: Hex64Schema.nullable(),
    object_key_sha256: Hex64Schema.nullable(),
    checkpoint_after: RemoteAnchorCheckpointSchema.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.decision === "rejected" && value.error_code === null) {
      context.addIssue({
        code: "custom",
        path: ["error_code"],
        message: "rejection code required",
      });
    }
    if (value.decision !== "rejected" && value.error_code !== null) {
      context.addIssue({
        code: "custom",
        path: ["error_code"],
        message: "non-rejection cannot carry an error",
      });
    }
    if (
      value.decision === "committed" &&
      (value.global_sequence === null ||
        value.previous_registry_head_sha256 === null ||
        value.registry_head_sha256 === null ||
        value.object_key_sha256 === null ||
        value.checkpoint_after === null)
    ) {
      context.addIssue({
        code: "custom",
        path: ["decision"],
        message: "committed receipt is incomplete",
      });
    }
    if (
      value.operation === "get_checkpoint" &&
      value.decision === "committed"
    ) {
      context.addIssue({
        code: "custom",
        path: ["decision"],
        message: "checkpoint reads cannot commit a mutation",
      });
    }
    if (
      value.operation !== "get_checkpoint" &&
      value.decision === "observed"
    ) {
      context.addIssue({
        code: "custom",
        path: ["decision"],
        message: "mutations cannot return an observed decision",
      });
    }
    if (
      value.decision === "observed" &&
      (value.global_sequence !== null ||
        value.previous_registry_head_sha256 !== null ||
        value.registry_head_sha256 === null ||
        value.object_key_sha256 === null ||
        value.checkpoint_after === null)
    ) {
      context.addIssue({
        code: "custom",
        path: ["decision"],
        message: "observed receipt is incomplete",
      });
    }
  });

export type RemoteAnchorReceiptPayload = z.infer<
  typeof RemoteAnchorReceiptPayloadSchema
>;

export const SignedRemoteAnchorReceiptSchema = z
  .object({
    payload: RemoteAnchorReceiptPayloadSchema,
    signature_algorithm: z.literal("Ed25519"),
    signature_base64: Base64SignatureSchema,
  })
  .strict();

export type SignedRemoteAnchorReceipt = z.infer<
  typeof SignedRemoteAnchorReceiptSchema
>;

export const REMOTE_ANCHOR_SIGNATURE_DOMAINS = Object.freeze({
  authority_request:
    "checkback.live-shadow.remote-anchor-authority-request-signature.v1",
  anchor_receipt:
    "checkback.live-shadow.remote-anchor-service-receipt-signature.v1",
});

export function signRemoteAnchorRequest(
  authorityPrivateKey: KeyObject,
  input: unknown,
): SignedRemoteAnchorRequest {
  const payload = RemoteAnchorRequestPayloadSchema.parse(input);
  if (payload.authority_key_id !== publicKeyId(authorityPrivateKey)) {
    throw new Error("remote_anchor_authority_signer_key_mismatch");
  }
  return SignedRemoteAnchorRequestSchema.parse({
    payload,
    signature_algorithm: "Ed25519",
    signature_base64: signCanonicalEd25519(
      authorityPrivateKey,
      REMOTE_ANCHOR_SIGNATURE_DOMAINS.authority_request,
      payload,
    ),
  });
}

export function verifyRemoteAnchorRequest(
  authorityPublicKey: KeyObject,
  input: unknown,
): SignedRemoteAnchorRequest {
  const envelope = SignedRemoteAnchorRequestSchema.parse(input);
  if (envelope.payload.authority_key_id !== publicKeyId(authorityPublicKey)) {
    throw new Error("remote_anchor_authority_key_mismatch");
  }
  if (
    !verifyCanonicalEd25519(
      authorityPublicKey,
      REMOTE_ANCHOR_SIGNATURE_DOMAINS.authority_request,
      envelope.payload,
      envelope.signature_base64,
    )
  ) {
    throw new Error("remote_anchor_authority_signature_invalid");
  }
  return envelope;
}

export function signRemoteAnchorReceipt(
  anchorPrivateKey: KeyObject,
  input: unknown,
): SignedRemoteAnchorReceipt {
  const payload = RemoteAnchorReceiptPayloadSchema.parse(input);
  if (payload.anchor_key_id !== publicKeyId(anchorPrivateKey)) {
    throw new Error("remote_anchor_receipt_signer_key_mismatch");
  }
  return SignedRemoteAnchorReceiptSchema.parse({
    payload,
    signature_algorithm: "Ed25519",
    signature_base64: signCanonicalEd25519(
      anchorPrivateKey,
      REMOTE_ANCHOR_SIGNATURE_DOMAINS.anchor_receipt,
      payload,
    ),
  });
}

export function verifyRemoteAnchorReceipt(
  anchorPublicKey: KeyObject,
  input: unknown,
): SignedRemoteAnchorReceipt {
  const envelope = SignedRemoteAnchorReceiptSchema.parse(input);
  if (envelope.payload.anchor_key_id !== publicKeyId(anchorPublicKey)) {
    throw new Error("remote_anchor_receipt_key_mismatch");
  }
  if (
    !verifyCanonicalEd25519(
      anchorPublicKey,
      REMOTE_ANCHOR_SIGNATURE_DOMAINS.anchor_receipt,
      envelope.payload,
      envelope.signature_base64,
    )
  ) {
    throw new Error("remote_anchor_receipt_signature_invalid");
  }
  return envelope;
}

export function remoteAnchorSignedRequestSha256(
  input: SignedRemoteAnchorRequest,
): string {
  return sha256Canonical(SignedRemoteAnchorRequestSchema.parse(input));
}

export function remoteAnchorReceiptSha256(
  input: SignedRemoteAnchorReceipt,
): string {
  return sha256Canonical(SignedRemoteAnchorReceiptSchema.parse(input));
}

export function decimalStringToBigInt(value: string): bigint {
  return BigInt(DecimalStringSchema.parse(value));
}

export function decimalStringToSafeInteger(value: string): number {
  const parsed = decimalStringToBigInt(value);
  const converted = Number(parsed);
  if (!Number.isSafeInteger(converted) || BigInt(converted) !== parsed) {
    throw new Error("remote_anchor_decimal_not_safe_integer");
  }
  return converted;
}

export function decimalString(value: bigint | number): string {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new Error("remote_anchor_decimal_not_safe_integer");
  }
  const normalized = typeof value === "number" ? BigInt(value) : value;
  if (normalized < BigInt(0) || normalized > BigInt("999999999999999999")) {
    throw new Error("remote_anchor_decimal_out_of_range");
  }
  return DecimalStringSchema.parse(normalized.toString());
}
