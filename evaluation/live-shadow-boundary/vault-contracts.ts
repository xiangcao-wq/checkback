import type { KeyObject } from "node:crypto";
import { z } from "zod";
import {
  canonicalJson,
  publicKeyId,
  sha256Bytes,
  signCanonicalEd25519,
  verifyCanonicalEd25519,
} from "../live-shadow/crypto.ts";

const MAX_OBJECT_BYTES = 32 * 1024 * 1024;
const MAX_BASE64_OBJECT_LENGTH = Math.ceil(MAX_OBJECT_BYTES / 3) * 4;

const Hex64Schema = z.string().regex(/^[a-f0-9]{64}$/);
const TimestampSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const HighEntropyIdentifierSchema = (prefix: string) =>
  z.string().regex(new RegExp(`^${prefix}_[a-f0-9]{64}$`));

function canonicalBase64Schema(maxLength: number) {
  return z
    .string()
    .min(4)
    .max(maxLength)
    .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/)
    .refine(
      (value) => {
        const decoded = Buffer.from(value, "base64");
        try {
          return decoded.toString("base64") === value;
        } finally {
          decoded.fill(0);
        }
      },
      { message: "base64 must use its canonical representation" },
    );
}

function decodedBase64Length(value: string): number {
  const decoded = Buffer.from(value, "base64");
  try {
    return decoded.byteLength;
  } finally {
    decoded.fill(0);
  }
}

const Base64NonceSchema = canonicalBase64Schema(16).refine(
  (value) => decodedBase64Length(value) === 12,
  { message: "AES-GCM nonce must be exactly 96 bits" },
);
const Base64TagSchema = canonicalBase64Schema(24).refine(
  (value) => decodedBase64Length(value) === 16,
  { message: "AES-GCM authentication tag must be exactly 128 bits" },
);
const Base64SignatureSchema = canonicalBase64Schema(88).refine(
  (value) => decodedBase64Length(value) === 64,
  { message: "Ed25519 signature must be exactly 64 bytes" },
);
const Base64CiphertextSchema = canonicalBase64Schema(MAX_BASE64_OBJECT_LENGTH);

export const VaultMediaPartSchema = z.enum(["reference", "comparison"]);
export type VaultMediaPart = z.infer<typeof VaultMediaPartSchema>;

/**
 * This object is the complete, canonical AES-GCM AAD claim. Adding a field to
 * the contract is intentionally a schema-version change, not an optional hint.
 */
export const VaultObjectBindingSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.vault-object-binding.v1"),
    authorization_fingerprint_sha256: Hex64Schema,
    execution_id: HighEntropyIdentifierSchema("exec"),
    media_scope_id: HighEntropyIdentifierSchema("scope"),
    pair_commitment_hmac_sha256: Hex64Schema,
    preprocessing_config_sha256: Hex64Schema,
    part: VaultMediaPartSchema,
    plaintext_length: z.number().int().min(1).max(MAX_OBJECT_BYTES),
    delete_by_ms: TimestampSchema,
  })
  .strict();

export type VaultObjectBinding = z.infer<typeof VaultObjectBindingSchema>;

export const VAULT_AAD_DOMAIN =
  "checkback.live-shadow.vault-object-aad.v1" as const;
export const VAULT_DELETION_RECEIPT_SIGNATURE_DOMAIN =
  "checkback.live-shadow.vault-key-destruction-receipt-signature.v1" as const;

/** The returned buffer belongs to the caller and must be zeroized after use. */
export function canonicalVaultAad(input: unknown): Buffer {
  const binding = VaultObjectBindingSchema.parse(input);
  const domain = Buffer.from(VAULT_AAD_DOMAIN, "utf8");
  const separator = Buffer.from([0]);
  const payload = Buffer.from(canonicalJson(binding), "utf8");
  try {
    return Buffer.concat([domain, separator, payload]);
  } finally {
    domain.fill(0);
    separator.fill(0);
    payload.fill(0);
  }
}

export function vaultAadSha256(input: unknown): string {
  const aad = canonicalVaultAad(input);
  try {
    return sha256Bytes(aad);
  } finally {
    aad.fill(0);
  }
}

export const VaultSealedObjectSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.vault-sealed-object.v1"),
    custody_mode: z.literal("offline_local_fake"),
    custody_id: HighEntropyIdentifierSchema("custody"),
    object_id: HighEntropyIdentifierSchema("vaultobj"),
    object_key_id: HighEntropyIdentifierSchema("vkey"),
    cipher_suite: z.literal("AES-256-GCM"),
    binding: VaultObjectBindingSchema,
    aad_sha256: Hex64Schema,
    nonce_base64: Base64NonceSchema,
    authentication_tag_base64: Base64TagSchema,
    ciphertext_base64: Base64CiphertextSchema,
    created_at_ms: TimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (value.created_at_ms >= value.binding.delete_by_ms) {
      context.addIssue({
        code: "custom",
        path: ["created_at_ms"],
        message: "object must be created before its deletion deadline",
      });
    }
    if (decodedBase64Length(value.ciphertext_base64) !== value.binding.plaintext_length) {
      context.addIssue({
        code: "custom",
        path: ["ciphertext_base64"],
        message: "ciphertext length must equal the bound plaintext length for GCM",
      });
    }
    if (value.aad_sha256 !== vaultAadSha256(value.binding)) {
      context.addIssue({
        code: "custom",
        path: ["aad_sha256"],
        message: "AAD hash does not match the canonical binding",
      });
    }
  });

export type VaultSealedObject = z.infer<typeof VaultSealedObjectSchema>;

export const VaultDeletionReasonSchema = z.enum([
  "retention_deadline",
  "authorization_revoked",
  "test_cleanup",
]);
export type VaultDeletionReason = z.infer<typeof VaultDeletionReasonSchema>;

export const VaultDeletionReceiptPayloadSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow.vault-key-destruction-receipt.v1",
    ),
    custody_mode: z.literal("offline_local_fake"),
    custody_id: HighEntropyIdentifierSchema("custody"),
    custody_receipt_key_id: Hex64Schema,
    receipt_id: HighEntropyIdentifierSchema("delreceipt"),
    object_id: HighEntropyIdentifierSchema("vaultobj"),
    object_key_id: HighEntropyIdentifierSchema("vkey"),
    binding: VaultObjectBindingSchema,
    aad_sha256: Hex64Schema,
    nonce_sha256: Hex64Schema,
    claim_type: z.literal("object_key_cryptographic_erasure"),
    claim_scope: z.literal("object_key_only"),
    object_key_state: z.literal("destroyed"),
    erasure_method: z.literal("in_memory_aes256_key_zeroized"),
    reason: VaultDeletionReasonSchema,
    destroyed_at_ms: TimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.reason === "retention_deadline" &&
      value.destroyed_at_ms < value.binding.delete_by_ms
    ) {
      context.addIssue({
        code: "custom",
        path: ["destroyed_at_ms"],
        message: "retention deadline destruction cannot be recorded early",
      });
    }
    if (value.aad_sha256 !== vaultAadSha256(value.binding)) {
      context.addIssue({
        code: "custom",
        path: ["aad_sha256"],
        message: "receipt AAD hash does not match the canonical binding",
      });
    }
  });

export type VaultDeletionReceiptPayload = z.infer<
  typeof VaultDeletionReceiptPayloadSchema
>;

export const VaultDeletionReceiptSchema = z
  .object({
    payload: VaultDeletionReceiptPayloadSchema,
    signer_key_id: Hex64Schema,
    signature_base64: Base64SignatureSchema,
  })
  .strict();

export type VaultDeletionReceipt = z.infer<typeof VaultDeletionReceiptSchema>;

export const VaultObjectKeyInspectionSchema = z.discriminatedUnion("state", [
  z
    .object({
      schema_version: z.literal(
        "checkback.live-shadow.vault-key-inspection.v1",
      ),
      custody_mode: z.literal("offline_local_fake"),
      custody_id: HighEntropyIdentifierSchema("custody"),
      object_id: HighEntropyIdentifierSchema("vaultobj"),
      object_key_id: HighEntropyIdentifierSchema("vkey"),
      state: z.literal("active"),
      key_material_exposed: z.literal(false),
      binding_sha256: Hex64Schema,
      aad_sha256: Hex64Schema,
      nonce_sha256: Hex64Schema,
      created_at_ms: TimestampSchema,
      delete_by_ms: TimestampSchema,
      destroyed_at_ms: z.null(),
    })
    .strict(),
  z
    .object({
      schema_version: z.literal(
        "checkback.live-shadow.vault-key-inspection.v1",
      ),
      custody_mode: z.literal("offline_local_fake"),
      custody_id: HighEntropyIdentifierSchema("custody"),
      object_id: HighEntropyIdentifierSchema("vaultobj"),
      object_key_id: HighEntropyIdentifierSchema("vkey"),
      state: z.literal("destroyed"),
      key_material_exposed: z.literal(false),
      binding_sha256: Hex64Schema,
      aad_sha256: Hex64Schema,
      nonce_sha256: Hex64Schema,
      created_at_ms: TimestampSchema,
      delete_by_ms: TimestampSchema,
      destroyed_at_ms: TimestampSchema,
    })
    .strict(),
]);

export type VaultObjectKeyInspection = z.infer<
  typeof VaultObjectKeyInspectionSchema
>;

export const VaultSealRequestSchema = z
  .object({
    binding: VaultObjectBindingSchema,
    plaintext: z.instanceof(Uint8Array),
    now_ms: TimestampSchema,
  })
  .strict();

export const VaultUnwrapRequestSchema = z
  .object({
    sealed_object: VaultSealedObjectSchema,
    expected_binding: VaultObjectBindingSchema,
    now_ms: TimestampSchema,
  })
  .strict();

export const VaultDestroyRequestSchema = z
  .object({
    sealed_object: VaultSealedObjectSchema,
    reason: VaultDeletionReasonSchema,
    destroyed_at_ms: TimestampSchema,
  })
  .strict();

export const VaultInspectRequestSchema = z
  .object({
    object_id: HighEntropyIdentifierSchema("vaultobj"),
    object_key_id: HighEntropyIdentifierSchema("vkey"),
  })
  .strict();

export interface VaultKeyCustody {
  sealObject(input: z.input<typeof VaultSealRequestSchema>): VaultSealedObject;
  unwrapObject(input: z.input<typeof VaultUnwrapRequestSchema>): Buffer;
  destroyObjectKey(
    input: z.input<typeof VaultDestroyRequestSchema>,
  ): VaultDeletionReceipt;
  inspectObjectKey(
    input: z.input<typeof VaultInspectRequestSchema>,
  ): VaultObjectKeyInspection;
  close(): void;
}

export function signVaultDeletionReceipt(
  privateKey: KeyObject,
  input: unknown,
): VaultDeletionReceipt {
  const payload = VaultDeletionReceiptPayloadSchema.parse(input);
  const signerKeyId = publicKeyId(privateKey);
  if (payload.custody_receipt_key_id !== signerKeyId) {
    throw new Error("vault_receipt_signer_key_mismatch");
  }
  return VaultDeletionReceiptSchema.parse({
    payload,
    signer_key_id: signerKeyId,
    signature_base64: signCanonicalEd25519(
      privateKey,
      VAULT_DELETION_RECEIPT_SIGNATURE_DOMAIN,
      payload,
    ),
  });
}

export function verifyVaultDeletionReceipt(
  publicKey: KeyObject,
  input: unknown,
): VaultDeletionReceipt {
  const receipt = VaultDeletionReceiptSchema.parse(input);
  const signerKeyId = publicKeyId(publicKey);
  if (
    receipt.signer_key_id !== signerKeyId ||
    receipt.payload.custody_receipt_key_id !== signerKeyId
  ) {
    throw new Error("vault_receipt_signer_key_mismatch");
  }
  if (
    !verifyCanonicalEd25519(
      publicKey,
      VAULT_DELETION_RECEIPT_SIGNATURE_DOMAIN,
      receipt.payload,
      receipt.signature_base64,
    )
  ) {
    throw new Error("vault_receipt_signature_invalid");
  }
  return receipt;
}
