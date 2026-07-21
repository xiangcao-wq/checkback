import type { KeyObject } from "node:crypto";
import { z } from "zod";
import {
  publicKeyId,
  sha256Canonical,
  signCanonicalEd25519,
  verifyCanonicalEd25519,
} from "../live-shadow/crypto.ts";
import {
  VaultDeletionReasonSchema,
  VaultObjectBindingSchema,
  vaultAadSha256,
} from "./vault-contracts.ts";

const Hex64Schema = z.string().regex(/^[a-f0-9]{64}$/);
const TimestampSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const HighEntropyIdentifierSchema = (prefix: string) =>
  z.string().regex(new RegExp(`^${prefix}_[a-f0-9]{64}$`));
const Base64SignatureSchema = z
  .string()
  .regex(/^[A-Za-z0-9+/]{86}==$/)
  .refine((value) => Buffer.from(value, "base64").toString("base64") === value, {
    message: "signature must use canonical Base64",
  });

export const RETENTION_VAULT_TOMBSTONE_SIGNATURE_DOMAIN =
  "checkback.live-shadow.retention-vault-tombstone-signature.v1" as const;

export const RetentionVaultProfileSchema = z
  .object({
    custody_id: HighEntropyIdentifierSchema("custody"),
    object_store_id: HighEntropyIdentifierSchema("vaultstore"),
    authority_key_id: Hex64Schema,
    receipt_key_id: Hex64Schema,
    vault_build_sha256: Hex64Schema,
  })
  .strict();

export type RetentionVaultProfile = z.infer<typeof RetentionVaultProfileSchema>;

export const RetentionVaultHandleSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.retention-vault-handle.v1"),
    custody_mode: z.literal("offline_sqlite_blob_fake"),
    custody_id: HighEntropyIdentifierSchema("custody"),
    object_store_id: HighEntropyIdentifierSchema("vaultstore"),
    object_id: HighEntropyIdentifierSchema("vaultobj"),
    object_key_id: HighEntropyIdentifierSchema("vkey"),
    seal_ticket_id: HighEntropyIdentifierSchema("vaultticket"),
    binding: VaultObjectBindingSchema,
    binding_sha256: Hex64Schema,
    aad_sha256: Hex64Schema,
    nonce_sha256: Hex64Schema,
    ciphertext_sha256: Hex64Schema,
    created_at_ms: TimestampSchema,
    delete_by_ms: TimestampSchema,
    state: z.literal("sealed"),
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.binding_sha256 !== sha256Canonical(value.binding) ||
      value.aad_sha256 !== vaultAadSha256(value.binding) ||
      value.delete_by_ms !== value.binding.delete_by_ms ||
      value.created_at_ms >= value.delete_by_ms
    ) {
      context.addIssue({
        code: "custom",
        path: ["binding"],
        message: "retention vault handle binding is inconsistent",
      });
    }
  });

export type RetentionVaultHandle = z.infer<typeof RetentionVaultHandleSchema>;

export const RetentionVaultTombstonePayloadSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow.retention-vault-tombstone.v1",
    ),
    custody_mode: z.literal("offline_sqlite_blob_fake"),
    custody_id: HighEntropyIdentifierSchema("custody"),
    object_store_id: HighEntropyIdentifierSchema("vaultstore"),
    receipt_key_id: Hex64Schema,
    receipt_id: HighEntropyIdentifierSchema("tombstone"),
    object_id: HighEntropyIdentifierSchema("vaultobj"),
    object_key_id: HighEntropyIdentifierSchema("vkey"),
    seal_ticket_id: HighEntropyIdentifierSchema("vaultticket"),
    binding: VaultObjectBindingSchema,
    binding_sha256: Hex64Schema,
    aad_sha256: Hex64Schema,
    nonce_sha256: Hex64Schema,
    ciphertext_sha256: Hex64Schema,
    deletion_intent_sha256: Hex64Schema,
    reason: VaultDeletionReasonSchema,
    deletion_requested_at_ms: TimestampSchema,
    key_reference_removed_at_ms: TimestampSchema,
    tombstoned_at_ms: TimestampSchema,
    claim_type: z.literal("logical_retention_tombstone"),
    claim_scope: z.literal(
      "active_database_key_reference_and_primary_ciphertext_path_only",
    ),
    key_action: z.literal("logical_key_reference_removed"),
    ciphertext_action: z.literal("primary_ciphertext_path_unlinked"),
    physical_media_erasure_verified: z.literal(false),
    sqlite_page_erasure_verified: z.literal(false),
    wal_erasure_verified: z.literal(false),
    backup_erasure_verified: z.literal(false),
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.binding_sha256 !== sha256Canonical(value.binding) ||
      value.aad_sha256 !== vaultAadSha256(value.binding)
    ) {
      context.addIssue({
        code: "custom",
        path: ["binding"],
        message: "tombstone binding is inconsistent",
      });
    }
    if (
      value.deletion_requested_at_ms > value.key_reference_removed_at_ms ||
      value.key_reference_removed_at_ms > value.tombstoned_at_ms ||
      (value.reason === "retention_deadline" &&
        value.deletion_requested_at_ms < value.binding.delete_by_ms)
    ) {
      context.addIssue({
        code: "custom",
        path: ["tombstoned_at_ms"],
        message: "tombstone timeline is inconsistent",
      });
    }
  });

export const RetentionVaultTombstoneReceiptSchema = z
  .object({
    payload: RetentionVaultTombstonePayloadSchema,
    signer_key_id: Hex64Schema,
    signature_base64: Base64SignatureSchema,
  })
  .strict();

export type RetentionVaultTombstoneReceipt = z.infer<
  typeof RetentionVaultTombstoneReceiptSchema
>;

export const RetentionVaultInspectionSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow.retention-vault-inspection.v1",
    ),
    custody_mode: z.literal("offline_sqlite_blob_fake"),
    custody_id: HighEntropyIdentifierSchema("custody"),
    object_store_id: HighEntropyIdentifierSchema("vaultstore"),
    object_id: HighEntropyIdentifierSchema("vaultobj"),
    object_key_id: HighEntropyIdentifierSchema("vkey"),
    state: z.enum([
      "staging",
      "sealed",
      "deleting",
      "key_reference_removed",
      "tombstoned",
    ]),
    key_material_exposed: z.literal(false),
    active_key_reference_present: z.boolean(),
    primary_ciphertext_path_state: z.enum(["present", "absent"]),
    created_at_ms: TimestampSchema,
    delete_by_ms: TimestampSchema,
    key_reference_removed_at_ms: TimestampSchema.nullable(),
    tombstoned_at_ms: TimestampSchema.nullable(),
  })
  .strict();

export type RetentionVaultInspection = z.infer<
  typeof RetentionVaultInspectionSchema
>;

export const RetentionVaultCheckpointSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow.retention-vault-checkpoint.v1",
    ),
    custody_id: HighEntropyIdentifierSchema("custody"),
    object_store_id: HighEntropyIdentifierSchema("vaultstore"),
    audit_sequence: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    audit_head_hmac_sha256: Hex64Schema,
    clock_watermark_ms: TimestampSchema,
    checkpoint_hmac_sha256: Hex64Schema,
  })
  .strict();

export type RetentionVaultCheckpoint = z.infer<
  typeof RetentionVaultCheckpointSchema
>;

export function signRetentionVaultTombstone(
  privateKey: KeyObject,
  payloadInput: unknown,
): RetentionVaultTombstoneReceipt {
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("retention_vault_ed25519_private_key_required");
  }
  const payload = RetentionVaultTombstonePayloadSchema.parse(payloadInput);
  const signerKeyId = publicKeyId(privateKey);
  if (payload.receipt_key_id !== signerKeyId) {
    throw new Error("retention_vault_receipt_signer_mismatch");
  }
  return RetentionVaultTombstoneReceiptSchema.parse({
    payload,
    signer_key_id: signerKeyId,
    signature_base64: signCanonicalEd25519(
      privateKey,
      RETENTION_VAULT_TOMBSTONE_SIGNATURE_DOMAIN,
      payload,
    ),
  });
}

export function verifyRetentionVaultTombstone(
  publicKey: KeyObject,
  input: unknown,
): RetentionVaultTombstoneReceipt {
  const receipt = RetentionVaultTombstoneReceiptSchema.parse(input);
  const keyId = publicKeyId(publicKey);
  if (
    receipt.signer_key_id !== keyId ||
    receipt.payload.receipt_key_id !== keyId
  ) {
    throw new Error("retention_vault_receipt_signer_mismatch");
  }
  if (
    !verifyCanonicalEd25519(
      publicKey,
      RETENTION_VAULT_TOMBSTONE_SIGNATURE_DOMAIN,
      receipt.payload,
      receipt.signature_base64,
    )
  ) {
    throw new Error("retention_vault_receipt_signature_invalid");
  }
  return receipt;
}
