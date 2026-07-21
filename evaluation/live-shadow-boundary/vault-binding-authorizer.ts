import { randomBytes, type KeyObject } from "node:crypto";
import { z } from "zod";
import {
  authorizeLiveExecution,
  type LiveExecutionPlan,
  type LiveRuntimeManifest,
  type LiveSignedConsent,
} from "../live-shadow/contracts.ts";
import {
  computeMediaPairCommitment,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
  signCanonicalEd25519,
  verifyCanonicalEd25519,
} from "../live-shadow/crypto.ts";
import {
  VaultObjectBindingSchema,
  type VaultObjectBinding,
} from "./vault-contracts.ts";
import { MAX_PREPROCESSED_MEDIA_PART_BYTES } from "./boundary-limits.ts";

const Hex64Schema = z.string().regex(/^[a-f0-9]{64}$/);
const TimestampSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const HighEntropyIdentifierSchema = (prefix: string) =>
  z.string().regex(new RegExp(`^${prefix}_[a-f0-9]{64}$`));
const Base64SignatureSchema = z
  .string()
  .regex(/^[A-Za-z0-9+/]{86}==$/);

export const VAULT_SEAL_TICKET_SIGNATURE_DOMAIN =
  "checkback.live-shadow.vault-seal-ticket-signature.v1" as const;

export const VaultSealTicketPayloadSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.vault-seal-ticket.v1"),
    ticket_id: HighEntropyIdentifierSchema("vaultticket"),
    pair_ticket_id: HighEntropyIdentifierSchema("vaultpair"),
    authority_key_id: Hex64Schema,
    expected_custody_id: HighEntropyIdentifierSchema("custody"),
    binding: VaultObjectBindingSchema,
    plaintext_commitment_sha256: Hex64Schema,
    issued_at_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.issued_at_ms >= value.expires_at_ms ||
      value.expires_at_ms > value.binding.delete_by_ms
    ) {
      context.addIssue({
        code: "custom",
        path: ["expires_at_ms"],
        message: "vault seal ticket validity window is invalid",
      });
    }
  });

export const VaultSignedSealTicketSchema = z
  .object({
    payload: VaultSealTicketPayloadSchema,
    signer_key_id: Hex64Schema,
    signature_base64: Base64SignatureSchema,
  })
  .strict();

export type VaultSealTicketPayload = z.infer<
  typeof VaultSealTicketPayloadSchema
>;
export type VaultSignedSealTicket = z.infer<
  typeof VaultSignedSealTicketSchema
>;

function randomIdentifier(prefix: "vaultticket" | "vaultpair"): string {
  const entropy = randomBytes(32);
  try {
    return `${prefix}_${sha256Bytes(entropy)}`;
  } finally {
    entropy.fill(0);
  }
}

function ticketPlaintextCommitment(
  ticketId: string,
  plaintext: Uint8Array,
): string {
  const domain = Buffer.from(
    "checkback.live-shadow.vault-seal-plaintext-commitment.v1\0",
    "utf8",
  );
  const ticket = Buffer.from(ticketId, "utf8");
  const plaintextCopy = Buffer.from(plaintext);
  const material = Buffer.concat([domain, ticket, plaintextCopy]);
  try {
    return sha256Bytes(material);
  } finally {
    domain.fill(0);
    ticket.fill(0);
    plaintextCopy.fill(0);
    material.fill(0);
  }
}

function signSealTicket(
  authorityPrivateKey: KeyObject,
  payloadInput: unknown,
): VaultSignedSealTicket {
  if (
    authorityPrivateKey.type !== "private" ||
    authorityPrivateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new Error("vault_authority_ed25519_private_key_required");
  }
  const payload = VaultSealTicketPayloadSchema.parse(payloadInput);
  const signerKeyId = publicKeyId(authorityPrivateKey);
  if (payload.authority_key_id !== signerKeyId) {
    throw new Error("vault_seal_ticket_signer_mismatch");
  }
  return VaultSignedSealTicketSchema.parse({
    payload,
    signer_key_id: signerKeyId,
    signature_base64: signCanonicalEd25519(
      authorityPrivateKey,
      VAULT_SEAL_TICKET_SIGNATURE_DOMAIN,
      payload,
    ),
  });
}

export function verifyVaultSealTicket(
  authorityPublicKey: KeyObject,
  input: unknown,
): VaultSignedSealTicket {
  const ticket = VaultSignedSealTicketSchema.parse(input);
  const signerKeyId = publicKeyId(authorityPublicKey);
  if (
    ticket.signer_key_id !== signerKeyId ||
    ticket.payload.authority_key_id !== signerKeyId
  ) {
    throw new Error("vault_seal_ticket_signer_mismatch");
  }
  if (
    !verifyCanonicalEd25519(
      authorityPublicKey,
      VAULT_SEAL_TICKET_SIGNATURE_DOMAIN,
      ticket.payload,
      ticket.signature_base64,
    )
  ) {
    throw new Error("vault_seal_ticket_signature_invalid");
  }
  return ticket;
}

export function issueVaultSealTicketsFromAuthorizedPair(input: {
  signed_consent: unknown;
  consent_public_key: KeyObject;
  execution_plan: unknown;
  runtime_manifest: unknown;
  authority_pair_secret: Uint8Array;
  authority_signing_private_key: KeyObject;
  expected_custody_id: string;
  before_plaintext: Uint8Array;
  after_plaintext: Uint8Array;
  now_ms: number;
  expires_at_ms: number;
}): Readonly<{
  reference: VaultSignedSealTicket;
  comparison: VaultSignedSealTicket;
}> {
  if (!(input.authority_pair_secret instanceof Uint8Array) || input.authority_pair_secret.byteLength < 32) {
    throw new Error("vault_authority_pair_secret_too_short");
  }
  if (
    !(input.before_plaintext instanceof Uint8Array) ||
    !(input.after_plaintext instanceof Uint8Array) ||
    input.before_plaintext.byteLength < 1 ||
    input.after_plaintext.byteLength < 1
  ) {
    throw new Error("vault_plaintext_pair_required");
  }
  if (
    input.before_plaintext.byteLength > MAX_PREPROCESSED_MEDIA_PART_BYTES ||
    input.after_plaintext.byteLength > MAX_PREPROCESSED_MEDIA_PART_BYTES
  ) {
    throw new Error("vault_media_part_too_large");
  }

  const beforeSnapshot = Buffer.from(input.before_plaintext);
  const afterSnapshot = Buffer.from(input.after_plaintext);
  try {
    const authorized = authorizeLiveExecution({
    signed_consent: input.signed_consent,
    consent_public_key: input.consent_public_key,
    execution_plan: input.execution_plan,
    runtime_manifest: input.runtime_manifest,
    now_ms: input.now_ms,
  }) as {
    signed_consent: LiveSignedConsent;
    runtime: LiveRuntimeManifest;
    plan: LiveExecutionPlan;
  };
  if (
    input.now_ms < authorized.plan.created_at_ms ||
    input.now_ms >= authorized.plan.expires_at_ms
  ) {
    throw new Error("vault_execution_plan_outside_validity_window");
  }
  if (
    !Number.isSafeInteger(input.expires_at_ms) ||
    input.expires_at_ms <= input.now_ms ||
    input.expires_at_ms > authorized.plan.expires_at_ms
  ) {
    throw new Error("vault_seal_ticket_expiry_invalid");
  }

  const scope = authorized.signed_consent.payload.media_scopes.find(
    (candidate) => candidate.media_scope_id === authorized.plan.media_scope_id,
  );
  if (
    !scope ||
    scope.pair_commitment_hmac_sha256 !==
      authorized.plan.pair_commitment_hmac_sha256 ||
    scope.preprocessing_config_sha256 !==
      authorized.runtime.preprocessing_config_sha256
  ) {
    throw new Error("vault_media_scope_binding_mismatch");
  }
  const recomputedCommitment = computeMediaPairCommitment(
    input.authority_pair_secret,
    {
      before_bytes: beforeSnapshot,
      after_bytes: afterSnapshot,
      preprocessing_config_sha256:
        authorized.runtime.preprocessing_config_sha256,
    },
  );
  if (
    recomputedCommitment !== scope.pair_commitment_hmac_sha256 ||
    recomputedCommitment !== authorized.plan.pair_commitment_hmac_sha256
  ) {
    throw new Error("vault_media_pair_not_authorized");
  }

  const pairTicketId = randomIdentifier("vaultpair");
  const authorityKeyId = publicKeyId(input.authority_signing_private_key);
  const authorizationFingerprint = sha256Canonical(
    authorized.signed_consent,
  );
  const common = {
    schema_version: "checkback.live-shadow.vault-object-binding.v1" as const,
    authorization_fingerprint_sha256: authorizationFingerprint,
    execution_id: authorized.plan.execution_id,
    media_scope_id: authorized.plan.media_scope_id,
    pair_commitment_hmac_sha256: recomputedCommitment,
    preprocessing_config_sha256:
      authorized.runtime.preprocessing_config_sha256,
    delete_by_ms:
      authorized.signed_consent.payload.local_media_delete_by_ms,
  };
  const issue = (
    part: "reference" | "comparison",
    plaintext: Uint8Array,
  ) => {
    const ticketId = randomIdentifier("vaultticket");
    return signSealTicket(input.authority_signing_private_key, {
      schema_version: "checkback.live-shadow.vault-seal-ticket.v1",
      ticket_id: ticketId,
      pair_ticket_id: pairTicketId,
      authority_key_id: authorityKeyId,
      expected_custody_id: input.expected_custody_id,
      binding: {
        ...common,
        part,
        plaintext_length: plaintext.byteLength,
      },
      plaintext_commitment_sha256: ticketPlaintextCommitment(
        ticketId,
        plaintext,
      ),
      issued_at_ms: input.now_ms,
      expires_at_ms: input.expires_at_ms,
    });
  };

    return Object.freeze({
      reference: issue("reference", beforeSnapshot),
      comparison: issue("comparison", afterSnapshot),
    });
  } finally {
    beforeSnapshot.fill(0);
    afterSnapshot.fill(0);
  }
}

/**
 * Verifies the Authority's seal ticket against one stable plaintext snapshot.
 * The caller owns `plaintext_snapshot`, must encrypt only that snapshot, consume
 * ticket_id plus the execution/part tuple atomically, and zeroize it afterward.
 */
export function createVaultObjectBindingFromAuthorization(input: {
  signed_seal_ticket: unknown;
  authority_public_key: KeyObject;
  expected_custody_id: string;
  plaintext: Uint8Array;
  now_ms: number;
}): Readonly<{
  ticket: VaultSignedSealTicket;
  binding: VaultObjectBinding;
  plaintext_snapshot: Buffer;
}> {
  const ticket = verifyVaultSealTicket(
    input.authority_public_key,
    input.signed_seal_ticket,
  );
  if (ticket.payload.expected_custody_id !== input.expected_custody_id) {
    throw new Error("vault_seal_ticket_custody_mismatch");
  }
  if (
    !Number.isSafeInteger(input.now_ms) ||
    input.now_ms < ticket.payload.issued_at_ms ||
    input.now_ms >= ticket.payload.expires_at_ms
  ) {
    throw new Error("vault_seal_ticket_outside_validity_window");
  }
  if (
    !(input.plaintext instanceof Uint8Array) ||
    input.plaintext.byteLength > MAX_PREPROCESSED_MEDIA_PART_BYTES
  ) {
    throw new Error("vault_seal_ticket_plaintext_mismatch");
  }
  const plaintextSnapshot = Buffer.from(input.plaintext);
  try {
    if (
      plaintextSnapshot.byteLength !== ticket.payload.binding.plaintext_length ||
      ticketPlaintextCommitment(ticket.payload.ticket_id, plaintextSnapshot) !==
        ticket.payload.plaintext_commitment_sha256
    ) {
      throw new Error("vault_seal_ticket_plaintext_mismatch");
    }
    return Object.freeze({
      ticket,
      binding: VaultObjectBindingSchema.parse(ticket.payload.binding),
      plaintext_snapshot: plaintextSnapshot,
    });
  } catch (error) {
    plaintextSnapshot.fill(0);
    throw error;
  }
}