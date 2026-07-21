import {
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import type { KeyObject } from "node:crypto";
import {
  VaultDeletionReceiptSchema,
  VaultDestroyRequestSchema,
  VaultInspectRequestSchema,
  VaultObjectKeyInspectionSchema,
  VaultSealRequestSchema,
  VaultSealedObjectSchema,
  VaultUnwrapRequestSchema,
  canonicalVaultAad,
  signVaultDeletionReceipt,
} from "./vault-contracts.ts";
import type {
  VaultDeletionReason,
  VaultDeletionReceipt,
  VaultKeyCustody,
  VaultObjectBinding,
  VaultObjectKeyInspection,
  VaultSealedObject,
} from "./vault-contracts.ts";
import {
  canonicalJson,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
} from "../live-shadow/crypto.ts";

interface KeyRecord {
  object_id: string;
  object_key_id: string;
  binding: VaultObjectBinding;
  binding_sha256: string;
  aad_sha256: string;
  nonce_sha256: string;
  nonce_base64: string;
  created_at_ms: number;
  key_material: Buffer | null;
  state: "active" | "destroyed";
  destroyed_at_ms: number | null;
  deletion_reason: VaultDeletionReason | null;
  deletion_receipt: VaultDeletionReceipt | null;
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function randomIdentifier(prefix: string): string {
  const entropy = randomBytes(32);
  try {
    return `${prefix}_${sha256Bytes(entropy)}`;
  } finally {
    entropy.fill(0);
  }
}

function partReservationKey(binding: VaultObjectBinding): string {
  return sha256Canonical({
    authorization_fingerprint_sha256:
      binding.authorization_fingerprint_sha256,
    execution_id: binding.execution_id,
    media_scope_id: binding.media_scope_id,
    pair_commitment_hmac_sha256: binding.pair_commitment_hmac_sha256,
    preprocessing_config_sha256: binding.preprocessing_config_sha256,
    part: binding.part,
  });
}

function sha256Base64Bytes(value: string): string {
  const decoded = Buffer.from(value, "base64");
  try {
    return sha256Bytes(decoded);
  } finally {
    decoded.fill(0);
  }
}

export interface FakeKeyCustodyOptions {
  custody_id?: string;
  receipt_signing_private_key?: KeyObject;
}

/**
 * Local-only fake used to test the key lifecycle contract. It deliberately has
 * no persistence, network adapter, provider credential, or production claim.
 */
export class FakeKeyCustody implements VaultKeyCustody {
  readonly #custodyId: string;
  readonly #receiptPrivateKey: KeyObject;
  readonly #receiptPublicKey: KeyObject;
  readonly #records = new Map<string, KeyRecord>();
  readonly #claimedParts = new Set<string>();
  readonly #usedNonces = new Set<string>();
  #closed = false;

  constructor(options: FakeKeyCustodyOptions = {}) {
    const privateKey =
      options.receipt_signing_private_key ??
      generateKeyPairSync("ed25519").privateKey;
    if (
      privateKey.type !== "private" ||
      privateKey.asymmetricKeyType !== "ed25519"
    ) {
      throw new Error("vault_ed25519_private_key_required");
    }
    const custodyId = options.custody_id ?? randomIdentifier("custody");
    if (!/^custody_[a-f0-9]{64}$/.test(custodyId)) {
      throw new Error("vault_custody_id_invalid");
    }
    this.#custodyId = custodyId;
    this.#receiptPrivateKey = privateKey;
    this.#receiptPublicKey = createPublicKey(privateKey);
  }

  get custodyId(): string {
    return this.#custodyId;
  }

  get receiptPublicKey(): KeyObject {
    return this.#receiptPublicKey;
  }

  sealObject(input: Parameters<VaultKeyCustody["sealObject"]>[0]): VaultSealedObject {
    this.#assertOpen();
    const request = VaultSealRequestSchema.parse(input);
    const binding = request.binding;
    if (request.plaintext.byteLength !== binding.plaintext_length) {
      throw new Error("vault_plaintext_length_mismatch");
    }
    if (request.now_ms >= binding.delete_by_ms) {
      throw new Error("vault_deadline_reached");
    }

    const partKey = partReservationKey(binding);
    if (this.#claimedParts.has(partKey)) {
      throw new Error("vault_part_already_sealed");
    }
    this.#claimedParts.add(partKey);

    const objectId = this.#uniqueIdentifier("vaultobj");
    const objectKeyId = this.#uniqueIdentifier("vkey");
    const objectKey = randomBytes(32);
    let nonce: Buffer | null = null;
    let plaintext: Buffer | null = null;
    let aad: Buffer | null = null;
    const encryptedChunks: Buffer[] = [];
    try {
      nonce = this.#reserveNonce();
      plaintext = Buffer.from(request.plaintext);
      aad = canonicalVaultAad(binding);
      const cipher = createCipheriv("aes-256-gcm", objectKey, nonce, {
        authTagLength: 16,
      });
      cipher.setAAD(aad, { plaintextLength: plaintext.byteLength });
      encryptedChunks.push(cipher.update(plaintext));
      encryptedChunks.push(cipher.final());

      let ciphertext: Buffer | null = null;
      let authenticationTag: Buffer | null = null;
      let sealed: VaultSealedObject;
      try {
        ciphertext = Buffer.concat(encryptedChunks);
        authenticationTag = cipher.getAuthTag();
        sealed = VaultSealedObjectSchema.parse({
          schema_version: "checkback.live-shadow.vault-sealed-object.v1",
          custody_mode: "offline_local_fake",
          custody_id: this.#custodyId,
          object_id: objectId,
          object_key_id: objectKeyId,
          cipher_suite: "AES-256-GCM",
          binding,
          aad_sha256: sha256Bytes(aad),
          nonce_base64: nonce.toString("base64"),
          authentication_tag_base64: authenticationTag.toString("base64"),
          ciphertext_base64: ciphertext.toString("base64"),
          created_at_ms: request.now_ms,
        });
      } finally {
        ciphertext?.fill(0);
        authenticationTag?.fill(0);
      }

      const output = cloneJson(sealed);
      const retainedKey = Buffer.from(objectKey);
      try {
        this.#records.set(objectKeyId, {
          object_id: objectId,
          object_key_id: objectKeyId,
          binding: cloneJson(binding),
          binding_sha256: sha256Canonical(binding),
          aad_sha256: sealed.aad_sha256,
          nonce_sha256: sha256Bytes(nonce),
          nonce_base64: sealed.nonce_base64,
          created_at_ms: request.now_ms,
          key_material: retainedKey,
          state: "active",
          destroyed_at_ms: null,
          deletion_reason: null,
          deletion_receipt: null,
        });
      } catch (error) {
        retainedKey.fill(0);
        throw error;
      }
      return output;
    } finally {
      objectKey.fill(0);
      nonce?.fill(0);
      plaintext?.fill(0);
      aad?.fill(0);
      for (const chunk of encryptedChunks) chunk.fill(0);
    }
  }

  unwrapObject(input: Parameters<VaultKeyCustody["unwrapObject"]>[0]): Buffer {
    this.#assertOpen();
    const request = VaultUnwrapRequestSchema.parse(input);
    const sealed = request.sealed_object;
    const record = this.#getMatchingRecord(sealed);
    if (record.state !== "active" || record.key_material === null) {
      throw new Error("vault_key_destroyed");
    }
    if (request.now_ms < record.created_at_ms) {
      throw new Error("vault_time_before_creation");
    }
    if (request.now_ms >= record.binding.delete_by_ms) {
      throw new Error("vault_deadline_reached");
    }
    if (
      canonicalJson(request.expected_binding) !== canonicalJson(record.binding)
    ) {
      throw new Error("vault_binding_mismatch");
    }

    const keyCopy = Buffer.from(record.key_material);
    let aad: Buffer | null = null;
    let nonce: Buffer | null = null;
    let authenticationTag: Buffer | null = null;
    let ciphertext: Buffer | null = null;
    const plaintextChunks: Buffer[] = [];
    try {
      aad = canonicalVaultAad(request.expected_binding);
      nonce = Buffer.from(sealed.nonce_base64, "base64");
      authenticationTag = Buffer.from(
        sealed.authentication_tag_base64,
        "base64",
      );
      ciphertext = Buffer.from(sealed.ciphertext_base64, "base64");
      const decipher = createDecipheriv("aes-256-gcm", keyCopy, nonce, {
        authTagLength: 16,
      });
      decipher.setAAD(aad, { plaintextLength: ciphertext.byteLength });
      decipher.setAuthTag(authenticationTag);
      plaintextChunks.push(decipher.update(ciphertext));
      plaintextChunks.push(decipher.final());
      return Buffer.concat(plaintextChunks);
    } catch {
      throw new Error("vault_authentication_failed");
    } finally {
      keyCopy.fill(0);
      aad?.fill(0);
      nonce?.fill(0);
      authenticationTag?.fill(0);
      ciphertext?.fill(0);
      for (const chunk of plaintextChunks) chunk.fill(0);
    }
  }

  destroyObjectKey(
    input: Parameters<VaultKeyCustody["destroyObjectKey"]>[0],
  ): VaultDeletionReceipt {
    this.#assertOpen();
    const request = VaultDestroyRequestSchema.parse(input);
    const record = this.#getMatchingRecord(request.sealed_object);
    if (request.destroyed_at_ms < record.created_at_ms) {
      throw new Error("vault_destruction_before_creation");
    }
    if (
      request.reason === "retention_deadline" &&
      request.destroyed_at_ms < record.binding.delete_by_ms
    ) {
      throw new Error("vault_retention_deadline_not_reached");
    }
    if (record.state === "destroyed") {
      if (
        record.deletion_receipt !== null &&
        record.destroyed_at_ms === request.destroyed_at_ms &&
        record.deletion_reason === request.reason
      ) {
        return cloneJson(record.deletion_receipt);
      }
      throw new Error("vault_key_already_destroyed");
    }
    if (record.key_material === null) {
      throw new Error("vault_key_state_invalid");
    }

    const material = record.key_material;
    const nonce = Buffer.from(record.nonce_base64, "base64");
    let nonceSha256: string;
    try {
      nonceSha256 = sha256Bytes(nonce);
    } finally {
      nonce.fill(0);
    }
    if (nonceSha256 !== record.nonce_sha256) {
      throw new Error("vault_nonce_record_mismatch");
    }

    // Build and validate the receipt before the irreversible key zeroization.
    // A signing/serialization failure must leave the active key recoverable so
    // compensation can retry instead of creating an unreceipted erasure.
    const receipt = signVaultDeletionReceipt(this.#receiptPrivateKey, {
      schema_version:
        "checkback.live-shadow.vault-key-destruction-receipt.v1",
      custody_mode: "offline_local_fake",
      custody_id: this.#custodyId,
      custody_receipt_key_id: publicKeyId(this.#receiptPublicKey),
      receipt_id: randomIdentifier("delreceipt"),
      object_id: record.object_id,
      object_key_id: record.object_key_id,
      binding: record.binding,
      aad_sha256: record.aad_sha256,
      nonce_sha256: record.nonce_sha256,
      claim_type: "object_key_cryptographic_erasure",
      claim_scope: "object_key_only",
      object_key_state: "destroyed",
      erasure_method: "in_memory_aes256_key_zeroized",
      reason: request.reason,
      destroyed_at_ms: request.destroyed_at_ms,
    });
    const storedReceipt = cloneJson(receipt);
    const result = VaultDeletionReceiptSchema.parse(cloneJson(receipt));

    material.fill(0);
    record.key_material = null;
    record.state = "destroyed";
    record.destroyed_at_ms = request.destroyed_at_ms;
    record.deletion_reason = request.reason;
    record.deletion_receipt = storedReceipt;
    return result;
  }

  inspectObjectKey(
    input: Parameters<VaultKeyCustody["inspectObjectKey"]>[0],
  ): VaultObjectKeyInspection {
    this.#assertOpen();
    const request = VaultInspectRequestSchema.parse(input);
    const record = this.#records.get(request.object_key_id);
    if (!record || record.object_id !== request.object_id) {
      throw new Error("vault_object_key_not_found");
    }
    return VaultObjectKeyInspectionSchema.parse({
      schema_version: "checkback.live-shadow.vault-key-inspection.v1",
      custody_mode: "offline_local_fake",
      custody_id: this.#custodyId,
      object_id: record.object_id,
      object_key_id: record.object_key_id,
      state: record.state,
      key_material_exposed: false,
      binding_sha256: record.binding_sha256,
      aad_sha256: record.aad_sha256,
      nonce_sha256: record.nonce_sha256,
      created_at_ms: record.created_at_ms,
      delete_by_ms: record.binding.delete_by_ms,
      destroyed_at_ms: record.destroyed_at_ms,
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const record of this.#records.values()) {
      if (record.key_material !== null) {
        record.key_material.fill(0);
        record.key_material = null;
      }
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error("vault_custody_closed");
  }

  #uniqueIdentifier(prefix: "vaultobj" | "vkey"): string {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      const id = randomIdentifier(prefix);
      if (
        prefix === "vaultobj"
          ? !Array.from(this.#records.values()).some(
              (record) => record.object_id === id,
            )
          : !this.#records.has(id)
      ) {
        return id;
      }
    }
    throw new Error("vault_identifier_generation_failed");
  }

  #reserveNonce(): Buffer {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      const nonce = randomBytes(12);
      const nonceHex = nonce.toString("hex");
      if (!this.#usedNonces.has(nonceHex)) {
        this.#usedNonces.add(nonceHex);
        return nonce;
      }
      nonce.fill(0);
    }
    throw new Error("vault_nonce_generation_failed");
  }

  #getMatchingRecord(sealed: VaultSealedObject): KeyRecord {
    if (sealed.custody_id !== this.#custodyId) {
      throw new Error("vault_custody_mismatch");
    }
    const record = this.#records.get(sealed.object_key_id);
    if (!record || record.object_id !== sealed.object_id) {
      throw new Error("vault_object_key_not_found");
    }
    if (
      record.binding_sha256 !== sha256Canonical(sealed.binding) ||
      record.aad_sha256 !== sealed.aad_sha256 ||
      record.nonce_base64 !== sealed.nonce_base64 ||
      record.nonce_sha256 !== sha256Base64Bytes(sealed.nonce_base64) ||
      record.created_at_ms !== sealed.created_at_ms
    ) {
      throw new Error("vault_sealed_object_binding_mismatch");
    }
    return record;
  }
}
