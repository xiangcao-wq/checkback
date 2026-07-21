import type { KeyObject } from "node:crypto";
import { TextDecoder } from "node:util";
import {
  canonicalJson,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
} from "../live-shadow/crypto.ts";
import {
  decimalStringToBigInt,
  decimalStringToSafeInteger,
  remoteAnchorRequestTimeStatus,
  RemoteAnchorOperationBodySchema,
  SignedRemoteAnchorReceiptSchema,
  signRemoteAnchorRequest,
  verifyRemoteAnchorReceipt,
} from "./remote-anchor-contracts.ts";
import type {
  RemoteAnchorCheckpoint,
  RemoteAnchorOperationBody,
  SignedRemoteAnchorReceipt,
  SignedRemoteAnchorRequest,
} from "./remote-anchor-contracts.ts";

const MAX_EXCHANGE_BYTES = 1_048_576;

type PreparedRecord = {
  request: SignedRemoteAnchorRequest;
  request_bytes: Buffer;
  request_sha256: string;
};

const PREPARED_REQUESTS = new WeakMap<object, PreparedRecord>();

export type PreparedRemoteAnchorRequest = object;

export interface RemoteAnchorTransport {
  readonly mode: string;
  exchangeOnce(requestBytes: Uint8Array): Promise<Uint8Array>;
}

export interface RemoteAnchorCommittedConsumeProof {
  readonly request: SignedRemoteAnchorRequest;
  readonly request_sha256: string;
  readonly receipt: SignedRemoteAnchorReceipt;
  readonly receipt_sha256: string;
  /** Caller-owned canonical bytes; wipe after framing the IPC attachment. */
  readonly receipt_bytes: Uint8Array;
  readonly anchor_time_ms: number;
}

export class RemoteAnchorClientError extends Error {
  readonly code: string;
  readonly outcomeMayBeCommitted: boolean;

  constructor(code: string, outcomeMayBeCommitted = false) {
    super(code);
    this.name = "RemoteAnchorClientError";
    this.code = code;
    this.outcomeMayBeCommitted = outcomeMayBeCommitted;
  }
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value as Record<string, unknown>)) {
      deepFreeze(item);
    }
  }
  return value;
}

function receiptTimeDecisionMatches(
  request: SignedRemoteAnchorRequest["payload"],
  receipt: SignedRemoteAnchorReceipt["payload"],
): boolean {
  const status = remoteAnchorRequestTimeStatus(request, receipt.anchor_time);
  if (receipt.decision !== "rejected") return status === "active";
  if (receipt.error_code === "remote_anchor_request_from_future") {
    return status === "future";
  }
  if (receipt.error_code === "remote_anchor_request_expired") {
    return status === "expired";
  }
  return status === "active";
}

function decodeCanonicalReceipt(bytes: Uint8Array): SignedRemoteAnchorReceipt {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.byteLength < 1 ||
    bytes.byteLength > MAX_EXCHANGE_BYTES
  ) {
    throw new RemoteAnchorClientError("remote_anchor_response_size_invalid");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new RemoteAnchorClientError("remote_anchor_response_utf8_invalid");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new RemoteAnchorClientError("remote_anchor_response_json_invalid");
  }
  const receipt = SignedRemoteAnchorReceiptSchema.parse(parsed);
  if (canonicalJson(receipt) !== text) {
    throw new RemoteAnchorClientError(
      "remote_anchor_response_not_canonical",
    );
  }
  return receipt;
}

export class RemoteAnchorClient {
  readonly mode = "remote_anchor_transport_neutral_client" as const;
  readonly realmId: string;
  readonly authorityRegistryId: string;
  readonly authorityKeyId: string;
  readonly anchorKeyId: string;
  #authorityPrivateKey: KeyObject;
  #anchorPublicKey: KeyObject;
  #expectedServiceProfile: "offline_simulator" | "production_external";
  #anchorEpochId: string;
  #timeSourceId: string;
  #timeEpochId: string;
  #maxTrustedTimeErrorMs: bigint;
  #lastAnchorTimeMs: bigint | null = null;
  #lastCheckpoint: RemoteAnchorCheckpoint | null = null;
  #seenRequestReceiptSha256 = new Map<string, string>();
  #closed = false;

  constructor(input: {
    realm_id: string;
    authority_registry_id: string;
    authority_private_key: KeyObject;
    authority_public_key: KeyObject;
    anchor_public_key: KeyObject;
    expected_service_profile: "offline_simulator" | "production_external";
    anchor_epoch_id: string;
    time_source_id: string;
    time_epoch_id: string;
    max_trusted_time_error_ms: number;
  }) {
    if (
      publicKeyId(input.authority_private_key) !==
      publicKeyId(input.authority_public_key)
    ) {
      throw new RemoteAnchorClientError(
        "remote_anchor_client_authority_keypair_mismatch",
      );
    }
    this.realmId = input.realm_id;
    this.authorityRegistryId = input.authority_registry_id;
    this.authorityKeyId = publicKeyId(input.authority_public_key);
    this.anchorKeyId = publicKeyId(input.anchor_public_key);
    this.#authorityPrivateKey = input.authority_private_key;
    this.#anchorPublicKey = input.anchor_public_key;
    this.#expectedServiceProfile = input.expected_service_profile;
    this.#anchorEpochId = input.anchor_epoch_id;
    this.#timeSourceId = input.time_source_id;
    this.#timeEpochId = input.time_epoch_id;
    this.#maxTrustedTimeErrorMs = BigInt(input.max_trusted_time_error_ms);
  }

  #assertOpen() {
    if (this.#closed) {
      throw new RemoteAnchorClientError("remote_anchor_client_closed");
    }
  }

  prepare(input: {
    request_id: string;
    idempotency_key: string;
    request_nonce_hex: string;
    issued_at_ms: string;
    expires_at_ms: string;
    expected_checkpoint: RemoteAnchorCheckpoint | null;
    body: RemoteAnchorOperationBody;
  }): PreparedRemoteAnchorRequest {
    this.#assertOpen();
    const body = RemoteAnchorOperationBodySchema.parse(input.body);
    const request = signRemoteAnchorRequest(this.#authorityPrivateKey, {
      schema_version: "checkback.live-shadow.remote-anchor-request.v1",
      anchor_realm_id: this.realmId,
      expected_service_profile: this.#expectedServiceProfile,
      authority_registry_id: this.authorityRegistryId,
      authority_key_id: this.authorityKeyId,
      request_id: input.request_id,
      idempotency_key: input.idempotency_key,
      request_nonce_hex: input.request_nonce_hex,
      operation: body.operation,
      issued_at_ms: input.issued_at_ms,
      expires_at_ms: input.expires_at_ms,
      expected_checkpoint: input.expected_checkpoint,
      body,
    });
    const requestBytes = Buffer.from(canonicalJson(request), "utf8");
    const prepared = Object.freeze({});
    PREPARED_REQUESTS.set(prepared, {
      request,
      request_bytes: requestBytes,
      request_sha256: sha256Bytes(requestBytes),
    });
    return prepared;
  }

  copyPreparedBytes(prepared: PreparedRemoteAnchorRequest): Buffer {
    this.#assertOpen();
    const record = PREPARED_REQUESTS.get(prepared);
    if (!record) {
      throw new RemoteAnchorClientError(
        "remote_anchor_prepared_request_invalid",
      );
    }
    return Buffer.from(record.request_bytes);
  }

  disposePrepared(prepared: PreparedRemoteAnchorRequest) {
    const record = PREPARED_REQUESTS.get(prepared);
    if (!record) return;
    record.request_bytes.fill(0);
    PREPARED_REQUESTS.delete(prepared);
  }

  #verifyBinding(
    record: PreparedRecord,
    receipt: SignedRemoteAnchorReceipt,
  ) {
    const payload = receipt.payload;
    const request = record.request.payload;
    if (
      payload.anchor_mode !== "remote_service" ||
      payload.service_profile !== this.#expectedServiceProfile ||
      payload.anchor_realm_id !== this.realmId ||
      payload.anchor_epoch_id !== this.#anchorEpochId ||
      payload.anchor_key_id !== this.anchorKeyId ||
      payload.authority_registry_id !== this.authorityRegistryId ||
      payload.authority_key_id !== this.authorityKeyId ||
      payload.request_id !== request.request_id ||
      payload.idempotency_key !== request.idempotency_key ||
      payload.request_nonce_sha256 !==
        sha256Bytes(request.request_nonce_hex) ||
      payload.signed_request_sha256 !== record.request_sha256 ||
      payload.operation !== request.operation ||
      payload.anchor_time.source_id !== this.#timeSourceId ||
      payload.anchor_time.epoch_id !== this.#timeEpochId ||
      decimalStringToBigInt(payload.anchor_time.max_error_ms) >
        this.#maxTrustedTimeErrorMs ||
      !receiptTimeDecisionMatches(request, payload)
    ) {
      throw new RemoteAnchorClientError(
        "remote_anchor_receipt_binding_invalid",
        true,
      );
    }
  }

  #verifyMonotonicReceipt(receipt: SignedRemoteAnchorReceipt) {
    const requestId = receipt.payload.request_id;
    const receiptSha256 = sha256Canonical(receipt);
    const priorReceiptSha256 = this.#seenRequestReceiptSha256.get(requestId);
    if (
      priorReceiptSha256 !== undefined &&
      priorReceiptSha256 !== receiptSha256
    ) {
      throw new RemoteAnchorClientError(
        "remote_anchor_receipt_changed_for_request",
        true,
      );
    }
    const anchorTime = decimalStringToBigInt(
      receipt.payload.anchor_time.unix_ms,
    );
    if (this.#lastAnchorTimeMs !== null && anchorTime < this.#lastAnchorTimeMs) {
      throw new RemoteAnchorClientError(
        "remote_anchor_receipt_time_rollback",
        true,
      );
    }
    const nextCheckpoint = receipt.payload.checkpoint_after;
    if (nextCheckpoint !== null && this.#lastCheckpoint !== null) {
      const previousSequence = decimalStringToBigInt(
        this.#lastCheckpoint.registry_sequence,
      );
      const nextSequence = decimalStringToBigInt(
        nextCheckpoint.registry_sequence,
      );
      if (nextSequence < previousSequence) {
        throw new RemoteAnchorClientError(
          "remote_anchor_receipt_sequence_rollback",
          true,
        );
      }
      if (
        nextSequence === previousSequence &&
        canonicalJson(nextCheckpoint) !== canonicalJson(this.#lastCheckpoint)
      ) {
        throw new RemoteAnchorClientError(
          "remote_anchor_checkpoint_fork",
          true,
        );
      }
      if (nextSequence > previousSequence) {
        if (
          receipt.payload.decision !== "committed" ||
          nextSequence !== previousSequence + BigInt(1) ||
          receipt.payload.previous_registry_head_sha256 !==
            this.#lastCheckpoint.registry_head_sha256
        ) {
          throw new RemoteAnchorClientError(
            "remote_anchor_checkpoint_chain_discontinuity",
            true,
          );
        }
      }
    }
    if (priorReceiptSha256 === undefined) {
      if (nextCheckpoint !== null) {
        this.#lastCheckpoint = { ...nextCheckpoint };
      }
      this.#lastAnchorTimeMs = anchorTime;
      this.#seenRequestReceiptSha256.set(requestId, receiptSha256);
    }
  }
  verifyResponse(
    prepared: PreparedRemoteAnchorRequest,
    responseBytes: Uint8Array,
  ): SignedRemoteAnchorReceipt {
    this.#assertOpen();
    const record = PREPARED_REQUESTS.get(prepared);
    if (!record) {
      throw new RemoteAnchorClientError(
        "remote_anchor_prepared_request_invalid",
      );
    }
    try {
      const receipt = verifyRemoteAnchorReceipt(
        this.#anchorPublicKey,
        decodeCanonicalReceipt(responseBytes),
      );
      this.#verifyBinding(record, receipt);
      this.#verifyMonotonicReceipt(receipt);
      return deepFreeze(receipt);
    } catch (error) {
      if (
        error instanceof RemoteAnchorClientError &&
        error.outcomeMayBeCommitted
      ) {
        throw error;
      }
      const code =
        error instanceof RemoteAnchorClientError
          ? error.code
          : "remote_anchor_receipt_verification_failed";
      throw new RemoteAnchorClientError(code, true);
    }
  }

  async exchangeOnce(
    prepared: PreparedRemoteAnchorRequest,
    transport: RemoteAnchorTransport,
  ): Promise<SignedRemoteAnchorReceipt> {
    this.#assertOpen();
    const requestBytes = this.copyPreparedBytes(prepared);
    let responseBytes: Buffer | undefined;
    try {
      let response: Uint8Array;
      try {
        response = await transport.exchangeOnce(requestBytes);
      } catch {
        throw new RemoteAnchorClientError(
          "remote_anchor_transport_outcome_unknown",
          true,
        );
      }
      responseBytes = Buffer.from(response);
      return this.verifyResponse(prepared, responseBytes);
    } finally {
      requestBytes.fill(0);
      responseBytes?.fill(0);
    }
  }

  async exchangeCommittedConsumeForIpc(
    prepared: PreparedRemoteAnchorRequest,
    transport: RemoteAnchorTransport,
  ): Promise<RemoteAnchorCommittedConsumeProof> {
    this.#assertOpen();
    const record = PREPARED_REQUESTS.get(prepared);
    if (!record) {
      throw new RemoteAnchorClientError(
        "remote_anchor_prepared_request_invalid",
      );
    }
    const receipt = await this.exchangeOnce(prepared, transport);
    if (
      record.request.payload.operation !== "consume_slot" ||
      record.request.payload.body.operation !== "consume_slot" ||
      receipt.payload.operation !== "consume_slot" ||
      receipt.payload.decision !== "committed" ||
      receipt.payload.object_key_sha256 !==
        sha256Canonical(record.request.payload.body.intent)
    ) {
      throw new RemoteAnchorClientError(
        "remote_anchor_committed_consume_proof_required",
        true,
      );
    }
    const canonicalReceipt = Buffer.from(canonicalJson(receipt), "utf8");
    try {
      const request = deepFreeze(
        JSON.parse(JSON.stringify(record.request)) as SignedRemoteAnchorRequest,
      );
      return {
        request,
        request_sha256: record.request_sha256,
        receipt,
        receipt_sha256: sha256Bytes(canonicalReceipt),
        receipt_bytes: new Uint8Array(canonicalReceipt),
        anchor_time_ms: decimalStringToSafeInteger(
          receipt.payload.anchor_time.unix_ms,
        ),
      };
    } finally {
      canonicalReceipt.fill(0);
    }
  }

  close() {
    if (this.#closed) return;
    this.#seenRequestReceiptSha256.clear();
    this.#closed = true;
  }
}

Object.freeze(RemoteAnchorClient.prototype);
