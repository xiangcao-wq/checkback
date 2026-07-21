import type { KeyObject } from "node:crypto";
import { TextDecoder } from "node:util";
import {
  LIVE_CALL_SLOTS,
  LiveDispatchIntentSchema,
} from "../live-shadow/contracts.ts";
import type { LiveCallSlot } from "../live-shadow/contracts.ts";
import {
  canonicalJson,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
} from "../live-shadow/crypto.ts";
import {
  decimalString,
  decimalStringToBigInt,
  remoteAnchorRequestTimeStatus,
  RemoteAnchorTimeSchema,
  SignedRemoteAnchorRequestSchema,
  signRemoteAnchorReceipt,
  verifyRemoteAnchorRequest,
} from "./remote-anchor-contracts.ts";
import type {
  RemoteAnchorCheckpoint,
  RemoteAnchorOperationBody,
  RemoteAnchorTime,
  SignedRemoteAnchorReceipt,
  SignedRemoteAnchorRequest,
} from "./remote-anchor-contracts.ts";

const ZERO_HASH = "0".repeat(64);
const MAX_REQUEST_BYTES = 1_048_576;
const MIN_LEASE_MS = BigInt(1_000);
const MAX_LEASE_MS = BigInt(300_000);

type Enrollment = {
  enrollment_id: string;
  authority_registry_id: string;
  authority_key_id: string;
  authority_public_key: KeyObject;
};

type RegistryRecord = {
  authority_key_id: string;
  registry_sequence: bigint;
  registry_head_sha256: string;
  active_session_id: string | null;
  fencing_token: bigint;
  session_lease_expires_at_ms: bigint | null;
};

type AuthorizationRecord = {
  authority_registry_id: string;
  authorization_fingerprint_sha256: string;
  signed_consent_sha256: string;
  runtime_manifest_sha256: string;
  expires_at_ms: bigint;
};

type ExecutionRecord = {
  authority_registry_id: string;
  authorization_id: string;
  position: number;
  media_scope_id: string;
  pair_commitment_hmac_sha256: string;
};

type SlotRecord = {
  authority_registry_id: string;
  authorization_id: string;
  execution_id: string;
  slot: LiveCallSlot;
  ordinal: number;
  state: "allocated" | "consumed";
  operation_id: string | null;
  dispatch_intent_sha256: string | null;
};

type ServiceState = {
  global_sequence: bigint;
  registries: Map<string, RegistryRecord>;
  authorizations: Map<string, AuthorizationRecord>;
  authorization_fingerprints: Map<string, string>;
  executions: Map<string, ExecutionRecord>;
  slots: Map<string, SlotRecord>;
  operations: Map<string, string>;
};

type StoredRequest = {
  signed_request_sha256: string;
  receipt_bytes: Buffer;
};

class RemoteAnchorDecisionError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "RemoteAnchorDecisionError";
    this.code = code;
  }
}

export class RemoteAnchorServiceError extends Error {
  readonly code: string;
  readonly outcomeMayBeCommitted: boolean;

  constructor(code: string, outcomeMayBeCommitted = false) {
    super(code);
    this.name = "RemoteAnchorServiceError";
    this.code = code;
    this.outcomeMayBeCommitted = outcomeMayBeCommitted;
  }
}

function cloneState(state: ServiceState): ServiceState {
  return {
    global_sequence: state.global_sequence,
    registries: new Map(
      [...state.registries].map(([key, value]) => [key, { ...value }]),
    ),
    authorizations: new Map(
      [...state.authorizations].map(([key, value]) => [key, { ...value }]),
    ),
    authorization_fingerprints: new Map(
      state.authorization_fingerprints,
    ),
    executions: new Map(
      [...state.executions].map(([key, value]) => [key, { ...value }]),
    ),
    slots: new Map(
      [...state.slots].map(([key, value]) => [key, { ...value }]),
    ),
    operations: new Map(state.operations),
  };
}

function checkpoint(record: RegistryRecord): RemoteAnchorCheckpoint {
  return {
    registry_sequence: decimalString(record.registry_sequence),
    registry_head_sha256: record.registry_head_sha256,
    active_session_id: record.active_session_id,
    fencing_token: decimalString(record.fencing_token),
    session_lease_expires_at_ms:
      record.session_lease_expires_at_ms === null
        ? null
        : decimalString(record.session_lease_expires_at_ms),
  };
}

function slotKey(input: {
  authorization_id: string;
  execution_id: string;
  slot: string;
}): string {
  return sha256Bytes(
    `checkback.live-shadow.slot.v1\0${input.authorization_id}\0${input.execution_id}\0${input.slot}`,
  );
}

function decodeCanonicalRequest(bytes: Uint8Array): {
  request: SignedRemoteAnchorRequest;
  canonical_bytes: Buffer;
} {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.byteLength < 1 ||
    bytes.byteLength > MAX_REQUEST_BYTES
  ) {
    throw new RemoteAnchorServiceError("remote_anchor_request_size_invalid");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new RemoteAnchorServiceError("remote_anchor_request_utf8_invalid");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new RemoteAnchorServiceError("remote_anchor_request_json_invalid");
  }
  const request = SignedRemoteAnchorRequestSchema.parse(parsed);
  const canonical = canonicalJson(request);
  if (canonical !== text) {
    throw new RemoteAnchorServiceError(
      "remote_anchor_request_not_canonical",
    );
  }
  return { request, canonical_bytes: Buffer.from(canonical, "utf8") };
}

function canonicalReceiptBytes(receipt: SignedRemoteAnchorReceipt): Buffer {
  return Buffer.from(canonicalJson(receipt), "utf8");
}

function requireRecord<T>(value: T | undefined, code: string): T {
  if (value === undefined) throw new RemoteAnchorDecisionError(code);
  return value;
}

function equalCheckpoint(
  expected: RemoteAnchorCheckpoint,
  actual: RemoteAnchorCheckpoint,
): boolean {
  return canonicalJson(expected) === canonicalJson(actual);
}

export class RemoteAnchorServiceSimulator {
  readonly mode = "offline_remote_anchor_simulator" as const;
  readonly realmId: string;
  readonly anchorEpochId: string;
  readonly anchorKeyId: string;
  #anchorPrivateKey: KeyObject;
  #clock: () => RemoteAnchorTime;
  #timeSourceId: string;
  #timeEpochId: string;
  #maxErrorMs: bigint;
  #lastClockMs: bigint | null = null;
  #enrollmentsById = new Map<string, Enrollment>();
  #enrollmentsByRegistry = new Map<string, Enrollment>();
  #requestsById = new Map<string, StoredRequest>();
  #requestIdByIdempotency = new Map<string, string>();
  #requestIdByNonce = new Map<string, string>();
  #replayConflictRegistries = new Set<string>();
  #state: ServiceState = {
    global_sequence: BigInt(0),
    registries: new Map(),
    authorizations: new Map(),
    authorization_fingerprints: new Map(),
    executions: new Map(),
    slots: new Map(),
    operations: new Map(),
  };
  #closed = false;
  #fatal = false;

  constructor(input: {
    realm_id: string;
    anchor_epoch_id: string;
    anchor_private_key: KeyObject;
    anchor_public_key: KeyObject;
    time_source_id: string;
    time_epoch_id: string;
    max_error_ms: number;
    clock: () => RemoteAnchorTime;
    enrollments: readonly {
      enrollment_id: string;
      authority_registry_id: string;
      authority_public_key: KeyObject;
    }[];
  }) {
    if (publicKeyId(input.anchor_private_key) !== publicKeyId(input.anchor_public_key)) {
      throw new RemoteAnchorServiceError("remote_anchor_keypair_mismatch");
    }
    this.realmId = input.realm_id;
    this.anchorEpochId = input.anchor_epoch_id;
    this.anchorKeyId = publicKeyId(input.anchor_public_key);
    this.#anchorPrivateKey = input.anchor_private_key;
    this.#timeSourceId = input.time_source_id;
    this.#timeEpochId = input.time_epoch_id;
    this.#maxErrorMs = BigInt(input.max_error_ms);
    this.#clock = input.clock;
    RemoteAnchorTimeSchema.parse({
      unix_ms: "0",
      source_id: input.time_source_id,
      epoch_id: input.time_epoch_id,
      max_error_ms: decimalString(input.max_error_ms),
    });
    for (const item of input.enrollments) {
      const enrollment: Enrollment = {
        enrollment_id: item.enrollment_id,
        authority_registry_id: item.authority_registry_id,
        authority_key_id: publicKeyId(item.authority_public_key),
        authority_public_key: item.authority_public_key,
      };
      if (
        this.#enrollmentsById.has(enrollment.enrollment_id) ||
        this.#enrollmentsByRegistry.has(enrollment.authority_registry_id)
      ) {
        throw new RemoteAnchorServiceError(
          "remote_anchor_enrollment_duplicate",
        );
      }
      this.#enrollmentsById.set(enrollment.enrollment_id, enrollment);
      this.#enrollmentsByRegistry.set(
        enrollment.authority_registry_id,
        enrollment,
      );
    }
  }

  #assertAvailable() {
    if (this.#closed) {
      throw new RemoteAnchorServiceError("remote_anchor_service_closed");
    }
    if (this.#fatal) {
      throw new RemoteAnchorServiceError("remote_anchor_service_fatal");
    }
  }

  #readTrustedTime(): RemoteAnchorTime {
    let parsed: RemoteAnchorTime;
    try {
      parsed = RemoteAnchorTimeSchema.parse(this.#clock());
    } catch {
      this.#fatal = true;
      throw new RemoteAnchorServiceError("remote_anchor_clock_invalid");
    }
    if (
      parsed.source_id !== this.#timeSourceId ||
      parsed.epoch_id !== this.#timeEpochId ||
      decimalStringToBigInt(parsed.max_error_ms) !== this.#maxErrorMs
    ) {
      this.#fatal = true;
      throw new RemoteAnchorServiceError("remote_anchor_clock_identity_changed");
    }
    const now = decimalStringToBigInt(parsed.unix_ms);
    if (this.#lastClockMs !== null && now < this.#lastClockMs) {
      this.#fatal = true;
      throw new RemoteAnchorServiceError("remote_anchor_clock_rollback");
    }
    this.#lastClockMs = now;
    return parsed;
  }

  #validateRequestTime(
    request: SignedRemoteAnchorRequest,
    anchorTime: RemoteAnchorTime,
  ) {
    const status = remoteAnchorRequestTimeStatus(request.payload, anchorTime);
    if (status === "future") {
      throw new RemoteAnchorDecisionError("remote_anchor_request_from_future");
    }
    if (status === "expired") {
      throw new RemoteAnchorDecisionError("remote_anchor_request_expired");
    }
  }

  #verifyExpectedCheckpoint(
    request: SignedRemoteAnchorRequest,
    registry: RegistryRecord,
  ) {
    const expected = request.payload.expected_checkpoint;
    if (expected === null || !equalCheckpoint(expected, checkpoint(registry))) {
      throw new RemoteAnchorDecisionError(
        "remote_anchor_checkpoint_mismatch",
      );
    }
  }

  #verifySession(
    registry: RegistryRecord,
    sessionId: string,
    fencingToken: string,
    anchorTime: RemoteAnchorTime,
  ) {
    if (
      registry.active_session_id !== sessionId ||
      registry.fencing_token !== decimalStringToBigInt(fencingToken) ||
      registry.session_lease_expires_at_ms === null ||
      registry.session_lease_expires_at_ms <=
        decimalStringToBigInt(anchorTime.unix_ms) +
          decimalStringToBigInt(anchorTime.max_error_ms)
    ) {
      throw new RemoteAnchorDecisionError(
        "remote_anchor_session_or_fencing_invalid",
      );
    }
  }

  #requestedLease(value: string): bigint {
    const lease = decimalStringToBigInt(value);
    if (lease < MIN_LEASE_MS || lease > MAX_LEASE_MS) {
      throw new RemoteAnchorDecisionError("remote_anchor_lease_invalid");
    }
    return lease;
  }

  #objectKey(body: RemoteAnchorOperationBody): string {
    if (body.operation === "consume_slot") {
      return sha256Canonical(LiveDispatchIntentSchema.parse(body.intent));
    }
    return sha256Canonical(body);
  }

  #storeRequest(
    request: SignedRemoteAnchorRequest,
    signedRequestSha256: string,
    receiptBytes: Buffer,
  ) {
    const requestId = request.payload.request_id;
    this.#requestsById.set(requestId, {
      signed_request_sha256: signedRequestSha256,
      receipt_bytes: Buffer.from(receiptBytes),
    });
    this.#requestIdByIdempotency.set(
      request.payload.idempotency_key,
      requestId,
    );
    this.#requestIdByNonce.set(request.payload.request_nonce_hex, requestId);
  }

  #replayOrConflict(
    request: SignedRemoteAnchorRequest,
    signedRequestSha256: string,
  ): Buffer | null {
    const existing = this.#requestsById.get(request.payload.request_id);
    if (existing) {
      if (existing.signed_request_sha256 === signedRequestSha256) {
        return Buffer.from(existing.receipt_bytes);
      }
      this.#replayConflictRegistries.add(
        request.payload.authority_registry_id,
      );
      throw new RemoteAnchorServiceError(
        "remote_anchor_request_id_conflict",
        true,
      );
    }
    const idempotencyOwner = this.#requestIdByIdempotency.get(
      request.payload.idempotency_key,
    );
    const nonceOwner = this.#requestIdByNonce.get(
      request.payload.request_nonce_hex,
    );
    if (idempotencyOwner !== undefined || nonceOwner !== undefined) {
      this.#replayConflictRegistries.add(
        request.payload.authority_registry_id,
      );
      throw new RemoteAnchorServiceError(
        idempotencyOwner !== undefined
          ? "remote_anchor_idempotency_conflict"
          : "remote_anchor_nonce_conflict",
        true,
      );
    }
    return null;
  }

  #buildRejectedReceipt(input: {
    request: SignedRemoteAnchorRequest;
    signed_request_sha256: string;
    anchor_time: RemoteAnchorTime;
    error_code: string;
  }): Buffer {
    const registry = this.#state.registries.get(
      input.request.payload.authority_registry_id,
    );
    const receipt = signRemoteAnchorReceipt(this.#anchorPrivateKey, {
      schema_version: "checkback.live-shadow.remote-anchor-receipt.v1",
      anchor_mode: "remote_service",
      service_profile: "offline_simulator",
      anchor_realm_id: this.realmId,
      anchor_epoch_id: this.anchorEpochId,
      anchor_key_id: this.anchorKeyId,
      authority_registry_id: input.request.payload.authority_registry_id,
      authority_key_id: input.request.payload.authority_key_id,
      request_id: input.request.payload.request_id,
      idempotency_key: input.request.payload.idempotency_key,
      request_nonce_sha256: sha256Bytes(
        input.request.payload.request_nonce_hex,
      ),
      signed_request_sha256: input.signed_request_sha256,
      operation: input.request.payload.operation,
      decision: "rejected",
      error_code: input.error_code,
      anchor_time: input.anchor_time,
      global_sequence: null,
      previous_registry_head_sha256: null,
      registry_head_sha256: registry?.registry_head_sha256 ?? null,
      object_key_sha256: null,
      checkpoint_after: registry ? checkpoint(registry) : null,
    });
    return canonicalReceiptBytes(receipt);
  }

  #buildObservedReceipt(input: {
    request: SignedRemoteAnchorRequest;
    signed_request_sha256: string;
    anchor_time: RemoteAnchorTime;
    registry: RegistryRecord;
  }): Buffer {
    const receipt = signRemoteAnchorReceipt(this.#anchorPrivateKey, {
      schema_version: "checkback.live-shadow.remote-anchor-receipt.v1",
      anchor_mode: "remote_service",
      service_profile: "offline_simulator",
      anchor_realm_id: this.realmId,
      anchor_epoch_id: this.anchorEpochId,
      anchor_key_id: this.anchorKeyId,
      authority_registry_id: input.request.payload.authority_registry_id,
      authority_key_id: input.request.payload.authority_key_id,
      request_id: input.request.payload.request_id,
      idempotency_key: input.request.payload.idempotency_key,
      request_nonce_sha256: sha256Bytes(
        input.request.payload.request_nonce_hex,
      ),
      signed_request_sha256: input.signed_request_sha256,
      operation: input.request.payload.operation,
      decision: "observed",
      error_code: null,
      anchor_time: input.anchor_time,
      global_sequence: null,
      previous_registry_head_sha256: null,
      registry_head_sha256: input.registry.registry_head_sha256,
      object_key_sha256: sha256Canonical({
        authority_registry_id: input.request.payload.authority_registry_id,
      }),
      checkpoint_after: checkpoint(input.registry),
    });
    return canonicalReceiptBytes(receipt);
  }

  #applyMutation(input: {
    request: SignedRemoteAnchorRequest;
    signed_request_sha256: string;
    anchor_time: RemoteAnchorTime;
  }): { state: ServiceState; receipt_bytes: Buffer } {
    const draft = cloneState(this.#state);
    const payload = input.request.payload;
    const body = payload.body;
    const now = decimalStringToBigInt(input.anchor_time.unix_ms);
    const upperBound = now + decimalStringToBigInt(input.anchor_time.max_error_ms);
    let registry = draft.registries.get(payload.authority_registry_id);

    if (body.operation === "register_registry") {
      const enrollment = requireRecord(
        this.#enrollmentsById.get(body.enrollment_id),
        "remote_anchor_enrollment_unknown",
      );
      if (
        enrollment.authority_registry_id !== payload.authority_registry_id ||
        enrollment.authority_key_id !== payload.authority_key_id ||
        registry !== undefined
      ) {
        throw new RemoteAnchorDecisionError(
          registry === undefined
            ? "remote_anchor_enrollment_binding_invalid"
            : "remote_anchor_registry_already_registered",
        );
      }
      registry = {
        authority_key_id: payload.authority_key_id,
        registry_sequence: BigInt(0),
        registry_head_sha256: ZERO_HASH,
        active_session_id: null,
        fencing_token: BigInt(0),
        session_lease_expires_at_ms: null,
      };
      draft.registries.set(payload.authority_registry_id, registry);
    } else {
      registry = requireRecord(
        registry,
        "remote_anchor_registry_unknown",
      );
      this.#verifyExpectedCheckpoint(input.request, registry);
    }

    switch (body.operation) {
      case "register_registry":
        break;
      case "get_checkpoint":
        throw new RemoteAnchorDecisionError(
          "remote_anchor_observation_not_mutation",
        );
      case "acquire_session": {
        const lease = this.#requestedLease(body.requested_lease_ms);
        if (
          registry.active_session_id !== null &&
          registry.session_lease_expires_at_ms !== null &&
          registry.session_lease_expires_at_ms > upperBound
        ) {
          throw new RemoteAnchorDecisionError(
            "remote_anchor_session_already_active",
          );
        }
        registry.active_session_id = body.session_id;
        registry.fencing_token += BigInt(1);
        registry.session_lease_expires_at_ms = now + lease;
        break;
      }
      case "renew_session": {
        this.#verifySession(
          registry,
          body.session_id,
          body.fencing_token,
          input.anchor_time,
        );
        const lease = this.#requestedLease(body.requested_lease_ms);
        registry.session_lease_expires_at_ms = now + lease;
        break;
      }
      case "claim_authorization": {
        this.#verifySession(
          registry,
          body.session_id,
          body.fencing_token,
          input.anchor_time,
        );
        if (decimalStringToBigInt(body.expires_at_ms) <= upperBound) {
          throw new RemoteAnchorDecisionError(
            "remote_anchor_authorization_expired",
          );
        }
        if (
          draft.authorizations.has(body.authorization_id) ||
          draft.authorization_fingerprints.has(
            body.authorization_fingerprint_sha256,
          )
        ) {
          throw new RemoteAnchorDecisionError(
            "remote_anchor_authorization_already_claimed",
          );
        }
        const executionIds = new Set<string>();
        const scopeIds = new Set<string>();
        for (const execution of body.executions) {
          if (
            executionIds.has(execution.execution_id) ||
            scopeIds.has(execution.media_scope_id) ||
            draft.executions.has(execution.execution_id)
          ) {
            throw new RemoteAnchorDecisionError(
              "remote_anchor_execution_already_claimed",
            );
          }
          executionIds.add(execution.execution_id);
          scopeIds.add(execution.media_scope_id);
        }
        draft.authorizations.set(body.authorization_id, {
          authority_registry_id: payload.authority_registry_id,
          authorization_fingerprint_sha256:
            body.authorization_fingerprint_sha256,
          signed_consent_sha256: body.signed_consent_sha256,
          runtime_manifest_sha256: body.runtime_manifest_sha256,
          expires_at_ms: decimalStringToBigInt(body.expires_at_ms),
        });
        draft.authorization_fingerprints.set(
          body.authorization_fingerprint_sha256,
          body.authorization_id,
        );
        body.executions.forEach((execution, position) => {
          draft.executions.set(execution.execution_id, {
            authority_registry_id: payload.authority_registry_id,
            authorization_id: body.authorization_id,
            position: position + 1,
            media_scope_id: execution.media_scope_id,
            pair_commitment_hmac_sha256:
              execution.pair_commitment_hmac_sha256,
          });
          LIVE_CALL_SLOTS.forEach((slot, slotIndex) => {
            const key = slotKey({
              authorization_id: body.authorization_id,
              execution_id: execution.execution_id,
              slot,
            });
            draft.slots.set(key, {
              authority_registry_id: payload.authority_registry_id,
              authorization_id: body.authorization_id,
              execution_id: execution.execution_id,
              slot,
              ordinal: slotIndex + 1,
              state: "allocated",
              operation_id: null,
              dispatch_intent_sha256: null,
            });
          });
        });
        break;
      }
      case "consume_slot": {
        this.#verifySession(
          registry,
          body.session_id,
          body.fencing_token,
          input.anchor_time,
        );
        const intent = LiveDispatchIntentSchema.parse(body.intent);
        const authorization = requireRecord(
          draft.authorizations.get(intent.authorization_id),
          "remote_anchor_authorization_unknown",
        );
        const execution = requireRecord(
          draft.executions.get(intent.execution_id),
          "remote_anchor_execution_unknown",
        );
        if (
          intent.authority_registry_id !== payload.authority_registry_id ||
          intent.anchor_realm_id !== this.realmId ||
          authorization.authority_registry_id !== payload.authority_registry_id ||
          authorization.authorization_fingerprint_sha256 !==
            intent.authorization_fingerprint_sha256 ||
          authorization.runtime_manifest_sha256 !==
            intent.runtime_manifest_sha256 ||
          authorization.expires_at_ms !== BigInt(intent.expires_at_ms) ||
          execution.authorization_id !== intent.authorization_id ||
          execution.media_scope_id !== intent.media_scope_id ||
          execution.pair_commitment_hmac_sha256 !==
            intent.pair_commitment_hmac_sha256 ||
          BigInt(intent.created_at_ms) > upperBound ||
          BigInt(intent.expires_at_ms) <= upperBound
        ) {
          throw new RemoteAnchorDecisionError(
            "remote_anchor_dispatch_binding_invalid",
          );
        }
        const key = slotKey(intent);
        const slot = requireRecord(
          draft.slots.get(key),
          "remote_anchor_slot_unknown",
        );
        if (
          slot.state !== "allocated" ||
          slot.slot !== intent.slot ||
          slot.ordinal !== intent.ordinal ||
          draft.operations.has(intent.operation_id)
        ) {
          throw new RemoteAnchorDecisionError(
            "remote_anchor_slot_or_operation_consumed",
          );
        }
        for (let index = 0; index < intent.ordinal - 1; index += 1) {
          const previousSlot = requireRecord(
            draft.slots.get(
              slotKey({
                authorization_id: intent.authorization_id,
                execution_id: intent.execution_id,
                slot: LIVE_CALL_SLOTS[index],
              }),
            ),
            "remote_anchor_previous_slot_missing",
          );
          if (previousSlot.state !== "consumed") {
            throw new RemoteAnchorDecisionError(
              "remote_anchor_slot_order_invalid",
            );
          }
        }
        slot.state = "consumed";
        slot.operation_id = intent.operation_id;
        slot.dispatch_intent_sha256 = sha256Canonical(intent);
        draft.operations.set(intent.operation_id, key);
        break;
      }
      case "release_session":
        this.#verifySession(
          registry,
          body.session_id,
          body.fencing_token,
          input.anchor_time,
        );
        registry.active_session_id = null;
        registry.session_lease_expires_at_ms = null;
        break;
    }

    const previousHead = registry.registry_head_sha256;
    registry.registry_sequence += BigInt(1);
    draft.global_sequence += BigInt(1);
    const objectKeySha256 = this.#objectKey(body);
    const checkpointBeforeHead = {
      registry_sequence: decimalString(registry.registry_sequence),
      active_session_id: registry.active_session_id,
      fencing_token: decimalString(registry.fencing_token),
      session_lease_expires_at_ms:
        registry.session_lease_expires_at_ms === null
          ? null
          : decimalString(registry.session_lease_expires_at_ms),
    };
    registry.registry_head_sha256 = sha256Canonical({
      schema_version: "checkback.live-shadow.remote-anchor-event.v1",
      anchor_realm_id: this.realmId,
      anchor_epoch_id: this.anchorEpochId,
      authority_registry_id: payload.authority_registry_id,
      authority_key_id: payload.authority_key_id,
      global_sequence: decimalString(draft.global_sequence),
      registry_sequence: decimalString(registry.registry_sequence),
      previous_registry_head_sha256: previousHead,
      signed_request_sha256: input.signed_request_sha256,
      request_id: payload.request_id,
      idempotency_key: payload.idempotency_key,
      operation: payload.operation,
      object_key_sha256: objectKeySha256,
      anchor_time: input.anchor_time,
      checkpoint_after_without_head: checkpointBeforeHead,
    });
    const receipt = signRemoteAnchorReceipt(this.#anchorPrivateKey, {
      schema_version: "checkback.live-shadow.remote-anchor-receipt.v1",
      anchor_mode: "remote_service",
      service_profile: "offline_simulator",
      anchor_realm_id: this.realmId,
      anchor_epoch_id: this.anchorEpochId,
      anchor_key_id: this.anchorKeyId,
      authority_registry_id: payload.authority_registry_id,
      authority_key_id: payload.authority_key_id,
      request_id: payload.request_id,
      idempotency_key: payload.idempotency_key,
      request_nonce_sha256: sha256Bytes(payload.request_nonce_hex),
      signed_request_sha256: input.signed_request_sha256,
      operation: payload.operation,
      decision: "committed",
      error_code: null,
      anchor_time: input.anchor_time,
      global_sequence: decimalString(draft.global_sequence),
      previous_registry_head_sha256: previousHead,
      registry_head_sha256: registry.registry_head_sha256,
      object_key_sha256: objectKeySha256,
      checkpoint_after: checkpoint(registry),
    });
    return { state: draft, receipt_bytes: canonicalReceiptBytes(receipt) };
  }

  handle(requestBytes: Uint8Array): Buffer {
    this.#assertAvailable();
    const decoded = decodeCanonicalRequest(requestBytes);
    const request = decoded.request;
    const enrollment = this.#enrollmentsByRegistry.get(
      request.payload.authority_registry_id,
    );
    if (enrollment === undefined) {
      throw new RemoteAnchorServiceError(
        "remote_anchor_authority_not_enrolled",
      );
    }
    verifyRemoteAnchorRequest(enrollment.authority_public_key, request);
    const signedRequestSha256 = sha256Bytes(decoded.canonical_bytes);
    const replay = this.#replayOrConflict(request, signedRequestSha256);
    if (replay) return replay;
    if (
      this.#replayConflictRegistries.has(
        request.payload.authority_registry_id,
      )
    ) {
      throw new RemoteAnchorServiceError(
        "remote_anchor_registry_replay_quarantined",
      );
    }
    const anchorTime = this.#readTrustedTime();
    let receiptBytes: Buffer;
    try {
      if (request.payload.anchor_realm_id !== this.realmId) {
        throw new RemoteAnchorDecisionError("remote_anchor_realm_mismatch");
      }
      if (request.payload.expected_service_profile !== "offline_simulator") {
        throw new RemoteAnchorDecisionError(
          "remote_anchor_service_profile_mismatch",
        );
      }
      this.#validateRequestTime(request, anchorTime);
      if (request.payload.operation === "get_checkpoint") {
        const registry = requireRecord(
          this.#state.registries.get(request.payload.authority_registry_id),
          "remote_anchor_registry_unknown",
        );
        if (
          request.payload.expected_checkpoint !== null &&
          !equalCheckpoint(
            request.payload.expected_checkpoint,
            checkpoint(registry),
          )
        ) {
          throw new RemoteAnchorDecisionError(
            "remote_anchor_checkpoint_mismatch",
          );
        }
        receiptBytes = this.#buildObservedReceipt({
          request,
          signed_request_sha256: signedRequestSha256,
          anchor_time: anchorTime,
          registry,
        });
      } else {
        const mutation = this.#applyMutation({
          request,
          signed_request_sha256: signedRequestSha256,
          anchor_time: anchorTime,
        });
        this.#state = mutation.state;
        receiptBytes = mutation.receipt_bytes;
      }
    } catch (error) {
      if (!(error instanceof RemoteAnchorDecisionError)) throw error;
      receiptBytes = this.#buildRejectedReceipt({
        request,
        signed_request_sha256: signedRequestSha256,
        anchor_time: anchorTime,
        error_code: error.code,
      });
    }
    this.#storeRequest(request, signedRequestSha256, receiptBytes);
    return Buffer.from(receiptBytes);
  }

  snapshot() {
    return Object.freeze({
      mode: this.mode,
      service_profile: "offline_simulator" as const,
      network_calls: 0 as const,
      global_sequence: decimalString(this.#state.global_sequence),
      registered_registries: this.#state.registries.size,
      authorizations: this.#state.authorizations.size,
      executions: this.#state.executions.size,
      call_slots: this.#state.slots.size,
      consumed_slots: [...this.#state.slots.values()].filter(
        (slot) => slot.state === "consumed",
      ).length,
      terminal_requests: this.#requestsById.size,
      replay_quarantines: this.#replayConflictRegistries.size,
      fatal: this.#fatal,
    });
  }

  close() {
    if (this.#closed) return;
    for (const stored of this.#requestsById.values()) {
      stored.receipt_bytes.fill(0);
    }
    this.#requestsById.clear();
    this.#requestIdByIdempotency.clear();
    this.#requestIdByNonce.clear();
    this.#enrollmentsById.clear();
    this.#enrollmentsByRegistry.clear();
    this.#state.registries.clear();
    this.#state.authorizations.clear();
    this.#state.authorization_fingerprints.clear();
    this.#state.executions.clear();
    this.#state.slots.clear();
    this.#state.operations.clear();
    this.#closed = true;
  }
}

Object.freeze(RemoteAnchorServiceSimulator.prototype);
