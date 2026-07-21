import {
  LiveCallSlotSchema,
  LiveExecutionPlanSchema,
  LiveRuntimeManifestSchema,
} from "./contracts.ts";
import type {
  LiveCallSlot,
  LiveExecutionPlan,
  LiveRuntimeManifest,
} from "./contracts.ts";
import { canonicalJson, sha256Canonical } from "./crypto.ts";

type RequestRecord = {
  execution_plan: LiveExecutionPlan;
  runtime_manifest: LiveRuntimeManifest;
  slot: LiveCallSlot;
  before_bytes: Buffer;
  after_bytes: Buffer;
  request_bytes: Buffer;
};

const REQUESTS = new WeakMap<object, RequestRecord>();

export type OfflineCanonicalRequestEnvelope = object;

function copyRecord(record: RequestRecord) {
  return {
    execution_plan: LiveExecutionPlanSchema.parse(record.execution_plan),
    runtime_manifest: LiveRuntimeManifestSchema.parse(record.runtime_manifest),
    slot: LiveCallSlotSchema.parse(record.slot),
    before_bytes: Buffer.from(record.before_bytes),
    after_bytes: Buffer.from(record.after_bytes),
    request_bytes: Buffer.from(record.request_bytes),
  };
}

export function createOfflineCanonicalRequest(input: {
  execution_plan: unknown;
  runtime_manifest: unknown;
  slot: unknown;
  before_bytes: Uint8Array;
  after_bytes: Uint8Array;
}): OfflineCanonicalRequestEnvelope {
  const executionPlan = LiveExecutionPlanSchema.parse(input.execution_plan);
  const runtimeManifest = LiveRuntimeManifestSchema.parse(
    input.runtime_manifest,
  );
  const slot = LiveCallSlotSchema.parse(input.slot);
  const beforeInput = input.before_bytes;
  const afterInput = input.after_bytes;
  if (
    !(beforeInput instanceof Uint8Array) ||
    !(afterInput instanceof Uint8Array) ||
    beforeInput.byteLength < 1 ||
    afterInput.byteLength < 1 ||
    beforeInput.byteLength + afterInput.byteLength > 31 * 1024 * 1024
  ) {
    throw new Error("offline_media_pair_invalid");
  }
  const beforeBytes = Buffer.from(beforeInput);
  const afterBytes = Buffer.from(afterInput);
  const header = Buffer.from(
    canonicalJson({
      schema_version: "checkback.live-shadow.offline-request.v1",
      execution_plan_sha256: sha256Canonical(executionPlan),
      runtime_manifest_sha256: sha256Canonical(runtimeManifest),
      slot,
      before_byte_length: beforeBytes.byteLength,
      after_byte_length: afterBytes.byteLength,
    }),
    "utf8",
  );
  const requestBytes = Buffer.concat([
    header,
    Buffer.from([0]),
    beforeBytes,
    Buffer.from([0]),
    afterBytes,
  ]);
  const envelope = Object.freeze({});
  REQUESTS.set(envelope, {
    execution_plan: executionPlan,
    runtime_manifest: runtimeManifest,
    slot,
    before_bytes: beforeBytes,
    after_bytes: afterBytes,
    request_bytes: requestBytes,
  });
  return envelope;
}

export function inspectOfflineCanonicalRequest(
  envelope: OfflineCanonicalRequestEnvelope,
) {
  const record = REQUESTS.get(envelope);
  if (!record) throw new Error("offline_request_envelope_invalid");
  return copyRecord(record);
}

export function copyOfflineCanonicalRequestBytes(
  envelope: OfflineCanonicalRequestEnvelope,
): Buffer {
  const record = REQUESTS.get(envelope);
  if (!record) throw new Error("offline_request_envelope_invalid");
  return Buffer.from(record.request_bytes);
}

export function disposeOfflineCanonicalRequest(
  envelope: OfflineCanonicalRequestEnvelope,
) {
  const record = REQUESTS.get(envelope);
  if (!record) return;
  record.before_bytes.fill(0);
  record.after_bytes.fill(0);
  record.request_bytes.fill(0);
  REQUESTS.delete(envelope);
}
