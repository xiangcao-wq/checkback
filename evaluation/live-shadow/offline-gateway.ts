import { LiveAuthorityRegistry } from "./authority-registry.ts";
import { canonicalJson, sha256Canonical } from "./crypto.ts";
import {
  copyOfflineCanonicalRequestBytes,
  createOfflineCanonicalRequest,
  disposeOfflineCanonicalRequest,
} from "./offline-request.ts";

type OfflineOutcome =
  | "success"
  | "request_error"
  | "timeout"
  | "invalid_output";

type OfflineFaultPoint =
  | "none"
  | "after_anchor_burn_before_send"
  | "after_send_before_result";

type FakeTransportSnapshot = {
  send_attempts: number;
  observed_request_lengths: readonly number[];
};

class OfflineCrashSimulation extends Error {
  readonly point: Exclude<OfflineFaultPoint, "none">;

  constructor(point: Exclude<OfflineFaultPoint, "none">) {
    super(`offline_crash_simulation:${point}`);
    this.name = "OfflineCrashSimulation";
    this.point = point;
  }
}

class InternalOfflineFakeTransport {
  #sendAttempts = 0;
  #observedRequestLengths: number[] = [];
  #outcome: OfflineOutcome;

  constructor(outcome: OfflineOutcome) {
    this.#outcome = outcome;
  }

  async sendOnce(input: {
    operation_id: string;
    request_bytes: Uint8Array;
  }): Promise<{ outcome: OfflineOutcome; response_bytes: Buffer }> {
    this.#sendAttempts += 1;
    this.#observedRequestLengths.push(input.request_bytes.byteLength);
    if (this.#outcome === "request_error") {
      throw new Error("offline_fake_transport_request_error");
    }
    const payload = {
      schema_version: "checkback.live-shadow.offline-fake-result.v1",
      mode: "offline_stub",
      provider: "fake_gateway",
      operation_id_sha256: sha256Canonical(input.operation_id),
      outcome: this.#outcome,
      request_byte_length: input.request_bytes.byteLength,
    };
    return {
      outcome: this.#outcome,
      response_bytes: Buffer.from(canonicalJson(payload), "utf8"),
    };
  }

  snapshot(): FakeTransportSnapshot {
    return Object.freeze({
      send_attempts: this.#sendAttempts,
      observed_request_lengths: Object.freeze([
        ...this.#observedRequestLengths,
      ]),
    });
  }
}

export class OfflineLiveShadowGateway {
  #authority: LiveAuthorityRegistry;
  #transport: InternalOfflineFakeTransport;

  constructor(input: {
    authority: LiveAuthorityRegistry;
    fake_outcome?: OfflineOutcome;
  }) {
    this.#authority = input.authority;
    this.#transport = new InternalOfflineFakeTransport(
      input.fake_outcome ?? "success",
    );
  }

  async dispatch(input: {
    execution_plan: unknown;
    runtime_manifest: unknown;
    slot: unknown;
    operation_id: string;
    media_pair: {
      before_bytes: Uint8Array;
      after_bytes: Uint8Array;
    };
    fault_point?: OfflineFaultPoint;
  }) {
    const executionPlan = input.execution_plan;
    const runtimeManifest = input.runtime_manifest;
    const slot = input.slot;
    const operationId = input.operation_id;
    const faultPoint = input.fault_point ?? "none";
    const mediaPair = input.media_pair;
    const beforeBytes = mediaPair.before_bytes;
    const afterBytes = mediaPair.after_bytes;
    const requestEnvelope = createOfflineCanonicalRequest({
      execution_plan: executionPlan,
      runtime_manifest: runtimeManifest,
      slot,
      before_bytes: beforeBytes,
      after_bytes: afterBytes,
    });
    let requestBytes: Buffer | undefined;
    try {
      const intent = this.#authority.prepareDispatch({
        request_envelope: requestEnvelope,
        operation_id: operationId,
      });
      const capability = this.#authority.burnDispatch(intent);
      if (faultPoint === "after_anchor_burn_before_send") {
        throw new OfflineCrashSimulation("after_anchor_burn_before_send");
      }

      requestBytes = copyOfflineCanonicalRequestBytes(requestEnvelope);
      let response;
      try {
        response = await this.#transport.sendOnce({
          operation_id: operationId,
          request_bytes: requestBytes,
        });
      } catch {
        const errorBytes = Buffer.from(
          canonicalJson({
            schema_version: "checkback.live-shadow.offline-fake-error.v1",
            mode: "offline_stub",
            error_code: "offline_fake_transport_request_error",
          }),
          "utf8",
        );
        try {
          const receipt = this.#authority.completeDispatch({
            capability,
            outcome: "request_error",
            result_bytes: errorBytes,
          });
          return Object.freeze({
            mode: "offline_stub" as const,
            provider: "fake_gateway" as const,
            network_calls: 0 as const,
            operation_id: operationId,
            dispatch_intent_sha256: sha256Canonical(intent),
            outcome: receipt.outcome,
            result_commitment_hmac_sha256:
              receipt.result_commitment_hmac_sha256,
          });
        } finally {
          errorBytes.fill(0);
        }
      }

      const responseBytes = response.response_bytes;
      try {
        if (faultPoint === "after_send_before_result") {
          throw new OfflineCrashSimulation("after_send_before_result");
        }
        const receipt = this.#authority.completeDispatch({
          capability,
          outcome: response.outcome,
          result_bytes: responseBytes,
        });
        return Object.freeze({
          mode: "offline_stub" as const,
          provider: "fake_gateway" as const,
          network_calls: 0 as const,
          operation_id: operationId,
          dispatch_intent_sha256: sha256Canonical(intent),
          outcome: receipt.outcome,
          result_commitment_hmac_sha256:
            receipt.result_commitment_hmac_sha256,
        });
      } finally {
        responseBytes.fill(0);
      }
    } finally {
      requestBytes?.fill(0);
      disposeOfflineCanonicalRequest(requestEnvelope);
    }
  }

  snapshot(): FakeTransportSnapshot {
    return this.#transport.snapshot();
  }
}

Object.freeze(OfflineLiveShadowGateway.prototype);