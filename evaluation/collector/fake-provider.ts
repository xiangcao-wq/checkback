import {
  CollectorCallSlotSchema,
  canonicalJson,
  SanitizedVerificationBatchSchema,
} from "./contracts.ts";
import type {
  CollectorCallSlot,
  SanitizedVerificationBatch,
} from "./contracts.ts";

type TerminalOutcome =
  | "success"
  | "timeout"
  | "request_error"
  | "invalid_output";

type FakePrimarySuccess = {
  outcome: "success";
  latency_ms: number;
  candidate_ids: string[];
  private_response_canary?: string;
};

type FakeVerifierSuccess = {
  outcome: "success";
  latency_ms: number;
  batch: SanitizedVerificationBatch;
  private_response_canary?: string;
};

type FakeFailure = {
  outcome: Exclude<TerminalOutcome, "success">;
  latency_ms: number;
  private_response_canary?: string;
};

export type FakePrimaryStep = FakePrimarySuccess | FakeFailure;
export type FakeVerifierStep = FakeVerifierSuccess | FakeFailure;

export type FakeProviderScript = {
  primary: FakePrimaryStep;
  flash: FakeVerifierStep;
  plus: FakeVerifierStep;
  private_request_canary?: string;
};

export type FakeProviderEnvelope<T> = {
  normalized: T;
  request_bytes: Buffer;
  response_bytes: Buffer;
};

export type FakePrimaryResult =
  | {
      outcome: "success";
      latency_ms: number;
      candidate_ids: string[];
    }
  | FakeFailure;

export type FakeVerifierResult =
  | {
      outcome: "success";
      latency_ms: number;
      batch: SanitizedVerificationBatch;
    }
  | FakeFailure;

const ITEM_ID = /^item-[0-9]{4,8}$/;

function assertLatency(value: number) {
  if (!Number.isInteger(value) || value < 0 || value > 300_000) {
    throw new Error("fake provider latency is invalid");
  }
}

function assertCandidateIds(candidateIds: readonly string[]) {
  if (candidateIds.length < 1 || candidateIds.length > 20) {
    throw new Error("fake primary must return between one and twenty candidates");
  }
  if (
    candidateIds.some((id) => !ITEM_ID.test(id)) ||
    new Set(candidateIds).size !== candidateIds.length
  ) {
    throw new Error("fake primary candidate IDs must be unique anonymous IDs");
  }
}

function cloneBatch(batch: SanitizedVerificationBatch) {
  return SanitizedVerificationBatchSchema.parse(
    JSON.parse(JSON.stringify(batch)),
  );
}

function exactCandidateCoverage(
  batch: SanitizedVerificationBatch,
  candidateIds: readonly string[],
) {
  const actual = batch.verifications.map((item) => item.id);
  return (
    actual.length === candidateIds.length &&
    new Set(actual).size === actual.length &&
    candidateIds.every((id) => actual.includes(id))
  );
}

function encodePrivateWireValue(
  slot: CollectorCallSlot,
  executionId: string,
  publicValue: unknown,
  privateCanary: string | undefined,
) {
  return Buffer.from(
    canonicalJson({
      slot,
      execution_id: executionId,
      payload: publicValue,
      private_wire_value: privateCanary ?? null,
    }),
    "utf8",
  );
}

export function parseFakeProviderWireEnvelope(bytes: Uint8Array) {
  if (bytes.byteLength < 2 || bytes.byteLength > 64 * 1024) {
    throw new Error("fake provider wire envelope size is invalid");
  }
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new Error("fake provider wire envelope is invalid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("fake provider wire envelope must be an object");
  }
  const source = value as Record<string, unknown>;
  const keys = Object.keys(source).sort();
  if (
    keys.join(",") !==
    "execution_id,payload,private_wire_value,slot"
  ) {
    throw new Error("fake provider wire envelope fields are invalid");
  }
  const slot = CollectorCallSlotSchema.parse(source.slot);
  if (
    typeof source.execution_id !== "string" ||
    !/^execution-[0-9]{4,8}$/.test(source.execution_id) ||
    !source.payload ||
    typeof source.payload !== "object" ||
    Array.isArray(source.payload) ||
    !(
      source.private_wire_value === null ||
      (
        typeof source.private_wire_value === "string" &&
        source.private_wire_value.length <= 4_096
      )
    )
  ) {
    throw new Error("fake provider wire envelope content is invalid");
  }
  return {
    slot,
    execution_id: source.execution_id,
    payload: source.payload as Record<string, unknown>,
  };
}

export class DeterministicFakeProvider {
  readonly providerId = "fake_local" as const;
  #calls: CollectorCallSlot[] = [];
  #script: FakeProviderScript;

  constructor(script: FakeProviderScript) {
    for (const step of [script.primary, script.flash, script.plus]) {
      assertLatency(step.latency_ms);
    }
    if (script.primary.outcome === "success") {
      assertCandidateIds(script.primary.candidate_ids);
    }
    for (const step of [script.flash, script.plus]) {
      if (step.outcome === "success") {
        cloneBatch(step.batch);
      }
    }
    this.#script = structuredClone(script);
  }

  get calls(): readonly CollectorCallSlot[] {
    return Object.freeze([...this.#calls]);
  }

  async invokePrimary(input: {
    execution_id: string;
  }): Promise<FakeProviderEnvelope<FakePrimaryResult>> {
    this.#calls.push("primary");
    const step = this.#script.primary;
    const publicRequest = {
      purpose: "shadow-rehearsal-primary",
    };
    if (step.outcome === "success") {
      const normalized: FakePrimaryResult = {
        outcome: "success",
        latency_ms: step.latency_ms,
        candidate_ids: [...step.candidate_ids],
      };
      return {
        normalized,
        request_bytes: encodePrivateWireValue(
          "primary",
          input.execution_id,
          publicRequest,
          this.#script.private_request_canary,
        ),
        response_bytes: encodePrivateWireValue(
          "primary",
          input.execution_id,
          normalized,
          step.private_response_canary,
        ),
      };
    }
    const normalized: FakePrimaryResult = {
      outcome: step.outcome,
      latency_ms: step.latency_ms,
    };
    return {
      normalized,
      request_bytes: encodePrivateWireValue(
        "primary",
        input.execution_id,
        publicRequest,
        this.#script.private_request_canary,
      ),
      response_bytes: encodePrivateWireValue(
        "primary",
        input.execution_id,
        normalized,
        step.private_response_canary,
      ),
    };
  }

  async invokeVerifier(
    slot: "flash" | "plus",
    input: {
      execution_id: string;
      candidate_ids: string[];
    },
  ): Promise<FakeProviderEnvelope<FakeVerifierResult>> {
    this.#calls.push(slot);
    assertCandidateIds(input.candidate_ids);
    const step = this.#script[slot];
    const publicRequest = {
      purpose: "shadow-rehearsal-verifier",
      candidate_ids: [...input.candidate_ids],
    };
    if (step.outcome === "success") {
      const batch = cloneBatch(step.batch);
      if (!exactCandidateCoverage(batch, input.candidate_ids)) {
        const normalized: FakeVerifierResult = {
          outcome: "invalid_output",
          latency_ms: step.latency_ms,
        };
        return {
          normalized,
          request_bytes: encodePrivateWireValue(
            slot,
            input.execution_id,
            publicRequest,
            this.#script.private_request_canary,
          ),
          response_bytes: encodePrivateWireValue(
            slot,
            input.execution_id,
            normalized,
            step.private_response_canary,
          ),
        };
      }
      const normalized: FakeVerifierResult = {
        outcome: "success",
        latency_ms: step.latency_ms,
        batch,
      };
      return {
        normalized,
        request_bytes: encodePrivateWireValue(
          slot,
          input.execution_id,
          publicRequest,
          this.#script.private_request_canary,
        ),
        response_bytes: encodePrivateWireValue(
          slot,
          input.execution_id,
          normalized,
          step.private_response_canary,
        ),
      };
    }
    const normalized: FakeVerifierResult = {
      outcome: step.outcome,
      latency_ms: step.latency_ms,
    };
    return {
      normalized,
      request_bytes: encodePrivateWireValue(
        slot,
        input.execution_id,
        publicRequest,
        this.#script.private_request_canary,
      ),
      response_bytes: encodePrivateWireValue(
        slot,
        input.execution_id,
        normalized,
        step.private_response_canary,
      ),
    };
  }
}

Object.freeze(DeterministicFakeProvider.prototype.invokePrimary);
Object.freeze(DeterministicFakeProvider.prototype.invokeVerifier);
Object.freeze(DeterministicFakeProvider.prototype);
Object.freeze(DeterministicFakeProvider);