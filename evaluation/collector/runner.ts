import {
  CollectorGroundTruthSchema,
  createCollectorGroundTruthEnvelope,
} from "./contracts.ts";
import type {
  CollectorExecutionPlan,
  CollectorGroundTruth,
} from "./contracts.ts";
import {
  DeterministicFakeProvider,
} from "./fake-provider.ts";
import type {
  FakePrimaryResult,
  FakeProviderScript,
  FakeVerifierResult,
} from "./fake-provider.ts";
import {
  LedgerError,
  ShadowCollectorLedger,
} from "./ledger.ts";

type GroundTruthProvider = (input: {
  execution_id: string;
  candidate_ids: readonly string[];
}) => CollectorGroundTruth | Promise<CollectorGroundTruth>;

function wipe(buffer: Buffer | undefined) {
  buffer?.fill(0);
}

export async function runOfflineShadowExecution(input: {
  ledger: ShadowCollectorLedger;
  execution_plan: CollectorExecutionPlan;
  provider_script: FakeProviderScript;
  signer: import("./contracts.ts").ReceiptSigner;
  ground_truth: GroundTruthProvider;
  now?: () => number;
  verify_cleanup?: () => boolean | Promise<boolean>;
}) {
  if (Object.prototype.hasOwnProperty.call(input, "provider")) {
    throw new LedgerError("rehearsal_provider_injection_forbidden");
  }
  const provider = new DeterministicFakeProvider(input.provider_script);
  const now = input.now ?? Date.now;
  const executionId = input.execution_plan.execution_id;
  input.ledger.claimExecution({
    round_id: input.execution_plan.round_id,
    execution_plan: input.execution_plan,
  });

  let cleanupAttempted = false;
  const cleanup = async () => {
    if (cleanupAttempted) return;
    cleanupAttempted = true;
    await verifyCleanupOrFail(input, executionId);
  };

  try {
  const finishPrimary = async () => {
    const reservation = input.ledger.reserveCall(executionId, "primary");
    const dispatch = input.ledger.markDispatched(reservation);
    let envelope:
      | Awaited<ReturnType<DeterministicFakeProvider["invokePrimary"]>>
      | undefined;
    try {
      envelope = await provider.invokePrimary({
        execution_id: executionId,
      });
      const requestReceipt = input.signer.signBytes(
        "collector.provider-request.primary.v1",
        envelope.request_bytes,
      );
      const responseReceipt = input.signer.signBytes(
        "collector.provider-response.primary.v1",
        envelope.response_bytes,
      );
      const normalized =
        envelope.normalized.outcome === "success"
          ? { candidate_ids: envelope.normalized.candidate_ids }
          : undefined;
      const result = input.ledger.finishCall({
        dispatch_token: dispatch,
        outcome: envelope.normalized.outcome,
        latency_ms: envelope.normalized.latency_ms,
        request_receipt: requestReceipt,
        response_receipt: responseReceipt,
        request_bytes: envelope.request_bytes,
        response_bytes: envelope.response_bytes,
        normalized,
      });
      return {
        provider_result: envelope.normalized,
        candidate_manifest: result.candidate_manifest,
      };
    } catch {
      input.ledger.markExecutionIncomplete(
        executionId,
        "primary_unhandled_exception",
      );
      throw new LedgerError("primary_unhandled_exception");
    } finally {
      wipe(envelope?.request_bytes);
      wipe(envelope?.response_bytes);
    }
  };

  const finishVerifier = async (slot: "flash" | "plus", candidateIds: string[]) => {
    const reservation = input.ledger.reserveCall(executionId, slot);
    const dispatch = input.ledger.markDispatched(reservation);
    let envelope:
      | Awaited<ReturnType<DeterministicFakeProvider["invokeVerifier"]>>
      | undefined;
    try {
      envelope = await provider.invokeVerifier(slot, {
        execution_id: executionId,
        candidate_ids: candidateIds,
      });
      const requestReceipt = input.signer.signBytes(
        "collector.provider-request." + slot + ".v1",
        envelope.request_bytes,
      );
      const responseReceipt = input.signer.signBytes(
        "collector.provider-response." + slot + ".v1",
        envelope.response_bytes,
      );
      const normalized =
        envelope.normalized.outcome === "success"
          ? envelope.normalized.batch
          : undefined;
      input.ledger.finishCall({
        dispatch_token: dispatch,
        outcome: envelope.normalized.outcome,
        latency_ms: envelope.normalized.latency_ms,
        request_receipt: requestReceipt,
        response_receipt: responseReceipt,
        request_bytes: envelope.request_bytes,
        response_bytes: envelope.response_bytes,
        normalized,
      });
      return envelope.normalized;
    } catch {
      input.ledger.markExecutionIncomplete(
        executionId,
        slot + "_unhandled_exception",
      );
      throw new LedgerError(slot + "_unhandled_exception");
    } finally {
      wipe(envelope?.request_bytes);
      wipe(envelope?.response_bytes);
    }
  };

  const primary = await finishPrimary();
  if (primary.provider_result.outcome !== "success") {
    input.ledger.markExecutionIncomplete(
      executionId,
      "primary_" + primary.provider_result.outcome,
    );
    await cleanup();
    return {
      status: "incomplete" as const,
      execution_id: executionId,
      reason: "primary_" + primary.provider_result.outcome,
      provider_calls: provider.calls,
    };
  }
  if (!primary.candidate_manifest) {
    input.ledger.markExecutionIncomplete(
      executionId,
      "primary_candidates_missing",
    );
    throw new LedgerError("primary_candidates_missing");
  }

  let groundTruth: CollectorGroundTruth;
  try {
    groundTruth = CollectorGroundTruthSchema.parse(
      await input.ground_truth({
        execution_id: executionId,
        candidate_ids: primary.candidate_manifest.ordered_item_ids,
      }),
    );
  } catch {
    input.ledger.markExecutionIncomplete(executionId, "ground_truth_invalid");
    throw new LedgerError("ground_truth_invalid");
  }
  const truthEnvelope = createCollectorGroundTruthEnvelope({
    execution_plan: input.execution_plan,
    candidate_manifest: primary.candidate_manifest,
    ground_truth: groundTruth,
    locked_at_ms: now(),
  });
  input.ledger.lockGroundTruth({
    execution_id: executionId,
    envelope: truthEnvelope,
  });

  const candidateIds = [...primary.candidate_manifest.ordered_item_ids];
  const flash = await finishVerifier("flash", candidateIds);
  const plus = await finishVerifier("plus", candidateIds);
  await cleanup();

  const evaluationCase = input.ledger.finalizeExecution(executionId);
  return {
    status: "complete" as const,
    execution_id: executionId,
    flash_outcome: flash.outcome,
    plus_outcome: plus.outcome,
    evaluation_case: evaluationCase,
    provider_calls: provider.calls,
  };
  } finally {
    if (!cleanupAttempted) await cleanup();
  }
}

async function verifyCleanupOrFail(
  input: {
    ledger: ShadowCollectorLedger;
    execution_plan: CollectorExecutionPlan;
    verify_cleanup?: () => boolean | Promise<boolean>;
  },
  executionId: string,
) {
  let clean = false;
  try {
    clean = input.verify_cleanup ? await input.verify_cleanup() : true;
  } catch {
    clean = false;
  }
  if (!clean) {
    input.ledger.markExecutionIncomplete(
      executionId,
      "cleanup_not_verified",
    );
    throw new LedgerError("cleanup_not_verified");
  }
}

export type OfflinePrimaryResult = FakePrimaryResult;
export type OfflineVerifierResult = FakeVerifierResult;