import { createHash, randomBytes } from "node:crypto";
import {
  FAKE_RUNTIME_PROFILE,
  ReceiptSigner,
  computePairCommitment,
  sha256Canonical,
  signCollectorManifest,
} from "./contracts.ts";
import type {
  CollectorConsentGrant,
  CollectorExecutionPlan,
  CollectorRoundManifest,
} from "./contracts.ts";
import {
  CHECKBACK_QWEN_SHADOW_CONFIG_SHA256,
  PINNED_QWEN_SHADOW_EVALUATION_CONFIG,
} from "../../app/lib/qwen-model-config.ts";

function sha256(value: string) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function numbered(prefix: string, value: number) {
  return prefix + "-" + String(value).padStart(4, "0");
}

export function createOfflineRehearsalBundle(input: {
  numeric_id?: number;
  execution_count?: number;
  created_at_ms?: number;
  lifetime_ms?: number;
  signer?: ReceiptSigner;
} = {}) {
  const numericId = input.numeric_id ?? 1;
  const executionCount = input.execution_count ?? 1;
  const createdAt = input.created_at_ms ?? Date.now();
  const lifetime = input.lifetime_ms ?? 60 * 60 * 1000;
  if (
    !Number.isInteger(numericId) ||
    numericId < 1 ||
    numericId > 9_999
  ) {
    throw new Error("numeric_id must be between 1 and 9999");
  }
  if (
    !Number.isInteger(executionCount) ||
    executionCount < 1 ||
    executionCount > 1_000
  ) {
    throw new Error("execution_count must be between 1 and 1000");
  }
  if (
    !Number.isInteger(lifetime) ||
    lifetime < 1_000 ||
    lifetime > 29 * 24 * 60 * 60 * 1000
  ) {
    throw new Error("lifetime_ms must be between one second and 29 days");
  }

  let signer = input.signer;
  if (!signer) {
    const key = randomBytes(32);
    signer = new ReceiptSigner(key);
    key.fill(0);
  }

  const config = { ...PINNED_QWEN_SHADOW_EVALUATION_CONFIG };
  const runtime = {
    provider_id: "fake_local" as const,
    ...FAKE_RUNTIME_PROFILE,
    collector_build_sha256: sha256("shadow-collector-rehearsal-v1"),
    primary_prompt_sha256: sha256("fake-primary-prompt-v1"),
    verifier_prompt_sha256: config.prompt_sha256,
    config_sha256: CHECKBACK_QWEN_SHADOW_CONFIG_SHA256,
  };
  const authorizedExecutions = Array.from(
    { length: executionCount },
    (_, index) => {
      const executionNumber = numericId * 1_000 + index + 1;
      return {
        execution_id: numbered("execution", executionNumber),
        pair_commitment_hmac_sha256: computePairCommitment(signer, {
          before_sha256: sha256("synthetic-before-" + executionNumber),
          after_sha256: sha256("synthetic-after-" + executionNumber),
          preprocessing_version: runtime.preprocessing_version,
        }),
      };
    },
  );
  const providerTerms = sha256("fake-provider-no-network-v1");
  const retentionUntil = Math.min(
    createdAt + 30 * 24 * 60 * 60 * 1000,
    createdAt + lifetime + 24 * 60 * 60 * 1000,
  );
  const grant: CollectorConsentGrant = {
    schema_version: "checkback.shadow-consent-grant.v1",
    run_mode: "rehearsal",
    authorization_id: numbered("authorization", numericId),
    purpose: "checkback-verifier-shadow-evaluation",
    provider_id: "fake_local",
    provider_terms_sha256: providerTerms,
    created_at_ms: createdAt,
    expires_at_ms: createdAt + lifetime,
    retention_until_ms: retentionUntil,
    max_executions: executionCount,
    max_provider_calls: executionCount * 3,
    authorized_executions: authorizedExecutions,
  };
  const manifest: CollectorRoundManifest = {
    schema_version: "checkback.shadow-collector-round.v1",
    run_mode: "rehearsal",
    purpose: "checkback-verifier-shadow-evaluation",
    round_id: numbered("round", numericId),
    authorization_id: grant.authorization_id,
    suite_id: numbered("suite", numericId),
    created_at_ms: createdAt,
    expires_at_ms: grant.expires_at_ms,
    retention_until_ms: grant.retention_until_ms,
    max_executions: executionCount,
    max_provider_calls: executionCount * 3,
    consent_grant_sha256: sha256Canonical(grant),
    provider_terms_sha256: providerTerms,
    receipt_key_id: signer.keyId,
    sampling_plan: {
      representative_plan_id: numbered("plan", numericId * 2 - 1),
      challenge_plan_id: numbered("plan", numericId * 2),
      locked_before_collection: true,
    },
    config,
    runtime,
    runtime_snapshot_sha256: sha256Canonical(runtime),
    authorized_executions: authorizedExecutions,
  };
  const signedManifest = signCollectorManifest(signer, manifest);
  const plans: CollectorExecutionPlan[] = authorizedExecutions.map(
    (authorized, index) => {
      const cohort = index % 2 === 0 ? "representative" : "challenge";
      return {
        schema_version: "checkback.shadow-collector-execution.v1",
        round_id: manifest.round_id,
        round_manifest_sha256: sha256Canonical(manifest),
        execution_id: authorized.execution_id,
        pair_commitment_hmac_sha256:
          authorized.pair_commitment_hmac_sha256,
        case_id: numbered("case", numericId * 1_000 + index + 1),
        scene_id: numbered("scene", numericId * 1_000 + index + 1),
        trial_id: numbered("trial", numericId * 1_000 + index + 1),
        split: "smoke",
        cohort,
        sampling_plan_id:
          cohort === "representative"
            ? manifest.sampling_plan.representative_plan_id
            : manifest.sampling_plan.challenge_plan_id,
        scenario: index % 2 === 0 ? "desk" : "lab",
        day_bucket: numbered("day", numericId),
        time_period: index % 3 === 0 ? "morning" : index % 3 === 1 ? "midday" : "evening",
      };
    },
  );

  return {
    signer,
    consent_grant: grant,
    manifest,
    signed_manifest: signedManifest,
    execution_plans: plans,
  };
}