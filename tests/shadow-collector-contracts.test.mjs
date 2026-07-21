import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  CollectorExecutionPlanSchema,
  CollectorRoundManifestSchema,
  authorizeCollectorExecution,
  computePairCommitment,
  signCollectorManifest,
  ReceiptSigner,
  sha256Canonical,
} from "../evaluation/collector/contracts.ts";
import { DeterministicFakeProvider } from "../evaluation/collector/fake-provider.ts";
import {
  CHECKBACK_QWEN_SHADOW_CONFIG_SHA256,
  PINNED_QWEN_SHADOW_EVALUATION_CONFIG,
} from "../app/lib/qwen-model-config.ts";

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function manifestValue() {
  const signer = new ReceiptSigner(Buffer.alloc(32, 7));
  const config = { ...PINNED_QWEN_SHADOW_EVALUATION_CONFIG };
  const runtime = {
    provider_id: "fake_local",
    endpoint_profile_id: "offline-none-v1",
    endpoint_url_sha256: hash("offline://none"),
    client_package: "checkback-fake-provider",
    client_version: "1.0.0",
    collector_build_sha256: hash("collector-build"),
    primary_prompt_sha256: hash("fake-primary-prompt"),
    verifier_prompt_sha256: config.prompt_sha256,
    preprocessing_version: "anonymous-fixture-v1",
    config_sha256: CHECKBACK_QWEN_SHADOW_CONFIG_SHA256,
  };
  const pairCommitment = computePairCommitment(signer, {
    before_sha256: hash("synthetic-before"),
    after_sha256: hash("synthetic-after"),
    preprocessing_version: runtime.preprocessing_version,
  });
  const authorizedExecutions = [
    {
      execution_id: "execution-0001",
      pair_commitment_hmac_sha256: pairCommitment,
    },
  ];
  const grant = {
    schema_version: "checkback.shadow-consent-grant.v1",
    run_mode: "rehearsal",
    authorization_id: "authorization-0001",
    purpose: "checkback-verifier-shadow-evaluation",
    provider_id: "fake_local",
    provider_terms_sha256: hash("fake-provider-no-network"),
    created_at_ms: 1_000,
    expires_at_ms: 11_000,
    retention_until_ms: 21_000,
    max_executions: 1,
    max_provider_calls: 3,
    authorized_executions: authorizedExecutions,
  };
  const value = {
    schema_version: "checkback.shadow-collector-round.v1",
    run_mode: "rehearsal",
    purpose: "checkback-verifier-shadow-evaluation",
    round_id: "round-0001",
    authorization_id: grant.authorization_id,
    suite_id: "suite-0001",
    created_at_ms: grant.created_at_ms,
    expires_at_ms: grant.expires_at_ms,
    retention_until_ms: 21_000,
    max_executions: grant.max_executions,
    max_provider_calls: grant.max_provider_calls,
    consent_grant_sha256: sha256Canonical(grant),
    provider_terms_sha256: grant.provider_terms_sha256,
    receipt_key_id: signer.keyId,
    sampling_plan: {
      representative_plan_id: "plan-0001",
      challenge_plan_id: "plan-0002",
      locked_before_collection: true,
    },
    config,
    runtime,
    runtime_snapshot_sha256: sha256Canonical(runtime),
    authorized_executions: authorizedExecutions,
  };
  return {
    signer,
    grant,
    value,
    plan: {
      schema_version: "checkback.shadow-collector-execution.v1",
      round_id: value.round_id,
      round_manifest_sha256: sha256Canonical(value),
      execution_id: "execution-0001",
      pair_commitment_hmac_sha256: pairCommitment,
      case_id: "case-0001",
      scene_id: "scene-0001",
      trial_id: "trial-0001",
      split: "smoke",
      cohort: "representative",
      sampling_plan_id: "plan-0001",
      scenario: "desk",
      day_bucket: "day-001",
      time_period: "morning",
    },
  };
}
test("collector manifest uses the frozen evaluator config fingerprint", () => {
  const { signer, value } = manifestValue();
  assert.equal(
    value.runtime.config_sha256,
    CHECKBACK_QWEN_SHADOW_CONFIG_SHA256,
  );
  assert.deepEqual(CollectorRoundManifestSchema.parse(value), value);
  signer.dispose();
});

test("rehearsal contracts cannot represent a real provider or gate split", () => {
  const { signer, value } = manifestValue();
  assert.throws(() =>
    CollectorRoundManifestSchema.parse({
      ...value,
      runtime: {
        ...value.runtime,
        provider_id: "aliyun_bailian_openai_compatible",
      },
    }),
  );
  assert.throws(() =>
    CollectorExecutionPlanSchema.parse({
      schema_version: "checkback.shadow-collector-execution.v1",
      round_id: "round-0001",
      round_manifest_sha256: hash("manifest"),
      execution_id: "execution-0001",
      pair_commitment_hmac_sha256: hash("anonymous-pair"),
      case_id: "case-0001",
      scene_id: "scene-0001",
      trial_id: "trial-0001",
      split: "holdout",
      cohort: "representative",
      sampling_plan_id: "plan-0001",
      scenario: "desk",
      day_bucket: "day-001",
      time_period: "morning",
    }),
  );
  signer.dispose();
});

test("collector manifest derives an exact 3N call cap", () => {
  const { signer, value } = manifestValue();
  assert.throws(() =>
    CollectorRoundManifestSchema.parse({
      ...value,
      max_provider_calls: 4,
    }),
  );
  signer.dispose();
});

test("receipt signer fails closed after disposal", () => {
  const signer = new ReceiptSigner(Buffer.alloc(32, 9));
  const receipt = signer.signValue("test.receipt", { ok: true });
  assert.equal(signer.verifyValue("test.receipt", { ok: true }, receipt), true);
  signer.dispose();
  assert.throws(
    () => signer.signValue("test.receipt", { ok: true }),
    /disposed/,
  );
});

test("fake provider keeps private canaries out of normalized results", async () => {
  const provider = new DeterministicFakeProvider({
    private_request_canary: "PRIVATE_REQUEST_PATH_C_DRIVE",
    primary: {
      outcome: "success",
      latency_ms: 7,
      candidate_ids: ["item-0001"],
      private_response_canary: "RAW_PRIMARY_LABEL",
    },
    flash: {
      outcome: "success",
      latency_ms: 8,
      batch: {
        verifications: [
          {
            id: "item-0001",
            verdict: "confirmed_missing",
            certainty: "high",
            current_location: null,
          },
        ],
      },
    },
    plus: {
      outcome: "timeout",
      latency_ms: 9,
      private_response_canary: "RAW_ERROR_DETAILS",
    },
  });
  const primary = await provider.invokePrimary({
    execution_id: "execution-0001",
  });
  assert.deepEqual(primary.normalized, {
    outcome: "success",
    latency_ms: 7,
    candidate_ids: ["item-0001"],
  });
  assert.equal(
    JSON.stringify(primary.normalized).includes("RAW_PRIMARY_LABEL"),
    false,
  );
  assert.match(primary.response_bytes.toString("utf8"), /RAW_PRIMARY_LABEL/);
  primary.request_bytes.fill(0);
  primary.response_bytes.fill(0);
});

test("fake verifier converts incomplete candidate coverage to invalid_output", async () => {
  const provider = new DeterministicFakeProvider({
    primary: {
      outcome: "success",
      latency_ms: 1,
      candidate_ids: ["item-0001", "item-0002"],
    },
    flash: {
      outcome: "success",
      latency_ms: 2,
      batch: {
        verifications: [
          {
            id: "item-0001",
            verdict: "confirmed_missing",
            certainty: "high",
            current_location: null,
          },
        ],
      },
    },
    plus: {
      outcome: "request_error",
      latency_ms: 3,
    },
  });
  const result = await provider.invokeVerifier("flash", {
    execution_id: "execution-0001",
    candidate_ids: ["item-0001", "item-0002"],
  });
  assert.deepEqual(result.normalized, {
    outcome: "invalid_output",
    latency_ms: 2,
  });
  result.request_bytes.fill(0);
  result.response_bytes.fill(0);
});
test("signed manifest, consent grant, and execution plan authorize as one bundle", () => {
  const { signer, grant, value, plan } = manifestValue();
  const signed = signCollectorManifest(signer, value);
  const authorized = authorizeCollectorExecution({
    signed_manifest: signed,
    consent_grant: grant,
    execution_plan: plan,
    signer,
    now_ms: 2_000,
  });
  assert.equal(authorized.execution_plan.execution_id, "execution-0001");
  assert.throws(
    () =>
      authorizeCollectorExecution({
        signed_manifest: {
          ...signed,
          payload: { ...signed.payload, max_provider_calls: 6 },
        },
        consent_grant: grant,
        execution_plan: plan,
        signer,
        now_ms: 2_000,
      }),
  );
  assert.throws(
    () =>
      authorizeCollectorExecution({
        signed_manifest: signed,
        consent_grant: grant,
        execution_plan: plan,
        signer,
        now_ms: 2_000,
        revoked_authorization_ids: new Set(["authorization-0001"]),
      }),
    /revoked/,
  );
  const retentionMismatch = {
    ...value,
    retention_until_ms: value.retention_until_ms - 1,
  };
  assert.throws(
    () =>
      authorizeCollectorExecution({
        signed_manifest: signCollectorManifest(signer, retentionMismatch),
        consent_grant: grant,
        execution_plan: plan,
        signer,
        now_ms: 2_000,
      }),
    /consent grant fields do not match/,
  );
  signer.dispose();
});
