import {
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";
import { z } from "zod";
import { computeShadowConfigSha256 } from "../shadow-evaluator.ts";
import {
  CHECKBACK_QWEN_SHADOW_CONFIG_SHA256,
  PINNED_QWEN_SHADOW_EVALUATION_CONFIG,
} from "../../app/lib/qwen-model-config.ts";

const Hex64Schema = z.string().regex(/^[a-f0-9]{64}$/);
const SafeIdentifierSchema = z
  .string()
  .min(1)
  .max(100)
  .regex(/^[A-Za-z0-9._-]+$/);
const SuiteIdentifierSchema = z.string().regex(/^suite-[0-9]{4,8}$/);
const RoundIdentifierSchema = z.string().regex(/^round-[0-9]{4,8}$/);
const AuthorizationIdentifierSchema = z
  .string()
  .regex(/^authorization-[0-9]{4,8}$/);
const ExecutionIdentifierSchema = z
  .string()
  .regex(/^execution-[0-9]{4,8}$/);
const CaseIdentifierSchema = z.string().regex(/^case-[0-9]{4,8}$/);
const SceneIdentifierSchema = z.string().regex(/^scene-[0-9]{4,8}$/);
const TrialIdentifierSchema = z.string().regex(/^trial-[0-9]{4,8}$/);
const ItemIdentifierSchema = z.string().regex(/^item-[0-9]{4,8}$/);
const ZoneIdentifierSchema = z.string().regex(/^zone-[0-9]{4,8}$/);
const DayBucketSchema = z.string().regex(/^day-[0-9]{3,6}$/);
const PlanIdentifierSchema = z.string().regex(/^plan-[0-9]{4,8}$/);
const TimestampSchema = z.number().int().nonnegative();
const LatencySchema = z.number().int().min(0).max(300_000);

export const FAKE_RUNTIME_PROFILE = Object.freeze({
  endpoint_profile_id: "offline-none-v1",
  endpoint_url_sha256: createHash("sha256")
    .update("offline://none")
    .digest("hex"),
  client_package: "checkback-fake-provider",
  client_version: "1.0.0",
  preprocessing_version: "anonymous-fixture-v1",
});

export const CollectorCallSlotSchema = z.enum([
  "primary",
  "flash",
  "plus",
]);

export type CollectorCallSlot = z.infer<typeof CollectorCallSlotSchema>;

export const CollectorProviderOutcomeSchema = z.enum([
  "success",
  "timeout",
  "request_error",
  "invalid_output",
  "unknown_after_crash",
  "cancelled_before_dispatch",
]);

export type CollectorProviderOutcome = z.infer<
  typeof CollectorProviderOutcomeSchema
>;

export const CollectorRuntimeSnapshotSchema = z
  .object({
    provider_id: z.literal("fake_local"),
    endpoint_profile_id: z.literal(FAKE_RUNTIME_PROFILE.endpoint_profile_id),
    endpoint_url_sha256: z.literal(FAKE_RUNTIME_PROFILE.endpoint_url_sha256),
    client_package: z.literal(FAKE_RUNTIME_PROFILE.client_package),
    client_version: z.literal(FAKE_RUNTIME_PROFILE.client_version),
    collector_build_sha256: Hex64Schema,
    primary_prompt_sha256: Hex64Schema,
    verifier_prompt_sha256: Hex64Schema,
    preprocessing_version: z.literal(FAKE_RUNTIME_PROFILE.preprocessing_version),
    config_sha256: Hex64Schema,
  })
  .strict();

export const CollectorShadowConfigSchema = z
  .object({
    primary_model: SafeIdentifierSchema,
    flash_model: SafeIdentifierSchema,
    plus_model: SafeIdentifierSchema,
    primary_timeout_ms: LatencySchema,
    fast_timeout_ms: LatencySchema,
    plus_timeout_ms: LatencySchema,
    max_retries: z.literal(0),
    prompt_version: SafeIdentifierSchema,
    prompt_sha256: Hex64Schema,
  })
  .strict()
  .superRefine((value, context) => {
    if (
      canonicalJson(value) !==
      canonicalJson(PINNED_QWEN_SHADOW_EVALUATION_CONFIG)
    ) {
      context.addIssue({
        code: "custom",
        message: "collector config must equal the frozen rehearsal config",
      });
    }
  });

const AuthorizedExecutionSchema = z
  .object({
    execution_id: ExecutionIdentifierSchema,
    pair_commitment_hmac_sha256: Hex64Schema,
  })
  .strict();

export const CollectorConsentGrantSchema = z
  .object({
    schema_version: z.literal("checkback.shadow-consent-grant.v1"),
    run_mode: z.literal("rehearsal"),
    authorization_id: AuthorizationIdentifierSchema,
    purpose: z.literal("checkback-verifier-shadow-evaluation"),
    provider_id: z.literal("fake_local"),
    provider_terms_sha256: Hex64Schema,
    created_at_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
    retention_until_ms: TimestampSchema,
    max_executions: z.number().int().min(1).max(10_000),
    max_provider_calls: z.number().int().min(3).max(30_000),
    authorized_executions: z.array(AuthorizedExecutionSchema).min(1).max(10_000),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.expires_at_ms <= value.created_at_ms) {
      context.addIssue({ code: "custom", path: ["expires_at_ms"], message: "grant must expire after creation" });
    }
    if (value.retention_until_ms < value.expires_at_ms) {
      context.addIssue({ code: "custom", path: ["retention_until_ms"], message: "grant retention cannot end before expiry" });
    }
    if (
      value.retention_until_ms >
      value.created_at_ms + 30 * 24 * 60 * 60 * 1000
    ) {
      context.addIssue({ code: "custom", path: ["retention_until_ms"], message: "grant retention cannot exceed 30 days" });
    }
    if (value.max_provider_calls !== value.max_executions * 3) {
      context.addIssue({ code: "custom", path: ["max_provider_calls"], message: "grant call cap must equal 3N" });
    }
    if (value.authorized_executions.length !== value.max_executions) {
      context.addIssue({ code: "custom", path: ["authorized_executions"], message: "grant must pre-allocate exactly N executions" });
    }
    const ids = value.authorized_executions.map((item) => item.execution_id);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({ code: "custom", path: ["authorized_executions"], message: "grant execution IDs must be unique" });
    }
  });

export type CollectorConsentGrant = z.infer<typeof CollectorConsentGrantSchema>;

export const CollectorRoundManifestSchema = z
  .object({
    schema_version: z.literal("checkback.shadow-collector-round.v1"),
    run_mode: z.literal("rehearsal"),
    purpose: z.literal("checkback-verifier-shadow-evaluation"),
    round_id: RoundIdentifierSchema,
    authorization_id: AuthorizationIdentifierSchema,
    suite_id: SuiteIdentifierSchema,
    created_at_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
    retention_until_ms: TimestampSchema,
    max_executions: z.number().int().min(1).max(10_000),
    max_provider_calls: z.number().int().min(3).max(30_000),
    consent_grant_sha256: Hex64Schema,
    provider_terms_sha256: Hex64Schema,
    receipt_key_id: z.string().regex(/^[a-f0-9]{32}$/),
    sampling_plan: z
      .object({
        representative_plan_id: PlanIdentifierSchema,
        challenge_plan_id: PlanIdentifierSchema,
        locked_before_collection: z.literal(true),
      })
      .strict(),
    config: CollectorShadowConfigSchema,
    runtime: CollectorRuntimeSnapshotSchema,
    runtime_snapshot_sha256: Hex64Schema,
    authorized_executions: z
      .array(AuthorizedExecutionSchema)
      .min(1)
      .max(10_000),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.max_provider_calls !== value.max_executions * 3) {
      context.addIssue({
        code: "custom",
        path: ["max_provider_calls"],
        message: "max_provider_calls must equal 3N",
      });
    }
    if (value.authorized_executions.length !== value.max_executions) {
      context.addIssue({
        code: "custom",
        path: ["authorized_executions"],
        message: "authorization must pre-allocate exactly N executions",
      });
    }
    const executionIds = value.authorized_executions.map(
      (item) => item.execution_id,
    );
    if (new Set(executionIds).size !== executionIds.length) {
      context.addIssue({
        code: "custom",
        path: ["authorized_executions"],
        message: "authorized execution IDs must be unique",
      });
    }
    if (value.expires_at_ms <= value.created_at_ms) {
      context.addIssue({
        code: "custom",
        path: ["expires_at_ms"],
        message: "authorization must expire after creation",
      });
    }
    if (value.retention_until_ms < value.expires_at_ms) {
      context.addIssue({
        code: "custom",
        path: ["retention_until_ms"],
        message: "retention cannot end before authorization expiry",
      });
    }
    if (
      value.retention_until_ms >
      value.created_at_ms + 30 * 24 * 60 * 60 * 1000
    ) {
      context.addIssue({
        code: "custom",
        path: ["retention_until_ms"],
        message: "retention cannot exceed 30 days",
      });
    }
    if (
      value.sampling_plan.representative_plan_id ===
      value.sampling_plan.challenge_plan_id
    ) {
      context.addIssue({
        code: "custom",
        path: ["sampling_plan", "challenge_plan_id"],
        message: "sampling plans must be distinct",
      });
    }
    if (value.runtime.provider_id !== "fake_local") {
      context.addIssue({
        code: "custom",
        path: ["runtime", "provider_id"],
        message: "v1 rehearsal manifests accept only the fake provider",
      });
    }
    if (
      value.runtime.config_sha256 !==
      computeShadowConfigSha256(value.config)
    ) {
      context.addIssue({
        code: "custom",
        path: ["runtime", "config_sha256"],
        message: "runtime config hash must match the declared config",
      });
    }
    if (
      value.runtime.verifier_prompt_sha256 !== value.config.prompt_sha256
    ) {
      context.addIssue({
        code: "custom",
        path: ["runtime", "verifier_prompt_sha256"],
        message: "runtime verifier prompt must match the frozen config",
      });
    }
    if (value.runtime.config_sha256 !== CHECKBACK_QWEN_SHADOW_CONFIG_SHA256) {
      context.addIssue({
        code: "custom",
        path: ["runtime", "config_sha256"],
        message: "runtime config hash must equal the frozen rehearsal hash",
      });
    }
    if (
      value.runtime_snapshot_sha256 !==
      sha256Canonical(value.runtime)
    ) {
      context.addIssue({
        code: "custom",
        path: ["runtime_snapshot_sha256"],
        message: "runtime snapshot hash mismatch",
      });
    }
  });

export type CollectorRoundManifest = z.infer<
  typeof CollectorRoundManifestSchema
>;

export const CollectorSignedManifestSchema = z
  .object({
    payload: CollectorRoundManifestSchema,
    signer_key_id: z.string().regex(/^[a-f0-9]{32}$/),
    signature_hmac_sha256: Hex64Schema,
  })
  .strict()
  .superRefine((value, context) => {
    if (value.signer_key_id !== value.payload.receipt_key_id) {
      context.addIssue({ code: "custom", path: ["signer_key_id"], message: "manifest signer key mismatch" });
    }
  });

export type CollectorSignedManifest = z.infer<typeof CollectorSignedManifestSchema>;

export const CollectorExecutionPlanSchema = z
  .object({
    schema_version: z.literal("checkback.shadow-collector-execution.v1"),
    round_id: RoundIdentifierSchema,
    round_manifest_sha256: Hex64Schema,
    execution_id: ExecutionIdentifierSchema,
    pair_commitment_hmac_sha256: Hex64Schema,
    case_id: CaseIdentifierSchema,
    scene_id: SceneIdentifierSchema,
    trial_id: TrialIdentifierSchema,
    split: z.literal("smoke"),
    cohort: z.enum(["representative", "challenge"]),
    sampling_plan_id: PlanIdentifierSchema,
    scenario: z.enum(["desk", "lab", "shared_tools", "other"]),
    day_bucket: DayBucketSchema,
    time_period: z.enum(["morning", "midday", "evening"]),
  })
  .strict();

export type CollectorExecutionPlan = z.infer<
  typeof CollectorExecutionPlanSchema
>;

export const CollectorCandidateManifestSchema = z
  .object({
    schema_version: z.literal("checkback.shadow-candidates.v1"),
    execution_id: ExecutionIdentifierSchema,
    ordered_item_ids: z.array(ItemIdentifierSchema).min(1).max(20),
    candidate_manifest_sha256: Hex64Schema,
  })
  .strict()
  .superRefine((value, context) => {
    if (new Set(value.ordered_item_ids).size !== value.ordered_item_ids.length) {
      context.addIssue({ code: "custom", path: ["ordered_item_ids"], message: "candidate IDs must be unique" });
    }
    const expected = sha256Canonical({
      schema_version: value.schema_version,
      execution_id: value.execution_id,
      ordered_item_ids: value.ordered_item_ids,
    });
    if (value.candidate_manifest_sha256 !== expected) {
      context.addIssue({ code: "custom", path: ["candidate_manifest_sha256"], message: "candidate manifest hash mismatch" });
    }
  });

export type CollectorCandidateManifest = z.infer<typeof CollectorCandidateManifestSchema>;

const CollectorGroundTruthItemSchema = z
  .object({
    id: ItemIdentifierSchema,
    state: z.enum(["missing", "same_place", "elsewhere"]),
    observability: z.enum(["supported", "not_comparable"]),
    expected_zone: ZoneIdentifierSchema.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    const requiresZone =
      value.state === "elsewhere" && value.observability === "supported";
    if (requiresZone === (value.expected_zone === null)) {
      context.addIssue({
        code: "custom",
        path: ["expected_zone"],
        message: "expected_zone is required only for supported elsewhere",
      });
    }
  });

export const CollectorGroundTruthSchema = z
  .object({
    truth_source: z.enum([
      "staged_protocol",
      "direct_inventory",
      "operator_log",
    ]),
    truth_locked_before_output: z.literal(true),
    labeler_count: z.number().int().min(1).max(5),
    adjudication: z.enum(["agreed", "adjudicated", "single_labeler"]),
    items: z.array(CollectorGroundTruthItemSchema).min(1).max(20),
  })
  .strict()
  .superRefine((value, context) => {
    const isSingle = value.labeler_count === 1;
    if (isSingle !== (value.adjudication === "single_labeler")) {
      context.addIssue({
        code: "custom",
        path: ["adjudication"],
        message: "single_labeler must match labeler_count=1",
      });
    }
    const ids = value.items.map((item) => item.id);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({
        code: "custom",
        path: ["items"],
        message: "ground-truth item IDs must be unique",
      });
    }
  });

export type CollectorGroundTruth = z.infer<
  typeof CollectorGroundTruthSchema
>;

export const CollectorGroundTruthEnvelopeSchema = z
  .object({
    schema_version: z.literal("checkback.shadow-ground-truth-envelope.v1"),
    execution_id: ExecutionIdentifierSchema,
    execution_plan_sha256: Hex64Schema,
    candidate_manifest_sha256: Hex64Schema,
    locked_at_ms: TimestampSchema,
    ground_truth: CollectorGroundTruthSchema,
  })
  .strict();

export type CollectorGroundTruthEnvelope = z.infer<typeof CollectorGroundTruthEnvelopeSchema>;

export const SanitizedVerificationItemSchema = z
  .object({
    id: ItemIdentifierSchema,
    verdict: z.enum([
      "confirmed_missing",
      "visible_same_place",
      "visible_elsewhere",
      "not_comparable",
    ]),
    certainty: z.enum(["high", "medium", "low"]),
    current_location: ZoneIdentifierSchema.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    const needsZone = value.verdict === "visible_elsewhere";
    if (needsZone === (value.current_location === null)) {
      context.addIssue({
        code: "custom",
        path: ["current_location"],
        message: "only visible_elsewhere requires an anonymous zone",
      });
    }
  });

export const SanitizedVerificationBatchSchema = z
  .object({
    verifications: z
      .array(SanitizedVerificationItemSchema)
      .min(1)
      .max(20),
  })
  .strict()
  .superRefine((value, context) => {
    const ids = value.verifications.map((item) => item.id);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({
        code: "custom",
        path: ["verifications"],
        message: "verification IDs must be unique",
      });
    }
  });

export type SanitizedVerificationBatch = z.infer<
  typeof SanitizedVerificationBatchSchema
>;

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("canonical JSON accepts only finite numbers");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (
    typeof value === "object" &&
    Object.getPrototypeOf(value) === Object.prototype
  ) {
    const source = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(source)
        .sort()
        .map((key) => [key, canonicalize(source[key])]),
    );
  }
  throw new TypeError("canonical JSON accepts only plain JSON values");
}

export function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export class ReceiptSigner {
  readonly keyId: string;
  #key: Buffer;
  #disposed = false;

  constructor(key: Uint8Array) {
    const bytes = Buffer.from(key);
    if (bytes.byteLength < 32) {
      bytes.fill(0);
      throw new Error("receipt key must contain at least 32 bytes");
    }
    this.#key = bytes;
    this.keyId = createHash("sha256")
      .update(bytes)
      .digest("hex")
      .slice(0, 32);
  }

  signValue(domain: string, value: unknown): string {
    return this.signBytes(domain, Buffer.from(canonicalJson(value), "utf8"));
  }

  signBytes(domain: string, value: Uint8Array): string {
    if (this.#disposed) throw new Error("receipt signer is disposed");
    if (!/^[A-Za-z0-9._-]{1,80}$/.test(domain)) {
      throw new Error("invalid receipt domain");
    }
    return createHmac("sha256", this.#key)
      .update(domain, "utf8")
      .update(Buffer.from([0]))
      .update(value)
      .digest("hex");
  }

  verifyBytes(
    domain: string,
    value: Uint8Array,
    expected: string,
  ): boolean {
    if (!/^[a-f0-9]{64}$/.test(expected)) return false;
    const actual = Buffer.from(this.signBytes(domain, value), "hex");
    const target = Buffer.from(expected, "hex");
    return timingSafeEqual(actual, target);
  }

  verifyValue(domain: string, value: unknown, expected: string): boolean {
    if (!/^[a-f0-9]{64}$/.test(expected)) return false;
    const actual = Buffer.from(this.signValue(domain, value), "hex");
    const target = Buffer.from(expected, "hex");
    return timingSafeEqual(actual, target);
  }

  dispose() {
    if (this.#disposed) return;
    this.#key.fill(0);
    this.#disposed = true;
  }
}
export const COLLECTOR_RECEIPT_DOMAINS = Object.freeze({
  manifest: "collector.manifest.v1",
  pair_commitment: "collector.pair.v1",
  execution_plan: "collector.execution-plan.v1",
  candidate_manifest: "collector.candidates.v1",
  ground_truth: "collector.ground-truth.v1",
  provider_request: "collector.provider-request.v1",
  provider_response: "collector.provider-response.v1",
  audit_event: "collector.audit-event.v1",
  audit_head: "collector.audit-head.v1",
});

export function signCollectorManifest(
  signer: ReceiptSigner,
  input: unknown,
): CollectorSignedManifest {
  const payload = CollectorRoundManifestSchema.parse(input);
  if (payload.receipt_key_id !== signer.keyId) {
    throw new Error("manifest receipt key does not match the signer");
  }
  return CollectorSignedManifestSchema.parse({
    payload,
    signer_key_id: signer.keyId,
    signature_hmac_sha256: signer.signValue(
      COLLECTOR_RECEIPT_DOMAINS.manifest,
      payload,
    ),
  });
}

export function verifyCollectorManifest(
  signer: ReceiptSigner,
  input: unknown,
): CollectorSignedManifest {
  const envelope = CollectorSignedManifestSchema.parse(input);
  if (envelope.signer_key_id !== signer.keyId) {
    throw new Error("manifest signer is not the active round signer");
  }
  if (
    !signer.verifyValue(
      COLLECTOR_RECEIPT_DOMAINS.manifest,
      envelope.payload,
      envelope.signature_hmac_sha256,
    )
  ) {
    throw new Error("manifest signature is invalid");
  }
  return envelope;
}

export function computePairCommitment(
  signer: ReceiptSigner,
  input: {
    before_sha256: string;
    after_sha256: string;
    preprocessing_version: string;
  },
) {
  const before = Hex64Schema.parse(input.before_sha256);
  const after = Hex64Schema.parse(input.after_sha256);
  const preprocessing = z
    .literal(FAKE_RUNTIME_PROFILE.preprocessing_version)
    .parse(input.preprocessing_version);
  return signer.signValue(COLLECTOR_RECEIPT_DOMAINS.pair_commitment, {
    before_sha256: before,
    after_sha256: after,
    preprocessing_version: preprocessing,
  });
}

export function authorizeCollectorExecution(input: {
  signed_manifest: unknown;
  consent_grant: unknown;
  execution_plan: unknown;
  signer: ReceiptSigner;
  now_ms: number;
  revoked_authorization_ids?: ReadonlySet<string>;
}) {
  const signedManifest = verifyCollectorManifest(
    input.signer,
    input.signed_manifest,
  );
  const manifest = signedManifest.payload;
  const grant = CollectorConsentGrantSchema.parse(input.consent_grant);
  const plan = CollectorExecutionPlanSchema.parse(input.execution_plan);
  const now = TimestampSchema.parse(input.now_ms);

  if (input.revoked_authorization_ids?.has(manifest.authorization_id)) {
    throw new Error("authorization is revoked");
  }
  if (
    now < manifest.created_at_ms ||
    now >= manifest.expires_at_ms ||
    now < grant.created_at_ms ||
    now >= grant.expires_at_ms
  ) {
    throw new Error("authorization is outside its valid time window");
  }
  if (manifest.consent_grant_sha256 !== sha256Canonical(grant)) {
    throw new Error("consent grant hash does not match the manifest");
  }
  const manifestGrantProjection = {
    authorization_id: manifest.authorization_id,
    purpose: manifest.purpose,
    provider_id: manifest.runtime.provider_id,
    provider_terms_sha256: manifest.provider_terms_sha256,
    created_at_ms: manifest.created_at_ms,
    expires_at_ms: manifest.expires_at_ms,
    retention_until_ms: manifest.retention_until_ms,
    max_executions: manifest.max_executions,
    max_provider_calls: manifest.max_provider_calls,
    authorized_executions: manifest.authorized_executions,
  };
  const consentProjection = {
    authorization_id: grant.authorization_id,
    purpose: grant.purpose,
    provider_id: grant.provider_id,
    provider_terms_sha256: grant.provider_terms_sha256,
    created_at_ms: grant.created_at_ms,
    expires_at_ms: grant.expires_at_ms,
    retention_until_ms: grant.retention_until_ms,
    max_executions: grant.max_executions,
    max_provider_calls: grant.max_provider_calls,
    authorized_executions: grant.authorized_executions,
  };
  if (canonicalJson(manifestGrantProjection) !== canonicalJson(consentProjection)) {
    throw new Error("consent grant fields do not match the manifest");
  }
  if (plan.round_id !== manifest.round_id) {
    throw new Error("execution plan belongs to another round");
  }
  if (plan.round_manifest_sha256 !== sha256Canonical(manifest)) {
    throw new Error("execution plan manifest hash mismatch");
  }
  const authorized = manifest.authorized_executions.find(
    (item) => item.execution_id === plan.execution_id,
  );
  if (!authorized) {
    throw new Error("execution ID is not pre-authorized");
  }
  if (
    authorized.pair_commitment_hmac_sha256 !==
    plan.pair_commitment_hmac_sha256
  ) {
    throw new Error("execution pair commitment mismatch");
  }
  const expectedPlan =
    plan.cohort === "representative"
      ? manifest.sampling_plan.representative_plan_id
      : manifest.sampling_plan.challenge_plan_id;
  if (plan.sampling_plan_id !== expectedPlan) {
    throw new Error("execution sampling plan does not match its cohort");
  }

  return {
    signed_manifest: signedManifest,
    manifest,
    consent_grant: grant,
    execution_plan: plan,
  };
}

export function createCollectorCandidateManifest(input: {
  execution_id: string;
  ordered_item_ids: string[];
}): CollectorCandidateManifest {
  const base = {
    schema_version: "checkback.shadow-candidates.v1" as const,
    execution_id: input.execution_id,
    ordered_item_ids: [...input.ordered_item_ids],
  };
  return CollectorCandidateManifestSchema.parse({
    ...base,
    candidate_manifest_sha256: sha256Canonical(base),
  });
}

export function createCollectorGroundTruthEnvelope(input: {
  execution_plan: unknown;
  candidate_manifest: unknown;
  ground_truth: unknown;
  locked_at_ms: number;
}): CollectorGroundTruthEnvelope {
  const plan = CollectorExecutionPlanSchema.parse(input.execution_plan);
  const candidates = CollectorCandidateManifestSchema.parse(
    input.candidate_manifest,
  );
  const groundTruth = CollectorGroundTruthSchema.parse(input.ground_truth);
  if (plan.execution_id !== candidates.execution_id) {
    throw new Error("candidate manifest belongs to another execution");
  }
  const truthIds = groundTruth.items.map((item) => item.id);
  if (
    truthIds.length !== candidates.ordered_item_ids.length ||
    new Set(truthIds).size !== truthIds.length ||
    candidates.ordered_item_ids.some((id) => !truthIds.includes(id))
  ) {
    throw new Error("ground truth must cover exactly the candidate manifest");
  }
  return CollectorGroundTruthEnvelopeSchema.parse({
    schema_version: "checkback.shadow-ground-truth-envelope.v1",
    execution_id: plan.execution_id,
    execution_plan_sha256: sha256Canonical(plan),
    candidate_manifest_sha256: candidates.candidate_manifest_sha256,
    locked_at_ms: input.locked_at_ms,
    ground_truth: groundTruth,
  });
}

export function validateCollectorVerificationCoverage(
  candidateInput: unknown,
  batchInput: unknown,
): SanitizedVerificationBatch {
  const candidates = CollectorCandidateManifestSchema.parse(candidateInput);
  const batch = SanitizedVerificationBatchSchema.parse(batchInput);
  const actual = batch.verifications.map((item) => item.id);
  if (
    actual.length !== candidates.ordered_item_ids.length ||
    candidates.ordered_item_ids.some((id) => !actual.includes(id))
  ) {
    throw new Error("verification must cover exactly the candidate manifest");
  }
  return batch;
}
