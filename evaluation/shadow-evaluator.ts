import { createHash } from "node:crypto";
import { z } from "zod";
import {
  runQwenVerificationPolicy,
  validateVerificationBatch,
  type VerificationBatchLike,
  type VerificationItemLike,
} from "../app/lib/verification-policy.ts";
import { PINNED_QWEN_SHADOW_EVALUATION_CONFIG } from "../app/lib/qwen-model-config.ts";

const IdentifierSchema = z.string().min(1).max(80).regex(/^[A-Za-z0-9._-]+$/);
const CaseIdentifierSchema = z.string().regex(/^case-[0-9]{4,8}$/);
const SceneIdentifierSchema = z.string().regex(/^scene-[0-9]{4,8}$/);
const TrialIdentifierSchema = z.string().regex(/^trial-[0-9]{4,8}$/);
const ExecutionIdentifierSchema = z.string().regex(/^execution-[0-9]{4,8}$/);
const ItemIdentifierSchema = z.string().regex(/^item-[0-9]{4,8}$/);
const ZoneIdentifierSchema = z.string().regex(/^zone-[0-9]{4,8}$/);
const DayBucketSchema = z.string().regex(/^day-[0-9]{3,6}$/);
const PlanIdentifierSchema = z.string().regex(/^plan-[0-9]{4,8}$/);
const LatencySchema = z.number().int().min(0).max(300_000);

type ShadowConfigFingerprintInput = {
  primary_model: string;
  flash_model: string;
  plus_model: string;
  primary_timeout_ms: number;
  fast_timeout_ms: number;
  plus_timeout_ms: number;
  max_retries: number;
  prompt_version: string;
  prompt_sha256: string;
};

export function computeShadowConfigSha256(
  config: ShadowConfigFingerprintInput,
) {
  const canonical = {
    primary_model: config.primary_model,
    flash_model: config.flash_model,
    plus_model: config.plus_model,
    primary_timeout_ms: config.primary_timeout_ms,
    fast_timeout_ms: config.fast_timeout_ms,
    plus_timeout_ms: config.plus_timeout_ms,
    max_retries: config.max_retries,
    prompt_version: config.prompt_version,
    prompt_sha256: config.prompt_sha256,
  };
  return createHash("sha256")
    .update(JSON.stringify(canonical))
    .digest("hex");
}

const VerificationItemFixtureSchema = z
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
  .strict();

const VerificationBatchFixtureSchema = z
  .object({
    verifications: z.array(VerificationItemFixtureSchema).max(20),
  })
  .strict();

const SuccessfulAttemptSchema = z
  .object({
    outcome: z.literal("success"),
    latency_ms: LatencySchema,
    batch: VerificationBatchFixtureSchema,
  })
  .strict();

const FailedAttemptSchema = z
  .object({
    outcome: z.enum(["timeout", "request_error", "invalid_output"]),
    latency_ms: LatencySchema,
  })
  .strict();

export const ShadowAttemptSchema = z.discriminatedUnion("outcome", [
  SuccessfulAttemptSchema,
  FailedAttemptSchema,
]);

const GroundTruthItemSchema = z
  .object({
    id: ItemIdentifierSchema,
    state: z.enum(["missing", "same_place", "elsewhere"]),
    observability: z.enum(["supported", "not_comparable"]),
    expected_zone: ZoneIdentifierSchema.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    const needsZone =
      value.state === "elsewhere" && value.observability === "supported";
    if (needsZone === (value.expected_zone === null)) {
      context.addIssue({
        code: "custom",
        path: ["expected_zone"],
        message:
          "expected_zone is required only for supported elsewhere ground truth",
      });
    }
  });

export const ShadowEvaluationCaseSchema = z
  .object({
    case_id: CaseIdentifierSchema,
    scene_id: SceneIdentifierSchema,
    trial_id: TrialIdentifierSchema,
    split: z.enum(["smoke", "gate", "holdout"]),
    cohort: z.enum(["representative", "challenge"]),
    sampling_plan_id: PlanIdentifierSchema,
    scenario: z.enum(["desk", "lab", "shared_tools", "other"]),
    day_bucket: DayBucketSchema,
    time_period: z.enum(["morning", "midday", "evening"]),
    candidates: z.array(ItemIdentifierSchema).min(1).max(20),
    ground_truth: z
      .object({
        truth_source: z.enum([
          "staged_protocol",
          "direct_inventory",
          "operator_log",
        ]),
        truth_locked_before_output: z.boolean(),
        labeler_count: z.number().int().min(1).max(5),
        adjudication: z.enum(["agreed", "adjudicated", "single_labeler"]),
        items: z.array(GroundTruthItemSchema).min(1).max(20),
      })
      .strict()
      .superRefine((groundTruth, context) => {
        const single = groundTruth.labeler_count === 1;
        const markedSingle = groundTruth.adjudication === "single_labeler";
        if (single !== markedSingle) {
          context.addIssue({
            code: "custom",
            path: ["adjudication"],
            message:
              "single_labeler must match a labeler_count of exactly one",
          });
        }
      }),
    execution: z
      .object({
        execution_id: ExecutionIdentifierSchema,
        config_sha256: z.string().regex(/^[a-f0-9]{64}$/),
        primary_calls: z.literal(1),
        flash_calls: z.literal(1),
        plus_calls: z.literal(1),
        retry_calls: z.literal(0),
        total_calls: z.literal(3),
      })
      .strict(),
    primary_latency_ms: LatencySchema,
    flash: ShadowAttemptSchema,
    plus: ShadowAttemptSchema,
  })
  .strict()
  .superRefine((value, context) => {
    const candidateIds = new Set(value.candidates);
    if (candidateIds.size !== value.candidates.length) {
      context.addIssue({
        code: "custom",
        path: ["candidates"],
        message: "candidate IDs must be unique",
      });
    }

    const truthIds = new Set(value.ground_truth.items.map((item) => item.id));
    if (truthIds.size !== value.ground_truth.items.length) {
      context.addIssue({
        code: "custom",
        path: ["ground_truth", "items"],
        message: "ground-truth IDs must be unique",
      });
    }

    if (
      candidateIds.size !== truthIds.size ||
      [...candidateIds].some((id) => !truthIds.has(id))
    ) {
      context.addIssue({
        code: "custom",
        path: ["ground_truth", "items"],
        message: "ground truth must cover exactly the verifier candidate IDs",
      });
    }
  });

export const ShadowEvaluationSuiteSchema = z
  .object({
    schema_version: z.literal("checkback.shadow-eval.v1"),
    suite_id: IdentifierSchema,
    scope: z.literal("verifier_only"),
    sampling_plan: z
      .object({
        representative_plan_id: PlanIdentifierSchema,
        challenge_plan_id: PlanIdentifierSchema,
        locked_before_collection: z.boolean(),
      })
      .strict()
      .superRefine((plan, context) => {
        if (plan.representative_plan_id === plan.challenge_plan_id) {
          context.addIssue({
            code: "custom",
            path: ["challenge_plan_id"],
            message: "representative and challenge plans must be distinct",
          });
        }
      }),
    config: z
      .object({
        primary_model: IdentifierSchema,
        flash_model: IdentifierSchema,
        plus_model: IdentifierSchema,
        primary_timeout_ms: LatencySchema,
        fast_timeout_ms: LatencySchema,
        plus_timeout_ms: LatencySchema,
        max_retries: z.literal(0),
        prompt_version: IdentifierSchema,
        prompt_sha256: z.string().regex(/^[a-f0-9]{64}$/),
      })
      .strict(),
    cases: z.array(ShadowEvaluationCaseSchema).min(1).max(10_000),
  })
  .strict()
  .superRefine((value, context) => {
    const expectedConfigSha256 = computeShadowConfigSha256(value.config);
    const caseIds = new Set<string>();
    const executionIds = new Set<string>();
    const trialKeys = new Set<string>();
    const sceneCohorts = new Map<
      string,
      "representative" | "challenge"
    >();
    const sceneScenarios = new Map<
      string,
      "desk" | "lab" | "shared_tools" | "other"
    >();

    value.cases.forEach((item, index) => {
      if (caseIds.has(item.case_id)) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "case_id"],
          message: "case_id must be unique",
        });
      }
      caseIds.add(item.case_id);

      if (item.execution.config_sha256 !== expectedConfigSha256) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "execution", "config_sha256"],
          message: "execution config hash must match the suite config",
        });
      }

      const expectedPlanId =
        item.cohort === "representative"
          ? value.sampling_plan.representative_plan_id
          : value.sampling_plan.challenge_plan_id;
      if (item.sampling_plan_id !== expectedPlanId) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "sampling_plan_id"],
          message: "sampling_plan_id must match the case cohort",
        });
      }

      if (executionIds.has(item.execution.execution_id)) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "execution", "execution_id"],
          message: "execution_id must be unique",
        });
      }
      executionIds.add(item.execution.execution_id);

      const trialKey = item.scene_id + "::" + item.trial_id;
      if (trialKeys.has(trialKey)) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "trial_id"],
          message: "scene_id and trial_id pair must be unique",
        });
      }
      trialKeys.add(trialKey);

      const priorCohort = sceneCohorts.get(item.scene_id);
      if (priorCohort && priorCohort !== item.cohort) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "cohort"],
          message: "a scene_id cannot cross representative and challenge cohorts",
        });
      } else {
        sceneCohorts.set(item.scene_id, item.cohort);
      }

      const priorScenario = sceneScenarios.get(item.scene_id);
      if (priorScenario && priorScenario !== item.scenario) {
        context.addIssue({
          code: "custom",
          path: ["cases", index, "scenario"],
          message: "a scene_id must keep the same scenario across trials",
        });
      } else {
        sceneScenarios.set(item.scene_id, item.scenario);
      }
    });
  });

export type ShadowAttempt = z.infer<typeof ShadowAttemptSchema>;
export type ShadowEvaluationSuite = z.infer<typeof ShadowEvaluationSuiteSchema>;
export type ShadowEvaluationCase = ShadowEvaluationSuite["cases"][number];

type TruthItem = ShadowEvaluationCase["ground_truth"]["items"][number];
type Decision = "missing" | "same_place" | "elsewhere" | "unresolved";

type ScoreAccumulator = {
  item_count: number;
  supported_item_count: number;
  unsupported_item_count: number;
  supported_missing_count: number;
  confirmed_missing_predictions: number;
  confirmed_missing_true_positives: number;
  unsafe_confirmation_count: number;
  supported_missing_cleared_count: number;
  supported_actionable_cleared_count: number;
  supported_missing_reported_elsewhere_count: number;
  supported_false_issue_count: number;
  supported_elsewhere_wrong_zone_count: number;
  supported_resolved_count: number;
  unsupported_resolved_count: number;
  correct_count: number;
};

export type VerifierGateThresholds = {
  min_trials: number;
  min_holdout_trials: number;
  min_representative_trials: number;
  min_challenge_trials: number;
  min_challenge_unique_scenes: number;
  max_challenge_scene_trial_share: number;
  max_challenge_scene_item_share: number;
  min_challenge_scene_macro_decision_coverage: number;
  min_challenge_scene_decision_coverage_floor: number;
  min_challenge_scene_macro_truth_accuracy: number;
  min_challenge_scene_truth_accuracy_floor: number;
  min_challenge_missing_scene_macro_recall: number;
  min_challenge_missing_scene_recall_floor: number;
  min_unique_scenes: number;
  max_scene_trial_share: number;
  min_day_buckets: number;
  min_complete_day_buckets: number;
  min_time_windows: number;
  min_window_trial_count: number;
  min_representative_window_macro_decision_coverage: number;
  min_representative_window_decision_coverage_floor: number;
  min_representative_window_macro_truth_accuracy: number;
  min_representative_window_truth_accuracy_floor: number;
  min_representative_window_macro_missing_recall: number;
  min_representative_window_missing_recall_floor: number;
  min_supported_missing: number;
  min_supported_missing_scenes: number;
  min_hard_negative_candidates: number;
  min_hard_negative_trials: number;
  min_hard_negative_scenes: number;
  min_supported_same_place_candidates: number;
  min_supported_elsewhere_candidates: number;
  min_not_comparable_candidates: number;
  min_not_comparable_trials: number;
  min_not_comparable_scenes: number;
  min_desk_scenes: number;
  min_lab_scenes: number;
  min_shared_tools_scenes: number;
  min_representative_scenario_trials: number;
  min_scenario_supported_missing_scenes: number;
  min_scenario_hard_negative_scenes: number;
  min_scenario_not_comparable_scenes: number;
  min_scenario_supported_missing_recall: number;
  min_scenario_decision_coverage: number;
  min_scenario_active_truth_accuracy: number;
  max_scenario_active_p95_ms: number;
  min_fast_accept_trials: number;
  min_fast_accept_candidate_rate: number;
  min_flash_batch_valid_rate: number;
  min_plus_batch_valid_rate: number;
  min_active_confirmed_missing_precision: number;
  min_active_supported_missing_recall: number;
  min_active_decision_coverage: number;
  min_active_truth_accuracy: number;
  min_fast_accept_rate: number;
  max_fallback_rate: number;
  max_unresolved_rate: number;
  max_active_p95_ms: number;
  max_worst_window_active_p95_ms: number;
  min_median_paired_improvement: number;
  min_p95_improvement: number;
};

export const DEFAULT_VERIFIER_RELEASE_GATES: VerifierGateThresholds = {
  min_trials: 1_000,
  min_holdout_trials: 1_000,
  min_representative_trials: 700,
  min_challenge_trials: 300,
  min_challenge_unique_scenes: 50,
  max_challenge_scene_trial_share: 0.05,
  max_challenge_scene_item_share: 0.05,
  min_challenge_scene_macro_decision_coverage: 0.95,
  min_challenge_scene_decision_coverage_floor: 0.8,
  min_challenge_scene_macro_truth_accuracy: 0.99,
  min_challenge_scene_truth_accuracy_floor: 0.9,
  min_challenge_missing_scene_macro_recall: 0.9,
  min_challenge_missing_scene_recall_floor: 0.8,
  min_unique_scenes: 50,
  max_scene_trial_share: 0.05,
  min_day_buckets: 7,
  min_complete_day_buckets: 7,
  min_time_windows: 21,
  min_window_trial_count: 30,
  min_representative_window_macro_decision_coverage: 0.95,
  min_representative_window_decision_coverage_floor: 0.8,
  min_representative_window_macro_truth_accuracy: 0.99,
  min_representative_window_truth_accuracy_floor: 0.9,
  min_representative_window_macro_missing_recall: 0.9,
  min_representative_window_missing_recall_floor: 0.8,
  min_supported_missing: 125,
  min_supported_missing_scenes: 20,
  min_hard_negative_candidates: 150,
  min_hard_negative_trials: 100,
  min_hard_negative_scenes: 20,
  min_supported_same_place_candidates: 75,
  min_supported_elsewhere_candidates: 75,
  min_not_comparable_candidates: 150,
  min_not_comparable_trials: 100,
  min_not_comparable_scenes: 20,
  min_desk_scenes: 10,
  min_lab_scenes: 10,
  min_shared_tools_scenes: 10,
  min_representative_scenario_trials: 100,
  min_scenario_supported_missing_scenes: 5,
  min_scenario_hard_negative_scenes: 5,
  min_scenario_not_comparable_scenes: 5,
  min_scenario_supported_missing_recall: 0.9,
  min_scenario_decision_coverage: 0.95,
  min_scenario_active_truth_accuracy: 0.99,
  max_scenario_active_p95_ms: 20_000,
  min_fast_accept_trials: 600,
  min_fast_accept_candidate_rate: 0.65,
  min_flash_batch_valid_rate: 0.99,
  min_plus_batch_valid_rate: 0.995,
  min_active_confirmed_missing_precision: 0.99,
  min_active_supported_missing_recall: 0.9,
  min_active_decision_coverage: 0.95,
  min_active_truth_accuracy: 0.99,
  min_fast_accept_rate: 0.65,
  max_fallback_rate: 0.35,
  max_unresolved_rate: 0.01,
  max_active_p95_ms: 20_000,
  max_worst_window_active_p95_ms: 20_000,
  min_median_paired_improvement: 0.2,
  min_p95_improvement: 0.15,
};

export function parseShadowEvaluationSuite(value: unknown): ShadowEvaluationSuite {
  return ShadowEvaluationSuiteSchema.parse(value);
}

function rate(numerator: number, denominator: number) {
  return denominator === 0 ? null : numerator / denominator;
}

function average(values: number[]) {
  return values.length === 0
    ? null
    : values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function nearestRank(values: number[], quantile: number) {
  if (values.length === 0) return null;
  if (!(quantile > 0 && quantile <= 1)) {
    throw new RangeError("quantile must be greater than zero and at most one");
  }

  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.max(0, Math.ceil(quantile * sorted.length) - 1);
  return sorted[index];
}

function latencyStats(values: number[]) {
  return {
    count: values.length,
    p50_ms: nearestRank(values, 0.5),
    p95_ms: nearestRank(values, 0.95),
  };
}

function attemptBatch(attempt: ShadowAttempt): VerificationBatchLike | null {
  return attempt.outcome === "success" ? attempt.batch : null;
}

async function runRecordedAttempt(attempt: ShadowAttempt) {
  if (attempt.outcome === "success") return attempt.batch;
  if (attempt.outcome === "invalid_output") return null;
  if (attempt.outcome === "timeout") throw new Error("evaluation timeout");
  throw new Error("evaluation request failure");
}

function decisionFromItem(item: VerificationItemLike | undefined): Decision {
  if (!item || item.certainty !== "high") return "unresolved";
  if (item.verdict === "confirmed_missing") return "missing";
  if (item.verdict === "visible_same_place") return "same_place";
  if (item.verdict === "visible_elsewhere") return "elsewhere";
  return "unresolved";
}

function verificationItemMap(
  candidateIds: string[],
  batch: VerificationBatchLike | null,
): Map<string, VerificationItemLike> {
  const candidates = candidateIds.map((id) => ({ id }));
  if (validateVerificationBatch(candidates, batch, false)) return new Map();

  return new Map(batch!.verifications.map((item) => [item.id, item]));
}

function isSupportedDecisionCorrect(
  truth: TruthItem,
  decision: Decision,
  currentLocation: string | null,
) {
  if (truth.observability !== "supported" || decision !== truth.state) {
    return false;
  }
  return truth.state !== "elsewhere" || currentLocation === truth.expected_zone;
}

function emptyScore(): ScoreAccumulator {
  return {
    item_count: 0,
    supported_item_count: 0,
    unsupported_item_count: 0,
    supported_missing_count: 0,
    confirmed_missing_predictions: 0,
    confirmed_missing_true_positives: 0,
    unsafe_confirmation_count: 0,
    supported_missing_cleared_count: 0,
    supported_actionable_cleared_count: 0,
    supported_missing_reported_elsewhere_count: 0,
    supported_false_issue_count: 0,
    supported_elsewhere_wrong_zone_count: 0,
    supported_resolved_count: 0,
    unsupported_resolved_count: 0,
    correct_count: 0,
  };
}

function scoreDecision(
  accumulator: ScoreAccumulator,
  truth: TruthItem,
  decision: Decision,
  currentLocation: string | null,
) {
  accumulator.item_count += 1;
  const supported = truth.observability === "supported";
  const resolved = decision !== "unresolved";
  if (supported) {
    accumulator.supported_item_count += 1;
    if (resolved) accumulator.supported_resolved_count += 1;
  } else {
    accumulator.unsupported_item_count += 1;
    if (resolved) accumulator.unsupported_resolved_count += 1;
  }

  const supportedMissing = truth.state === "missing" && supported;
  if (supportedMissing) accumulator.supported_missing_count += 1;

  if (decision === "missing") {
    accumulator.confirmed_missing_predictions += 1;
    if (supportedMissing) accumulator.confirmed_missing_true_positives += 1;
    else accumulator.unsafe_confirmation_count += 1;
  }

  if (supportedMissing && decision === "same_place") {
    accumulator.supported_missing_cleared_count += 1;
  }
  if (supported && truth.state !== "same_place" && decision === "same_place") {
    accumulator.supported_actionable_cleared_count += 1;
  }
  if (supportedMissing && decision === "elsewhere") {
    accumulator.supported_missing_reported_elsewhere_count += 1;
  }
  if (
    supported &&
    truth.state === "same_place" &&
    (decision === "missing" || decision === "elsewhere")
  ) {
    accumulator.supported_false_issue_count += 1;
  }
  if (
    supported &&
    truth.state === "elsewhere" &&
    decision === "elsewhere" &&
    currentLocation !== truth.expected_zone
  ) {
    accumulator.supported_elsewhere_wrong_zone_count += 1;
  }
  if (isSupportedDecisionCorrect(truth, decision, currentLocation)) {
    accumulator.correct_count += 1;
  }
}

function finalizeScore(accumulator: ScoreAccumulator) {
  return {
    ...accumulator,
    confirmed_missing_precision: rate(
      accumulator.confirmed_missing_true_positives,
      accumulator.confirmed_missing_predictions,
    ),
    supported_missing_recall: rate(
      accumulator.confirmed_missing_true_positives,
      accumulator.supported_missing_count,
    ),
    decision_coverage: rate(
      accumulator.supported_resolved_count,
      accumulator.supported_item_count,
    ),
    unsupported_resolution_rate: rate(
      accumulator.unsupported_resolved_count,
      accumulator.unsupported_item_count,
    ),
    truth_accuracy: rate(
      accumulator.correct_count,
      accumulator.supported_item_count,
    ),
  };
}

function summarizeGroupedScores(scores: Iterable<ScoreAccumulator>) {
  const summaries = [...scores].map((score) => finalizeScore(score));
  const supported = summaries.filter((score) => score.supported_item_count > 0);
  const missing = summaries.filter(
    (score) => score.supported_missing_count > 0,
  );
  const decisionCoverage = supported
    .map((score) => score.decision_coverage)
    .filter((value): value is number => value !== null);
  const truthAccuracy = supported
    .map((score) => score.truth_accuracy)
    .filter((value): value is number => value !== null);
  const missingRecall = missing
    .map((score) => score.supported_missing_recall)
    .filter((value): value is number => value !== null);

  return {
    supported_scene_count: supported.length,
    missing_scene_count: missing.length,
    macro_decision_coverage: average(decisionCoverage),
    decision_coverage_floor:
      decisionCoverage.length > 0 ? Math.min(...decisionCoverage) : null,
    macro_truth_accuracy: average(truthAccuracy),
    truth_accuracy_floor:
      truthAccuracy.length > 0 ? Math.min(...truthAccuracy) : null,
    missing_scene_macro_recall: average(missingRecall),
    missing_scene_recall_floor:
      missingRecall.length > 0 ? Math.min(...missingRecall) : null,
  };
}

type CaseQuality = {
  decision_coverage: number | null;
  truth_accuracy: number | null;
  supported_missing_recall: number | null;
};

function summarizeCaseMacroGroups(groups: Iterable<CaseQuality[]>) {
  const groupSummaries = [...groups].map((cases) => ({
    decision_coverage: average(
      cases
        .map((item) => item.decision_coverage)
        .filter((value): value is number => value !== null),
    ),
    truth_accuracy: average(
      cases
        .map((item) => item.truth_accuracy)
        .filter((value): value is number => value !== null),
    ),
    supported_missing_recall: average(
      cases
        .map((item) => item.supported_missing_recall)
        .filter((value): value is number => value !== null),
    ),
  }));
  const decisionCoverage = groupSummaries
    .map((item) => item.decision_coverage)
    .filter((value): value is number => value !== null);
  const truthAccuracy = groupSummaries
    .map((item) => item.truth_accuracy)
    .filter((value): value is number => value !== null);
  const missingRecall = groupSummaries
    .map((item) => item.supported_missing_recall)
    .filter((value): value is number => value !== null);

  return {
    case_macro_decision_coverage: average(decisionCoverage),
    case_macro_decision_coverage_floor:
      decisionCoverage.length > 0 ? Math.min(...decisionCoverage) : null,
    case_macro_truth_accuracy: average(truthAccuracy),
    case_macro_truth_accuracy_floor:
      truthAccuracy.length > 0 ? Math.min(...truthAccuracy) : null,
    case_macro_missing_recall: average(missingRecall),
    case_macro_missing_recall_floor:
      missingRecall.length > 0 ? Math.min(...missingRecall) : null,
  };
}

export async function evaluateShadowSuite(suite: ShadowEvaluationSuite) {
  const flashScore = emptyScore();
  const plusScore = emptyScore();
  const activeScore = emptyScore();
  const representativeScore = emptyScore();
  const challengeScore = emptyScore();
  const gatedScenarios = ["desk", "lab", "shared_tools"] as const;
  const scenarioEvaluation = {
    desk: {
      representativeScore: emptyScore(),
      challengeScore: emptyScore(),
      challengeTrialCount: 0,
      supportedMissingScenes: new Set<string>(),
      hardNegativeScenes: new Set<string>(),
      notComparableScenes: new Set<string>(),
      representativeTrialCount: 0,
      representativeActiveLatencies: [] as number[],
    },
    lab: {
      representativeScore: emptyScore(),
      challengeScore: emptyScore(),
      challengeTrialCount: 0,
      supportedMissingScenes: new Set<string>(),
      hardNegativeScenes: new Set<string>(),
      notComparableScenes: new Set<string>(),
      representativeTrialCount: 0,
      representativeActiveLatencies: [] as number[],
    },
    shared_tools: {
      representativeScore: emptyScore(),
      challengeScore: emptyScore(),
      challengeTrialCount: 0,
      supportedMissingScenes: new Set<string>(),
      hardNegativeScenes: new Set<string>(),
      notComparableScenes: new Set<string>(),
      representativeTrialCount: 0,
      representativeActiveLatencies: [] as number[],
    },
  };

  let flashStructuredSuccess = 0;
  let plusStructuredSuccess = 0;
  let flashBatchValid = 0;
  let plusBatchValid = 0;
  let fastAcceptCount = 0;
  let fallbackCount = 0;
  let unresolvedCount = 0;
  let shadowAgreementCount = 0;
  let shadowAgreementEvaluableCount = 0;
  let activePlusDecisionMatchCount = 0;
  let comparisonItemCount = 0;
  let truthRegressionVsPlusCount = 0;
  let unsafeConfirmationRegressionVsPlusCount = 0;
  let supportedMissingClearRegressionVsPlusCount = 0;
  let fastFalseAcceptCaseCount = 0;
  let representativeFlashStructuredSuccess = 0;
  let representativePlusStructuredSuccess = 0;
  let representativeFlashBatchValid = 0;
  let representativePlusBatchValid = 0;
  let representativeFastAcceptCount = 0;
  let representativeFastAcceptedCandidateCount = 0;
  let representativeFallbackCount = 0;
  let representativeUnresolvedCount = 0;

  const baselineLatencies: number[] = [];
  const shadowLatencies: number[] = [];
  const activeLatencies: number[] = [];
  const pairedImprovements: number[] = [];
  const representativeBaselineLatencies: number[] = [];
  const representativeActiveLatencies: number[] = [];
  const representativePairedImprovements: number[] = [];

  const sceneCounts = new Map<string, number>();
  const representativeSceneCounts = new Map<string, number>();
  const representativeSceneScores = new Map<string, ScoreAccumulator>();
  const challengeSceneTrialCounts = new Map<string, number>();
  const challengeSceneItemCounts = new Map<string, number>();
  const challengeSceneScores = new Map<string, ScoreAccumulator>();
  const timeWindows = new Set<string>();
  const windowTrialCounts = new Map<string, number>();
  const windowActiveLatencies = new Map<string, number[]>();
  const representativeTimeWindows = new Set<string>();
  const representativeWindowTrialCounts = new Map<string, number>();
  const representativeWindowActiveLatencies = new Map<string, number[]>();
  const representativeWindowScores = new Map<string, ScoreAccumulator>();
  const representativeWindowCaseQualities = new Map<string, CaseQuality[]>();
  const dayPeriods = new Map<string, Set<ShadowEvaluationCase["time_period"]>>();
  const representativeDayPeriods = new Map<
    string,
    Set<ShadowEvaluationCase["time_period"]>
  >();
  const splitCounts = { smoke: 0, gate: 0, holdout: 0 };
  const cohortCounts = { representative: 0, challenge: 0 };
  const scenarioScenes = {
    desk: new Set<string>(),
    lab: new Set<string>(),
    shared_tools: new Set<string>(),
    other: new Set<string>(),
  };
  const supportedMissingScenes = new Set<string>();
  const hardNegativeScenes = new Set<string>();
  const notComparableScenes = new Set<string>();
  const challengeSupportedMissingScenes = new Set<string>();
  const challengeHardNegativeScenes = new Set<string>();
  const challengeNotComparableScenes = new Set<string>();

  let truthLockViolationCount = 0;
  let labelingViolationCount = 0;
  let candidateCount = 0;
  let challengeCandidateCount = 0;
  let challengeSupportedMissingCount = 0;
  let challengeHardNegativeCount = 0;
  let challengeHardNegativeTrialCount = 0;
  let challengeSupportedSamePlaceCount = 0;
  let challengeSupportedElsewhereCount = 0;
  let challengeNotComparableCount = 0;
  let challengeNotComparableTrialCount = 0;
  let supportedMissingCount = 0;
  let hardNegativeCount = 0;
  let hardNegativeTrialCount = 0;
  let supportedSamePlaceCount = 0;
  let supportedElsewhereCount = 0;
  let notComparableCount = 0;
  let notComparableTrialCount = 0;

  for (const item of suite.cases) {
    sceneCounts.set(item.scene_id, (sceneCounts.get(item.scene_id) ?? 0) + 1);
    scenarioScenes[item.scenario].add(item.scene_id);
    splitCounts[item.split] += 1;
    cohortCounts[item.cohort] += 1;
    if (!item.ground_truth.truth_locked_before_output) {
      truthLockViolationCount += 1;
    }
    if (
      item.ground_truth.labeler_count < 2 ||
      item.ground_truth.adjudication === "single_labeler"
    ) {
      labelingViolationCount += 1;
    }
    const windowKey = item.day_bucket + "::" + item.time_period;
    timeWindows.add(windowKey);
    windowTrialCounts.set(windowKey, (windowTrialCounts.get(windowKey) ?? 0) + 1);
    const periods = dayPeriods.get(item.day_bucket) ?? new Set();
    periods.add(item.time_period);
    dayPeriods.set(item.day_bucket, periods);
    candidateCount += item.candidates.length;

    if (item.cohort === "representative") {
      representativeSceneCounts.set(
        item.scene_id,
        (representativeSceneCounts.get(item.scene_id) ?? 0) + 1,
      );
      representativeTimeWindows.add(windowKey);
      representativeWindowTrialCounts.set(
        windowKey,
        (representativeWindowTrialCounts.get(windowKey) ?? 0) + 1,
      );
      const representativePeriods =
        representativeDayPeriods.get(item.day_bucket) ?? new Set();
      representativePeriods.add(item.time_period);
      representativeDayPeriods.set(item.day_bucket, representativePeriods);
      if (item.scenario !== "other") {
        scenarioEvaluation[item.scenario].representativeTrialCount += 1;
      }
    } else {
      challengeCandidateCount += item.candidates.length;
      challengeSceneTrialCounts.set(
        item.scene_id,
        (challengeSceneTrialCounts.get(item.scene_id) ?? 0) + 1,
      );
      challengeSceneItemCounts.set(
        item.scene_id,
        (challengeSceneItemCounts.get(item.scene_id) ?? 0) +
          item.ground_truth.items.length,
      );
      if (item.scenario !== "other") {
        scenarioEvaluation[item.scenario].challengeTrialCount += 1;
      }
    }

    let trialHasHardNegative = false;
    let trialHasNotComparable = false;
    let challengeTrialHasHardNegative = false;
    let challengeTrialHasNotComparable = false;
    for (const truth of item.ground_truth.items) {
      const scenarioStats =
        item.cohort === "challenge" && item.scenario !== "other"
          ? scenarioEvaluation[item.scenario]
          : null;
      if (truth.observability === "not_comparable") {
        notComparableCount += 1;
        trialHasNotComparable = true;
        notComparableScenes.add(item.scene_id);
        if (item.cohort === "challenge") {
          challengeNotComparableCount += 1;
          challengeTrialHasNotComparable = true;
          challengeNotComparableScenes.add(item.scene_id);
          scenarioStats?.notComparableScenes.add(item.scene_id);
        }
      } else if (truth.state === "missing") {
        supportedMissingCount += 1;
        supportedMissingScenes.add(item.scene_id);
        if (item.cohort === "challenge") {
          challengeSupportedMissingCount += 1;
          challengeSupportedMissingScenes.add(item.scene_id);
          scenarioStats?.supportedMissingScenes.add(item.scene_id);
        }
      } else {
        hardNegativeCount += 1;
        trialHasHardNegative = true;
        hardNegativeScenes.add(item.scene_id);
        if (truth.state === "same_place") supportedSamePlaceCount += 1;
        if (truth.state === "elsewhere") supportedElsewhereCount += 1;
        if (item.cohort === "challenge") {
          challengeHardNegativeCount += 1;
          challengeTrialHasHardNegative = true;
          challengeHardNegativeScenes.add(item.scene_id);
          scenarioStats?.hardNegativeScenes.add(item.scene_id);
          if (truth.state === "same_place") {
            challengeSupportedSamePlaceCount += 1;
          }
          if (truth.state === "elsewhere") {
            challengeSupportedElsewhereCount += 1;
          }
        }
      }
    }
    if (trialHasHardNegative) hardNegativeTrialCount += 1;
    if (trialHasNotComparable) notComparableTrialCount += 1;
    if (challengeTrialHasHardNegative) challengeHardNegativeTrialCount += 1;
    if (challengeTrialHasNotComparable) challengeNotComparableTrialCount += 1;

    if (item.flash.outcome === "success") flashStructuredSuccess += 1;
    if (item.plus.outcome === "success") plusStructuredSuccess += 1;

    const candidates = item.candidates.map((id) => ({ id }));
    const flashBatch = attemptBatch(item.flash);
    const plusBatch = attemptBatch(item.plus);
    const flashBatchReason = validateVerificationBatch(
      candidates,
      flashBatch,
      false,
    );
    const plusBatchReason = validateVerificationBatch(candidates, plusBatch, false);
    if (!flashBatchReason) flashBatchValid += 1;
    if (!plusBatchReason) plusBatchValid += 1;
    if (item.cohort === "representative") {
      if (item.flash.outcome === "success") {
        representativeFlashStructuredSuccess += 1;
      }
      if (item.plus.outcome === "success") {
        representativePlusStructuredSuccess += 1;
      }
      if (!flashBatchReason) representativeFlashBatchValid += 1;
      if (!plusBatchReason) representativePlusBatchValid += 1;
    }

    const active = await runQwenVerificationPolicy({
      mode: "active",
      candidates,
      runFast: async () => runRecordedAttempt(item.flash),
      runFallback: async () => runRecordedAttempt(item.plus),
    });
    const shadow = await runQwenVerificationPolicy({
      mode: "shadow",
      candidates,
      runFast: async () => runRecordedAttempt(item.flash),
      runFallback: async () => runRecordedAttempt(item.plus),
    });

    const fastAccepted = active.diagnostics.path === "qwen_fast";
    if (fastAccepted) fastAcceptCount += 1;
    else fallbackCount += 1;
    if (active.diagnostics.path === "qwen_unresolved") unresolvedCount += 1;
    if (item.cohort === "representative") {
      if (fastAccepted) {
        representativeFastAcceptCount += 1;
        representativeFastAcceptedCandidateCount += item.candidates.length;
      } else {
        representativeFallbackCount += 1;
      }
      if (active.diagnostics.path === "qwen_unresolved") {
        representativeUnresolvedCount += 1;
      }
    }

    if (shadow.diagnostics.shadow_agreement !== null) {
      shadowAgreementEvaluableCount += 1;
      if (shadow.diagnostics.shadow_agreement) shadowAgreementCount += 1;
    }

    const flashItems = verificationItemMap(item.candidates, flashBatch);
    const plusItems = verificationItemMap(item.candidates, plusBatch);
    const activeItems = verificationItemMap(item.candidates, active.verification);

    let caseHasUnsafeFastConfirmation = false;
    const activeCaseScore = emptyScore();
    for (const truth of item.ground_truth.items) {
      const flashItem = flashItems.get(truth.id);
      const plusItem = plusItems.get(truth.id);
      const activeItem = activeItems.get(truth.id);
      const flashDecision = decisionFromItem(flashItem);
      const plusDecision = decisionFromItem(plusItem);
      const activeDecision = decisionFromItem(activeItem);

      scoreDecision(
        flashScore,
        truth,
        flashDecision,
        flashItem?.current_location ?? null,
      );
      scoreDecision(
        plusScore,
        truth,
        plusDecision,
        plusItem?.current_location ?? null,
      );
      scoreDecision(
        activeScore,
        truth,
        activeDecision,
        activeItem?.current_location ?? null,
      );
      scoreDecision(
        activeCaseScore,
        truth,
        activeDecision,
        activeItem?.current_location ?? null,
      );
      if (item.cohort === "representative") {
        scoreDecision(
          representativeScore,
          truth,
          activeDecision,
          activeItem?.current_location ?? null,
        );
        const representativeSceneScore =
          representativeSceneScores.get(item.scene_id) ?? emptyScore();
        scoreDecision(
          representativeSceneScore,
          truth,
          activeDecision,
          activeItem?.current_location ?? null,
        );
        representativeSceneScores.set(item.scene_id, representativeSceneScore);
        const representativeWindowScore =
          representativeWindowScores.get(windowKey) ?? emptyScore();
        scoreDecision(
          representativeWindowScore,
          truth,
          activeDecision,
          activeItem?.current_location ?? null,
        );
        representativeWindowScores.set(windowKey, representativeWindowScore);
        if (item.scenario !== "other") {
          scoreDecision(
            scenarioEvaluation[item.scenario].representativeScore,
            truth,
            activeDecision,
            activeItem?.current_location ?? null,
          );
        }
      } else {
        scoreDecision(
          challengeScore,
          truth,
          activeDecision,
          activeItem?.current_location ?? null,
        );
        const challengeSceneScore =
          challengeSceneScores.get(item.scene_id) ?? emptyScore();
        scoreDecision(
          challengeSceneScore,
          truth,
          activeDecision,
          activeItem?.current_location ?? null,
        );
        challengeSceneScores.set(item.scene_id, challengeSceneScore);
        if (item.scenario !== "other") {
          scoreDecision(
            scenarioEvaluation[item.scenario].challengeScore,
            truth,
            activeDecision,
            activeItem?.current_location ?? null,
          );
        }
      }

      comparisonItemCount += 1;
      if (
        activeDecision === plusDecision &&
        activeItem?.current_location === plusItem?.current_location
      ) {
        activePlusDecisionMatchCount += 1;
      }
      const plusCorrect = isSupportedDecisionCorrect(
        truth,
        plusDecision,
        plusItem?.current_location ?? null,
      );
      const activeCorrect = isSupportedDecisionCorrect(
        truth,
        activeDecision,
        activeItem?.current_location ?? null,
      );
      if (plusCorrect && !activeCorrect) truthRegressionVsPlusCount += 1;

      const supportedMissing =
        truth.state === "missing" && truth.observability === "supported";
      const activeUnsafe = activeDecision === "missing" && !supportedMissing;
      const plusUnsafe = plusDecision === "missing" && !supportedMissing;
      if (activeUnsafe && !plusUnsafe) {
        unsafeConfirmationRegressionVsPlusCount += 1;
      }
      if (fastAccepted && activeUnsafe) caseHasUnsafeFastConfirmation = true;

      if (
        supportedMissing &&
        activeDecision === "same_place" &&
        plusDecision !== "same_place"
      ) {
        supportedMissingClearRegressionVsPlusCount += 1;
      }
    }
    if (item.cohort === "representative") {
      const caseQuality = finalizeScore(activeCaseScore);
      const windowCaseQualities =
        representativeWindowCaseQualities.get(windowKey) ?? [];
      windowCaseQualities.push({
        decision_coverage: caseQuality.decision_coverage,
        truth_accuracy: caseQuality.truth_accuracy,
        supported_missing_recall: caseQuality.supported_missing_recall,
      });
      representativeWindowCaseQualities.set(windowKey, windowCaseQualities);
    }
    if (caseHasUnsafeFastConfirmation) fastFalseAcceptCaseCount += 1;

    const baselineLatency = item.primary_latency_ms + item.plus.latency_ms;
    const shadowLatency =
      item.primary_latency_ms + item.flash.latency_ms + item.plus.latency_ms;
    const activeLatency =
      item.primary_latency_ms +
      item.flash.latency_ms +
      (fastAccepted ? 0 : item.plus.latency_ms);

    baselineLatencies.push(baselineLatency);
    shadowLatencies.push(shadowLatency);
    activeLatencies.push(activeLatency);
    const windowLatencies = windowActiveLatencies.get(windowKey) ?? [];
    windowLatencies.push(activeLatency);
    windowActiveLatencies.set(windowKey, windowLatencies);
    if (baselineLatency > 0) {
      pairedImprovements.push((baselineLatency - activeLatency) / baselineLatency);
    }
    if (item.cohort === "representative") {
      representativeBaselineLatencies.push(baselineLatency);
      representativeActiveLatencies.push(activeLatency);
      const representativeWindowLatencies =
        representativeWindowActiveLatencies.get(windowKey) ?? [];
      representativeWindowLatencies.push(activeLatency);
      representativeWindowActiveLatencies.set(
        windowKey,
        representativeWindowLatencies,
      );
      if (item.scenario !== "other") {
        scenarioEvaluation[item.scenario].representativeActiveLatencies.push(
          activeLatency,
        );
      }
      if (baselineLatency > 0) {
        representativePairedImprovements.push(
          (baselineLatency - activeLatency) / baselineLatency,
        );
      }
    }
  }

  const trialCount = suite.cases.length;
  const representativeTrialCount = cohortCounts.representative;
  const baselineStats = latencyStats(baselineLatencies);
  const activeStats = latencyStats(activeLatencies);
  const representativeBaselineStats = latencyStats(
    representativeBaselineLatencies,
  );
  const representativeActiveStats = latencyStats(
    representativeActiveLatencies,
  );
  const maxSceneTrials = Math.max(...sceneCounts.values());
  const representativeMaxSceneTrials =
    representativeSceneCounts.size > 0
      ? Math.max(...representativeSceneCounts.values())
      : 0;
  const completeDayBucketCount = [...dayPeriods.values()].filter(
    (periods) => periods.size === 3,
  ).length;
  const representativeCompleteDayBucketCount = [
    ...representativeDayPeriods.values(),
  ].filter((periods) => periods.size === 3).length;
  const minWindowTrialCount = Math.min(...windowTrialCounts.values());
  const representativeMinWindowTrialCount =
    representativeWindowTrialCounts.size > 0
      ? Math.min(...representativeWindowTrialCounts.values())
      : 0;
  const worstWindowActiveP95Ms = Math.max(
    ...[...windowActiveLatencies.values()].map(
      (values) => nearestRank(values, 0.95) ?? 0,
    ),
  );
  const representativeWorstWindowActiveP95Ms =
    representativeWindowActiveLatencies.size > 0
      ? Math.max(
          ...[...representativeWindowActiveLatencies.values()].map(
            (values) => nearestRank(values, 0.95) ?? 0,
          ),
        )
      : null;
  const scenarioQuality = Object.fromEntries(
    gatedScenarios.map((scenario) => {
      const values = scenarioEvaluation[scenario];
      const challengeMetrics = finalizeScore(values.challengeScore);
      const representativeMetrics = finalizeScore(values.representativeScore);
      return [
        scenario,
        {
          challenge_trial_count: values.challengeTrialCount,
          challenge_supported_missing_scene_count:
            values.supportedMissingScenes.size,
          challenge_hard_negative_scene_count: values.hardNegativeScenes.size,
          challenge_not_comparable_scene_count:
            values.notComparableScenes.size,
          challenge_supported_missing_count:
            challengeMetrics.supported_missing_count,
          challenge_supported_missing_recall:
            challengeMetrics.supported_missing_recall,
          challenge_decision_coverage: challengeMetrics.decision_coverage,
          challenge_truth_accuracy: challengeMetrics.truth_accuracy,
          representative_trial_count: values.representativeTrialCount,
          representative_supported_missing_recall:
            representativeMetrics.supported_missing_recall,
          representative_decision_coverage:
            representativeMetrics.decision_coverage,
          representative_truth_accuracy: representativeMetrics.truth_accuracy,
          representative_active_p95_ms: nearestRank(
            values.representativeActiveLatencies,
            0.95,
          ),
        },
      ];
    }),
  ) as Record<(typeof gatedScenarios)[number], {
    challenge_trial_count: number;
    challenge_supported_missing_scene_count: number;
    challenge_hard_negative_scene_count: number;
    challenge_not_comparable_scene_count: number;
    challenge_supported_missing_count: number;
    challenge_supported_missing_recall: number | null;
    challenge_decision_coverage: number | null;
    challenge_truth_accuracy: number | null;
    representative_trial_count: number;
    representative_supported_missing_recall: number | null;
    representative_decision_coverage: number | null;
    representative_truth_accuracy: number | null;
    representative_active_p95_ms: number | null;
  }>;
  const representativeSceneQuality = summarizeGroupedScores(
    representativeSceneScores.values(),
  );
  const representativeWindowQuality = {
    ...summarizeGroupedScores(representativeWindowScores.values()),
    ...summarizeCaseMacroGroups(representativeWindowCaseQualities.values()),
  };
  const challengeSceneQuality = summarizeGroupedScores(
    challengeSceneScores.values(),
  );
  const challengeMaxSceneTrials =
    challengeSceneTrialCounts.size > 0
      ? Math.max(...challengeSceneTrialCounts.values())
      : 0;
  const challengeMaxSceneItems =
    challengeSceneItemCounts.size > 0
      ? Math.max(...challengeSceneItemCounts.values())
      : 0;

  const configMatchesExpected = Object.entries(
    PINNED_QWEN_SHADOW_EVALUATION_CONFIG,
  ).every(([key, expected]) =>
    suite.config[key as keyof typeof suite.config] === expected,
  );

  return {
    schema_version: suite.schema_version,
    suite_id: suite.suite_id,
    scope: suite.scope,
    sampling_plan: suite.sampling_plan,
    sampling_plan_locked: suite.sampling_plan.locked_before_collection,
    config: suite.config,
    expected_config: PINNED_QWEN_SHADOW_EVALUATION_CONFIG,
    config_matches_expected: configMatchesExpected,
    limitations: [
      "Verifier-only candidates cannot measure primary candidate recall.",
      "Verifier-only candidates cannot prove case-level unsafe-clear performance.",
      "Synthetic or repeated trials cannot establish a production latency SLA.",
      "Cohort labels and truth provenance require external audit evidence.",
    ],
    counts: {
      trial_count: trialCount,
      holdout_trial_count: splitCounts.holdout,
      non_holdout_trial_count: splitCounts.smoke + splitCounts.gate,
      split_counts: splitCounts,
      cohort_counts: cohortCounts,
      truth_lock_violation_count: truthLockViolationCount,
      labeling_violation_count: labelingViolationCount,
      unique_scene_count: sceneCounts.size,
      day_bucket_count: dayPeriods.size,
      complete_day_bucket_count: completeDayBucketCount,
      time_window_count: timeWindows.size,
      min_window_trial_count: minWindowTrialCount,
      candidate_count: candidateCount,
      supported_missing_count: supportedMissingCount,
      supported_missing_scene_count: supportedMissingScenes.size,
      hard_negative_candidate_count: hardNegativeCount,
      hard_negative_trial_count: hardNegativeTrialCount,
      hard_negative_scene_count: hardNegativeScenes.size,
      supported_same_place_candidate_count: supportedSamePlaceCount,
      supported_elsewhere_candidate_count: supportedElsewhereCount,
      not_comparable_candidate_count: notComparableCount,
      not_comparable_trial_count: notComparableTrialCount,
      not_comparable_scene_count: notComparableScenes.size,
      scenario_scene_counts: {
        desk: scenarioScenes.desk.size,
        lab: scenarioScenes.lab.size,
        shared_tools: scenarioScenes.shared_tools.size,
        other: scenarioScenes.other.size,
      },
      max_scene_trial_share: maxSceneTrials / trialCount,
      challenge: {
        trial_count: cohortCounts.challenge,
        unique_scene_count: challengeSceneTrialCounts.size,
        max_scene_trial_share: rate(
          challengeMaxSceneTrials,
          cohortCounts.challenge,
        ),
        max_scene_item_share: rate(
          challengeMaxSceneItems,
          challengeCandidateCount,
        ),
        candidate_count: challengeCandidateCount,
        supported_missing_count: challengeSupportedMissingCount,
        supported_missing_scene_count: challengeSupportedMissingScenes.size,
        hard_negative_candidate_count: challengeHardNegativeCount,
        hard_negative_trial_count: challengeHardNegativeTrialCount,
        hard_negative_scene_count: challengeHardNegativeScenes.size,
        supported_same_place_candidate_count: challengeSupportedSamePlaceCount,
        supported_elsewhere_candidate_count: challengeSupportedElsewhereCount,
        not_comparable_candidate_count: challengeNotComparableCount,
        not_comparable_trial_count: challengeNotComparableTrialCount,
        not_comparable_scene_count: challengeNotComparableScenes.size,
      },
      representative: {
        trial_count: representativeTrialCount,
        unique_scene_count: representativeSceneCounts.size,
        max_scene_trial_share: rate(
          representativeMaxSceneTrials,
          representativeTrialCount,
        ),
        day_bucket_count: representativeDayPeriods.size,
        complete_day_bucket_count: representativeCompleteDayBucketCount,
        time_window_count: representativeTimeWindows.size,
        min_window_trial_count: representativeMinWindowTrialCount,
      },
    },
    scenario_quality: scenarioQuality,
    representative_scene_quality: representativeSceneQuality,
    representative_window_quality: representativeWindowQuality,
    challenge_scene_quality: challengeSceneQuality,
    structure: {
      flash_structured_success_rate: rate(flashStructuredSuccess, trialCount),
      plus_structured_success_rate: rate(plusStructuredSuccess, trialCount),
      flash_batch_valid_rate: rate(flashBatchValid, trialCount),
      plus_batch_valid_rate: rate(plusBatchValid, trialCount),
      representative: {
        flash_structured_success_rate: rate(
          representativeFlashStructuredSuccess,
          representativeTrialCount,
        ),
        plus_structured_success_rate: rate(
          representativePlusStructuredSuccess,
          representativeTrialCount,
        ),
        flash_batch_valid_rate: rate(
          representativeFlashBatchValid,
          representativeTrialCount,
        ),
        plus_batch_valid_rate: rate(
          representativePlusBatchValid,
          representativeTrialCount,
        ),
      },
    },
    policy: {
      fast_accept_count: fastAcceptCount,
      fast_accept_rate: rate(fastAcceptCount, trialCount),
      fallback_count: fallbackCount,
      fallback_rate: rate(fallbackCount, trialCount),
      unresolved_count: unresolvedCount,
      unresolved_rate: rate(unresolvedCount, trialCount),
      shadow_agreement_count: shadowAgreementCount,
      shadow_agreement_evaluable_count: shadowAgreementEvaluableCount,
      shadow_agreement_rate: rate(
        shadowAgreementCount,
        shadowAgreementEvaluableCount,
      ),
      fast_false_accept_case_count: fastFalseAcceptCaseCount,
      representative: {
        fast_accept_count: representativeFastAcceptCount,
        fast_accept_rate: rate(
          representativeFastAcceptCount,
          representativeTrialCount,
        ),
        fast_accept_candidate_count: representativeFastAcceptedCandidateCount,
        fast_accept_candidate_rate: rate(
          representativeFastAcceptedCandidateCount,
          representativeScore.item_count,
        ),
        item_unresolved_rate: rate(
          representativeScore.supported_item_count -
            representativeScore.supported_resolved_count,
          representativeScore.supported_item_count,
        ),
        terminal_unresolved_case_count: representativeUnresolvedCount,
        terminal_unresolved_case_rate: rate(
          representativeUnresolvedCount,
          representativeTrialCount,
        ),
        fallback_count: representativeFallbackCount,
        fallback_rate: rate(
          representativeFallbackCount,
          representativeTrialCount,
        ),
        unresolved_count: representativeUnresolvedCount,
        unresolved_rate: rate(
          representativeUnresolvedCount,
          representativeTrialCount,
        ),
      },
    },
    flash: finalizeScore(flashScore),
    plus: finalizeScore(plusScore),
    active: finalizeScore(activeScore),
    representative: finalizeScore(representativeScore),
    challenge: finalizeScore(challengeScore),
    comparison: {
      item_count: comparisonItemCount,
      active_plus_decision_match_rate: rate(
        activePlusDecisionMatchCount,
        comparisonItemCount,
      ),
      truth_regression_vs_plus_count: truthRegressionVsPlusCount,
      unsafe_confirmation_regression_vs_plus_count:
        unsafeConfirmationRegressionVsPlusCount,
      supported_missing_clear_regression_vs_plus_count:
        supportedMissingClearRegressionVsPlusCount,
    },
    latency: {
      unit: "model_path_ms",
      percentile_method: "nearest_rank",
      baseline_plus: baselineStats,
      observed_shadow: latencyStats(shadowLatencies),
      simulated_active: activeStats,
      worst_window_active_p95_ms: worstWindowActiveP95Ms,
      representative: {
        baseline_plus: representativeBaselineStats,
        simulated_active: representativeActiveStats,
        worst_window_active_p95_ms: representativeWorstWindowActiveP95Ms,
        median_paired_improvement: nearestRank(
          representativePairedImprovements,
          0.5,
        ),
        p95_improvement:
          representativeBaselineStats.p95_ms !== null &&
          representativeBaselineStats.p95_ms > 0 &&
          representativeActiveStats.p95_ms !== null
            ? (representativeBaselineStats.p95_ms -
                representativeActiveStats.p95_ms) /
              representativeBaselineStats.p95_ms
            : null,
      },
      median_paired_improvement: nearestRank(pairedImprovements, 0.5),
      p95_improvement:
        baselineStats.p95_ms !== null &&
        baselineStats.p95_ms > 0 &&
        activeStats.p95_ms !== null
          ? (baselineStats.p95_ms - activeStats.p95_ms) /
            baselineStats.p95_ms
          : null,
    },
  };
}

export type ShadowEvaluationMetrics = Awaited<
  ReturnType<typeof evaluateShadowSuite>
>;

type GateCheck = {
  id: string;
  passed: boolean;
  actual: number | null;
  requirement: string;
};

function atLeast(
  id: string,
  actual: number | null,
  minimum: number,
): GateCheck {
  return {
    id,
    passed: actual !== null && actual >= minimum,
    actual,
    requirement: ">= " + minimum,
  };
}

function atMost(
  id: string,
  actual: number | null,
  maximum: number,
): GateCheck {
  return {
    id,
    passed: actual !== null && actual <= maximum,
    actual,
    requirement: "<= " + maximum,
  };
}

export function evaluateVerifierGates(
  metrics: ShadowEvaluationMetrics,
  thresholds: VerifierGateThresholds = DEFAULT_VERIFIER_RELEASE_GATES,
) {
  const checks: GateCheck[] = [
    atLeast("pinned_config_match", Number(metrics.config_matches_expected), 1),
    atLeast("sampling_plan_locked", Number(metrics.sampling_plan_locked), 1),
    atMost("non_holdout_trial_count", metrics.counts.non_holdout_trial_count, 0),
    atMost(
      "truth_lock_violation_count",
      metrics.counts.truth_lock_violation_count,
      0,
    ),
    atMost(
      "labeling_violation_count",
      metrics.counts.labeling_violation_count,
      0,
    ),
    atLeast(
      "holdout_trial_count",
      metrics.counts.holdout_trial_count,
      thresholds.min_holdout_trials,
    ),
    atLeast("trial_count", metrics.counts.trial_count, thresholds.min_trials),
    atLeast(
      "representative_trial_count",
      metrics.counts.cohort_counts.representative,
      thresholds.min_representative_trials,
    ),
    atLeast(
      "challenge_trial_count",
      metrics.counts.cohort_counts.challenge,
      thresholds.min_challenge_trials,
    ),
    atLeast(
      "challenge_unique_scene_count",
      metrics.counts.challenge.unique_scene_count,
      thresholds.min_challenge_unique_scenes,
    ),
    atMost(
      "challenge_max_scene_trial_share",
      metrics.counts.challenge.max_scene_trial_share,
      thresholds.max_challenge_scene_trial_share,
    ),
    atMost(
      "challenge_max_scene_item_share",
      metrics.counts.challenge.max_scene_item_share,
      thresholds.max_challenge_scene_item_share,
    ),
    atLeast(
      "challenge_scene_macro_decision_coverage",
      metrics.challenge_scene_quality.macro_decision_coverage,
      thresholds.min_challenge_scene_macro_decision_coverage,
    ),
    atLeast(
      "challenge_scene_decision_coverage_floor",
      metrics.challenge_scene_quality.decision_coverage_floor,
      thresholds.min_challenge_scene_decision_coverage_floor,
    ),
    atLeast(
      "challenge_scene_macro_truth_accuracy",
      metrics.challenge_scene_quality.macro_truth_accuracy,
      thresholds.min_challenge_scene_macro_truth_accuracy,
    ),
    atLeast(
      "challenge_scene_truth_accuracy_floor",
      metrics.challenge_scene_quality.truth_accuracy_floor,
      thresholds.min_challenge_scene_truth_accuracy_floor,
    ),
    atLeast(
      "challenge_missing_scene_macro_recall",
      metrics.challenge_scene_quality.missing_scene_macro_recall,
      thresholds.min_challenge_missing_scene_macro_recall,
    ),
    atLeast(
      "challenge_missing_scene_recall_floor",
      metrics.challenge_scene_quality.missing_scene_recall_floor,
      thresholds.min_challenge_missing_scene_recall_floor,
    ),
    atLeast(
      "representative_scene_macro_decision_coverage",
      metrics.representative_scene_quality.macro_decision_coverage,
      thresholds.min_challenge_scene_macro_decision_coverage,
    ),
    atLeast(
      "representative_scene_decision_coverage_floor",
      metrics.representative_scene_quality.decision_coverage_floor,
      thresholds.min_challenge_scene_decision_coverage_floor,
    ),
    atLeast(
      "representative_scene_macro_truth_accuracy",
      metrics.representative_scene_quality.macro_truth_accuracy,
      thresholds.min_challenge_scene_macro_truth_accuracy,
    ),
    atLeast(
      "representative_scene_truth_accuracy_floor",
      metrics.representative_scene_quality.truth_accuracy_floor,
      thresholds.min_challenge_scene_truth_accuracy_floor,
    ),
    atLeast(
      "representative_missing_scene_macro_recall",
      metrics.representative_scene_quality.missing_scene_macro_recall,
      thresholds.min_challenge_missing_scene_macro_recall,
    ),
    atLeast(
      "representative_missing_scene_recall_floor",
      metrics.representative_scene_quality.missing_scene_recall_floor,
      thresholds.min_challenge_missing_scene_recall_floor,
    ),
    atLeast(
      "representative_unique_scene_count",
      metrics.counts.representative.unique_scene_count,
      thresholds.min_unique_scenes,
    ),
    atMost(
      "representative_max_scene_trial_share",
      metrics.counts.representative.max_scene_trial_share,
      thresholds.max_scene_trial_share,
    ),
    atLeast(
      "representative_day_bucket_count",
      metrics.counts.representative.day_bucket_count,
      thresholds.min_day_buckets,
    ),
    atLeast(
      "representative_complete_day_bucket_count",
      metrics.counts.representative.complete_day_bucket_count,
      thresholds.min_complete_day_buckets,
    ),
    atLeast(
      "representative_time_window_count",
      metrics.counts.representative.time_window_count,
      thresholds.min_time_windows,
    ),
    atLeast(
      "min_window_trial_count",
      metrics.counts.representative.min_window_trial_count,
      thresholds.min_window_trial_count,
    ),
    atLeast(
      "representative_window_macro_decision_coverage",
      metrics.representative_window_quality.macro_decision_coverage,
      thresholds.min_representative_window_macro_decision_coverage,
    ),
    atLeast(
      "representative_window_decision_coverage_floor",
      metrics.representative_window_quality.decision_coverage_floor,
      thresholds.min_representative_window_decision_coverage_floor,
    ),
    atLeast(
      "representative_window_macro_truth_accuracy",
      metrics.representative_window_quality.macro_truth_accuracy,
      thresholds.min_representative_window_macro_truth_accuracy,
    ),
    atLeast(
      "representative_window_truth_accuracy_floor",
      metrics.representative_window_quality.truth_accuracy_floor,
      thresholds.min_representative_window_truth_accuracy_floor,
    ),
    atLeast(
      "representative_window_macro_missing_recall",
      metrics.representative_window_quality.missing_scene_macro_recall,
      thresholds.min_representative_window_macro_missing_recall,
    ),
    atLeast(
      "representative_window_missing_recall_floor",
      metrics.representative_window_quality.missing_scene_recall_floor,
      thresholds.min_representative_window_missing_recall_floor,
    ),
    atLeast(
      "representative_window_case_macro_decision_coverage",
      metrics.representative_window_quality.case_macro_decision_coverage,
      thresholds.min_representative_window_macro_decision_coverage,
    ),
    atLeast(
      "representative_window_case_decision_coverage_floor",
      metrics.representative_window_quality.case_macro_decision_coverage_floor,
      thresholds.min_representative_window_decision_coverage_floor,
    ),
    atLeast(
      "representative_window_case_macro_truth_accuracy",
      metrics.representative_window_quality.case_macro_truth_accuracy,
      thresholds.min_representative_window_macro_truth_accuracy,
    ),
    atLeast(
      "representative_window_case_truth_accuracy_floor",
      metrics.representative_window_quality.case_macro_truth_accuracy_floor,
      thresholds.min_representative_window_truth_accuracy_floor,
    ),
    atLeast(
      "representative_window_case_macro_missing_recall",
      metrics.representative_window_quality.case_macro_missing_recall,
      thresholds.min_representative_window_macro_missing_recall,
    ),
    atLeast(
      "representative_window_case_missing_recall_floor",
      metrics.representative_window_quality.case_macro_missing_recall_floor,
      thresholds.min_representative_window_missing_recall_floor,
    ),
    atLeast(
      "supported_missing_count",
      metrics.counts.challenge.supported_missing_count,
      thresholds.min_supported_missing,
    ),
    atLeast(
      "supported_missing_scene_count",
      metrics.counts.challenge.supported_missing_scene_count,
      thresholds.min_supported_missing_scenes,
    ),
    atLeast(
      "hard_negative_candidate_count",
      metrics.counts.challenge.hard_negative_candidate_count,
      thresholds.min_hard_negative_candidates,
    ),
    atLeast(
      "hard_negative_trial_count",
      metrics.counts.challenge.hard_negative_trial_count,
      thresholds.min_hard_negative_trials,
    ),
    atLeast(
      "hard_negative_scene_count",
      metrics.counts.challenge.hard_negative_scene_count,
      thresholds.min_hard_negative_scenes,
    ),
    atLeast(
      "supported_same_place_candidate_count",
      metrics.counts.challenge.supported_same_place_candidate_count,
      thresholds.min_supported_same_place_candidates,
    ),
    atLeast(
      "supported_elsewhere_candidate_count",
      metrics.counts.challenge.supported_elsewhere_candidate_count,
      thresholds.min_supported_elsewhere_candidates,
    ),
    atLeast(
      "not_comparable_candidate_count",
      metrics.counts.challenge.not_comparable_candidate_count,
      thresholds.min_not_comparable_candidates,
    ),
    atLeast(
      "not_comparable_trial_count",
      metrics.counts.challenge.not_comparable_trial_count,
      thresholds.min_not_comparable_trials,
    ),
    atLeast(
      "not_comparable_scene_count",
      metrics.counts.challenge.not_comparable_scene_count,
      thresholds.min_not_comparable_scenes,
    ),
    atLeast(
      "desk_scene_count",
      metrics.counts.scenario_scene_counts.desk,
      thresholds.min_desk_scenes,
    ),
    atLeast(
      "lab_scene_count",
      metrics.counts.scenario_scene_counts.lab,
      thresholds.min_lab_scenes,
    ),
    atLeast(
      "shared_tools_scene_count",
      metrics.counts.scenario_scene_counts.shared_tools,
      thresholds.min_shared_tools_scenes,
    ),
    atLeast(
      "fast_accept_count",
      metrics.policy.representative.fast_accept_count,
      thresholds.min_fast_accept_trials,
    ),
    atLeast(
      "fast_accept_candidate_rate",
      metrics.policy.representative.fast_accept_candidate_rate,
      thresholds.min_fast_accept_candidate_rate,
    ),
    atLeast(
      "flash_batch_valid_rate",
      metrics.structure.representative.flash_batch_valid_rate,
      thresholds.min_flash_batch_valid_rate,
    ),
    atLeast(
      "plus_batch_valid_rate",
      metrics.structure.representative.plus_batch_valid_rate,
      thresholds.min_plus_batch_valid_rate,
    ),
    atLeast(
      "active_confirmed_missing_precision",
      metrics.challenge.confirmed_missing_precision,
      thresholds.min_active_confirmed_missing_precision,
    ),
    atLeast(
      "active_supported_missing_recall",
      metrics.challenge.supported_missing_recall,
      thresholds.min_active_supported_missing_recall,
    ),
    atMost(
      "active_unsafe_confirmation_count",
      metrics.active.unsafe_confirmation_count,
      0,
    ),
    atMost(
      "active_supported_missing_cleared_count",
      metrics.active.supported_missing_cleared_count,
      0,
    ),
    atMost(
      "active_supported_actionable_cleared_count",
      metrics.active.supported_actionable_cleared_count,
      0,
    ),
    atMost(
      "active_supported_missing_reported_elsewhere_count",
      metrics.active.supported_missing_reported_elsewhere_count,
      0,
    ),
    atMost(
      "active_supported_false_issue_count",
      metrics.active.supported_false_issue_count,
      0,
    ),
    atMost(
      "active_supported_elsewhere_wrong_zone_count",
      metrics.active.supported_elsewhere_wrong_zone_count,
      0,
    ),
    atMost(
      "active_unsupported_resolved_count",
      metrics.active.unsupported_resolved_count,
      0,
    ),
    atMost(
      "truth_regression_vs_plus_count",
      metrics.comparison.truth_regression_vs_plus_count,
      0,
    ),
    atLeast(
      "active_decision_coverage",
      metrics.challenge.decision_coverage,
      thresholds.min_active_decision_coverage,
    ),
    atLeast(
      "active_truth_accuracy",
      metrics.challenge.truth_accuracy,
      thresholds.min_active_truth_accuracy,
    ),
    atLeast(
      "representative_supported_missing_recall",
      metrics.representative.supported_missing_recall,
      thresholds.min_active_supported_missing_recall,
    ),
    atLeast(
      "representative_decision_coverage",
      metrics.representative.decision_coverage,
      thresholds.min_active_decision_coverage,
    ),
    atLeast(
      "representative_truth_accuracy",
      metrics.representative.truth_accuracy,
      thresholds.min_active_truth_accuracy,
    ),
    atLeast(
      "fast_accept_rate",
      metrics.policy.representative.fast_accept_rate,
      thresholds.min_fast_accept_rate,
    ),
    atMost(
      "fallback_rate",
      metrics.policy.representative.fallback_rate,
      thresholds.max_fallback_rate,
    ),
    atMost(
      "unresolved_rate",
      metrics.policy.representative.unresolved_rate,
      thresholds.max_unresolved_rate,
    ),
    atMost(
      "active_p95_ms",
      metrics.latency.representative.simulated_active.p95_ms,
      thresholds.max_active_p95_ms,
    ),
    atMost(
      "worst_window_active_p95_ms",
      metrics.latency.representative.worst_window_active_p95_ms,
      thresholds.max_worst_window_active_p95_ms,
    ),
    atLeast(
      "median_paired_improvement",
      metrics.latency.representative.median_paired_improvement,
      thresholds.min_median_paired_improvement,
    ),
    atLeast(
      "p95_improvement",
      metrics.latency.representative.p95_improvement,
      thresholds.min_p95_improvement,
    ),
  ];

  for (const scenario of ["desk", "lab", "shared_tools"] as const) {
    const values = metrics.scenario_quality[scenario];
    checks.push(
      atLeast(
        scenario + "_representative_trial_count",
        values.representative_trial_count,
        thresholds.min_representative_scenario_trials,
      ),
      atLeast(
        scenario + "_challenge_supported_missing_scene_count",
        values.challenge_supported_missing_scene_count,
        thresholds.min_scenario_supported_missing_scenes,
      ),
      atLeast(
        scenario + "_challenge_hard_negative_scene_count",
        values.challenge_hard_negative_scene_count,
        thresholds.min_scenario_hard_negative_scenes,
      ),
      atLeast(
        scenario + "_challenge_not_comparable_scene_count",
        values.challenge_not_comparable_scene_count,
        thresholds.min_scenario_not_comparable_scenes,
      ),
      atLeast(
        scenario + "_challenge_supported_missing_recall",
        values.challenge_supported_missing_recall,
        thresholds.min_scenario_supported_missing_recall,
      ),
      atLeast(
        scenario + "_challenge_decision_coverage",
        values.challenge_decision_coverage,
        thresholds.min_scenario_decision_coverage,
      ),
      atLeast(
        scenario + "_challenge_truth_accuracy",
        values.challenge_truth_accuracy,
        thresholds.min_scenario_active_truth_accuracy,
      ),
      atLeast(
        scenario + "_representative_supported_missing_recall",
        values.representative_supported_missing_recall,
        thresholds.min_scenario_supported_missing_recall,
      ),
      atLeast(
        scenario + "_representative_decision_coverage",
        values.representative_decision_coverage,
        thresholds.min_scenario_decision_coverage,
      ),
      atLeast(
        scenario + "_representative_truth_accuracy",
        values.representative_truth_accuracy,
        thresholds.min_scenario_active_truth_accuracy,
      ),
      atMost(
        scenario + "_representative_active_p95_ms",
        values.representative_active_p95_ms,
        thresholds.max_scenario_active_p95_ms,
      ),
    );
  }

  return {
    verifier_gate_passed: checks.every((check) => check.passed),
    active_release_ready: false,
    checks,
    release_blockers: [
      "A verifier-only suite cannot prove end-to-end primary recall or unsafe-clear safety.",
      "Verifier PASS requires a pinned-config, frozen representative/challenge plan, independently labeled holdout, and seven complete day buckets.",
      "Public Shadow requires explicit opt-in and a privacy disclosure for provider processing and the third model call.",
      "Production readiness requires controlled cohort routing and multi-window labeled data.",
      "The previously exposed provider credential must be rotated before public testing.",
    ],
  };
}

function percent(value: number | null) {
  return value === null ? "n/a" : (value * 100).toFixed(1) + "%";
}

export function formatShadowEvaluationReport(
  metrics: ShadowEvaluationMetrics,
  gates = evaluateVerifierGates(metrics),
) {
  const failedChecks = gates.checks.filter((check) => !check.passed).length;
  return [
    "CheckBack Shadow evaluation (verifier-only)",
    "Suite: " + metrics.suite_id,
    "Pinned config: " + (metrics.config_matches_expected ? "MATCH" : "MISMATCH"),
    "Splits smoke/gate/holdout: " +
      metrics.counts.split_counts.smoke +
      "/" +
      metrics.counts.split_counts.gate +
      "/" +
      metrics.counts.split_counts.holdout,
    "Trials representative/challenge: " +
      metrics.counts.cohort_counts.representative +
      "/" +
      metrics.counts.cohort_counts.challenge,
    "Representative scenes/days/windows: " +
      metrics.counts.representative.unique_scene_count +
      "/" +
      metrics.counts.representative.day_bucket_count +
      "/" +
      metrics.counts.representative.time_window_count,
    "Challenge missing precision/recall: " +
      percent(metrics.challenge.confirmed_missing_precision) +
      "/" +
      percent(metrics.challenge.supported_missing_recall),
    "Unsafe confirmations/actionable clears/missing-as-elsewhere/false issues/wrong zones: " +
      metrics.active.unsafe_confirmation_count +
      "/" +
      metrics.active.supported_actionable_cleared_count +
      "/" +
      metrics.active.supported_missing_reported_elsewhere_count +
      "/" +
      metrics.active.supported_false_issue_count +
      "/" +
      metrics.active.supported_elsewhere_wrong_zone_count,
    "Representative window min trials/worst active p95: " +
      metrics.counts.representative.min_window_trial_count +
      "/" +
      metrics.latency.representative.worst_window_active_p95_ms +
      " ms",
    "Representative fast accept case/candidate/fallback: " +
      percent(metrics.policy.representative.fast_accept_rate) +
      "/" +
      percent(metrics.policy.representative.fast_accept_candidate_rate) +
      "/" +
      percent(metrics.policy.representative.fallback_rate),
    "Representative item coverage/accuracy: " +
      percent(metrics.representative.decision_coverage) +
      "/" +
      percent(metrics.representative.truth_accuracy),
    "Representative active model-path p50/p95: " +
      metrics.latency.representative.simulated_active.p50_ms +
      "/" +
      metrics.latency.representative.simulated_active.p95_ms +
      " ms",
    "Verifier gate: " +
      (gates.verifier_gate_passed ? "PASS" : "FAIL (" + failedChecks + " checks)"),
    "Active release ready: NO (end-to-end and consent gates remain)",
  ].join("\n");
}
