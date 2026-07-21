import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  CHECKBACK_QWEN_SHADOW_CONFIG_SHA256,
  PINNED_QWEN_SHADOW_EVALUATION_CONFIG,
} from "../app/lib/qwen-model-config.ts";
import {
  DEFAULT_VERIFIER_RELEASE_GATES,
  computeShadowConfigSha256,
  evaluateShadowSuite,
  evaluateVerifierGates,
  nearestRank,
  parseShadowEvaluationSuite,
} from "../evaluation/shadow-evaluator.ts";
import { runCli } from "../scripts/evaluate-shadow.mjs";

const fixtureUrl = new URL(
  "../evaluation/fixtures/v1/synthetic.json",
  import.meta.url,
);
const packageUrl = new URL("../package.json", import.meta.url);

async function fixtureValue() {
  return JSON.parse(await readFile(fixtureUrl, "utf8"));
}

function thresholdsAtObservedMetrics(metrics) {
  const scenarioValues = Object.values(metrics.scenario_quality);
  const finiteMin = (values) => {
    const finite = values.filter((value) => Number.isFinite(value));
    return finite.length === 0 ? 0 : Math.min(...finite);
  };
  const finiteMax = (values) => {
    const finite = values.filter((value) => Number.isFinite(value));
    return finite.length === 0 ? 0 : Math.max(...finite);
  };

  return {
    ...DEFAULT_VERIFIER_RELEASE_GATES,
    min_trials: metrics.counts.trial_count,
    min_holdout_trials: metrics.counts.holdout_trial_count,
    min_representative_trials: metrics.counts.cohort_counts.representative,
    min_challenge_trials: metrics.counts.cohort_counts.challenge,
    min_challenge_unique_scenes: metrics.counts.challenge.unique_scene_count,
    max_challenge_scene_trial_share:
      metrics.counts.challenge.max_scene_trial_share,
    max_challenge_scene_item_share:
      metrics.counts.challenge.max_scene_item_share,
    min_challenge_scene_macro_decision_coverage: finiteMin([
      metrics.challenge_scene_quality.macro_decision_coverage,
      metrics.representative_scene_quality.macro_decision_coverage,
    ]),
    min_challenge_scene_decision_coverage_floor: finiteMin([
      metrics.challenge_scene_quality.decision_coverage_floor,
      metrics.representative_scene_quality.decision_coverage_floor,
    ]),
    min_challenge_scene_macro_truth_accuracy: finiteMin([
      metrics.challenge_scene_quality.macro_truth_accuracy,
      metrics.representative_scene_quality.macro_truth_accuracy,
    ]),
    min_challenge_scene_truth_accuracy_floor: finiteMin([
      metrics.challenge_scene_quality.truth_accuracy_floor,
      metrics.representative_scene_quality.truth_accuracy_floor,
    ]),
    min_challenge_missing_scene_macro_recall: finiteMin([
      metrics.challenge_scene_quality.missing_scene_macro_recall,
      metrics.representative_scene_quality.missing_scene_macro_recall,
    ]),
    min_challenge_missing_scene_recall_floor: finiteMin([
      metrics.challenge_scene_quality.missing_scene_recall_floor,
      metrics.representative_scene_quality.missing_scene_recall_floor,
    ]),
    min_unique_scenes: metrics.counts.representative.unique_scene_count,
    max_scene_trial_share: metrics.counts.representative.max_scene_trial_share,
    min_day_buckets: metrics.counts.representative.day_bucket_count,
    min_complete_day_buckets:
      metrics.counts.representative.complete_day_bucket_count,
    min_time_windows: metrics.counts.representative.time_window_count,
    min_window_trial_count:
      metrics.counts.representative.min_window_trial_count,
    min_representative_window_macro_decision_coverage:
      metrics.representative_window_quality.macro_decision_coverage ?? 0,
    min_representative_window_decision_coverage_floor:
      metrics.representative_window_quality.decision_coverage_floor ?? 0,
    min_representative_window_macro_truth_accuracy:
      metrics.representative_window_quality.macro_truth_accuracy ?? 0,
    min_representative_window_truth_accuracy_floor:
      metrics.representative_window_quality.truth_accuracy_floor ?? 0,
    min_representative_window_macro_missing_recall:
      metrics.representative_window_quality.missing_scene_macro_recall ?? 0,
    min_representative_window_missing_recall_floor:
      metrics.representative_window_quality.missing_scene_recall_floor ?? 0,
    min_supported_missing: metrics.counts.challenge.supported_missing_count,
    min_supported_missing_scenes:
      metrics.counts.challenge.supported_missing_scene_count,
    min_hard_negative_candidates:
      metrics.counts.challenge.hard_negative_candidate_count,
    min_hard_negative_trials:
      metrics.counts.challenge.hard_negative_trial_count,
    min_hard_negative_scenes:
      metrics.counts.challenge.hard_negative_scene_count,
    min_supported_same_place_candidates:
      metrics.counts.challenge.supported_same_place_candidate_count,
    min_supported_elsewhere_candidates:
      metrics.counts.challenge.supported_elsewhere_candidate_count,
    min_not_comparable_candidates:
      metrics.counts.challenge.not_comparable_candidate_count,
    min_not_comparable_trials:
      metrics.counts.challenge.not_comparable_trial_count,
    min_not_comparable_scenes:
      metrics.counts.challenge.not_comparable_scene_count,
    min_desk_scenes: metrics.counts.scenario_scene_counts.desk,
    min_lab_scenes: metrics.counts.scenario_scene_counts.lab,
    min_shared_tools_scenes: metrics.counts.scenario_scene_counts.shared_tools,
    min_representative_scenario_trials: finiteMin(
      scenarioValues.map((value) => value.representative_trial_count),
    ),
    min_scenario_supported_missing_scenes: finiteMin(
      scenarioValues.map(
        (value) => value.challenge_supported_missing_scene_count,
      ),
    ),
    min_scenario_hard_negative_scenes: finiteMin(
      scenarioValues.map((value) => value.challenge_hard_negative_scene_count),
    ),
    min_scenario_not_comparable_scenes: finiteMin(
      scenarioValues.map(
        (value) => value.challenge_not_comparable_scene_count,
      ),
    ),
    min_scenario_supported_missing_recall: finiteMin(
      scenarioValues.flatMap((value) => [
        value.challenge_supported_missing_recall,
        value.representative_supported_missing_recall,
      ]),
    ),
    min_scenario_decision_coverage: finiteMin(
      scenarioValues.flatMap((value) => [
        value.challenge_decision_coverage,
        value.representative_decision_coverage,
      ]),
    ),
    min_scenario_active_truth_accuracy: finiteMin(
      scenarioValues.flatMap((value) => [
        value.challenge_truth_accuracy,
        value.representative_truth_accuracy,
      ]),
    ),
    max_scenario_active_p95_ms: finiteMax(
      scenarioValues.map((value) => value.representative_active_p95_ms),
    ),
    min_fast_accept_trials: metrics.policy.representative.fast_accept_count,
    min_fast_accept_candidate_rate:
      metrics.policy.representative.fast_accept_candidate_rate,
    min_flash_batch_valid_rate:
      metrics.structure.representative.flash_batch_valid_rate,
    min_plus_batch_valid_rate:
      metrics.structure.representative.plus_batch_valid_rate,
    min_active_confirmed_missing_precision:
      metrics.challenge.confirmed_missing_precision,
    min_active_supported_missing_recall: finiteMin([
      metrics.challenge.supported_missing_recall,
      metrics.representative.supported_missing_recall,
    ]),
    min_active_decision_coverage: finiteMin([
      metrics.challenge.decision_coverage,
      metrics.representative.decision_coverage,
    ]),
    min_active_truth_accuracy: finiteMin([
      metrics.challenge.truth_accuracy,
      metrics.representative.truth_accuracy,
    ]),
    min_fast_accept_rate: metrics.policy.representative.fast_accept_rate,
    max_fallback_rate: metrics.policy.representative.fallback_rate,
    max_unresolved_rate: metrics.policy.representative.unresolved_rate,
    max_active_p95_ms:
      metrics.latency.representative.simulated_active.p95_ms,
    max_worst_window_active_p95_ms:
      metrics.latency.representative.worst_window_active_p95_ms,
    min_median_paired_improvement:
      metrics.latency.representative.median_paired_improvement,
    min_p95_improvement:
      metrics.latency.representative.p95_improvement,
  };
}

async function singleSafeSuite(split = "holdout") {
  const value = await fixtureValue();
  const base = value.cases[0];
  const scenarios = ["desk", "lab", "shared_tools"];
  value.cases = ["representative", "challenge"].flatMap((cohort, group) =>
    scenarios.map((scenario, index) => ({
      ...structuredClone(base),
      case_id: `case-${String(200 + group * 10 + index).padStart(4, "0")}`,
      scene_id: `scene-${String(200 + group * 10 + index).padStart(4, "0")}`,
      trial_id: `trial-${String(200 + group * 10 + index).padStart(4, "0")}`,
      execution: {
        ...structuredClone(base.execution),
        execution_id: `execution-${String(200 + group * 10 + index).padStart(4, "0")}`,
      },
      split,
      cohort,
      sampling_plan_id:
        cohort === "representative"
          ? value.sampling_plan.representative_plan_id
          : value.sampling_plan.challenge_plan_id,
      scenario,
      day_bucket: "day-001",
      time_period: "morning",
    })),
  );
  return parseShadowEvaluationSuite(value);
}
function successfulAttempt(id, verdict, currentLocation = null) {
  return {
    outcome: "success",
    latency_ms: 100,
    batch: {
      verifications: [
        {
          id,
          verdict,
          certainty: "high",
          current_location: currentLocation,
        },
      ],
    },
  };
}

test("parses the privacy-minimized v1 fixture and reports expected safety failures", async () => {
  const suite = parseShadowEvaluationSuite(await fixtureValue());
  const metrics = await evaluateShadowSuite(suite);

  assert.equal(metrics.scope, "verifier_only");
  assert.equal(metrics.config_matches_expected, true);
  assert.deepEqual(metrics.counts.split_counts, {
    smoke: 6,
    gate: 0,
    holdout: 0,
  });
  assert.equal(metrics.counts.trial_count, 6);
  assert.deepEqual(metrics.counts.cohort_counts, {
    representative: 3,
    challenge: 3,
  });
  assert.equal(metrics.counts.unique_scene_count, 4);
  assert.equal(metrics.counts.day_bucket_count, 2);
  assert.equal(metrics.counts.complete_day_bucket_count, 2);
  assert.equal(metrics.counts.time_window_count, 6);
  assert.equal(metrics.counts.supported_missing_count, 3);
  assert.equal(metrics.counts.hard_negative_candidate_count, 2);
  assert.equal(metrics.counts.not_comparable_candidate_count, 1);
  assert.equal(metrics.policy.fast_accept_count, 2);
  assert.equal(metrics.policy.fallback_count, 4);
  assert.equal(metrics.policy.unresolved_count, 1);
  assert.equal(metrics.active.confirmed_missing_precision, 2 / 3);
  assert.equal(metrics.active.supported_missing_recall, 2 / 3);
  assert.equal(metrics.active.unsafe_confirmation_count, 1);
  assert.equal(metrics.active.decision_coverage, 4 / 5);
  assert.equal(metrics.active.unsupported_resolved_count, 0);
  assert.equal(metrics.comparison.truth_regression_vs_plus_count, 1);
  assert.equal(metrics.policy.fast_false_accept_case_count, 1);
  assert.equal(metrics.latency.baseline_plus.p50_ms, 11_500);
  assert.equal(metrics.latency.simulated_active.p95_ms, 32_400);
});

test("strict schemas reject privacy-bearing fields and unknown versions", async () => {
  const privacyBearing = await fixtureValue();
  privacyBearing.cases[0].image_url = "data:image/jpeg;base64,private";
  assert.throws(() => parseShadowEvaluationSuite(privacyBearing));

  const unknownVersion = await fixtureValue();
  unknownVersion.schema_version = "checkback.shadow-eval.v2";
  assert.throws(() => parseShadowEvaluationSuite(unknownVersion));
});

test("entity and moved-location IDs reject semantic text", async () => {
  const rawLocation = await fixtureValue();
  rawLocation.cases[0].flash.batch.verifications[0] = {
    ...rawLocation.cases[0].flash.batch.verifications[0],
    verdict: "visible_elsewhere",
    current_location: "zone-next-to-personal-document",
  };
  assert.throws(() => parseShadowEvaluationSuite(rawLocation));

  const semanticCase = await fixtureValue();
  semanticCase.cases[0].case_id = "case-personal-desk";
  assert.throws(() => parseShadowEvaluationSuite(semanticCase));
});

test("ground truth must cover the exact anonymous candidate ID set", async () => {
  const mismatched = await fixtureValue();
  mismatched.cases[0].ground_truth.items[0].id = "item-9999";
  assert.throws(
    () => parseShadowEvaluationSuite(mismatched),
    /ground truth must cover exactly/,
  );
});

test("nearest-rank percentiles are deterministic for small samples", () => {
  assert.equal(nearestRank([], 0.5), null);
  assert.equal(nearestRank([10], 0.95), 10);
  assert.equal(nearestRank([10, 20], 0.5), 10);
  assert.equal(nearestRank([10, 20], 0.95), 20);
  assert.equal(
    nearestRank(Array.from({ length: 20 }, (_, index) => index + 1), 0.95),
    19,
  );
  assert.throws(() => nearestRank([1], 0), RangeError);
});

test("a partial Flash batch falls back to the valid Plus batch", async () => {
  const value = await fixtureValue();
  const base = value.cases[0];
  value.cases = [
    {
      ...base,
      case_id: "case-0100",
      flash: {
        outcome: "success",
        latency_ms: 100,
        batch: { verifications: [] },
      },
    },
  ];

  const metrics = await evaluateShadowSuite(parseShadowEvaluationSuite(value));
  assert.equal(metrics.policy.fast_accept_count, 0);
  assert.equal(metrics.policy.fallback_count, 1);
  assert.equal(metrics.policy.unresolved_count, 0);
  assert.equal(metrics.active.confirmed_missing_precision, 1);
  assert.equal(metrics.active.supported_missing_recall, 1);
});

test("zero baseline latency produces no p95 improvement ratio", async () => {
  const value = await fixtureValue();
  const base = value.cases[0];
  value.cases = [
    {
      ...base,
      case_id: "case-0101",
      primary_latency_ms: 0,
      flash: { ...base.flash, latency_ms: 0 },
      plus: { ...base.plus, latency_ms: 0 },
    },
  ];

  const metrics = await evaluateShadowSuite(parseShadowEvaluationSuite(value));
  assert.equal(metrics.latency.baseline_plus.p95_ms, 0);
  assert.equal(metrics.latency.p95_improvement, null);
});

test("default verifier release gates fail the synthetic smoke suite", async () => {
  const metrics = await evaluateShadowSuite(
    parseShadowEvaluationSuite(await fixtureValue()),
  );
  const gates = evaluateVerifierGates(metrics);

  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(gates.active_release_ready, false);
  assert.equal(
    gates.checks.find((item) => item.id === "non_holdout_trial_count").passed,
    false,
  );
  assert.equal(
    gates.checks.find((item) => item.id === "active_unsafe_confirmation_count")
      .passed,
    false,
  );
  assert.ok(gates.release_blockers.some((value) => /end-to-end/i.test(value)));
});

test("a smoke-only suite cannot pass even with observed-value thresholds", async () => {
  const metrics = await evaluateShadowSuite(await singleSafeSuite("smoke"));
  const gates = evaluateVerifierGates(
    metrics,
    thresholdsAtObservedMetrics(metrics),
  );

  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find((item) => item.id === "non_holdout_trial_count").passed,
    false,
  );
});

test("a safe holdout suite can pass observed-value verifier boundaries only", async () => {
  const metrics = await evaluateShadowSuite(await singleSafeSuite("holdout"));
  const gates = evaluateVerifierGates(
    metrics,
    thresholdsAtObservedMetrics(metrics),
  );

  assert.equal(gates.verifier_gate_passed, true);
  assert.equal(gates.active_release_ready, false);
});

test("a pinned model or prompt mismatch is a non-overridable gate failure", async () => {
  const value = await fixtureValue();
  value.config.flash_model = value.config.plus_model;
  const configSha256 = computeShadowConfigSha256(value.config);
  value.cases = [
    {
      ...value.cases[0],
      split: "holdout",
      execution: {
        ...value.cases[0].execution,
        config_sha256: configSha256,
      },
    },
  ];
  const metrics = await evaluateShadowSuite(parseShadowEvaluationSuite(value));
  const gates = evaluateVerifierGates(
    metrics,
    thresholdsAtObservedMetrics(metrics),
  );

  assert.equal(metrics.config_matches_expected, false);
  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find((item) => item.id === "pinned_config_match").passed,
    false,
  );
});

test("the per-case config fingerprint matches the canonical pinned config", () => {
  const actual = createHash("sha256")
    .update(JSON.stringify(PINNED_QWEN_SHADOW_EVALUATION_CONFIG))
    .digest("hex");

  assert.equal(actual, CHECKBACK_QWEN_SHADOW_CONFIG_SHA256);
});

test("case execution records reject a wrong config hash or extra calls", async () => {
  const wrongHash = await fixtureValue();
  wrongHash.cases[0].execution.config_sha256 = "0".repeat(64);
  assert.throws(() => parseShadowEvaluationSuite(wrongHash));

  const extraCall = await fixtureValue();
  extraCall.cases[0].execution.total_calls = 4;
  assert.throws(() => parseShadowEvaluationSuite(extraCall));
});

test("execution IDs must be unique across cases", async () => {
  const value = await fixtureValue();
  value.cases[1].execution.execution_id =
    value.cases[0].execution.execution_id;

  assert.throws(
    () => parseShadowEvaluationSuite(value),
    /execution_id must be unique/,
  );
});

test("sampling plans must match cohorts and scenes cannot cross cohorts", async () => {
  const wrongPlan = await fixtureValue();
  wrongPlan.cases[0].sampling_plan_id =
    wrongPlan.sampling_plan.challenge_plan_id;
  assert.throws(
    () => parseShadowEvaluationSuite(wrongPlan),
    /sampling_plan_id must match the case cohort/,
  );

  const crossedScene = await fixtureValue();
  crossedScene.cases[3].scene_id = crossedScene.cases[0].scene_id;
  crossedScene.cases[3].trial_id = "trial-9000";
  assert.throws(
    () => parseShadowEvaluationSuite(crossedScene),
    /cannot cross representative and challenge cohorts/,
  );
});

test("resolving an unsupported item cannot increase coverage or pass gates", async () => {
  const value = await fixtureValue();
  const unsupported = value.cases[5];
  const unsupportedId = unsupported.candidates[0];
  const resolvedAttempt = {
    outcome: "success",
    latency_ms: 100,
    batch: {
      verifications: [
        {
          id: unsupportedId,
          verdict: "visible_same_place",
          certainty: "high",
          current_location: null,
        },
      ],
    },
  };
  value.cases = [
    { ...value.cases[0], split: "holdout" },
    {
      ...unsupported,
      split: "holdout",
      flash: resolvedAttempt,
      plus: resolvedAttempt,
    },
  ];

  const metrics = await evaluateShadowSuite(parseShadowEvaluationSuite(value));
  const gates = evaluateVerifierGates(
    metrics,
    thresholdsAtObservedMetrics(metrics),
  );

  assert.equal(metrics.active.supported_item_count, 1);
  assert.equal(metrics.active.unsupported_item_count, 1);
  assert.equal(metrics.active.decision_coverage, 1);
  assert.equal(metrics.active.unsupported_resolved_count, 1);
  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) => item.id === "active_unsupported_resolved_count",
    ).passed,
    false,
  );
});

test("default gates cannot pass without not-comparable coverage or dense windows", async () => {
  const metrics = await evaluateShadowSuite(await singleSafeSuite("holdout"));
  const gates = evaluateVerifierGates(metrics);

  assert.equal(metrics.counts.challenge.not_comparable_candidate_count, 0);
  assert.equal(metrics.counts.representative.min_window_trial_count, 3);
  assert.equal(
    gates.checks.find((item) => item.id === "not_comparable_candidate_count")
      .passed,
    false,
  );
  assert.equal(
    gates.checks.find((item) => item.id === "min_window_trial_count").passed,
    false,
  );
});

test("candidate-dense representative unresolved items cannot be diluted by case counts", async () => {
  const suite = await singleSafeSuite("holdout");
  const dense = suite.cases.find(
    (item) => item.cohort === "representative" && item.scenario === "desk",
  );
  assert.ok(dense);

  const ids = Array.from(
    { length: 20 },
    (_, index) => "item-" + String(8000 + index).padStart(4, "0"),
  );
  dense.candidates = ids;
  dense.ground_truth.items = ids.map((id) => ({
    id,
    state: "missing",
    observability: "supported",
    expected_zone: null,
  }));
  const unresolved = {
    outcome: "success",
    latency_ms: 100,
    batch: {
      verifications: ids.map((id) => ({
        id,
        verdict: "not_comparable",
        certainty: "high",
        current_location: null,
      })),
    },
  };
  dense.flash = structuredClone(unresolved);
  dense.plus = structuredClone(unresolved);

  const metrics = await evaluateShadowSuite(suite);
  assert.equal(metrics.policy.representative.terminal_unresolved_case_rate, 0);
  assert.ok(metrics.policy.representative.item_unresolved_rate > 0.9);
  assert.ok(metrics.policy.representative.fast_accept_rate >= 0.65);
  assert.ok(metrics.policy.representative.fast_accept_candidate_rate < 0.1);
  assert.equal(
    metrics.representative_scene_quality.decision_coverage_floor,
    0,
  );

  const thresholds = thresholdsAtObservedMetrics(metrics);
  thresholds.min_fast_accept_candidate_rate = 0.65;
  thresholds.min_active_decision_coverage = 0.95;
  thresholds.min_active_truth_accuracy = 0.99;
  thresholds.min_challenge_scene_decision_coverage_floor = 0.8;
  thresholds.min_challenge_missing_scene_recall_floor = 0.8;
  const gates = evaluateVerifierGates(metrics, thresholds);

  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) => item.id === "fast_accept_candidate_rate",
    ).passed,
    false,
  );
  assert.equal(
    gates.checks.find(
      (item) => item.id === "representative_scene_decision_coverage_floor",
    ).passed,
    false,
  );
});

test("one unresolved representative time window cannot hide behind global quality", async () => {
  const suite = await singleSafeSuite("holdout");
  const representative = suite.cases.filter(
    (item) => item.cohort === "representative",
  );
  assert.equal(representative.length, 3);

  representative[0].time_period = "morning";
  representative[1].time_period = "midday";
  representative[2].time_period = "evening";
  representative[0].flash = successfulAttempt(
    representative[0].candidates[0],
    "not_comparable",
  );
  representative[0].plus = successfulAttempt(
    representative[0].candidates[0],
    "not_comparable",
  );

  const metrics = await evaluateShadowSuite(suite);
  assert.equal(
    metrics.representative_window_quality.decision_coverage_floor,
    0,
  );
  assert.equal(
    metrics.representative_window_quality.case_macro_decision_coverage_floor,
    0,
  );

  const thresholds = thresholdsAtObservedMetrics(metrics);
  thresholds.min_representative_window_decision_coverage_floor = 0.8;
  const gates = evaluateVerifierGates(metrics, thresholds);

  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) => item.id === "representative_window_decision_coverage_floor",
    ).passed,
    false,
  );
  assert.equal(
    gates.checks.find(
      (item) =>
        item.id === "representative_window_case_decision_coverage_floor",
    ).passed,
    false,
  );
});

test("a supported moved item mislabeled same-place is a hard gate failure", async () => {
  const value = await fixtureValue();
  const moved = structuredClone(value.cases[1]);
  moved.split = "holdout";
  moved.ground_truth.items[0].state = "elsewhere";
  moved.ground_truth.items[0].expected_zone = "zone-0001";
  moved.flash = successfulAttempt(moved.candidates[0], "visible_same_place");
  moved.plus = successfulAttempt(moved.candidates[0], "visible_same_place");
  value.cases = [{ ...value.cases[0], split: "holdout" }, moved];

  const metrics = await evaluateShadowSuite(parseShadowEvaluationSuite(value));
  const gates = evaluateVerifierGates(
    metrics,
    thresholdsAtObservedMetrics(metrics),
  );

  assert.equal(metrics.active.supported_actionable_cleared_count, 1);
  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) => item.id === "active_supported_actionable_cleared_count",
    ).passed,
    false,
  );
});

test("a truly missing item reported elsewhere is a hard gate failure", async () => {
  const value = await fixtureValue();
  const missing = structuredClone(value.cases[0]);
  missing.split = "holdout";
  missing.flash = successfulAttempt(
    missing.candidates[0],
    "visible_elsewhere",
    "zone-0002",
  );
  missing.plus = successfulAttempt(
    missing.candidates[0],
    "visible_elsewhere",
    "zone-0002",
  );
  value.cases = [missing];

  const metrics = await evaluateShadowSuite(parseShadowEvaluationSuite(value));
  const gates = evaluateVerifierGates(
    metrics,
    thresholdsAtObservedMetrics(metrics),
  );

  assert.equal(
    metrics.active.supported_missing_reported_elsewhere_count,
    1,
  );
  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) =>
        item.id === "active_supported_missing_reported_elsewhere_count",
    ).passed,
    false,
  );
});

test("a supported same-place item turned into an issue is a hard gate failure", async () => {
  const value = await fixtureValue();
  const falseIssue = structuredClone(value.cases[1]);
  falseIssue.split = "holdout";
  falseIssue.flash = successfulAttempt(
    falseIssue.candidates[0],
    "visible_elsewhere",
    "zone-0002",
  );
  falseIssue.plus = successfulAttempt(
    falseIssue.candidates[0],
    "visible_elsewhere",
    "zone-0002",
  );
  value.cases = [{ ...value.cases[0], split: "holdout" }, falseIssue];

  const metrics = await evaluateShadowSuite(parseShadowEvaluationSuite(value));
  const gates = evaluateVerifierGates(
    metrics,
    thresholdsAtObservedMetrics(metrics),
  );

  assert.equal(metrics.active.supported_false_issue_count, 1);
  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) => item.id === "active_supported_false_issue_count",
    ).passed,
    false,
  );
});

test("an elsewhere verdict with the wrong anonymous zone is a hard gate failure", async () => {
  const value = await fixtureValue();
  const wrongZone = structuredClone(value.cases[1]);
  wrongZone.split = "holdout";
  wrongZone.ground_truth.items[0].state = "elsewhere";
  wrongZone.ground_truth.items[0].expected_zone = "zone-0001";
  wrongZone.flash = successfulAttempt(
    wrongZone.candidates[0],
    "visible_elsewhere",
    "zone-0002",
  );
  wrongZone.plus = successfulAttempt(
    wrongZone.candidates[0],
    "visible_elsewhere",
    "zone-0002",
  );
  value.cases = [{ ...value.cases[0], split: "holdout" }, wrongZone];

  const metrics = await evaluateShadowSuite(parseShadowEvaluationSuite(value));
  const gates = evaluateVerifierGates(
    metrics,
    thresholdsAtObservedMetrics(metrics),
  );

  assert.equal(metrics.active.supported_elsewhere_wrong_zone_count, 1);
  assert.equal(metrics.active.truth_accuracy, 0.5);
  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) => item.id === "active_supported_elsewhere_wrong_zone_count",
    ).passed,
    false,
  );
});

test("a bad time window cannot hide behind the aggregate p95", async () => {
  const value = await fixtureValue();
  const base = value.cases[0];
  value.cases = Array.from({ length: 40 }, (_, index) => {
    const slowWindowTail = index >= 38;
    return {
      ...structuredClone(base),
      case_id: `case-${String(1000 + index).padStart(4, "0")}`,
      trial_id: `trial-${String(1000 + index).padStart(4, "0")}`,
      execution: {
        ...structuredClone(base.execution),
        execution_id: `execution-${String(1000 + index).padStart(4, "0")}`,
      },
      split: "holdout",
      day_bucket: "day-001",
      time_period: index < 20 ? "morning" : "midday",
      primary_latency_ms: slowWindowTail ? 4_900 : 100,
      flash: { ...structuredClone(base.flash), latency_ms: 100 },
      plus: { ...structuredClone(base.plus), latency_ms: 1_000 },
    };
  });

  const metrics = await evaluateShadowSuite(parseShadowEvaluationSuite(value));
  assert.equal(metrics.latency.simulated_active.p95_ms, 200);
  assert.equal(metrics.latency.worst_window_active_p95_ms, 5_000);

  const thresholds = thresholdsAtObservedMetrics(metrics);
  thresholds.max_worst_window_active_p95_ms =
    metrics.latency.simulated_active.p95_ms;
  const gates = evaluateVerifierGates(metrics, thresholds);

  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find((item) => item.id === "active_p95_ms").passed,
    true,
  );
  assert.equal(
    gates.checks.find((item) => item.id === "worst_window_active_p95_ms")
      .passed,
    false,
  );
});
test("scene scenarios and expected zones are schema-enforced", async () => {
  const conflictingScenario = await fixtureValue();
  conflictingScenario.cases[1].scenario = "lab";
  assert.throws(
    () => parseShadowEvaluationSuite(conflictingScenario),
    /same scenario/,
  );

  const missingZone = await fixtureValue();
  missingZone.cases[1].ground_truth.items[0].state = "elsewhere";
  assert.throws(
    () => parseShadowEvaluationSuite(missingZone),
    /expected_zone is required/,
  );

  const unexpectedZone = await fixtureValue();
  unexpectedZone.cases[1].ground_truth.items[0].expected_zone = "zone-0001";
  assert.throws(
    () => parseShadowEvaluationSuite(unexpectedZone),
    /expected_zone is required only/,
  );
});
test("frozen sampling and independent truth metadata are non-overridable gates", async () => {
  const suite = await singleSafeSuite("holdout");
  suite.sampling_plan.locked_before_collection = false;
  suite.cases[0].ground_truth.truth_locked_before_output = false;
  suite.cases[1].ground_truth.labeler_count = 1;
  suite.cases[1].ground_truth.adjudication = "single_labeler";

  const metrics = await evaluateShadowSuite(suite);
  const gates = evaluateVerifierGates(
    metrics,
    thresholdsAtObservedMetrics(metrics),
  );

  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find((item) => item.id === "sampling_plan_locked").passed,
    false,
  );
  assert.equal(
    gates.checks.find((item) => item.id === "truth_lock_violation_count")
      .passed,
    false,
  );
  assert.equal(
    gates.checks.find((item) => item.id === "labeling_violation_count").passed,
    false,
  );

  const modelDerivedTruth = await fixtureValue();
  modelDerivedTruth.cases[0].ground_truth.truth_source = "plus_output";
  assert.throws(() => parseShadowEvaluationSuite(modelDerivedTruth));
});

test("each product scenario needs its own supported challenge coverage", async () => {
  const suite = await singleSafeSuite("holdout");
  for (const item of suite.cases) {
    if (item.cohort !== "challenge" || item.scenario === "desk") continue;
    item.ground_truth.items[0].observability = "not_comparable";
    item.flash = successfulAttempt(item.candidates[0], "not_comparable");
    item.plus = successfulAttempt(item.candidates[0], "not_comparable");
  }

  const metrics = await evaluateShadowSuite(suite);
  const thresholds = thresholdsAtObservedMetrics(metrics);
  thresholds.min_scenario_supported_missing_scenes = 1;
  const gates = evaluateVerifierGates(metrics, thresholds);

  assert.equal(
    metrics.scenario_quality.desk.challenge_supported_missing_scene_count,
    1,
  );
  assert.equal(
    metrics.scenario_quality.lab.challenge_supported_missing_scene_count,
    0,
  );
  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) => item.id === "lab_challenge_supported_missing_scene_count",
    ).passed,
    false,
  );
  assert.equal(
    gates.checks.find(
      (item) =>
        item.id === "shared_tools_challenge_supported_missing_scene_count",
    ).passed,
    false,
  );
});
test("one scenario cannot hide zero missing recall behind global accuracy", async () => {
  const suite = await singleSafeSuite("holdout");
  const labChallenge = suite.cases.find(
    (item) => item.cohort === "challenge" && item.scenario === "lab",
  );
  assert.ok(labChallenge);
  labChallenge.flash = successfulAttempt(
    labChallenge.candidates[0],
    "not_comparable",
  );
  labChallenge.plus = successfulAttempt(
    labChallenge.candidates[0],
    "not_comparable",
  );

  const metrics = await evaluateShadowSuite(suite);
  assert.equal(metrics.challenge.supported_missing_recall, 2 / 3);
  assert.equal(
    metrics.scenario_quality.lab.challenge_supported_missing_count,
    1,
  );
  assert.equal(
    metrics.scenario_quality.lab.challenge_supported_missing_recall,
    0,
  );

  const thresholds = thresholdsAtObservedMetrics(metrics);
  thresholds.min_scenario_supported_missing_recall = 0.9;
  const gates = evaluateVerifierGates(metrics, thresholds);

  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) => item.id === "lab_challenge_supported_missing_recall",
    ).passed,
    false,
  );
});
test("dense repeated scenes cannot hide a fully unresolved challenge scene", async () => {
  const suite = await singleSafeSuite("holdout");
  const dense = suite.cases.find(
    (item) => item.cohort === "challenge" && item.scenario === "desk",
  );
  assert.ok(dense);

  const repeated = Array.from({ length: 99 }, (_, index) => ({
    ...structuredClone(dense),
    case_id: `case-${String(3000 + index).padStart(4, "0")}`,
    trial_id: `trial-${String(3000 + index).padStart(4, "0")}`,
    execution: {
      ...structuredClone(dense.execution),
      execution_id: `execution-${String(3000 + index).padStart(4, "0")}`,
    },
  }));
  const unresolved = {
    ...structuredClone(dense),
    case_id: "case-3999",
    scene_id: "scene-3999",
    trial_id: "trial-3999",
    execution: {
      ...structuredClone(dense.execution),
      execution_id: "execution-3999",
    },
    flash: successfulAttempt(dense.candidates[0], "not_comparable"),
    plus: successfulAttempt(dense.candidates[0], "not_comparable"),
  };
  suite.cases.push(...repeated, unresolved);

  const metrics = await evaluateShadowSuite(suite);
  assert.ok(metrics.challenge.truth_accuracy >= 0.99);
  assert.ok(metrics.challenge.supported_missing_recall >= 0.99);
  assert.ok(metrics.scenario_quality.desk.challenge_truth_accuracy >= 0.99);
  assert.equal(
    metrics.challenge_scene_quality.decision_coverage_floor,
    0,
  );
  assert.equal(metrics.challenge_scene_quality.missing_scene_recall_floor, 0);

  const thresholds = thresholdsAtObservedMetrics(metrics);
  thresholds.max_challenge_scene_trial_share = 0.05;
  thresholds.max_challenge_scene_item_share = 0.05;
  thresholds.min_challenge_scene_macro_decision_coverage = 0.95;
  thresholds.min_challenge_scene_decision_coverage_floor = 0.8;
  thresholds.min_challenge_scene_macro_truth_accuracy = 0.99;
  thresholds.min_challenge_scene_truth_accuracy_floor = 0.9;
  thresholds.min_challenge_missing_scene_macro_recall = 0.9;
  thresholds.min_challenge_missing_scene_recall_floor = 0.8;
  const gates = evaluateVerifierGates(metrics, thresholds);

  assert.equal(gates.verifier_gate_passed, false);
  assert.equal(
    gates.checks.find(
      (item) => item.id === "challenge_max_scene_trial_share",
    ).passed,
    false,
  );
  assert.equal(
    gates.checks.find(
      (item) => item.id === "challenge_scene_decision_coverage_floor",
    ).passed,
    false,
  );
  assert.equal(
    gates.checks.find(
      (item) => item.id === "challenge_missing_scene_recall_floor",
    ).passed,
    false,
  );
});
test("package scripts separate report generation from enforced gates", async () => {
  const packageJson = JSON.parse(await readFile(packageUrl, "utf8"));
  assert.equal(
    packageJson.scripts["eval:shadow"],
    "node --experimental-strip-types scripts/evaluate-shadow.mjs",
  );
  assert.match(
    packageJson.scripts["eval:shadow:gate"],
    /--enforce-verifier-gates/,
  );
});

test("CLI returns 0 for a valid report, 1 for enforced gate failure, and 2 for invalid data", async () => {
  const validInput = JSON.stringify(await fixtureValue());
  let stdout = "";
  let stderr = "";
  const io = {
    readFile: async () => validInput,
    stdout: (value) => {
      stdout += value;
    },
    stderr: (value) => {
      stderr += value;
    },
  };

  assert.equal(await runCli([], io), 0);
  assert.match(stdout, /Pinned config: MATCH/);
  assert.equal(stderr, "");

  stdout = "";
  assert.equal(await runCli(["fixture.json", "--json"], io), 0);
  assert.equal(JSON.parse(stdout).metrics.scope, "verifier_only");
  assert.equal(stderr, "");

  stdout = "";
  stderr = "";
  assert.equal(
    await runCli(["fixture.json", "--enforce-verifier-gates"], io),
    1,
  );
  assert.match(stdout, /Verifier gate: FAIL/);
  assert.equal(stderr, "");

  stdout = "";
  stderr = "";
  const invalidIo = {
    ...io,
    readFile: async () => "{not-json",
  };
  assert.equal(await runCli(["fixture.json"], invalidIo), 2);
  assert.equal(stdout, "");
  assert.match(stderr, /not valid JSON/);
  assert.doesNotMatch(stderr, /not-json/);
});
