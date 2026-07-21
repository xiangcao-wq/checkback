import test from "node:test";
import assert from "node:assert/strict";
import { normalizeCheckbackReport } from "../app/lib/checkback-analysis.ts";
import {
  MISSING_SCOUT_MAX_CANDIDATES,
  mergeMissingScoutCandidates,
  parseMissingScoutValue,
} from "../app/lib/qwen-missing-scout.ts";

const baseRaw = {
  scene: { match: "same", overlap: "high", reason: "same scene" },
  quality_issues: [],
  changes: [],
  checked_item_count: 10,
  summary: "checked",
};

function candidate(overrides = {}) {
  return {
    label: "speaker",
    baseline_location: "right tray",
    certainty: "high",
    baseline_visible: true,
    expected_region_visible: true,
    evidence: "not visible in the expected region",
    ...overrides,
  };
}

function scout(overrides = {}) {
  return {
    comparison: "usable",
    reason: "sufficient common coverage",
    candidates: [candidate()],
    ...overrides,
  };
}

test("missing scout parsing removes extra keys and bounds prose", () => {
  const parsed = parseMissingScoutValue({
    ...scout(),
    ignored: true,
    reason: "r".repeat(200),
    candidates: [
      {
        ...candidate(),
        label: "l".repeat(100),
        evidence: "e".repeat(400),
        ignored: true,
      },
    ],
  });

  assert.ok(parsed);
  assert.equal(parsed.reason.length, 160);
  assert.equal(parsed.candidates[0].label.length, 80);
  assert.equal(parsed.candidates[0].evidence.length, 300);
  assert.equal(Object.hasOwn(parsed, "ignored"), false);
  assert.equal(Object.hasOwn(parsed.candidates[0], "ignored"), false);
});

test("missing scout parsing rejects unsafe semantic coercion", () => {
  const parsed = parseMissingScoutValue({
    ...scout(),
    candidates: [{ ...candidate(), baseline_visible: "true" }],
  });
  assert.equal(parsed, null);
});

test("independent scout candidates receive deterministic provenance", () => {
  const result = mergeMissingScoutCandidates(baseRaw, scout());

  assert.equal(result.scout_candidate_count, 1);
  assert.equal(result.added_candidate_count, 1);
  assert.equal(result.merged_candidate_count, 1);
  assert.equal(result.analysis.changes.length, 1);
  assert.equal(result.analysis.changes[0].id, "scout-0001");
  assert.equal(result.analysis.changes[0].origin, "scout");
  assert.equal(
    result.analysis.quality_issues.some((issue) => issue.severity === "blocking"),
    false,
  );
});

test("scout deduplicates the same object without losing its stable id", () => {
  const raw = {
    ...baseRaw,
    changes: [
      {
        id: "primary-item",
        label: "speaker",
        type: "misplaced",
        certainty: "medium",
        baseline_location: "right tray",
        current_location: "left tray",
        baseline_visible: true,
        expected_region_visible: true,
        evidence: "possible move",
        action: "check",
      },
    ],
  };
  const result = mergeMissingScoutCandidates(raw, scout());

  assert.equal(result.analysis.changes.length, 1);
  assert.equal(result.analysis.changes[0].id, "primary-item");
  assert.equal(result.analysis.changes[0].type, "missing");
  assert.equal(result.analysis.changes[0].origin, "scout");
  assert.equal(result.added_candidate_count, 0);
});

test("uncertain coverage fails closed instead of reporting clear", () => {
  const result = mergeMissingScoutCandidates(
    baseRaw,
    scout({
      comparison: "uncertain",
      candidates: [
        candidate({
          expected_region_visible: false,
          certainty: "medium",
        }),
      ],
    }),
  );

  assert.equal(result.analysis.changes.length, 0);
  assert.equal(
    result.analysis.quality_issues.some((issue) => issue.severity === "blocking"),
    true,
  );
  const report = normalizeCheckbackReport(result.analysis, null, {
    analysisId: "coverage",
    processingMs: 10,
  });
  assert.equal(report.status, "incomplete");
});

test("a saturated scout response cannot produce a clear result", () => {
  const candidates = Array.from(
    { length: MISSING_SCOUT_MAX_CANDIDATES },
    (_, index) =>
      candidate({
        label: "item-" + index,
        baseline_location: "region-" + index,
      }),
  );
  const result = mergeMissingScoutCandidates(
    baseRaw,
    scout({ candidates }),
  );

  assert.equal(result.saturated, true);
  assert.equal(
    result.analysis.quality_issues.some((issue) => issue.severity === "blocking"),
    true,
  );
});

test("medium scout evidence becomes missing only after high-confidence Plus confirmation", () => {
  const result = mergeMissingScoutCandidates(
    baseRaw,
    scout({ candidates: [candidate({ certainty: "medium" })] }),
  );
  const item = result.analysis.changes[0];
  const withoutVerification = normalizeCheckbackReport(result.analysis, null, {
    analysisId: "without-verification",
    processingMs: 10,
  });
  assert.equal(withoutVerification.status, "incomplete");

  const withVerification = normalizeCheckbackReport(
    result.analysis,
    {
      verifications: [
        {
          id: item.id,
          verdict: "confirmed_missing",
          certainty: "high",
          current_location: null,
          evidence: "independently confirmed",
        },
      ],
    },
    { analysisId: "with-verification", processingMs: 10 },
  );
  assert.equal(withVerification.status, "issues");
  assert.equal(withVerification.verified_missing_count, 1);
  assert.equal(withVerification.items[0].type, "missing");
});
