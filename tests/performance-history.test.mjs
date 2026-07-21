import assert from "node:assert/strict";
import test from "node:test";
import {
  PERFORMANCE_HISTORY_KEY,
  PERFORMANCE_HISTORY_LIMIT,
  PERFORMANCE_LATEST_KEY,
  persistPerformanceSample,
} from "../app/lib/performance-history.ts";

class MemoryStorage {
  values = new Map();

  getItem(key) {
    return this.values.get(key) ?? null;
  }

  setItem(key, value) {
    this.values.set(key, String(value));
  }
}

function sample(seed = 1) {
  return {
    source_bytes: seed,
    upload_bytes: seed + 1,
    preparation_ms: seed + 2,
    upload_ms: seed + 3,
    server_wait_ms: seed + 4,
    response_headers_ms: seed + 5,
    response_download_ms: seed + 6,
    response_parse_ms: seed + 7,
    response_bytes: seed + 8,
    request_ms: seed + 9,
    server_total_ms: seed + 10,
    request_parse_ms: seed + 11,
    image_prepare_ms: seed + 12,
    data_url_ms: seed + 13,
    preprocessing_ms: seed + 14,
    primary_ai_ms: seed + 15,
    observer_ai_ms: seed + 16,
    missing_scout_ms: seed + 17,
    observer_provider_calls: 2,
    missing_scout_provider_calls: 1,
    dual_observer_enabled: 1,
    missing_scout_candidate_count: 1,
    missing_scout_merged_count: 1,
    missing_scout_added_count: 1,
    verification_ai_ms: seed + 16,
    report_assembly_ms: seed + 17,
    fast_verifier_ms: seed + 18,
    verification_fallback_ms: seed + 19,
    verification_provider_calls: 1,
    verification_fallback_used: 0,
    verification_shadow_agreement: -1,
    verification_active_fast_eligible: -1,
    total_ms: seed + 20,
  };
}

test("keeps only the newest bounded performance samples", () => {
  const historyStorage = new MemoryStorage();
  const latestStorage = new MemoryStorage();

  for (let index = 0; index < PERFORMANCE_HISTORY_LIMIT + 3; index += 1) {
    persistPerformanceSample(historyStorage, latestStorage, sample(index));
  }

  const history = JSON.parse(historyStorage.getItem(PERFORMANCE_HISTORY_KEY));
  const latest = JSON.parse(latestStorage.getItem(PERFORMANCE_LATEST_KEY));
  assert.equal(history.length, PERFORMANCE_HISTORY_LIMIT);
  assert.deepEqual(
    history.map((entry) => entry.source_bytes),
    Array.from({ length: PERFORMANCE_HISTORY_LIMIT }, (_, index) => index + 3),
  );
  assert.equal(latest.source_bytes, PERFORMANCE_HISTORY_LIMIT + 2);
  assert.equal(latest.schema_version, 1);
  assert.equal("recorded_at_ms" in latest, false);
});

test("fails closed for malformed and oversized prior storage", () => {
  const latestStorage = new MemoryStorage();

  for (const malformed of ["{", JSON.stringify({ not: "an array" }), "x".repeat(70_000)]) {
    const historyStorage = new MemoryStorage();
    historyStorage.setItem(PERFORMANCE_HISTORY_KEY, malformed);
    persistPerformanceSample(historyStorage, latestStorage, sample(7));
    const history = JSON.parse(historyStorage.getItem(PERFORMANCE_HISTORY_KEY));
    assert.equal(history.length, 1);
    assert.equal(history[0].source_bytes, 7);
  }
});

test("rebuilds a numeric allowlist and removes sensitive or unknown data", () => {
  const historyStorage = new MemoryStorage();
  const latestStorage = new MemoryStorage();
  const canary = "sk-test Authorization: Bearer data:image/jpeg;base64,CANARY C:\\private.jpg";
  historyStorage.setItem(
    PERFORMANCE_HISTORY_KEY,
    JSON.stringify([{ ...sample(1), filename: canary, raw_response: canary }]),
  );

  persistPerformanceSample(historyStorage, latestStorage, {
    ...sample(2),
    label: canary,
    path: canary,
    error_message: canary,
  });

  const serialized = historyStorage.getItem(PERFORMANCE_HISTORY_KEY);
  assert.equal(serialized.includes(canary), false);
  const history = JSON.parse(serialized);
  assert.equal("filename" in history[0], false);
  assert.equal("label" in history[1], false);
  assert.deepEqual(
    Object.keys(history[1]).sort(),
    [...Object.keys(sample()), "schema_version"].sort(),
  );
});

test("normalizes invalid metrics without throwing", () => {
  const historyStorage = new MemoryStorage();
  const latestStorage = new MemoryStorage();
  const invalid = {
    ...sample(1),
    upload_ms: -25,
    primary_ai_ms: Number.POSITIVE_INFINITY,
    response_parse_ms: Number.NaN,
    verification_shadow_agreement: 8,
    verification_active_fast_eligible: 0.6,
  };

  const stored = persistPerformanceSample(historyStorage, latestStorage, invalid);
  assert.equal(stored.upload_ms, 0);
  assert.equal(stored.primary_ai_ms, 0);
  assert.equal(stored.response_parse_ms, 0);
  assert.equal(stored.verification_shadow_agreement, -1);
  assert.equal(stored.verification_active_fast_eligible, 1);
});

test("storage failures never interrupt a check", () => {
  const brokenStorage = {
    getItem() {
      throw new Error("read blocked");
    },
    setItem() {
      throw new Error("quota exceeded");
    },
  };

  assert.doesNotThrow(() =>
    persistPerformanceSample(brokenStorage, brokenStorage, sample(4)),
  );
});
