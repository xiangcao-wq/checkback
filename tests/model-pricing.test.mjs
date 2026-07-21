import test from "node:test";
import assert from "node:assert/strict";
import {
  QWEN_PRICING_CHECKED_DATE,
  QWEN_PRICING_SOURCE_URL,
  estimateQwenCallCost,
} from "../evaluation/pilot/model-pricing.ts";

test("prices the moving Plus alias at list and current advertised rates", () => {
  const result = estimateQwenCallCost("qwen3.7-plus", {
    prompt_tokens: 10_000,
    completion_tokens: 1_000,
    total_tokens: 11_000,
  });
  assert.equal(result.public_list_equivalent_cny, 0.028);
  assert.equal(result.current_advertised_equivalent_cny, 0.0224);
  assert.equal(result.input_cny_per_million, 2);
  assert.equal(result.output_cny_per_million, 8);
  assert.equal(result.pricing_tier, "up_to_256k");
  assert.equal(QWEN_PRICING_CHECKED_DATE, "2026-07-16");
  assert.match(QWEN_PRICING_SOURCE_URL, /^https:\/\/help\.aliyun\.com\//);
});

test("prices the pinned Plus version without alias promotion", () => {
  const result = estimateQwenCallCost("qwen3.7-plus-2026-05-26", {
    prompt_tokens: 10_000,
    completion_tokens: 1_000,
    total_tokens: 11_000,
  });
  assert.equal(result.public_list_equivalent_cny, 0.028);
  assert.equal(result.current_advertised_equivalent_cny, 0.028);
});

test("prices the pinned Flash scout using separate input and output rates", () => {
  const result = estimateQwenCallCost("qwen3.6-flash-2026-04-16", {
    prompt_tokens: 10_000,
    completion_tokens: 1_000,
    total_tokens: 11_000,
  });
  assert.equal(result.public_list_equivalent_cny, 0.0192);
  assert.equal(result.current_advertised_equivalent_cny, 0.0192);
  assert.equal(result.input_cny_per_million, 1.2);
  assert.equal(result.output_cny_per_million, 7.2);
});

test("uses the official long-input tier above 256K", () => {
  const result = estimateQwenCallCost("qwen3.7-plus", {
    prompt_tokens: 300_000,
    completion_tokens: 1_000,
    total_tokens: 301_000,
  });
  assert.equal(result.pricing_tier, "over_256k_to_1m");
  assert.equal(result.input_cny_per_million, 6);
  assert.equal(result.output_cny_per_million, 24);
});

test("rejects unknown models and inconsistent usage", () => {
  assert.throws(
    () =>
      estimateQwenCallCost("unpriced-model", {
        prompt_tokens: 100,
        completion_tokens: 20,
        total_tokens: 120,
      }),
    /qwen_pricing_model_not_pinned/,
  );
  assert.throws(
    () =>
      estimateQwenCallCost("qwen3.7-plus", {
        prompt_tokens: 100,
        completion_tokens: 20,
        total_tokens: 999,
      }),
    /qwen_pricing_usage_invalid/,
  );
});
