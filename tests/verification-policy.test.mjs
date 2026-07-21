import assert from "node:assert/strict";
import test from "node:test";
import {
  parseBoundedInteger,
  parseFastVerifierMode,
  runQwenVerificationPolicy,
} from "../app/lib/verification-policy.ts";

const candidates = [{ id: "keys" }, { id: "glasses" }];

function batch(items) {
  return { verifications: items };
}

function confirmed(id) {
  return {
    id,
    verdict: "confirmed_missing",
    certainty: "high",
    current_location: null,
  };
}

function completeBatch() {
  return batch([confirmed("keys"), confirmed("glasses")]);
}

function clock() {
  let value = 0;
  return () => (value += 5);
}

test("parses verifier mode and bounded timeouts fail-closed", () => {
  assert.equal(parseFastVerifierMode(undefined), "off");
  assert.equal(parseFastVerifierMode("ACTIVE"), "active");
  assert.equal(parseFastVerifierMode("shadow"), "shadow");
  assert.equal(parseFastVerifierMode("true"), "off");
  assert.equal(parseBoundedInteger("20000", 10, 5, 30000), 20000);
  assert.equal(parseBoundedInteger("99999", 10, 5, 30000), 10);
  assert.equal(parseBoundedInteger("20000ms", 10, 5, 30000), 10);
});

test("does not call a verifier when there are no qualifying candidates", async () => {
  let calls = 0;
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates: [],
    runFast: async () => { calls += 1; return completeBatch(); },
    runFallback: async () => { calls += 1; return completeBatch(); },
  });
  assert.equal(calls, 0);
  assert.equal(result.verification, null);
  assert.equal(result.diagnostics.path, "not_needed");
});

test("active mode accepts one complete high-certainty Flash batch", async () => {
  let fallbackCalls = 0;
  const expected = completeBatch();
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates,
    runFast: async () => expected,
    runFallback: async () => { fallbackCalls += 1; return completeBatch(); },
    now: clock(),
  });
  assert.equal(fallbackCalls, 0);
  assert.equal(result.verification, expected);
  assert.equal(result.diagnostics.path, "qwen_fast");
  assert.equal(result.diagnostics.provider_calls, 1);
  assert.equal(result.diagnostics.active_fast_eligible, true);
});

for (const [name, fastBatch, reason] of [
  ["missing ID", batch([confirmed("keys")]), "incomplete"],
  ["unknown ID", batch([confirmed("keys"), confirmed("glasses"), confirmed("ghost")]), "unknown_id"],
  ["duplicate ID", batch([confirmed("keys"), confirmed("keys")]), "duplicate_id"],
  ["low certainty", batch([{ ...confirmed("keys"), certainty: "medium" }, confirmed("glasses")]), "low_confidence"],
  ["not comparable", batch([{ ...confirmed("keys"), verdict: "not_comparable" }, confirmed("glasses")]), "not_comparable"],
  ["missing moved location", batch([{ ...confirmed("keys"), verdict: "visible_elsewhere" }, confirmed("glasses")]), "missing_location"],
]) {
  test(`active mode falls back for ${name}`, async () => {
    const fallback = completeBatch();
    const result = await runQwenVerificationPolicy({
      mode: "active",
      candidates,
      runFast: async () => fastBatch,
      runFallback: async () => fallback,
    });
    assert.equal(result.verification, fallback);
    assert.equal(result.diagnostics.path, "qwen_fast_fallback");
    assert.equal(result.diagnostics.fallback_reason, reason);
    assert.equal(result.diagnostics.active_fast_eligible, false);
    assert.equal(result.diagnostics.active_fallback_reason, reason);
    assert.equal(result.diagnostics.provider_calls, 2);
  });
}

test("active mode falls back after a Flash timeout", async () => {
  const fallback = completeBatch();
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates,
    runFast: async () => { throw new Error("Request timed out"); },
    runFallback: async () => fallback,
  });
  assert.equal(result.verification, fallback);
  assert.equal(result.diagnostics.fallback_reason, "timeout");
  assert.equal(result.diagnostics.active_fast_eligible, false);
  assert.equal(result.diagnostics.active_fallback_reason, "timeout");
});

test("invalid Plus output fails closed instead of partially confirming missing", async () => {
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates,
    runFast: async () => null,
    runFallback: async () => batch([confirmed("keys")]),
  });
  assert.equal(result.verification, null);
  assert.equal(result.diagnostics.path, "qwen_unresolved");
  assert.equal(result.diagnostics.terminal_reason, "incomplete");
});

test("duplicate source candidate IDs fail closed without any model call", async () => {
  let calls = 0;
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates: [{ id: "keys" }, { id: "keys" }],
    runFast: async () => { calls += 1; return completeBatch(); },
    runFallback: async () => { calls += 1; return completeBatch(); },
  });
  assert.equal(calls, 0);
  assert.equal(result.verification, null);
  assert.equal(result.diagnostics.terminal_reason, "duplicate_candidate_id");
});

test("shadow mode always returns Plus and records model agreement", async () => {
  const plus = completeBatch();
  const result = await runQwenVerificationPolicy({
    mode: "shadow",
    candidates,
    runFast: async () => completeBatch(),
    runFallback: async () => plus,
  });
  assert.equal(result.verification, plus);
  assert.equal(result.diagnostics.path, "qwen_shadow");
  assert.equal(result.diagnostics.shadow_agreement, true);
  assert.equal(result.diagnostics.active_fast_eligible, true);
  assert.equal(result.diagnostics.provider_calls, 2);
});

test("off mode calls only the Plus verifier", async () => {
  let fastCalls = 0;
  const plus = completeBatch();
  const result = await runQwenVerificationPolicy({
    mode: "off",
    candidates,
    runFast: async () => { fastCalls += 1; return completeBatch(); },
    runFallback: async () => plus,
  });
  assert.equal(fastCalls, 0);
  assert.equal(result.verification, plus);
  assert.equal(result.diagnostics.path, "qwen_primary");
  assert.equal(result.diagnostics.provider_calls, 1);
});


test("active mode falls back when Flash returns no parseable batch", async () => {
  const plus = completeBatch();
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates,
    runFast: async () => null,
    runFallback: async () => plus,
  });
  assert.equal(result.verification, plus);
  assert.equal(result.diagnostics.fallback_reason, "invalid_output");
});

test("a failed Plus fallback produces an unresolved result", async () => {
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates,
    runFast: async () => null,
    runFallback: async () => { throw new Error("upstream unavailable"); },
  });
  assert.equal(result.verification, null);
  assert.equal(result.diagnostics.path, "qwen_unresolved");
  assert.equal(result.diagnostics.terminal_reason, "request_error");
});

test("more than twenty candidates fail closed without model calls", async () => {
  let calls = 0;
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates: Array.from({ length: 21 }, (_, index) => ({ id: "item-" + index })),
    runFast: async () => { calls += 1; return completeBatch(); },
    runFallback: async () => { calls += 1; return completeBatch(); },
  });
  assert.equal(calls, 0);
  assert.equal(result.verification, null);
  assert.equal(result.diagnostics.terminal_reason, "too_many_candidates");
});

test("trusted Flash missing confirmations may arrive in a different candidate order", async () => {
  const fast = batch([confirmed("glasses"), confirmed("keys")]);
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates,
    runFast: async () => fast,
    runFallback: async () => null,
  });
  assert.equal(result.verification, fast);
  assert.equal(result.diagnostics.path, "qwen_fast");
});

test("shadow mode records disagreement but still returns Plus", async () => {
  const plus = batch([
    { ...confirmed("keys"), verdict: "visible_same_place" },
    confirmed("glasses"),
  ]);
  const result = await runQwenVerificationPolicy({
    mode: "shadow",
    candidates,
    runFast: async () => completeBatch(),
    runFallback: async () => plus,
  });
  assert.equal(result.verification, plus);
  assert.equal(result.diagnostics.shadow_agreement, false);
});

test("active mode sends visible-same-place conflicts to Plus", async () => {
  let fallbackCalls = 0;
  const fallback = completeBatch();
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates,
    runFast: async () => batch([
      { ...confirmed("keys"), verdict: "visible_same_place", current_location: "on the tray" },
      confirmed("glasses"),
    ]),
    runFallback: async () => { fallbackCalls += 1; return fallback; },
  });
  assert.equal(fallbackCalls, 1);
  assert.equal(result.verification, fallback);
  assert.equal(result.diagnostics.fallback_reason, "conflicts_with_primary");
});

test("active mode sends visible-elsewhere conflicts to Plus", async () => {
  const fallback = completeBatch();
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates,
    runFast: async () => batch([
      { ...confirmed("keys"), verdict: "visible_elsewhere", current_location: "beside the notebook" },
      confirmed("glasses"),
    ]),
    runFallback: async () => fallback,
  });
  assert.equal(result.verification, fallback);
  assert.equal(result.diagnostics.fallback_reason, "conflicts_with_primary");
});

test("confirmed-missing with a current location is invalid", async () => {
  const fallback = completeBatch();
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates,
    runFast: async () => batch([
      { ...confirmed("keys"), current_location: "contradictory location" },
      confirmed("glasses"),
    ]),
    runFallback: async () => fallback,
  });
  assert.equal(result.verification, fallback);
  assert.equal(result.diagnostics.fallback_reason, "unexpected_location");
});

test("shadow agreement compares moved-item locations", async () => {
  const fast = batch([
    { ...confirmed("keys"), verdict: "visible_elsewhere", current_location: "left shelf" },
    confirmed("glasses"),
  ]);
  const plus = batch([
    { ...confirmed("keys"), verdict: "visible_elsewhere", current_location: "right shelf" },
    confirmed("glasses"),
  ]);
  const result = await runQwenVerificationPolicy({
    mode: "shadow",
    candidates,
    runFast: async () => fast,
    runFallback: async () => plus,
  });
  assert.equal(result.verification, plus);
  assert.equal(result.diagnostics.shadow_agreement, false);
});

test("exactly twenty candidates remain eligible for verification", async () => {
  const twentyCandidates = Array.from({ length: 20 }, (_, index) => ({ id: "item-" + index }));
  const twentyBatch = batch(twentyCandidates.map((item) => confirmed(item.id)));
  let fallbackCalls = 0;
  const result = await runQwenVerificationPolicy({
    mode: "active",
    candidates: twentyCandidates,
    runFast: async () => twentyBatch,
    runFallback: async () => { fallbackCalls += 1; return null; },
  });
  assert.equal(fallbackCalls, 0);
  assert.equal(result.verification, twentyBatch);
  assert.equal(result.diagnostics.path, "qwen_fast");
});

test("shadow agreement does not imply active fast eligibility", async () => {
  const visible = batch([
    { ...confirmed("keys"), verdict: "visible_same_place", current_location: "tray" },
    { ...confirmed("glasses"), verdict: "visible_same_place", current_location: "case" },
  ]);
  const result = await runQwenVerificationPolicy({
    mode: "shadow",
    candidates,
    runFast: async () => visible,
    runFallback: async () => visible,
  });
  assert.equal(result.diagnostics.shadow_agreement, true);
  assert.equal(result.diagnostics.active_fast_eligible, false);
  assert.equal(result.diagnostics.active_fallback_reason, "conflicts_with_primary");
});