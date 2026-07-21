import test from "node:test";
import assert from "node:assert/strict";
import {
  ADAPTIVE_MIN_REMAINING_TOKENS_PER_MODEL,
  ADAPTIVE_REQUEST_RESERVE_TOKENS,
  createAdaptiveFinalReservation,
  createAdaptiveInitialReservations,
  createAdaptiveSettlement,
  summarizeAdaptiveTokenEvents,
} from "../evaluation/pilot/adaptive-token-budget.ts";

const PRIOR = { plus: 120_167, flash: 24_805 };

function settle(events, reservation, total = 5_000) {
  const settlement = createAdaptiveSettlement(events, PRIOR, {
    call_id: reservation.call_id,
    prompt_tokens: total - 200,
    completion_tokens: 200,
    total_tokens: total,
  });
  return [...events, settlement];
}

test("atomically reserves the parallel Plus primary and Flash scout", () => {
  const [primary, scout] = createAdaptiveInitialReservations(
    [],
    PRIOR,
    "case-0022",
  );
  const summary = summarizeAdaptiveTokenEvents([primary, scout], PRIOR);
  assert.equal(primary.slot, "primary");
  assert.equal(scout.slot, "scout");
  assert.equal(summary.pending.length, 2);
  assert.equal(
    summary.new_charged_or_reserved.plus,
    ADAPTIVE_REQUEST_RESERVE_TOKENS,
  );
  assert.equal(
    summary.new_charged_or_reserved.flash,
    ADAPTIVE_REQUEST_RESERVE_TOKENS,
  );
});

test("parallel calls may settle in either completion order", () => {
  let events = [
    ...createAdaptiveInitialReservations([], PRIOR, "case-0022"),
  ];
  events = settle(events, events[1], 4_200);
  events = settle(events, events[0], 6_300);
  const summary = summarizeAdaptiveTokenEvents(events, PRIOR);
  assert.equal(summary.pending.length, 0);
  assert.deepEqual(summary.new_settled, { plus: 6_300, flash: 4_200 });
  assert.deepEqual(summary.charged_or_reserved_including_prior, {
    plus: 126_467,
    flash: 29_005,
  });
});

test("a crash leaves the full unresolved reservation charged and blocks progress", () => {
  const events = [
    ...createAdaptiveInitialReservations([], PRIOR, "case-0022"),
  ];
  assert.throws(
    () => createAdaptiveInitialReservations(events, PRIOR, "case-0008"),
    /adaptive_pending_call_requires_stop/,
  );
  assert.throws(
    () => createAdaptiveFinalReservation(events, PRIOR, "case-0022"),
    /adaptive_pending_call_requires_stop/,
  );
});

test("reserves a Plus final adjudication only after both observers settle", () => {
  let events = [
    ...createAdaptiveInitialReservations([], PRIOR, "case-0022"),
  ];
  events = settle(events, events[0]);
  events = settle(events, events[1]);
  const finalReservation = createAdaptiveFinalReservation(
    events,
    PRIOR,
    "case-0022",
  );
  events.push(finalReservation);
  const summary = summarizeAdaptiveTokenEvents(events, PRIOR);
  assert.equal(finalReservation.slot, "final");
  assert.equal(summary.pending.length, 1);
  assert.equal(summary.new_charged_or_reserved.plus, 30_000);
  assert.equal(summary.new_charged_or_reserved.flash, 5_000);
});

test("rejects provider usage beyond the pre-dispatch reservation", () => {
  const [primary, scout] = createAdaptiveInitialReservations(
    [],
    PRIOR,
    "case-0022",
  );
  assert.throws(
    () =>
      createAdaptiveSettlement([primary, scout], PRIOR, {
        call_id: primary.call_id,
        prompt_tokens: ADAPTIVE_REQUEST_RESERVE_TOKENS,
        completion_tokens: 1,
        total_tokens: ADAPTIVE_REQUEST_RESERVE_TOKENS + 1,
      }),
    /adaptive_token_settlement_exceeds_reservation/,
  );
});

test("imports prior usage and preserves the 300K red line", () => {
  assert.throws(
    () =>
      createAdaptiveInitialReservations(
        [],
        {
          plus:
            1_000_000 -
            ADAPTIVE_MIN_REMAINING_TOKENS_PER_MODEL -
            ADAPTIVE_REQUEST_RESERVE_TOKENS +
            1,
          flash: 0,
        },
        "case-0022",
      ),
    /adaptive_user_token_red_line_crossed/,
  );
});
