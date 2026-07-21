import test from "node:test";
import assert from "node:assert/strict";
import {
  PILOT_FLASH_RUN_CAP_TOKENS,
  PILOT_PLUS_RUN_CAP_TOKENS,
  PILOT_REQUEST_RESERVE_TOKENS,
  assertPilotReserveLeavesRedLine,
  createPilotReservation,
  createPilotSettlement,
  summarizePilotTokenEvents,
} from "../evaluation/pilot/token-budget.ts";

function settle(events, reservation, total = 5_000) {
  const settlement = createPilotSettlement(events, {
    call_id: reservation.call_id,
    prompt_tokens: total - 200,
    completion_tokens: 200,
    total_tokens: total,
  });
  return [...events, settlement];
}

test("reserves before dispatch and releases only the unused portion after usage", () => {
  let events = [];
  const reservation = createPilotReservation(events, {
    case_id: "case-0001",
    slot: "primary",
  });
  events = [...events, reservation];
  assert.equal(
    summarizePilotTokenEvents(events).charged_or_reserved.plus,
    PILOT_REQUEST_RESERVE_TOKENS,
  );
  events = settle(events, reservation, 5_000);
  const summary = assertPilotReserveLeavesRedLine(events);
  assert.equal(summary.charged_or_reserved.plus, 5_000);
  assert.equal(summary.remaining_from_stated_allowance.plus, 995_000);
});

test("an unsettled request consumes its full reservation and blocks another call", () => {
  const reservation = createPilotReservation([], {
    case_id: "case-0001",
    slot: "primary",
  });
  const events = [reservation];
  assert.equal(summarizePilotTokenEvents(events).pending.length, 1);
  assert.throws(
    () =>
      createPilotReservation(events, {
        case_id: "case-0001",
        slot: "flash",
      }),
    /pilot_token_pending_call_requires_stop/,
  );
});

test("enforces primary, Flash, Plus order and distinct per-model budgets", () => {
  let events = [];
  for (const slot of ["primary", "flash", "plus"]) {
    const reservation = createPilotReservation(events, {
      case_id: "case-0001",
      slot,
    });
    events.push(reservation);
    events = settle(events, reservation, 4_500);
  }
  const summary = summarizePilotTokenEvents(events);
  assert.equal(summary.charged_or_reserved.plus, 9_000);
  assert.equal(summary.charged_or_reserved.flash, 4_500);
  assert.throws(
    () =>
      createPilotReservation([], {
        case_id: "case-0002",
        slot: "flash",
      }),
    /pilot_token_slot_order_invalid/,
  );
});

test("successful typical calls fit the pilot while preserving the user red line", () => {
  let events = [];
  for (let caseNumber = 1; caseNumber <= 60; caseNumber += 1) {
    const caseId = `case-${String(caseNumber).padStart(4, "0")}`;
    for (const slot of ["primary", "flash", "plus"]) {
      const reservation = createPilotReservation(events, {
        case_id: caseId,
        slot,
      });
      events.push(reservation);
      events = settle(events, reservation, 4_800);
    }
  }
  const summary = assertPilotReserveLeavesRedLine(events);
  assert.equal(summary.call_count, 180);
  assert.equal(summary.charged_or_reserved.plus, 576_000);
  assert.equal(summary.charged_or_reserved.flash, 288_000);
  assert.ok(summary.charged_or_reserved.plus < PILOT_PLUS_RUN_CAP_TOKENS);
  assert.ok(summary.charged_or_reserved.flash < PILOT_FLASH_RUN_CAP_TOKENS);
  assert.ok(summary.remaining_from_stated_allowance.plus > 300_000);
  assert.ok(summary.remaining_from_stated_allowance.flash > 300_000);
});

test("rejects usage above the pre-dispatch reservation", () => {
  const reservation = createPilotReservation([], {
    case_id: "case-0001",
    slot: "primary",
  });
  assert.throws(
    () =>
      createPilotSettlement([reservation], {
        call_id: reservation.call_id,
        prompt_tokens: PILOT_REQUEST_RESERVE_TOKENS,
        completion_tokens: 1,
        total_tokens: PILOT_REQUEST_RESERVE_TOKENS + 1,
      }),
    /pilot_token_settlement_exceeds_reservation/,
  );
});

test("allows one explicit second attempt with a distinct call id", () => {
  let events = [];
  const first = createPilotReservation(events, {
    case_id: "case-0001",
    slot: "primary",
  });
  events.push(first);
  events = settle(events, first);

  const second = createPilotReservation(events, {
    case_id: "case-0001",
    slot: "primary",
    attempt: 2,
  });
  assert.equal(second.call_id, "case-0001-attempt-2-primary");
  assert.equal(second.attempt, 2);
  events.push(second);
  events = settle(events, second);
  assert.equal(summarizePilotTokenEvents(events).call_count, 2);

  assert.throws(
    () =>
      createPilotReservation(events, {
        case_id: "case-0001",
        slot: "primary",
        attempt: 3,
      }),
    /pilot_token_attempt_invalid/,
  );
});