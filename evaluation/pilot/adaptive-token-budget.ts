import { DEFAULT_QWEN_FAST_VERIFICATION_MODEL } from "../../app/lib/qwen-model-config.ts";

export const ADAPTIVE_STARTING_TOKENS_PER_MODEL = 1_000_000;
export const ADAPTIVE_MIN_REMAINING_TOKENS_PER_MODEL = 300_000;
export const ADAPTIVE_REQUEST_RESERVE_TOKENS = 25_000;
export const ADAPTIVE_MAX_PROVIDER_CALLS = 18;
export const ADAPTIVE_PLUS_RUN_CAP_TOKENS = 100_000;
export const ADAPTIVE_FLASH_RUN_CAP_TOKENS = 75_000;
export const ADAPTIVE_PLUS_MODEL = "qwen3.7-plus";
export const ADAPTIVE_FLASH_MODEL = DEFAULT_QWEN_FAST_VERIFICATION_MODEL;

export type AdaptiveCallSlot = "primary" | "scout" | "final";
export type AdaptiveModelTier = "plus" | "flash";
export type AdaptivePriorUsage = { plus: number; flash: number };

export type AdaptiveReserveEvent = {
  schema_version: "checkback.adaptive-token-event.v1";
  event: "reserve";
  sequence: number;
  call_id: string;
  case_id: string;
  slot: AdaptiveCallSlot;
  model: string;
  reserved_tokens: typeof ADAPTIVE_REQUEST_RESERVE_TOKENS;
};

export type AdaptiveSettleEvent = {
  schema_version: "checkback.adaptive-token-event.v1";
  event: "settle";
  sequence: number;
  call_id: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
};

export type AdaptiveTokenEvent =
  | AdaptiveReserveEvent
  | AdaptiveSettleEvent;

type CallState = {
  reservation: AdaptiveReserveEvent;
  settlement?: AdaptiveSettleEvent;
};

function positiveInteger(value: unknown, code: string) {
  if (!Number.isInteger(value) || Number(value) < 1) throw new Error(code);
  return Number(value);
}

function nonNegativeInteger(value: unknown, code: string) {
  if (!Number.isInteger(value) || Number(value) < 0) throw new Error(code);
  return Number(value);
}

function modelForSlot(slot: AdaptiveCallSlot) {
  return slot === "scout" ? ADAPTIVE_FLASH_MODEL : ADAPTIVE_PLUS_MODEL;
}

function tierForModel(model: string): AdaptiveModelTier {
  if (model === ADAPTIVE_PLUS_MODEL) return "plus";
  if (model === ADAPTIVE_FLASH_MODEL) return "flash";
  throw new Error("adaptive_token_model_not_pinned");
}

function callId(caseId: string, slot: AdaptiveCallSlot) {
  return "adaptive-" + caseId + "-" + slot;
}

function validatePriorUsage(prior: AdaptivePriorUsage) {
  const plus = nonNegativeInteger(prior?.plus, "adaptive_prior_plus_invalid");
  const flash = nonNegativeInteger(prior?.flash, "adaptive_prior_flash_invalid");
  if (
    plus > ADAPTIVE_STARTING_TOKENS_PER_MODEL ||
    flash > ADAPTIVE_STARTING_TOKENS_PER_MODEL
  ) {
    throw new Error("adaptive_prior_usage_exceeds_allowance");
  }
  return { plus, flash };
}

export function summarizeAdaptiveTokenEvents(
  events: readonly AdaptiveTokenEvent[],
  priorUsage: AdaptivePriorUsage,
) {
  const prior = validatePriorUsage(priorUsage);
  const calls = new Map<string, CallState>();
  const slotsByCase = new Map<string, AdaptiveCallSlot[]>();
  let expectedSequence = 1;

  for (const event of events) {
    if (
      event?.schema_version !== "checkback.adaptive-token-event.v1" ||
      event.sequence !== expectedSequence
    ) {
      throw new Error("adaptive_token_event_sequence_invalid");
    }
    expectedSequence += 1;

    if (event.event === "reserve") {
      if (
        !/^case-[0-9]{4}$/.test(event.case_id) ||
        !["primary", "scout", "final"].includes(event.slot) ||
        event.call_id !== callId(event.case_id, event.slot) ||
        event.model !== modelForSlot(event.slot) ||
        event.reserved_tokens !== ADAPTIVE_REQUEST_RESERVE_TOKENS ||
        calls.has(event.call_id)
      ) {
        throw new Error("adaptive_token_reservation_invalid");
      }
      const slots = slotsByCase.get(event.case_id) ?? [];
      const expectedSlot = (["primary", "scout", "final"] as const)[
        slots.length
      ];
      if (event.slot !== expectedSlot) {
        throw new Error("adaptive_token_slot_order_invalid");
      }
      slots.push(event.slot);
      slotsByCase.set(event.case_id, slots);
      calls.set(event.call_id, { reservation: event });
      if (calls.size > ADAPTIVE_MAX_PROVIDER_CALLS) {
        throw new Error("adaptive_token_call_cap_exceeded");
      }
      continue;
    }

    if (event.event === "settle") {
      const state = calls.get(event.call_id);
      if (!state || state.settlement) {
        throw new Error("adaptive_token_settlement_without_reservation");
      }
      const prompt = positiveInteger(
        event.prompt_tokens,
        "adaptive_prompt_tokens_invalid",
      );
      const completion = positiveInteger(
        event.completion_tokens,
        "adaptive_completion_tokens_invalid",
      );
      const total = positiveInteger(
        event.total_tokens,
        "adaptive_total_tokens_invalid",
      );
      if (
        prompt + completion !== total ||
        total > state.reservation.reserved_tokens
      ) {
        throw new Error("adaptive_token_settlement_exceeds_reservation");
      }
      state.settlement = event;
      continue;
    }

    throw new Error("adaptive_token_event_type_invalid");
  }

  const newCharged = { plus: 0, flash: 0 };
  const newSettled = { plus: 0, flash: 0 };
  const pending: AdaptiveReserveEvent[] = [];
  for (const state of calls.values()) {
    const tier = tierForModel(state.reservation.model);
    if (state.settlement) {
      newCharged[tier] += state.settlement.total_tokens;
      newSettled[tier] += state.settlement.total_tokens;
    } else {
      newCharged[tier] += state.reservation.reserved_tokens;
      pending.push(state.reservation);
    }
  }

  if (
    newCharged.plus > ADAPTIVE_PLUS_RUN_CAP_TOKENS ||
    newCharged.flash > ADAPTIVE_FLASH_RUN_CAP_TOKENS
  ) {
    throw new Error("adaptive_token_run_cap_exceeded");
  }

  const chargedIncludingPrior = {
    plus: prior.plus + newCharged.plus,
    flash: prior.flash + newCharged.flash,
  };
  const remaining = {
    plus: ADAPTIVE_STARTING_TOKENS_PER_MODEL - chargedIncludingPrior.plus,
    flash:
      ADAPTIVE_STARTING_TOKENS_PER_MODEL - chargedIncludingPrior.flash,
  };
  if (
    remaining.plus < ADAPTIVE_MIN_REMAINING_TOKENS_PER_MODEL ||
    remaining.flash < ADAPTIVE_MIN_REMAINING_TOKENS_PER_MODEL
  ) {
    throw new Error("adaptive_user_token_red_line_crossed");
  }

  return {
    event_count: events.length,
    call_count: calls.size,
    imported_prior_settled: prior,
    new_charged_or_reserved: newCharged,
    new_settled: newSettled,
    charged_or_reserved_including_prior: chargedIncludingPrior,
    remaining_from_stated_allowance: remaining,
    pending,
  };
}

function reservation(
  sequence: number,
  caseId: string,
  slot: AdaptiveCallSlot,
): AdaptiveReserveEvent {
  return {
    schema_version: "checkback.adaptive-token-event.v1",
    event: "reserve",
    sequence,
    call_id: callId(caseId, slot),
    case_id: caseId,
    slot,
    model: modelForSlot(slot),
    reserved_tokens: ADAPTIVE_REQUEST_RESERVE_TOKENS,
  };
}

export function createAdaptiveInitialReservations(
  events: readonly AdaptiveTokenEvent[],
  priorUsage: AdaptivePriorUsage,
  caseId: string,
) {
  const summary = summarizeAdaptiveTokenEvents(events, priorUsage);
  if (summary.pending.length > 0) {
    throw new Error("adaptive_pending_call_requires_stop");
  }
  if (summary.call_count + 2 > ADAPTIVE_MAX_PROVIDER_CALLS) {
    throw new Error("adaptive_token_call_cap_exhausted");
  }
  const primary = reservation(events.length + 1, caseId, "primary");
  const scout = reservation(events.length + 2, caseId, "scout");
  summarizeAdaptiveTokenEvents([...events, primary, scout], priorUsage);
  return [primary, scout] as const;
}

export function createAdaptiveFinalReservation(
  events: readonly AdaptiveTokenEvent[],
  priorUsage: AdaptivePriorUsage,
  caseId: string,
) {
  const summary = summarizeAdaptiveTokenEvents(events, priorUsage);
  if (summary.pending.length > 0) {
    throw new Error("adaptive_pending_call_requires_stop");
  }
  const caseReservations = events.filter(
    (event): event is AdaptiveReserveEvent =>
      event.event === "reserve" && event.case_id === caseId,
  );
  if (
    caseReservations.length !== 2 ||
    caseReservations[0].slot !== "primary" ||
    caseReservations[1].slot !== "scout"
  ) {
    throw new Error("adaptive_final_reservation_order_invalid");
  }
  const event = reservation(events.length + 1, caseId, "final");
  summarizeAdaptiveTokenEvents([...events, event], priorUsage);
  return event;
}

export function createAdaptiveSettlement(
  events: readonly AdaptiveTokenEvent[],
  priorUsage: AdaptivePriorUsage,
  input: {
    call_id: string;
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  },
): AdaptiveSettleEvent {
  const summary = summarizeAdaptiveTokenEvents(events, priorUsage);
  if (!summary.pending.some((event) => event.call_id === input.call_id)) {
    throw new Error("adaptive_settlement_pending_call_mismatch");
  }
  const event: AdaptiveSettleEvent = {
    schema_version: "checkback.adaptive-token-event.v1",
    event: "settle",
    sequence: events.length + 1,
    call_id: input.call_id,
    prompt_tokens: input.prompt_tokens,
    completion_tokens: input.completion_tokens,
    total_tokens: input.total_tokens,
  };
  summarizeAdaptiveTokenEvents([...events, event], priorUsage);
  return event;
}
