import { DEFAULT_QWEN_FAST_VERIFICATION_MODEL } from "../../app/lib/qwen-model-config.ts";

export const PILOT_STARTING_TOKENS_PER_MODEL = 1_000_000;
export const PILOT_MIN_REMAINING_TOKENS_PER_MODEL = 300_000;
export const PILOT_PLUS_RUN_CAP_TOKENS = 650_000;
export const PILOT_FLASH_RUN_CAP_TOKENS = 400_000;
export const PILOT_REQUEST_RESERVE_TOKENS = 25_000;
export const PILOT_MAX_PROVIDER_CALLS = 180;
export const PILOT_MAX_ATTEMPTS_PER_CASE = 2;
export const PILOT_PLUS_MODEL = "qwen3.7-plus";
export const PILOT_FLASH_MODEL = DEFAULT_QWEN_FAST_VERIFICATION_MODEL;

export type PilotCallSlot = "primary" | "flash" | "plus";
export type PilotModelTier = "plus" | "flash";

export type PilotReserveEvent = {
  schema_version: "checkback.pilot-token-event.v1";
  event: "reserve";
  sequence: number;
  call_id: string;
  case_id: string;
  attempt?: number;
  slot: PilotCallSlot;
  model: string;
  reserved_tokens: typeof PILOT_REQUEST_RESERVE_TOKENS;
};

export type PilotSettleEvent = {
  schema_version: "checkback.pilot-token-event.v1";
  event: "settle";
  sequence: number;
  call_id: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
};

export type PilotTokenEvent = PilotReserveEvent | PilotSettleEvent;

type CallState = {
  reservation: PilotReserveEvent;
  settlement?: PilotSettleEvent;
};

function modelTier(model: string): PilotModelTier {
  if (model === PILOT_PLUS_MODEL) return "plus";
  if (model === PILOT_FLASH_MODEL) return "flash";
  throw new Error("pilot_token_model_not_pinned");
}

function expectedModel(slot: PilotCallSlot) {
  return slot === "flash" ? PILOT_FLASH_MODEL : PILOT_PLUS_MODEL;
}

function positiveInteger(value: unknown, code: string) {
  if (!Number.isInteger(value) || Number(value) < 1) throw new Error(code);
  return Number(value);
}

export function summarizePilotTokenEvents(events: readonly PilotTokenEvent[]) {
  const calls = new Map<string, CallState>();
  const slotsByAttempt = new Map<string, PilotCallSlot[]>();
  const attemptsByCase = new Map<string, Set<number>>();
  let expectedSequence = 1;

  for (const event of events) {
    if (
      event?.schema_version !== "checkback.pilot-token-event.v1" ||
      event.sequence !== expectedSequence
    ) {
      throw new Error("pilot_token_event_sequence_invalid");
    }
    expectedSequence += 1;
    if (event.event === "reserve") {
      const attempt = event.attempt ?? 1;
      const expectedCallId =
        attempt === 1
          ? `${event.case_id}-${event.slot}`
          : `${event.case_id}-attempt-${attempt}-${event.slot}`;
      if (
        !/^case-[0-9]{4}$/.test(event.case_id) ||
        !Number.isInteger(attempt) ||
        attempt < 1 ||
        attempt > PILOT_MAX_ATTEMPTS_PER_CASE ||
        event.call_id !== expectedCallId ||
        !["primary", "flash", "plus"].includes(event.slot) ||
        event.model !== expectedModel(event.slot) ||
        event.reserved_tokens !== PILOT_REQUEST_RESERVE_TOKENS ||
        calls.has(event.call_id)
      ) {
        throw new Error("pilot_token_reservation_invalid");
      }
      const attempts = attemptsByCase.get(event.case_id) ?? new Set<number>();
      if (attempt > 1 && !attempts.has(attempt - 1)) {
        throw new Error("pilot_token_attempt_order_invalid");
      }
      attempts.add(attempt);
      attemptsByCase.set(event.case_id, attempts);
      const attemptKey = `${event.case_id}#${attempt}`;
      const slots = slotsByAttempt.get(attemptKey) ?? [];
      const expectedSlot = (["primary", "flash", "plus"] as const)[slots.length];
      if (event.slot !== expectedSlot) {
        throw new Error("pilot_token_slot_order_invalid");
      }
      slots.push(event.slot);
      slotsByAttempt.set(attemptKey, slots);
      calls.set(event.call_id, { reservation: event });
      if (calls.size > PILOT_MAX_PROVIDER_CALLS) {
        throw new Error("pilot_token_call_cap_exceeded");
      }
    } else if (event.event === "settle") {
      const state = calls.get(event.call_id);
      if (!state || state.settlement) {
        throw new Error("pilot_token_settlement_without_reservation");
      }
      const prompt = positiveInteger(
        event.prompt_tokens,
        "pilot_prompt_tokens_invalid",
      );
      const completion = positiveInteger(
        event.completion_tokens,
        "pilot_completion_tokens_invalid",
      );
      const total = positiveInteger(
        event.total_tokens,
        "pilot_total_tokens_invalid",
      );
      if (
        prompt + completion !== total ||
        total > state.reservation.reserved_tokens
      ) {
        throw new Error("pilot_token_settlement_exceeds_reservation");
      }
      state.settlement = event;
    } else {
      throw new Error("pilot_token_event_type_invalid");
    }
  }

  const charged = { plus: 0, flash: 0 };
  const settled = { plus: 0, flash: 0 };
  const pending: PilotReserveEvent[] = [];
  for (const state of calls.values()) {
    const tier = modelTier(state.reservation.model);
    if (state.settlement) {
      charged[tier] += state.settlement.total_tokens;
      settled[tier] += state.settlement.total_tokens;
    } else {
      charged[tier] += state.reservation.reserved_tokens;
      pending.push(state.reservation);
    }
  }
  if (
    charged.plus > PILOT_PLUS_RUN_CAP_TOKENS ||
    charged.flash > PILOT_FLASH_RUN_CAP_TOKENS
  ) {
    throw new Error("pilot_token_run_cap_exceeded");
  }

  return {
    event_count: events.length,
    call_count: calls.size,
    charged_or_reserved: charged,
    settled,
    remaining_from_stated_allowance: {
      plus: PILOT_STARTING_TOKENS_PER_MODEL - charged.plus,
      flash: PILOT_STARTING_TOKENS_PER_MODEL - charged.flash,
    },
    pending,
  };
}

export function createPilotReservation(
  events: readonly PilotTokenEvent[],
  input: { case_id: string; slot: PilotCallSlot; attempt?: number },
): PilotReserveEvent {
  const summary = summarizePilotTokenEvents(events);
  if (summary.pending.length > 0) {
    throw new Error("pilot_token_pending_call_requires_stop");
  }
  if (summary.call_count >= PILOT_MAX_PROVIDER_CALLS) {
    throw new Error("pilot_token_call_cap_exhausted");
  }
  const model = expectedModel(input.slot);
  const attempt = input.attempt ?? 1;
  if (
    !Number.isInteger(attempt) ||
    attempt < 1 ||
    attempt > PILOT_MAX_ATTEMPTS_PER_CASE
  ) {
    throw new Error("pilot_token_attempt_invalid");
  }
  const tier = modelTier(model);
  const cap =
    tier === "plus"
      ? PILOT_PLUS_RUN_CAP_TOKENS
      : PILOT_FLASH_RUN_CAP_TOKENS;
  if (
    summary.charged_or_reserved[tier] + PILOT_REQUEST_RESERVE_TOKENS >
    cap
  ) {
    throw new Error(`pilot_token_${tier}_budget_exhausted`);
  }
  const event: PilotReserveEvent = {
    schema_version: "checkback.pilot-token-event.v1",
    event: "reserve",
    sequence: events.length + 1,
    call_id:
      attempt === 1
        ? `${input.case_id}-${input.slot}`
        : `${input.case_id}-attempt-${attempt}-${input.slot}`,
    case_id: input.case_id,
    ...(attempt === 1 ? {} : { attempt }),
    slot: input.slot,
    model,
    reserved_tokens: PILOT_REQUEST_RESERVE_TOKENS,
  };
  summarizePilotTokenEvents([...events, event]);
  return event;
}

export function createPilotSettlement(
  events: readonly PilotTokenEvent[],
  input: {
    call_id: string;
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  },
): PilotSettleEvent {
  const summary = summarizePilotTokenEvents(events);
  if (
    summary.pending.length !== 1 ||
    summary.pending[0].call_id !== input.call_id
  ) {
    throw new Error("pilot_token_settlement_pending_call_mismatch");
  }
  const event: PilotSettleEvent = {
    schema_version: "checkback.pilot-token-event.v1",
    event: "settle",
    sequence: events.length + 1,
    call_id: input.call_id,
    prompt_tokens: input.prompt_tokens,
    completion_tokens: input.completion_tokens,
    total_tokens: input.total_tokens,
  };
  summarizePilotTokenEvents([...events, event]);
  return event;
}

export function assertPilotReserveLeavesRedLine(
  events: readonly PilotTokenEvent[],
) {
  const summary = summarizePilotTokenEvents(events);
  if (
    summary.remaining_from_stated_allowance.plus <
      PILOT_MIN_REMAINING_TOKENS_PER_MODEL ||
    summary.remaining_from_stated_allowance.flash <
      PILOT_MIN_REMAINING_TOKENS_PER_MODEL
  ) {
    throw new Error("pilot_user_token_red_line_crossed");
  }
  return summary;
}
