export const MAX_VERIFICATION_CANDIDATES = 20;

export type FastVerifierMode = "off" | "shadow" | "active";

export type VerificationVerdict =
  | "confirmed_missing"
  | "visible_same_place"
  | "visible_elsewhere"
  | "not_comparable";

export type VerificationCandidate = { id: string };

export type VerificationItemLike = {
  id: string;
  verdict: VerificationVerdict;
  certainty: "high" | "medium" | "low";
  current_location: string | null;
};

export type VerificationBatchLike = {
  verifications: VerificationItemLike[];
};

export type VerificationFailureReason =
  | "duplicate_candidate_id"
  | "too_many_candidates"
  | "timeout"
  | "request_error"
  | "invalid_output"
  | "incomplete"
  | "duplicate_id"
  | "unknown_id"
  | "low_confidence"
  | "not_comparable"
  | "missing_location"
  | "unexpected_location"
  | "conflicts_with_primary";

export type VerificationPath =
  | "not_needed"
  | "openai"
  | "qwen_primary"
  | "qwen_fast"
  | "qwen_fast_fallback"
  | "qwen_shadow"
  | "qwen_unresolved";

export type VerificationDiagnostics = {
  path: VerificationPath;
  fast_ms: number;
  fallback_ms: number;
  provider_calls: number;
  fallback_reason?: VerificationFailureReason;
  terminal_reason?: VerificationFailureReason;
  shadow_agreement: boolean | null;
  active_fast_eligible: boolean | null;
  active_fallback_reason?: VerificationFailureReason;
};

export type VerificationPolicyResult<T extends VerificationBatchLike> = {
  verification: T | null;
  diagnostics: VerificationDiagnostics;
};

export function parseFastVerifierMode(value: string | undefined): FastVerifierMode {
  const normalized = value?.trim().toLowerCase();
  return normalized === "shadow" || normalized === "active" ? normalized : "off";
}

export function parseBoundedInteger(
  value: string | undefined,
  fallback: number,
  min: number,
  max: number,
) {
  if (!value?.trim()) return fallback;
  if (!/^\d+$/.test(value.trim())) return fallback;
  const parsed = Number.parseInt(value.trim(), 10);
  return Number.isFinite(parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}

export function validateVerificationCandidates(
  candidates: VerificationCandidate[],
): VerificationFailureReason | null {
  if (candidates.length > MAX_VERIFICATION_CANDIDATES) return "too_many_candidates";
  const ids = new Set<string>();
  for (const candidate of candidates) {
    if (ids.has(candidate.id)) return "duplicate_candidate_id";
    ids.add(candidate.id);
  }
  return null;
}

export function validateVerificationBatch(
  candidates: VerificationCandidate[],
  batch: VerificationBatchLike | null,
  fast: boolean,
): VerificationFailureReason | null {
  if (!batch || !Array.isArray(batch.verifications)) return "invalid_output";

  const expected = new Set(candidates.map((candidate) => candidate.id));
  const seen = new Set<string>();

  for (const item of batch.verifications) {
    if (seen.has(item.id)) return "duplicate_id";
    if (!expected.has(item.id)) return "unknown_id";
    seen.add(item.id);
  }

  if (seen.size !== expected.size || batch.verifications.length !== candidates.length) {
    return "incomplete";
  }

  for (const item of batch.verifications) {
    if (item.verdict === "visible_elsewhere" && !item.current_location?.trim()) {
      return "missing_location";
    }
    if (item.verdict === "confirmed_missing" && item.current_location?.trim()) {
      return "unexpected_location";
    }
    if (!fast) continue;
    if (item.certainty !== "high") return "low_confidence";
    if (item.verdict === "not_comparable") return "not_comparable";
  }

  return null;
}

function classifyRequestError(error: unknown): VerificationFailureReason {
  if (
    error instanceof Error &&
    (/timeout|timed out|abort/i.test(error.message) || error.name === "AbortError")
  ) {
    return "timeout";
  }
  return "request_error";
}

function batchesAgree(a: VerificationBatchLike, b: VerificationBatchLike) {
  const byId = new Map(b.verifications.map((item) => [item.id, item]));
  return a.verifications.every((item) => {
    const other = byId.get(item.id);
    if (other?.verdict !== item.verdict || other.certainty !== item.certainty) return false;
    if (item.verdict !== "visible_elsewhere") return true;
    return item.current_location?.trim().toLowerCase() === other.current_location?.trim().toLowerCase();
  });
}

async function runAttempt<T extends VerificationBatchLike>(
  runner: () => Promise<T | null>,
  now: () => number,
) {
  const startedAt = now();
  try {
    return {
      value: await runner(),
      ms: Math.max(0, now() - startedAt),
      error: null as VerificationFailureReason | null,
    };
  } catch (error) {
    return {
      value: null,
      ms: Math.max(0, now() - startedAt),
      error: classifyRequestError(error),
    };
  }
}

export async function runQwenVerificationPolicy<T extends VerificationBatchLike>({
  mode,
  candidates,
  runFast,
  runFallback,
  now = Date.now,
}: {
  mode: FastVerifierMode;
  candidates: VerificationCandidate[];
  runFast: () => Promise<T | null>;
  runFallback: () => Promise<T | null>;
  now?: () => number;
}): Promise<VerificationPolicyResult<T>> {
  const baseDiagnostics: VerificationDiagnostics = {
    path: "not_needed",
    fast_ms: 0,
    fallback_ms: 0,
    provider_calls: 0,
    shadow_agreement: null,
    active_fast_eligible: null,
  };

  if (candidates.length === 0) {
    return { verification: null, diagnostics: baseDiagnostics };
  }

  const candidateFailure = validateVerificationCandidates(candidates);
  if (candidateFailure) {
    return {
      verification: null,
      diagnostics: {
        ...baseDiagnostics,
        path: "qwen_unresolved",
        terminal_reason: candidateFailure,
      },
    };
  }

  if (mode === "off") {
    const fallback = await runAttempt(runFallback, now);
    const terminalReason = fallback.error ?? validateVerificationBatch(candidates, fallback.value, false);
    return {
      verification: terminalReason ? null : fallback.value,
      diagnostics: {
        ...baseDiagnostics,
        path: terminalReason ? "qwen_unresolved" : "qwen_primary",
        fallback_ms: fallback.ms,
        provider_calls: 1,
        terminal_reason: terminalReason ?? undefined,
      },
    };
  }

  const fast = await runAttempt(runFast, now);
  const fastReason = fast.error ?? validateVerificationBatch(candidates, fast.value, true);

  const activeReason =
    fastReason ??
    (fast.value?.verifications.some((item) => item.verdict !== "confirmed_missing")
      ? "conflicts_with_primary"
      : null);

  if (mode === "active" && !activeReason) {
    return {
      verification: fast.value,
      diagnostics: {
        ...baseDiagnostics,
        path: "qwen_fast",
        fast_ms: fast.ms,
        provider_calls: 1,
        active_fast_eligible: true,
      },
    };
  }

  const fallback = await runAttempt(runFallback, now);
  const terminalReason = fallback.error ?? validateVerificationBatch(candidates, fallback.value, false);
  const fallbackValid = !terminalReason && fallback.value !== null;

  if (mode === "shadow") {
    return {
      verification: fallbackValid ? fallback.value : null,
      diagnostics: {
        ...baseDiagnostics,
        path: fallbackValid ? "qwen_shadow" : "qwen_unresolved",
        fast_ms: fast.ms,
        fallback_ms: fallback.ms,
        provider_calls: 2,
        fallback_reason: fastReason ?? undefined,
        active_fast_eligible: !activeReason,
        active_fallback_reason: activeReason ?? undefined,
        terminal_reason: terminalReason ?? undefined,
        shadow_agreement:
          !fastReason && fast.value && fallbackValid
            ? batchesAgree(fast.value, fallback.value!)
            : null,
      },
    };
  }

  return {
    verification: fallbackValid ? fallback.value : null,
    diagnostics: {
      ...baseDiagnostics,
      path: fallbackValid ? "qwen_fast_fallback" : "qwen_unresolved",
      fast_ms: fast.ms,
      fallback_ms: fallback.ms,
      provider_calls: 2,
      fallback_reason: mode === "active" ? activeReason ?? undefined : fastReason ?? undefined,
      active_fast_eligible: false,
      active_fallback_reason: activeReason ?? undefined,
      terminal_reason: terminalReason ?? undefined,
    },
  };
}
