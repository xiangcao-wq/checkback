export const PERFORMANCE_LATEST_KEY = "checkback:last-performance";
export const PERFORMANCE_HISTORY_KEY = "checkback:performance-history-v1";
export const PERFORMANCE_HISTORY_LIMIT = 20;
const MAX_RAW_STORAGE_BYTES = 64 * 1024;

const PERFORMANCE_SAMPLE_KEYS = [
  "source_bytes",
  "upload_bytes",
  "preparation_ms",
  "upload_ms",
  "server_wait_ms",
  "response_headers_ms",
  "response_download_ms",
  "response_parse_ms",
  "response_bytes",
  "request_ms",
  "server_total_ms",
  "request_parse_ms",
  "image_prepare_ms",
  "data_url_ms",
  "preprocessing_ms",
  "primary_ai_ms",
  "observer_ai_ms",
  "missing_scout_ms",
  "observer_provider_calls",
  "missing_scout_provider_calls",
  "dual_observer_enabled",
  "missing_scout_candidate_count",
  "missing_scout_merged_count",
  "missing_scout_added_count",
  "verification_ai_ms",
  "report_assembly_ms",
  "fast_verifier_ms",
  "verification_fallback_ms",
  "verification_provider_calls",
  "verification_fallback_used",
  "verification_shadow_agreement",
  "verification_active_fast_eligible",
  "total_ms",
] as const;

type PerformanceMetric = (typeof PERFORMANCE_SAMPLE_KEYS)[number];
export type PerformanceSample = Record<PerformanceMetric, number>;
export type StoredPerformanceSample = PerformanceSample & { schema_version: 1 };

type StorageLike = Pick<Storage, "getItem" | "setItem">;

function normalizeMetric(key: PerformanceMetric, value: unknown) {
  if (typeof value !== "number" || !Number.isFinite(value)) return 0;
  const rounded = Math.round(value);
  if (
    key === "verification_shadow_agreement" ||
    key === "dual_observer_enabled" ||
    key === "verification_active_fast_eligible"
  ) {
    return rounded === 1 ? 1 : rounded === 0 ? 0 : -1;
  }
  return Math.max(0, rounded);
}

function normalizeSample(sample: Partial<Record<PerformanceMetric, unknown>>) {
  const normalized = {} as PerformanceSample;
  for (const key of PERFORMANCE_SAMPLE_KEYS) {
    normalized[key] = normalizeMetric(key, sample[key]);
  }
  return { ...normalized, schema_version: 1 as const };
}

function readHistory(storage: StorageLike): StoredPerformanceSample[] {
  try {
    const raw = storage.getItem(PERFORMANCE_HISTORY_KEY) ?? "[]";
    if (raw.length > MAX_RAW_STORAGE_BYTES) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .slice(-PERFORMANCE_HISTORY_LIMIT)
      .filter((item): item is Record<string, unknown> =>
        typeof item === "object" && item !== null && !Array.isArray(item),
      )
      .map((item) => normalizeSample(item));
  } catch {
    return [];
  }
}

export function persistPerformanceSample(
  historyStorage: StorageLike,
  latestStorage: StorageLike,
  sample: PerformanceSample,
) {
  const normalized = normalizeSample(sample);

  try {
    latestStorage.setItem(PERFORMANCE_LATEST_KEY, JSON.stringify(normalized));
  } catch {
    // Diagnostics must never interrupt a check.
  }

  try {
    const history = readHistory(historyStorage);
    history.push(normalized);
    historyStorage.setItem(
      PERFORMANCE_HISTORY_KEY,
      JSON.stringify(history.slice(-PERFORMANCE_HISTORY_LIMIT)),
    );
  } catch {
    // Diagnostics must never interrupt a check.
  }

  return normalized;
}