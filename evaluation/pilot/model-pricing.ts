export const QWEN_PRICING_SOURCE_URL =
  "https://help.aliyun.com/zh/model-studio/model-pricing";
export const QWEN_PRICING_CHECKED_DATE = "2026-07-16";
export const QWEN_PRICING_CURRENCY = "CNY";

export type QwenTokenUsage = {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
};

export type QwenCallCost = {
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  input_cny_per_million: number;
  output_cny_per_million: number;
  advertised_input_cny_per_million: number;
  advertised_output_cny_per_million: number;
  public_list_equivalent_cny: number;
  current_advertised_equivalent_cny: number;
  pricing_tier: "up_to_256k" | "over_256k_to_1m";
};

function assertUsage(usage: QwenTokenUsage) {
  if (
    !Number.isInteger(usage.prompt_tokens) ||
    usage.prompt_tokens < 1 ||
    !Number.isInteger(usage.completion_tokens) ||
    usage.completion_tokens < 1 ||
    !Number.isInteger(usage.total_tokens) ||
    usage.total_tokens !== usage.prompt_tokens + usage.completion_tokens
  ) {
    throw new Error("qwen_pricing_usage_invalid");
  }
  if (usage.prompt_tokens > 1_000_000) {
    throw new Error("qwen_pricing_input_tier_unsupported");
  }
}

function roundCny(value: number) {
  return Math.round(value * 100_000_000) / 100_000_000;
}

function ratesFor(model: string, promptTokens: number) {
  const longInput = promptTokens > 256_000;
  if (model === "qwen3.7-plus" || /^qwen3\.7-plus-2026-05-26$/.test(model)) {
    const input = longInput ? 6 : 2;
    const output = longInput ? 24 : 8;
    const advertisedFactor = model === "qwen3.7-plus" ? 0.8 : 1;
    return {
      input,
      output,
      advertisedInput: input * advertisedFactor,
      advertisedOutput: output * advertisedFactor,
    };
  }
  if (
    model === "qwen3.6-flash" ||
    /^qwen3\.6-flash-2026-04-16$/.test(model)
  ) {
    const input = longInput ? 4.8 : 1.2;
    const output = longInput ? 28.8 : 7.2;
    return {
      input,
      output,
      advertisedInput: input,
      advertisedOutput: output,
    };
  }
  throw new Error("qwen_pricing_model_not_pinned");
}

export function estimateQwenCallCost(
  model: string,
  usage: QwenTokenUsage,
): QwenCallCost {
  assertUsage(usage);
  const rates = ratesFor(model, usage.prompt_tokens);
  const publicList =
    (usage.prompt_tokens * rates.input +
      usage.completion_tokens * rates.output) /
    1_000_000;
  const advertised =
    (usage.prompt_tokens * rates.advertisedInput +
      usage.completion_tokens * rates.advertisedOutput) /
    1_000_000;
  return {
    model,
    ...usage,
    input_cny_per_million: rates.input,
    output_cny_per_million: rates.output,
    advertised_input_cny_per_million: rates.advertisedInput,
    advertised_output_cny_per_million: rates.advertisedOutput,
    public_list_equivalent_cny: roundCny(publicList),
    current_advertised_equivalent_cny: roundCny(advertised),
    pricing_tier:
      usage.prompt_tokens > 256_000
        ? "over_256k_to_1m"
        : "up_to_256k",
  };
}
