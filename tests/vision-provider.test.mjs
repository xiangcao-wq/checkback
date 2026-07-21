import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  CHECKBACK_VERIFIER_PROMPT_SHA256,
  CHECKBACK_VERIFIER_PROMPT_VERSION,
  DEFAULT_QWEN_PRIMARY_MODEL,
  DEFAULT_QWEN_VERIFICATION_FALLBACK_MODEL,
  QWEN_VERIFIER_FINGERPRINT_SOURCE,
  QWEN_VERIFIER_SYSTEM_PROMPT,
  analyzeImagePair,
  getVisionRuntime,
  verifyMissingCandidates,
} from "../app/lib/vision-provider.ts";
import { normalizeCheckbackReport } from "../app/lib/checkback-analysis.ts";

const FLASH_MODEL = "qwen3.6-flash-2026-04-16";
const PLUS_MODEL = "qwen3.7-plus-2026-05-26";

const missing = {
  id: "speaker",
  label: "蓝牙音箱",
  type: "missing",
  certainty: "high",
  baseline_location: "桌面右下角",
  current_location: null,
  baseline_visible: true,
  expected_region_visible: true,
  evidence: "当前位置未看到音箱",
  action: "检查音箱",
};

const raw = {
  scene: { match: "same", overlap: "high", reason: "共同区域清晰" },
  quality_issues: [],
  changes: [missing],
  checked_item_count: 8,
  summary: "发现一项变化",
};

function verification(verdict, currentLocation = null, certainty = "high") {
  return {
    verifications: [
      {
        id: "speaker",
        verdict,
        certainty,
        current_location: currentLocation,
        evidence: "独立复核证据",
      },
    ],
  };
}

function fakeQwenRuntime(mode, queuedResponses, settings = {}) {
  const calls = [];
  const queue = [...queuedResponses];
  const client = {
    chat: {
      completions: {
        create: async (params, options) => {
          calls.push({ params, options });
          const next = queue.shift();
          if (next instanceof Error) throw next;
          return {
            choices: [
              {
                message: {
                  content: typeof next === "string" ? next : JSON.stringify(next),
                },
              },
            ],
          };
        },
      },
    },
  };

  return {
    calls,
    runtime: {
      provider: "qwen",
      model: PLUS_MODEL,
      client,
      qwenVerification: {
        mode,
        fastModel: FLASH_MODEL,
        fallbackModel: PLUS_MODEL,
        promptVersion: CHECKBACK_VERIFIER_PROMPT_VERSION,
        promptSha256: CHECKBACK_VERIFIER_PROMPT_SHA256,
        fastTimeoutMs: 12_345,
        fallbackTimeoutMs: 67_890,
        ...settings,
      },
    },
  };
}

const runtimeEnvNames = [
  "AI_VISION_PROVIDER",
  "DASHSCOPE_API_KEY",
  "QWEN_VISION_MODEL",
  "CHECKBACK_FAST_VERIFIER_MODE",
  "QWEN_FAST_VERIFICATION_MODEL",
  "QWEN_VERIFICATION_FALLBACK_MODEL",
  "QWEN_FAST_VERIFICATION_TIMEOUT_MS",
  "QWEN_VERIFICATION_FALLBACK_TIMEOUT_MS",
];

async function withRuntimeEnv(values, callback) {
  const previous = Object.fromEntries(runtimeEnvNames.map((name) => [name, process.env[name]]));
  try {
    for (const name of runtimeEnvNames) delete process.env[name];
    for (const [name, value] of Object.entries(values)) process.env[name] = value;
    return await callback();
  } finally {
    for (const name of runtimeEnvNames) {
      const value = previous[name];
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test("verifier prompt fingerprint matches the pinned evaluation config", () => {
  const fingerprint = createHash("sha256")
    .update(QWEN_VERIFIER_FINGERPRINT_SOURCE)
    .digest("hex");

  assert.equal(fingerprint, CHECKBACK_VERIFIER_PROMPT_SHA256);
});
test("runtime defaults are pinned and unsafe verifier model tiers fail closed", async () => {
  await withRuntimeEnv(
    {
      AI_VISION_PROVIDER: "qwen",
      DASHSCOPE_API_KEY: "test-only-key",
      CHECKBACK_FAST_VERIFIER_MODE: "enabled",
      QWEN_FAST_VERIFICATION_MODEL: PLUS_MODEL,
      QWEN_VERIFICATION_FALLBACK_MODEL: FLASH_MODEL,
      QWEN_FAST_VERIFICATION_TIMEOUT_MS: "31000ms",
      QWEN_VERIFICATION_FALLBACK_TIMEOUT_MS: "45000ms",
    },
    async () => {
      const runtime = getVisionRuntime();
      assert.ok(runtime);
      assert.equal(runtime.model, DEFAULT_QWEN_PRIMARY_MODEL);
      assert.equal(runtime.qwenVerification.mode, "off");
      assert.equal(runtime.qwenVerification.fastModel, FLASH_MODEL);
      assert.equal(
        runtime.qwenVerification.promptVersion,
        CHECKBACK_VERIFIER_PROMPT_VERSION,
      );
      assert.equal(
        runtime.qwenVerification.promptSha256,
        CHECKBACK_VERIFIER_PROMPT_SHA256,
      );
      assert.equal(
        runtime.qwenVerification.fallbackModel,
        DEFAULT_QWEN_VERIFICATION_FALLBACK_MODEL,
      );
      assert.equal(runtime.qwenVerification.fastTimeoutMs, 20_000);
      assert.equal(runtime.qwenVerification.fallbackTimeoutMs, 90_000);
    },
  );
});

test("Qwen primary image analysis disables implicit SDK retries", async () => {
  const { runtime, calls } = fakeQwenRuntime("shadow", [raw]);
  const result = await analyzeImagePair(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
  );

  assert.ok(result);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].options, { maxRetries: 0, timeout: 90_000 });
  assert.equal(calls[0].params.max_tokens, 4_000);
  assert.deepEqual(calls[0].params.response_format, { type: "json_object" });
  assert.match(calls[0].params.messages[0].content, /at most 16/);
  assert.match(calls[0].params.messages[0].content, /Never omit a possible missing/);
  assert.match(calls[0].params.messages[0].content, /only the requested JSON keys/);
});

test("Qwen primary safely removes extra keys and bounds prose", async () => {
  const noisy = {
    ...raw,
    ignored: "extra",
    scene: {
      ...raw.scene,
      reason: "r".repeat(300),
      ignored: true,
    },
    changes: [
      {
        ...missing,
        label: "l".repeat(100),
        evidence: "e".repeat(400),
        ignored: "extra",
      },
    ],
    summary: "s".repeat(500),
  };
  const { runtime } = fakeQwenRuntime("shadow", [noisy]);
  const result = await analyzeImagePair(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
  );

  assert.ok(result);
  assert.equal(result.scene.reason.length, 240);
  assert.equal(result.changes[0].label.length, 80);
  assert.equal(result.changes[0].evidence.length, 300);
  assert.equal(result.summary.length, 360);
  assert.equal(Object.hasOwn(result, "ignored"), false);
  assert.equal(Object.hasOwn(result.scene, "ignored"), false);
  assert.equal(Object.hasOwn(result.changes[0], "ignored"), false);
});

test("Qwen primary still rejects unsafe semantic field changes", async () => {
  const unsafe = {
    ...raw,
    changes: [{ ...missing, expected_region_visible: "true" }],
  };
  const { runtime } = fakeQwenRuntime("shadow", [unsafe]);
  const result = await analyzeImagePair(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
  );

  assert.equal(result, null);
});

test("Qwen primary turns a saturated no-missing result into incomplete", async () => {
  const saturated = {
    ...raw,
    changes: Array.from({ length: 16 }, (_, index) => ({
      ...missing,
      id: `change-${index + 1}`,
      type: "misplaced",
      current_location: "current region",
    })),
  };
  const { runtime } = fakeQwenRuntime("shadow", [saturated]);
  const result = await analyzeImagePair(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
  );

  assert.ok(result);
  assert.equal(
    result.quality_issues.some((issue) => issue.severity === "blocking"),
    true,
  );
  const report = normalizeCheckbackReport(result, null, {
    analysisId: "saturated-primary",
    processingMs: 100,
  });
  assert.equal(report.status, "incomplete");
});
test("off mode preserves the legacy Plus request options and result", async () => {
  const { runtime, calls } = fakeQwenRuntime("off", [verification("confirmed_missing")]);
  const result = await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", raw);

  assert.equal(calls.length, 1);
  assert.equal(calls[0].params.model, PLUS_MODEL);
  assert.equal(calls[0].options, undefined);
  assert.equal(result.diagnostics.path, "qwen_primary");
  assert.equal(result.verification.verifications[0].verdict, "confirmed_missing");
});

test("Qwen verification removes extra keys and bounds evidence", async () => {
  const response = {
    extra_root: "ignored",
    verifications: [
      {
        ...verification("confirmed_missing").verifications[0],
        evidence: "e".repeat(600),
        extra_item: "ignored",
      },
    ],
  };
  const { runtime } = fakeQwenRuntime("off", [response]);
  const result = await verifyMissingCandidates(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
    raw,
  );

  assert.equal(result.diagnostics.path, "qwen_primary");
  assert.equal(result.verification.verifications[0].evidence.length, 300);
  assert.equal("extra_item" in result.verification.verifications[0], false);
});

test("Qwen verification safely restores an omitted null location", async () => {
  const response = verification("confirmed_missing");
  delete response.verifications[0].current_location;
  const { runtime } = fakeQwenRuntime("off", [response]);
  const result = await verifyMissingCandidates(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
    raw,
  );

  assert.equal(result.diagnostics.path, "qwen_primary");
  assert.equal(
    result.verification.verifications[0].current_location,
    null,
  );
});

test("Qwen verification never invents an omitted moved location", async () => {
  const response = verification("visible_elsewhere");
  delete response.verifications[0].current_location;
  const { runtime } = fakeQwenRuntime("off", [response]);
  const result = await verifyMissingCandidates(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
    raw,
  );

  assert.equal(result.verification, null);
  assert.equal(result.diagnostics.path, "qwen_unresolved");
  assert.equal(result.diagnostics.terminal_reason, "invalid_output");
});

test("Qwen verification sanitizer still rejects semantic coercion", async () => {
  const response = verification("confirmed_missing");
  response.verifications[0].certainty = "HIGH";
  const { runtime } = fakeQwenRuntime("off", [response]);
  const result = await verifyMissingCandidates(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
    raw,
  );

  assert.equal(result.verification, null);
  assert.equal(result.diagnostics.path, "qwen_unresolved");
  assert.equal(result.diagnostics.terminal_reason, "invalid_output");
});

test("off mode preserves legacy provider error propagation", async () => {
  const upstream = new Error("429 quota exceeded");
  const { runtime } = fakeQwenRuntime("off", [upstream]);

  await assert.rejects(
    verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", raw),
    (error) => error === upstream,
  );
});

test("active mode accepts only a complete high-confidence missing confirmation", async () => {
  const { runtime, calls } = fakeQwenRuntime("active", [
    verification("confirmed_missing"),
  ]);
  const result = await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", raw);

  assert.equal(calls.length, 1);
  assert.equal(calls[0].params.model, FLASH_MODEL);
  assert.deepEqual(calls[0].options, { maxRetries: 0, timeout: 12_345 });
  assert.match(calls[0].params.messages[0].content, /untrusted evidence/);
  assert.equal(calls[0].params.messages[0].content, QWEN_VERIFIER_SYSTEM_PROMPT);
  assert.deepEqual(
    calls[0].params.messages[1].content.map((part) => part.type),
    ["text", "text", "image_url", "text", "image_url"],
  );
  assert.equal(result.diagnostics.path, "qwen_fast");
});

test("active mode sends semantic conflicts to Plus and cannot create a false clear", async () => {
  const { runtime, calls } = fakeQwenRuntime("active", [
    verification("visible_same_place", "桌面右下角"),
    verification("confirmed_missing"),
  ]);
  const result = await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", raw);
  const report = normalizeCheckbackReport(raw, result.verification, {
    analysisId: "provider-integration",
    processingMs: 100,
  });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].params.model, FLASH_MODEL);
  assert.equal(calls[1].params.model, PLUS_MODEL);
  assert.deepEqual(calls[1].options, { maxRetries: 0, timeout: 67_890 });
  assert.equal(result.diagnostics.path, "qwen_fast_fallback");
  assert.equal(result.diagnostics.fallback_reason, "conflicts_with_primary");
  assert.equal(report.status, "issues");
  assert.equal(report.items[0].type, "missing");
});

test("active mode falls back after malformed Qwen JSON", async () => {
  const { runtime, calls } = fakeQwenRuntime("active", [
    "not-json",
    verification("confirmed_missing"),
  ]);
  const result = await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", raw);

  assert.equal(calls.length, 2);
  assert.equal(result.diagnostics.fallback_reason, "invalid_output");
  assert.equal(result.verification.verifications[0].verdict, "confirmed_missing");
});

test("provider invocation re-sanitizes unsafe fast and fallback model settings", async () => {
  const { runtime, calls } = fakeQwenRuntime(
    "active",
    [
      verification("visible_same_place", "桌面右下角"),
      verification("confirmed_missing"),
    ],
    { fastModel: PLUS_MODEL, fallbackModel: FLASH_MODEL },
  );
  await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", raw);

  assert.equal(calls.length, 2);
  assert.equal(calls[0].params.model, FLASH_MODEL);
  assert.equal(calls[1].params.model, PLUS_MODEL);
});

test("OpenAI verification path remains single-call and unchanged", async () => {
  const calls = [];
  const expected = verification("confirmed_missing");
  const runtime = {
    provider: "openai",
    model: "gpt-test",
    client: {
      responses: {
        parse: async (params) => {
          calls.push(params);
          return { output_parsed: expected };
        },
      },
    },
  };
  const result = await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", raw);

  assert.equal(calls.length, 1);
  assert.equal(calls[0].model, "gpt-test");
  assert.equal(calls[0].store, false);
  assert.equal(result.verification, expected);
  assert.equal(result.diagnostics.path, "openai");
  assert.equal(result.diagnostics.provider_calls, 1);
});
test("a failed Plus fallback stays incomplete instead of clear", async () => {
  const { runtime } = fakeQwenRuntime("active", [
    verification("visible_same_place", "桌面右下角"),
    new Error("fallback unavailable"),
  ]);
  const result = await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", raw);
  const report = normalizeCheckbackReport(raw, result.verification, {
    analysisId: "failed-fallback-integration",
    processingMs: 100,
  });

  assert.equal(result.verification, null);
  assert.equal(result.diagnostics.path, "qwen_unresolved");
  assert.equal(result.diagnostics.terminal_reason, "request_error");
  assert.equal(report.status, "incomplete");
  assert.equal(report.items[0].type, "uncertain");
});
function verificationItem(id) {
  return {
    id,
    verdict: "confirmed_missing",
    certainty: "high",
    current_location: null,
    evidence: "独立复核证据",
  };
}

test("off mode rejects duplicate source candidate IDs before calling Plus", async () => {
  const duplicateRaw = {
    ...raw,
    changes: [
      { ...missing, id: "duplicate", label: "物品一" },
      { ...missing, id: "duplicate", label: "物品二", baseline_location: "桌面左侧" },
    ],
  };
  const { runtime, calls } = fakeQwenRuntime("off", []);
  const result = await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", duplicateRaw);

  assert.equal(calls.length, 0);
  assert.equal(result.verification, null);
  assert.equal(result.diagnostics.path, "qwen_unresolved");
  assert.equal(result.diagnostics.terminal_reason, "duplicate_candidate_id");
});

for (const [name, response, reason] of [
  ["partial", { verifications: [verificationItem("speaker")] }, "incomplete"],
  [
    "unknown",
    { verifications: [verificationItem("speaker"), verificationItem("keyboard"), verificationItem("ghost")] },
    "unknown_id",
  ],
  [
    "duplicate",
    { verifications: [verificationItem("speaker"), verificationItem("speaker")] },
    "duplicate_id",
  ],
]) {
  test(`off mode rejects ${name} Plus candidate coverage`, async () => {
    const twoCandidateRaw = {
      ...raw,
      changes: [
        missing,
        { ...missing, id: "keyboard", label: "键盘", baseline_location: "桌面中央" },
      ],
    };
    const { runtime, calls } = fakeQwenRuntime("off", [response]);
    const result = await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", twoCandidateRaw);

    assert.equal(calls.length, 1);
    assert.equal(calls[0].params.model, PLUS_MODEL);
    assert.equal(calls[0].options, undefined);
    assert.equal(result.verification, null);
    assert.equal(result.diagnostics.path, "qwen_unresolved");
    assert.equal(result.diagnostics.terminal_reason, reason);
  });
}

test("shadow mode calls Flash then Plus with isolated request options", async () => {
  const { runtime, calls } = fakeQwenRuntime("shadow", [
    verification("confirmed_missing"),
    verification("confirmed_missing"),
  ]);
  const result = await verifyMissingCandidates(runtime, "data:image/jpeg;base64,A", "data:image/jpeg;base64,B", raw);

  assert.equal(calls.length, 2);
  assert.equal(calls[0].params.model, FLASH_MODEL);
  assert.deepEqual(calls[0].options, { maxRetries: 0, timeout: 12_345 });
  assert.equal(calls[1].params.model, PLUS_MODEL);
  assert.deepEqual(calls[1].options, { maxRetries: 0, timeout: 67_890 });
  assert.equal(result.diagnostics.path, "qwen_shadow");
  assert.equal(result.diagnostics.shadow_agreement, true);
});