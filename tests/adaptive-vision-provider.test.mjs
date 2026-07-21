import test from "node:test";
import assert from "node:assert/strict";
import {
  analyzeImagePairWithScout,
  getVisionRuntime,
  parseMissingScoutMode,
  verifyMissingCandidates,
} from "../app/lib/vision-provider.ts";
import { normalizeCheckbackReport } from "../app/lib/checkback-analysis.ts";

const FLASH_MODEL = "qwen3.6-flash-2026-04-16";
const PLUS_MODEL = "qwen3.7-plus-2026-05-26";

const clearPrimary = {
  scene: { match: "same", overlap: "high", reason: "same scene" },
  quality_issues: [],
  changes: [],
  checked_item_count: 12,
  summary: "clear",
};

const scoutCandidate = {
  comparison: "usable",
  reason: "enough overlap",
  candidates: [
    {
      label: "speaker",
      baseline_location: "right tray",
      certainty: "medium",
      baseline_visible: true,
      expected_region_visible: true,
      evidence: "not visible in the expected region",
    },
  ],
};

function completion(value) {
  return {
    choices: [
      {
        message: {
          content: typeof value === "string" ? value : JSON.stringify(value),
        },
      },
    ],
  };
}

function fakeRuntime(responses, overrides = {}) {
  const calls = [];
  const queue = [...responses];
  const runtime = {
    provider: "qwen",
    model: PLUS_MODEL,
    client: {
      chat: {
        completions: {
          create: async (params, options) => {
            calls.push({ params, options });
            const value = queue.shift();
            if (value instanceof Error) throw value;
            return completion(value);
          },
        },
      },
    },
    qwenMissingScout: {
      mode: "active",
      model: FLASH_MODEL,
      timeoutMs: 12_345,
      promptVersion: "checkback-missing-scout-v1",
    },
    qwenVerification: {
      mode: "active",
      fastModel: FLASH_MODEL,
      fallbackModel: PLUS_MODEL,
      promptVersion: "test",
      promptSha256: "test",
      fastTimeoutMs: 12_345,
      fallbackTimeoutMs: 67_890,
    },
    ...overrides,
  };
  return { runtime, calls };
}

test("missing scout mode fails closed unless explicitly active", () => {
  assert.equal(parseMissingScoutMode(undefined), "off");
  assert.equal(parseMissingScoutMode("shadow"), "off");
  assert.equal(parseMissingScoutMode("enabled"), "off");
  assert.equal(parseMissingScoutMode(" ACTIVE "), "active");
});

test("runtime pins the active missing scout to the Flash tier", () => {
  const names = [
    "AI_VISION_PROVIDER",
    "DASHSCOPE_API_KEY",
    "CHECKBACK_MISSING_SCOUT_MODE",
    "QWEN_FAST_VERIFICATION_MODEL",
  ];
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  try {
    process.env.AI_VISION_PROVIDER = "qwen";
    process.env.DASHSCOPE_API_KEY = "test-only-key";
    process.env.CHECKBACK_MISSING_SCOUT_MODE = "active";
    process.env.QWEN_FAST_VERIFICATION_MODEL = PLUS_MODEL;
    const runtime = getVisionRuntime();
    assert.ok(runtime);
    assert.equal(runtime.qwenMissingScout.mode, "active");
    assert.equal(runtime.qwenMissingScout.model, FLASH_MODEL);
    assert.equal(runtime.qwenMissingScout.timeoutMs, 20_000);
  } finally {
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
  }
});

test("Plus primary and Flash scout start in parallel", async () => {
  const calls = [];
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const { runtime } = fakeRuntime([]);
  runtime.client.chat.completions.create = async (params, options) => {
    calls.push({ params, options });
    await gate;
    return completion(params.model === FLASH_MODEL ? scoutCandidate : clearPrimary);
  };

  const pending = analyzeImagePairWithScout(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
  );
  await Promise.resolve();
  assert.equal(calls.length, 2);
  release();
  const result = await pending;

  assert.ok(result.analysis);
  assert.equal(result.diagnostics.path, "parallel");
  assert.equal(result.diagnostics.provider_calls, 2);
  assert.equal(calls[0].params.model, PLUS_MODEL);
  assert.equal(calls[1].params.model, FLASH_MODEL);
  assert.equal(calls[0].params.max_tokens, 4_000);
  assert.equal(calls[1].params.max_tokens, 1_600);
  assert.deepEqual(calls[1].options, { maxRetries: 0, timeout: 12_345 });
  assert.equal(result.analysis.changes[0].origin, "scout");
});

test("invalid scout output becomes incomplete instead of clear", async () => {
  const { runtime, calls } = fakeRuntime([clearPrimary, "not-json"]);
  const result = await analyzeImagePairWithScout(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
  );

  assert.equal(calls.length, 2);
  assert.equal(result.diagnostics.path, "scout_unresolved");
  assert.ok(result.analysis);
  const report = normalizeCheckbackReport(result.analysis, null, {
    analysisId: "invalid-scout",
    processingMs: 10,
  });
  assert.equal(report.status, "incomplete");
});

test("scout-origin medium candidates are finalized by Plus when override is off", async () => {
  const verification = {
    verifications: [
      {
        id: "scout-0001",
        verdict: "confirmed_missing",
        certainty: "high",
        current_location: null,
        evidence: "confirmed by Plus",
      },
    ],
  };
  const raw = {
    ...clearPrimary,
    changes: [
      {
        id: "scout-0001",
        label: "speaker",
        type: "missing",
        certainty: "medium",
        baseline_location: "right tray",
        current_location: null,
        baseline_visible: true,
        expected_region_visible: true,
        origin: "scout",
        evidence: "scout candidate",
        action: "check",
      },
    ],
  };
  const { runtime, calls } = fakeRuntime([verification]);
  const result = await verifyMissingCandidates(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
    raw,
    { qwenModeOverride: "off" },
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].params.model, PLUS_MODEL);
  assert.equal(result.diagnostics.path, "qwen_primary");
  const report = normalizeCheckbackReport(raw, result.verification, {
    analysisId: "adaptive-final",
    processingMs: 10,
  });
  assert.equal(report.status, "issues");
  assert.equal(report.verified_missing_count, 1);
});

test("propagates the caller abort signal to both parallel observer calls", async () => {
  const controller = new AbortController();
  const { runtime, calls } = fakeRuntime([clearPrimary, scoutCandidate]);

  await analyzeImagePairWithScout(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
    controller.signal,
  );

  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.signal, controller.signal);
  assert.equal(calls[1].options.signal, controller.signal);
});

test("propagates the caller abort signal to missing-item verification", async () => {
  const controller = new AbortController();
  const raw = {
    ...clearPrimary,
    changes: [
      {
        id: "missing-1",
        label: "speaker",
        type: "missing",
        certainty: "high",
        baseline_location: "right tray",
        current_location: null,
        baseline_visible: true,
        expected_region_visible: true,
        evidence: "not visible",
        action: "check",
      },
    ],
  };
  const verification = {
    verifications: [
      {
        id: "missing-1",
        verdict: "confirmed_missing",
        certainty: "high",
        current_location: null,
        evidence: "confirmed",
      },
    ],
  };
  const { runtime, calls } = fakeRuntime([verification]);

  await verifyMissingCandidates(
    runtime,
    "data:image/jpeg;base64,A",
    "data:image/jpeg;base64,B",
    raw,
    { qwenModeOverride: "off", signal: controller.signal },
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.signal, controller.signal);
});
