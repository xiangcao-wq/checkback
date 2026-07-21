import assert from "node:assert/strict";
import { after, test } from "node:test";

const ENV_KEYS = [
  "AI_VISION_PROVIDER",
  "DASHSCOPE_API_KEY",
  "DASHSCOPE_BASE_URL",
  "QWEN_VISION_MODEL",
  "CHECKBACK_FAST_VERIFIER_MODE",
  "CHECKBACK_ANALYSIS_ENABLED",
  "CHECKBACK_PUBLIC_ORIGIN",
  "CHECKBACK_RATE_LIMIT",
  "CHECKBACK_DAILY_LIMIT",
  "CHECKBACK_MAX_CONCURRENT",
];
const savedEnvironment = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
const originalFetch = globalThis.fetch;

Object.assign(process.env, {
  AI_VISION_PROVIDER: "qwen",
  DASHSCOPE_API_KEY: "offline-test-key",
  DASHSCOPE_BASE_URL: "https://offline.invalid/compatible-mode/v1",
  QWEN_VISION_MODEL: "qwen3.7-plus-2026-05-26",
  CHECKBACK_FAST_VERIFIER_MODE: "off",
  CHECKBACK_ANALYSIS_ENABLED: "true",
  CHECKBACK_RATE_LIMIT: "1000",
  CHECKBACK_DAILY_LIMIT: "1000",
  CHECKBACK_MAX_CONCURRENT: "3",
});
delete process.env.CHECKBACK_PUBLIC_ORIGIN;

after(() => {
  globalThis.fetch = originalFetch;
  for (const key of ENV_KEYS) {
    const value = savedEnvironment[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

const SYNTHETIC_JPEG = new Uint8Array([
  0xff, 0xd8,
  0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x01, 0x00, 0x01, 0x03,
  0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00,
  0xff, 0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
  0x00, 0x3f, 0x00, 0x00, 0xff, 0xd9,
]);

const clearAnalysis = {
  scene: { match: "same", overlap: "high", reason: "合成测试画面一致" },
  quality_issues: [],
  changes: [],
  checked_item_count: 3,
  summary: "合成测试未发现变化",
};

const missingAnalysis = {
  ...clearAnalysis,
  changes: [
    {
      id: "synthetic-speaker",
      label: "合成音箱",
      type: "missing",
      certainty: "high",
      baseline_location: "桌面右侧",
      current_location: null,
      baseline_visible: true,
      expected_region_visible: true,
      evidence: "合成测试候选",
      action: "检查桌面右侧",
    },
  ],
  summary: "合成测试发现一个候选",
};

const missingVerification = {
  verifications: [
    {
      id: "synthetic-speaker",
      verdict: "confirmed_missing",
      certainty: "high",
      current_location: null,
      evidence: "合成测试复核确认",
    },
  ],
};

function installFakeQwen(responses) {
  const queue = [...responses];
  const calls = [];
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    assert.equal(request.url.startsWith("https://offline.invalid/"), true);
    const body = JSON.parse(await request.text());
    calls.push(body);
    const payload = queue.shift();
    if (!payload) throw new Error("unexpected extra provider call");
    return new Response(
      JSON.stringify({
        id: "offline-chat-completion",
        object: "chat.completion",
        created: 0,
        model: body.model,
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: JSON.stringify(payload) },
            finish_reason: "stop",
          },
        ],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }),
      {
        status: 200,
        headers: {
          "content-type": "application/json",
          "x-request-id": "offline-request-id",
        },
      },
    );
  };
  return calls;
}

async function dispatchAnalysis(address) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("performance-test", address + "-" + Date.now());
  const { default: worker } = await import(workerUrl.href);
  const formData = new FormData();
  formData.append("baseline", new File([SYNTHETIC_JPEG], "baseline.jpg", { type: "image/jpeg" }));
  formData.append("current", new File([SYNTHETIC_JPEG], "current.jpg", { type: "image/jpeg" }));

  return worker.fetch(
    new Request("http://localhost/api/analyze", {
      method: "POST",
      body: formData,
      headers: { "x-forwarded-for": address },
    }),
    {
      ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

function assertTimingContract(response, body) {
  const names = [
    "request_parse",
    "image_prepare",
    "data_url",
    "preprocessing",
    "primary_ai",
    "observer_ai",
    "missing_scout",
    "verification_ai",
    "verification_fast",
    "verification_fallback",
    "report_assembly",
    "total",
  ];
  const header = response.headers.get("server-timing") ?? "";
  const parsed = new Map(
    header.split(",").map((entry) => {
      const [name, duration] = entry.trim().split(";dur=");
      return [name, Number(duration)];
    }),
  );
  assert.deepEqual([...parsed.keys()], names);

  const diagnostics = body.diagnostics;
  const bodyByHeader = {
    request_parse: diagnostics.request_parse_ms,
    image_prepare: diagnostics.image_prepare_ms,
    data_url: diagnostics.data_url_ms,
    preprocessing: diagnostics.preprocessing_ms,
    primary_ai: diagnostics.primary_ai_ms,
    observer_ai: diagnostics.observer_ai_ms,
    missing_scout: diagnostics.missing_scout_ms,
    verification_ai: diagnostics.verification_ai_ms,
    verification_fast: diagnostics.fast_verifier_ms,
    verification_fallback: diagnostics.verification_fallback_ms,
    report_assembly: diagnostics.report_assembly_ms,
    total: diagnostics.total_ms,
  };
  for (const name of names) {
    assert.equal(Number.isInteger(bodyByHeader[name]), true, name);
    assert.equal(bodyByHeader[name] >= 0, true, name);
    assert.equal(parsed.get(name), bodyByHeader[name], name);
  }
  assert.equal(body.report.processing_ms, diagnostics.total_ms);
}

test("offline route uses one Plus call when verification is unnecessary", async () => {
  const calls = installFakeQwen([clearAnalysis]);
  const response = await dispatchAnalysis("198.51.100.10");
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].model, "qwen3.7-plus-2026-05-26");
  assert.equal(body.report.status, "clear");
  assert.equal(body.diagnostics.verification_provider_calls, 0);
  assertTimingContract(response, body);
});

test("offline default route keeps the conservative two-Plus missing path", async () => {
  const calls = installFakeQwen([missingAnalysis, missingVerification]);
  const response = await dispatchAnalysis("198.51.100.11");
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(calls.length, 2);
  assert.deepEqual(
    calls.map((call) => call.model),
    ["qwen3.7-plus-2026-05-26", "qwen3.7-plus-2026-05-26"],
  );
  assert.equal(calls.some((call) => /flash/i.test(call.model)), false);
  assert.equal(body.report.status, "issues");
  assert.equal(body.report.verified_missing_count, 1);
  assert.equal(body.diagnostics.verification_provider_calls, 1);
  assert.equal(body.diagnostics.verification_plus_role, "primary_verifier");
  assertTimingContract(response, body);
});

test("ten-pair offline route smoke preserves bounded provider calls", async () => {
  const responses = [];
  for (let index = 0; index < 10; index += 1) {
    if (index % 2 === 0) responses.push(clearAnalysis);
    else responses.push(missingAnalysis, missingVerification);
  }
  const calls = installFakeQwen(responses);

  for (let index = 0; index < 10; index += 1) {
    const response = await dispatchAnalysis("198.51.100." + (30 + index));
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.report.status, index % 2 === 0 ? "clear" : "issues");
    assertTimingContract(response, body);
  }

  assert.equal(calls.length, 15);
  assert.equal(calls.every((call) => /plus/i.test(call.model)), true);
  assert.equal(calls.some((call) => /flash/i.test(call.model)), false);
});