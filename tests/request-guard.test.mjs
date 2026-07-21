import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import {
  acquireAnalysisPermit,
  validateAnalysisRequest,
} from "../app/lib/request-guard.ts";

import { parseRequestFormData } from "../app/lib/request-form-data.ts";

const MAX_ANALYSIS_FORM_BYTES = 1024 * 1024;

async function dispatch(request) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("request-guard-test", process.pid + "-" + Date.now() + "-" + Math.random());
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    request,
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

const MANAGED_ENV_KEYS = [
  "CHECKBACK_ANALYSIS_ENABLED",
  "CHECKBACK_PUBLIC_ORIGIN",
  "CHECKBACK_RATE_WINDOW_MS",
  "CHECKBACK_RATE_LIMIT",
  "CHECKBACK_DAILY_LIMIT",
  "CHECKBACK_MAX_CONCURRENT",
];

function resetGuard() {
  globalThis.__checkbackGuardState = undefined;
}

afterEach(() => {
  resetGuard();
  for (const key of MANAGED_ENV_KEYS) delete process.env[key];
});

test("rejects cross-site and mismatched-origin analysis requests", () => {
  process.env.CHECKBACK_PUBLIC_ORIGIN = "https://checkback.example";

  const crossSite = validateAnalysisRequest(
    new Request("https://checkback.example/api/analyze", {
      method: "POST",
      headers: {
        origin: "https://attacker.example",
        "sec-fetch-site": "cross-site",
      },
    }),
  );
  assert.equal(crossSite?.status, 403);
  assert.equal(crossSite?.code, "UNTRUSTED_ORIGIN");

  const sameSite = validateAnalysisRequest(
    new Request("https://checkback.example/api/analyze", {
      method: "POST",
      headers: {
        origin: "https://checkback.example",
        "sec-fetch-site": "same-origin",
      },
    }),
  );
  assert.equal(sameSite, null);
});

test("supports an emergency analysis shutdown", () => {
  process.env.CHECKBACK_ANALYSIS_ENABLED = "false";
  const rejection = validateAnalysisRequest(
    new Request("https://checkback.example/api/analyze", { method: "POST" }),
  );
  assert.equal(rejection?.status, 503);
  assert.equal(rejection?.code, "ANALYSIS_DISABLED");
});

test("rejects a request body that cannot be parsed as form data", async () => {
  const result = await parseRequestFormData(
    new Request("https://checkback.example/api/analyze", { method: "POST" }),
  );
  assert.equal(result.ok, false);
});

test("enforces concurrency and per-client limits", () => {
  process.env.CHECKBACK_RATE_WINDOW_MS = "60000";
  process.env.CHECKBACK_RATE_LIMIT = "2";
  process.env.CHECKBACK_DAILY_LIMIT = "20";
  process.env.CHECKBACK_MAX_CONCURRENT = "1";
  const request = new Request("https://checkback.example/api/analyze", {
    headers: { "x-real-ip": "203.0.113.10" },
  });

  const first = acquireAnalysisPermit(request);
  assert.equal(first.ok, true);
  const whileBusy = acquireAnalysisPermit(request);
  assert.equal(whileBusy.ok, false);
  assert.equal(whileBusy.code, "CONCURRENCY_LIMIT");

  first.release();
  first.release();
  const second = acquireAnalysisPermit(request);
  assert.equal(second.ok, true);
  second.release();

  const limited = acquireAnalysisPermit(request);
  assert.equal(limited.ok, false);
  assert.equal(limited.code, "CLIENT_RATE_LIMIT");
});

test("enforces the global daily analysis budget", () => {
  process.env.CHECKBACK_RATE_LIMIT = "20";
  process.env.CHECKBACK_DAILY_LIMIT = "1";
  process.env.CHECKBACK_MAX_CONCURRENT = "3";
  const request = new Request("https://checkback.example/api/analyze", {
    headers: { "x-real-ip": "203.0.113.20" },
  });

  const first = acquireAnalysisPermit(request);
  assert.equal(first.ok, true);
  first.release();

  const limited = acquireAnalysisPermit(request);
  assert.equal(limited.ok, false);
  assert.equal(limited.code, "DAILY_LIMIT");
});

test("rejects an oversized body before form-data parsing even without a content-length header", async () => {
  const result = await parseRequestFormData(
    new Request("https://checkback.example/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new Uint8Array(64),
    }),
    32,
  );

  assert.equal(result.ok, false);
  assert.equal(result.reason, "too_large");
});

test("still parses a legitimate multipart request below the product limit", async () => {
  const formData = new FormData();
  formData.append("baseline", new File([new Uint8Array([1, 2, 3])], "baseline.jpg", {
    type: "image/jpeg",
  }));
  formData.append("current", new File([new Uint8Array([4, 5, 6])], "current.jpg", {
    type: "image/jpeg",
  }));

  const result = await parseRequestFormData(
    new Request("https://checkback.example/api/analyze", {
      method: "POST",
      body: formData,
    }),
    MAX_ANALYSIS_FORM_BYTES,
  );

  assert.equal(result.ok, true);
  assert.equal(result.formData.get("baseline")?.name, "baseline.jpg");
  assert.equal(result.formData.get("current")?.name, "current.jpg");
});

test("holds an analysis permit before parsing multipart data", async () => {
  const previousProvider = process.env.AI_VISION_PROVIDER;
  const previousKey = process.env.DASHSCOPE_API_KEY;
  process.env.AI_VISION_PROVIDER = "qwen";
  process.env.DASHSCOPE_API_KEY = "test-only-key";
  process.env.CHECKBACK_RATE_LIMIT = "20";
  process.env.CHECKBACK_DAILY_LIMIT = "20";
  process.env.CHECKBACK_MAX_CONCURRENT = "1";

  const held = acquireAnalysisPermit(
    new Request("https://checkback.example/api/analyze", {
      headers: { "x-real-ip": "203.0.113.30" },
    }),
  );
  assert.equal(held.ok, true);

  let formDataCalls = 0;
  const blockedRequest = new Request("https://checkback.example/api/analyze", {
    method: "POST",
    headers: { "x-real-ip": "203.0.113.31" },
  });
  Object.defineProperty(blockedRequest, "formData", {
    value: async () => {
      formDataCalls += 1;
      return new FormData();
    },
  });

  try {
    const response = await dispatch(blockedRequest);
    const body = await response.json();

    assert.equal(response.status, 429);
    assert.equal(body.code, "CONCURRENCY_LIMIT");
    assert.equal(formDataCalls, 0);
  } finally {
    held.release();
    if (previousProvider === undefined) delete process.env.AI_VISION_PROVIDER;
    else process.env.AI_VISION_PROVIDER = previousProvider;
    if (previousKey === undefined) delete process.env.DASHSCOPE_API_KEY;
    else process.env.DASHSCOPE_API_KEY = previousKey;
  }
});
