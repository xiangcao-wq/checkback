import { createHash } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import OpenAI from "openai";
import sharp from "sharp";
import {
  analyzeImagePair,
  verifyMissingCandidates,
} from "../app/lib/vision-provider.ts";
import {
  CHECKBACK_VERIFIER_PROMPT_SHA256,
  CHECKBACK_VERIFIER_PROMPT_VERSION,
  DEFAULT_QWEN_FAST_VERIFICATION_TIMEOUT_MS,
  DEFAULT_QWEN_MAX_RETRIES,
  DEFAULT_QWEN_PRIMARY_TIMEOUT_MS,
  DEFAULT_QWEN_VERIFICATION_FALLBACK_TIMEOUT_MS,
} from "../app/lib/qwen-model-config.ts";
import {
  PILOT_FLASH_MODEL,
  PILOT_PLUS_MODEL,
  assertPilotReserveLeavesRedLine,
  createPilotReservation,
  createPilotSettlement,
  summarizePilotTokenEvents,
} from "../evaluation/pilot/token-budget.ts";

const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PILOT_ROOT = resolve(
  WEB_ROOT,
  ".shadow-private",
  "mvtec-loco",
  "pilot",
);
const MANIFEST_PATH = resolve(PILOT_ROOT, "pilot-manifest.json");
const RUN_ROOT = resolve(PILOT_ROOT, "live-run-v1");
const TOKEN_LEDGER_PATH = resolve(RUN_ROOT, "token-ledger.jsonl");
const RESULTS_PATH = resolve(RUN_ROOT, "results.jsonl");
const ENV_PATH = resolve(WEB_ROOT, ".env.local");
const PINNED_QWEN_BASE_URL =
  "https://llm-2th4ful6vems5zkd.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_PREPARED_BYTES = 430 * 1024;
const MAX_INPUT_PIXELS = 32_000_000;
const NATIVE_FETCH = globalThis.fetch.bind(globalThis);

const { values } = parseArgs({
  options: {
    "dry-run": { type: "boolean", default: false },
    execute: { type: "boolean", default: false },
    "allow-settled-case-retry": { type: "boolean", default: false },
    "max-cases": { type: "string", default: "1" },
  },
  strict: true,
});

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function round(value) {
  return Math.round(value * 10) / 10;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function collectSafeErrorCandidates(error, depth = 0, output = []) {
  if (depth > 3 || typeof error !== "object" || error === null) return output;
  if ("code" in error && ["string", "number"].includes(typeof error.code)) {
    output.push(String(error.code));
  }
  if (error instanceof Error) output.push(error.message);
  if ("cause" in error) collectSafeErrorCandidates(error.cause, depth + 1, output);
  return output;
}

function safeError(error) {
  const code = collectSafeErrorCandidates(error).find((value) =>
    /^[a-z0-9_.:-]{1,128}$/i.test(value),
  );
  const status =
    typeof error === "object" && error !== null && "status" in error
      ? Number(error.status) || null
      : null;
  return {
    name: error instanceof Error ? error.name : "UnknownError",
    code: code || "pilot_unclassified_error",
    status,
  };
}

function parsePositiveInteger(value, code) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) fail(code);
  return parsed;
}

function readJson(path, maxBytes) {
  const bytes = readFileSync(path);
  try {
    if (bytes.byteLength < 2 || bytes.byteLength > maxBytes) {
      fail("pilot_json_size_invalid");
    }
    return JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
  }
}

function readJsonLines(path, maxBytes) {
  if (!existsSync(path)) return [];
  const bytes = readFileSync(path);
  try {
    if (bytes.byteLength > maxBytes) fail("pilot_jsonl_size_invalid");
    const text = bytes.toString("utf8");
    if (text && !text.endsWith("\n")) fail("pilot_jsonl_truncated");
    return text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } finally {
    bytes.fill(0);
  }
}

function appendJsonLine(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const line = Buffer.from(JSON.stringify(value) + "\n", "utf8");
  const descriptor = openSync(path, "a", 0o600);
  try {
    appendFileSync(descriptor, line);
    fsyncSync(descriptor);
  } finally {
    line.fill(0);
    closeSync(descriptor);
  }
}

function loadQwenConfiguration() {
  const bytes = readFileSync(ENV_PATH);
  try {
    if (bytes.byteLength > 64 * 1024) fail("pilot_env_file_too_large");
    const required = new Map();
    for (const rawLine of bytes.toString("utf8").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const match = /^([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
      if (!match) continue;
      const name = match[1];
      if (!['DASHSCOPE_API_KEY', 'DASHSCOPE_BASE_URL'].includes(name)) continue;
      if (required.has(name)) fail("pilot_qwen_configuration_duplicate");
      let value = match[2].trim();
      if (
        value.length >= 2 &&
        ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'")))
      ) {
        value = value.slice(1, -1);
      }
      required.set(name, value);
    }
    const apiKey = required.get("DASHSCOPE_API_KEY");
    const baseURL = required.get("DASHSCOPE_BASE_URL");
    if (
      typeof apiKey !== "string" ||
      apiKey.length < 40 ||
      apiKey.length > 512 ||
      /[\r\n\0]/.test(apiKey) ||
      baseURL !== PINNED_QWEN_BASE_URL
    ) {
      fail("pilot_qwen_configuration_invalid");
    }
    return { apiKey, baseURL };
  } finally {
    bytes.fill(0);
  }
}

function validateManifest(value) {
  if (
    value?.schema_version !==
      "checkback.mvtec-end-to-end-pilot-manifest.v1" ||
    value.asset_revision !== "464875d33af84257cac350ebcf2c4210343f85a3" ||
    value.source_license !== "CC-BY-NC-SA-4.0" ||
    value.noncommercial_evaluation_only !== true ||
    value.preprocessing_policy !== "checkback-mobile-1600px-430k-v1" ||
    !Array.isArray(value.cases) ||
    value.cases.length !== 60 ||
    !Array.isArray(value.assets) ||
    value.assets.length !== 65
  ) {
    fail("pilot_manifest_contract_invalid");
  }
  const assets = new Map();
  for (const asset of value.assets) {
    if (
      !/^asset-[0-9]{4}$/.test(asset?.asset_id) ||
      !/^assets\/asset-[0-9]{4}\.png$/.test(asset.local_relpath) ||
      !/^[a-f0-9]{64}$/.test(asset.sha256) ||
      !Number.isInteger(asset.expected_bytes) ||
      asset.expected_bytes < 1 ||
      asset.expected_bytes > MAX_SOURCE_BYTES ||
      assets.has(asset.asset_id)
    ) {
      fail("pilot_manifest_asset_invalid");
    }
    assets.set(asset.asset_id, asset);
  }
  const caseIds = new Set();
  for (const item of value.cases) {
    if (
      !/^case-[0-9]{4}$/.test(item?.case_id) ||
      !/^scene-[0-9]{4}$/.test(item.scene_id) ||
      !["observable_missing", "hard_negative", "not_comparable"].includes(
        item.truth_class,
      ) ||
      !["none", "blur", "occlusion", "crop", "darkness"].includes(
        item.current_transform,
      ) ||
      !assets.has(item.baseline_asset_id) ||
      !assets.has(item.current_asset_id) ||
      caseIds.has(item.case_id)
    ) {
      fail("pilot_manifest_case_invalid");
    }
    caseIds.add(item.case_id);
  }
  return { manifest: value, assets };
}

function validateExistingResults(results, manifest) {
  const caseIds = new Set(manifest.cases.map((item) => item.case_id));
  const completed = new Set();
  for (const result of results) {
    if (
      result?.schema_version !== "checkback.mvtec-pilot-result.v1" ||
      !caseIds.has(result.case_id) ||
      completed.has(result.case_id) ||
      typeof result.case_pass !== "boolean" ||
      !Array.isArray(result.calls) ||
      result.calls.length < 1 ||
      result.calls.length > 3
    ) {
      fail("pilot_existing_result_invalid");
    }
    completed.add(result.case_id);
  }
  return completed;
}

class TokenStore {
  constructor(events, persist) {
    this.events = events;
    this.persist = persist;
    assertPilotReserveLeavesRedLine(this.events);
  }

  reserve(caseId, slot, attempt) {
    const event = createPilotReservation(this.events, {
      case_id: caseId,
      slot,
      attempt,
    });
    if (this.persist) appendJsonLine(TOKEN_LEDGER_PATH, event);
    this.events.push(event);
    assertPilotReserveLeavesRedLine(this.events);
    return event;
  }

  settle(callId, usage) {
    const event = createPilotSettlement(this.events, {
      call_id: callId,
      prompt_tokens: usage.prompt_tokens,
      completion_tokens: usage.completion_tokens,
      total_tokens: usage.total_tokens,
    });
    if (this.persist) appendJsonLine(TOKEN_LEDGER_PATH, event);
    this.events.push(event);
    return assertPilotReserveLeavesRedLine(this.events);
  }

  summary() {
    return assertPilotReserveLeavesRedLine(this.events);
  }
}

function assetPath(asset) {
  const path = resolve(PILOT_ROOT, asset.local_relpath);
  const assetRoot = resolve(PILOT_ROOT, "assets");
  if (!path.startsWith(assetRoot + "\\")) fail("pilot_asset_path_outside_cache");
  return path;
}

async function prepareAsset(asset, transform) {
  const startedAt = performance.now();
  const source = readFileSync(assetPath(asset));
  try {
    if (
      source.byteLength !== asset.expected_bytes ||
      sha256(source) !== asset.sha256
    ) {
      fail("pilot_asset_integrity_mismatch");
    }
    const metadata = await sharp(source, {
      failOn: "error",
      limitInputPixels: MAX_INPUT_PIXELS,
      sequentialRead: true,
    }).metadata();
    if (
      metadata.format !== "png" ||
      !metadata.width ||
      !metadata.height ||
      metadata.width * metadata.height > MAX_INPUT_PIXELS
    ) {
      fail("pilot_asset_dimensions_invalid");
    }

    let maxSide = 1600;
    let quality = 82;
    for (let attempt = 0; attempt < 9; attempt += 1) {
      let sourceWidth = metadata.width;
      const sourceHeight = metadata.height;
      let pipeline = sharp(source, {
        failOn: "error",
        limitInputPixels: MAX_INPUT_PIXELS,
        sequentialRead: true,
      }).rotate();
      if (transform === "crop") {
        sourceWidth = Math.max(1, Math.floor(sourceWidth * 0.48));
        pipeline = pipeline.extract({
          left: 0,
          top: 0,
          width: sourceWidth,
          height: sourceHeight,
        });
      } else if (transform === "blur") {
        pipeline = pipeline.blur(20);
      } else if (transform === "darkness") {
        pipeline = pipeline.modulate({ brightness: 0.08 }).blur(2);
      }
      const scale = Math.min(1, maxSide / Math.max(sourceWidth, sourceHeight));
      const width = Math.max(1, Math.round(sourceWidth * scale));
      const height = Math.max(1, Math.round(sourceHeight * scale));
      pipeline = pipeline.resize(width, height, { fit: "fill" });
      let overlay;
      if (transform === "occlusion") {
        const overlayWidth = Math.max(1, Math.round(width * 0.72));
        const overlayHeight = Math.max(1, Math.round(height * 0.72));
        overlay = await sharp({
          create: {
            width: overlayWidth,
            height: overlayHeight,
            channels: 3,
            background: "#6b7280",
          },
        })
          .png()
          .toBuffer();
        pipeline = pipeline.composite([
          {
            input: overlay,
            left: Math.round((width - overlayWidth) / 2),
            top: Math.round((height - overlayHeight) / 2),
          },
        ]);
      }
      const prepared = await pipeline
        .jpeg({
          quality,
          chromaSubsampling: "4:2:0",
          progressive: false,
          optimizeCoding: true,
        })
        .toBuffer();
      overlay?.fill(0);
      if (prepared.byteLength <= MAX_PREPARED_BYTES) {
        const outputMetadata = await sharp(prepared).metadata();
        if (
          outputMetadata.format !== "jpeg" ||
          outputMetadata.exif ||
          outputMetadata.icc ||
          outputMetadata.iptc ||
          outputMetadata.xmp
        ) {
          prepared.fill(0);
          fail("pilot_prepared_image_invalid");
        }
        return {
          buffer: prepared,
          dataUrl: "data:image/jpeg;base64," + prepared.toString("base64"),
          sha256: sha256(prepared),
          bytes: prepared.byteLength,
          width: outputMetadata.width,
          height: outputMetadata.height,
          preprocessing_ms: round(performance.now() - startedAt),
        };
      }
      prepared.fill(0);
      if (quality > 58) quality -= 8;
      else {
        maxSide = Math.round(maxSide * 0.8);
        quality = 72;
      }
    }
    fail("pilot_prepared_image_too_large");
  } finally {
    source.fill(0);
  }
}

function collectDataUrls(value, output = []) {
  if (typeof value === "string") {
    if (value.startsWith("data:")) output.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectDataUrls(item, output);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectDataUrls(item, output);
  }
  return output;
}

function validateEmbeddedImage(dataUrl, expected) {
  const prefix = "data:image/jpeg;base64,";
  if (typeof dataUrl !== "string" || !dataUrl.startsWith(prefix)) {
    fail("pilot_request_image_type_invalid");
  }
  const encoded = dataUrl.slice(prefix.length);
  const decoded = Buffer.from(encoded, "base64");
  try {
    if (
      decoded.byteLength !== expected.bytes ||
      sha256(decoded) !== expected.sha256 ||
      decoded.toString("base64") !== encoded
    ) {
      fail("pilot_request_image_mismatch");
    }
  } finally {
    decoded.fill(0);
  }
}

function requestSlot(body) {
  if (body.model === PILOT_PLUS_MODEL && body.max_tokens === 4000) {
    return "primary";
  }
  if (body.model === PILOT_FLASH_MODEL && body.max_tokens === 2200) {
    return "flash";
  }
  if (body.model === PILOT_PLUS_MODEL && body.max_tokens === 2200) {
    return "plus";
  }
  fail("pilot_request_model_or_slot_invalid");
}

function verifierDecisions(completion) {
  const content = completion?.choices?.[0]?.message?.content;
  if (typeof content !== "string") return null;
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed?.verifications)) return null;
  const allowedVerdicts = new Set([
    "confirmed_missing",
    "visible_same_place",
    "visible_elsewhere",
    "not_comparable",
  ]);
  const allowedCertainty = new Set(["high", "medium", "low"]);
  const decisions = [];
  for (const item of parsed.verifications) {
    if (
      typeof item?.id !== "string" ||
      !allowedVerdicts.has(item.verdict) ||
      !allowedCertainty.has(item.certainty)
    ) {
      return null;
    }
    decisions.push({
      id: item.id,
      verdict: item.verdict,
      certainty: item.certainty,
      current_location_present:
        typeof item.current_location === "string" &&
        item.current_location.trim().length > 0,
    });
  }
  return decisions;
}

function fakeCompletion(slot, truthClass) {
  let content;
  if (slot === "primary") {
    const missing = truthClass === "observable_missing";
    const difficult = truthClass === "not_comparable";
    content = JSON.stringify({
      scene: {
        match: difficult ? "possible" : "same",
        overlap: difficult ? "low" : "high",
        reason: "offline rehearsal",
      },
      quality_issues: difficult
        ? [
            {
              type: "framing",
              severity: "blocking",
              message: "offline rehearsal",
            },
          ]
        : [],
      changes: missing
        ? [
            {
              id: "candidate-0001",
              label: "fixture item",
              type: "missing",
              certainty: "high",
              baseline_location: "reference region",
              current_location: null,
              baseline_visible: true,
              expected_region_visible: true,
              evidence: "offline rehearsal",
              action: "offline rehearsal",
            },
          ]
        : [],
      checked_item_count: missing ? 1 : 0,
      summary: "offline rehearsal",
    });
  } else {
    content = JSON.stringify({
      verifications: [
        {
          id: "candidate-0001",
          verdict: "confirmed_missing",
          certainty: "high",
          current_location: null,
          evidence: "offline rehearsal",
        },
      ],
    });
  }
  const promptTokens = slot === "primary" ? 4_800 : 4_300;
  const completionTokens = 200;
  return {
    id: "offline-rehearsal",
    object: "chat.completion",
    created: 0,
    model: slot === "flash" ? PILOT_FLASH_MODEL : PILOT_PLUS_MODEL,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens,
    },
  };
}

function createPilotFetch({
  apiKey,
  baseURL,
  caseItem,
  expectedImages,
  tokenStore,
  callRecords,
  dryRun,
  attempt,
}) {
  const endpoint = baseURL.replace(/\/$/, "") + "/chat/completions";
  return async (input, init) => {
    const webRequest = new Request(input, init);
    const bodyBytes = Buffer.from(await webRequest.arrayBuffer());
    let responseBytes;
    try {
      if (
        webRequest.url !== endpoint ||
        webRequest.method !== "POST" ||
        webRequest.headers.get("authorization") !== `Bearer ${apiKey}` ||
        webRequest.headers.get("content-type") !== "application/json" ||
        bodyBytes.byteLength < 2 ||
        bodyBytes.byteLength > MAX_REQUEST_BYTES
      ) {
        fail("pilot_request_transport_invalid");
      }
      const keyBytes = Buffer.from(apiKey, "utf8");
      try {
        if (bodyBytes.indexOf(keyBytes) !== -1) {
          fail("pilot_credential_in_request_body");
        }
      } finally {
        keyBytes.fill(0);
      }
      let body;
      try {
        body = JSON.parse(bodyBytes.toString("utf8"));
      } catch {
        fail("pilot_request_json_invalid");
      }
      const slot = requestSlot(body);
      const expectedSlot = ["primary", "flash", "plus"][callRecords.length];
      if (
        slot !== expectedSlot ||
        body.response_format?.type !== "json_object" ||
        body.enable_thinking !== false ||
        body.vl_high_resolution_images !== true ||
        !Array.isArray(body.messages) ||
        body.messages.length !== 2
      ) {
        fail("pilot_request_shape_invalid");
      }
      const images = collectDataUrls(body);
      if (images.length !== 2) fail("pilot_request_image_count_invalid");
      validateEmbeddedImage(images[0], expectedImages[0]);
      validateEmbeddedImage(images[1], expectedImages[1]);

      const reservation = tokenStore.reserve(caseItem.case_id, slot, attempt);
      const startedAt = performance.now();
      let status;
      let responseHeaders;
      if (dryRun) {
        responseBytes = Buffer.from(
          JSON.stringify(fakeCompletion(slot, caseItem.truth_class)),
          "utf8",
        );
        status = 200;
        responseHeaders = new Headers({ "content-type": "application/json" });
      } else {
        const nativeResponse = await NATIVE_FETCH(webRequest.url, {
          method: "POST",
          headers: webRequest.headers,
          body: bodyBytes,
          redirect: "error",
          signal: webRequest.signal,
        });
        status = nativeResponse.status;
        const declaredLength = Number(nativeResponse.headers.get("content-length"));
        if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
          fail("pilot_response_too_large");
        }
        responseBytes = Buffer.from(await nativeResponse.arrayBuffer());
        responseHeaders = new Headers(nativeResponse.headers);
      }
      if (
        status !== 200 ||
        responseBytes.byteLength < 2 ||
        responseBytes.byteLength > MAX_RESPONSE_BYTES
      ) {
        fail("pilot_provider_response_invalid");
      }
      let completion;
      try {
        completion = JSON.parse(responseBytes.toString("utf8"));
      } catch {
        fail("pilot_provider_response_json_invalid");
      }
      const usage = {
        prompt_tokens: parsePositiveInteger(
          completion?.usage?.prompt_tokens,
          "pilot_prompt_tokens_missing",
        ),
        completion_tokens: parsePositiveInteger(
          completion?.usage?.completion_tokens,
          "pilot_completion_tokens_missing",
        ),
        total_tokens: parsePositiveInteger(
          completion?.usage?.total_tokens,
          "pilot_total_tokens_missing",
        ),
      };
      tokenStore.settle(reservation.call_id, usage);
      callRecords.push({
        slot,
        model_tier: slot === "flash" ? "flash" : "plus",
        model: slot === "flash" ? PILOT_FLASH_MODEL : PILOT_PLUS_MODEL,
        latency_ms: round(performance.now() - startedAt),
        request_bytes: bodyBytes.byteLength,
        response_bytes: responseBytes.byteLength,
        status,
        ...usage,
        verifier_decisions:
          slot === "primary" ? null : verifierDecisions(completion),
      });

      responseHeaders.delete("content-encoding");
      responseHeaders.delete("content-length");
      const response = new Response(responseBytes, {
        status,
        headers: responseHeaders,
      });
      return response;
    } finally {
      bodyBytes.fill(0);
      responseBytes?.fill(0);
    }
  };
}

function sanitizeDecisions(record, candidateMap) {
  if (!record) return null;
  if (!Array.isArray(record.verifier_decisions)) return null;
  return record.verifier_decisions.map((decision) => {
    const anonymousId = candidateMap.get(decision.id);
    if (!anonymousId) fail("pilot_verifier_candidate_id_mismatch");
    return {
      id: anonymousId,
      verdict: decision.verdict,
      certainty: decision.certainty,
      current_location_present: decision.current_location_present,
    };
  });
}

function verdictCounts(decisions) {
  const counts = {
    confirmed_missing: 0,
    visible_same_place: 0,
    visible_elsewhere: 0,
    not_comparable: 0,
  };
  for (const decision of decisions ?? []) counts[decision.verdict] += 1;
  return counts;
}

async function runCase({
  caseItem,
  assets,
  tokenStore,
  apiKey,
  baseURL,
  dryRun,
  attempt,
}) {
  const caseStartedAt = performance.now();
  const baselineAsset = assets.get(caseItem.baseline_asset_id);
  const currentAsset = assets.get(caseItem.current_asset_id);
  if (!baselineAsset || !currentAsset) fail("pilot_case_asset_missing");
  let baseline;
  let current;
  try {
    baseline = await prepareAsset(baselineAsset, "none");
    current = await prepareAsset(currentAsset, caseItem.current_transform);
    const callRecords = [];
    const client = new OpenAI({
      apiKey,
      baseURL,
      maxRetries: DEFAULT_QWEN_MAX_RETRIES,
      timeout: DEFAULT_QWEN_PRIMARY_TIMEOUT_MS,
      logLevel: "off",
      fetch: createPilotFetch({
        apiKey,
        baseURL,
        caseItem,
        expectedImages: [baseline, current],
        tokenStore,
        callRecords,
        dryRun,
        attempt,
      }),
    });
    const runtime = {
      provider: "qwen",
      model: PILOT_PLUS_MODEL,
      client,
      qwenVerification: {
        mode: "shadow",
        fastModel: PILOT_FLASH_MODEL,
        fallbackModel: PILOT_PLUS_MODEL,
        promptVersion: CHECKBACK_VERIFIER_PROMPT_VERSION,
        promptSha256: CHECKBACK_VERIFIER_PROMPT_SHA256,
        fastTimeoutMs: DEFAULT_QWEN_FAST_VERIFICATION_TIMEOUT_MS,
        fallbackTimeoutMs: DEFAULT_QWEN_VERIFICATION_FALLBACK_TIMEOUT_MS,
      },
    };
    const primary = await analyzeImagePair(
      runtime,
      baseline.dataUrl,
      current.dataUrl,
    );
    if (!primary) fail("pilot_primary_schema_invalid");
    const candidates = primary.changes.filter(
      (change) =>
        change.type === "missing" &&
        change.certainty === "high" &&
        change.baseline_visible &&
        change.expected_region_visible,
    );
    const verification = await verifyMissingCandidates(
      runtime,
      baseline.dataUrl,
      current.dataUrl,
      primary,
    );
    const expectedCalls = candidates.length > 0 ? 3 : 1;
    if (
      callRecords.length !== expectedCalls ||
      verification.diagnostics.provider_calls !== expectedCalls - 1
    ) {
      fail("pilot_provider_call_contract_invalid");
    }
    const candidateMap = new Map(
      candidates.map((candidate, index) => [
        candidate.id,
        `item-${String(index + 1).padStart(4, "0")}`,
      ]),
    );
    const flashRecord = callRecords.find((record) => record.slot === "flash");
    const plusRecord = callRecords.find((record) => record.slot === "plus");
    const flashDecisions = sanitizeDecisions(flashRecord, candidateMap);
    const plusDecisions = sanitizeDecisions(plusRecord, candidateMap);
    if (candidates.length > 0 && (!flashDecisions || !plusDecisions)) {
      fail("pilot_verifier_schema_capture_invalid");
    }
    const flashCounts = verdictCounts(flashDecisions);
    const plusCounts = verdictCounts(plusDecisions);
    const publicMissingCount = plusCounts.confirmed_missing;
    let safetyStopReason = null;
    if (
      verification.diagnostics.path === "qwen_unresolved" ||
      (candidates.length > 0 && verification.verification === null)
    ) {
      safetyStopReason = "verification_unresolved";
    } else if (
      caseItem.truth_class === "observable_missing" &&
      publicMissingCount < 1
    ) {
      safetyStopReason = "missed_known_missing";
    } else if (
      caseItem.truth_class !== "observable_missing" &&
      publicMissingCount > 0
    ) {
      safetyStopReason = "false_missing_safe_path";
    } else if (
      caseItem.truth_class !== "observable_missing" &&
      verification.diagnostics.active_fast_eligible === true
    ) {
      safetyStopReason = "false_missing_fast_path";
    }
    const primaryRecord = callRecords.find((record) => record.slot === "primary");
    const actualShadowMs = callRecords.reduce(
      (total, record) => total + record.latency_ms,
      0,
    );
    const safePathMs =
      (primaryRecord?.latency_ms ?? 0) + (plusRecord?.latency_ms ?? 0);
    const simulatedActiveMs =
      candidates.length === 0
        ? primaryRecord?.latency_ms ?? 0
        : verification.diagnostics.active_fast_eligible
          ? (primaryRecord?.latency_ms ?? 0) + (flashRecord?.latency_ms ?? 0)
          : actualShadowMs;
    const sanitizedCalls = callRecords.map((record) => ({
      slot: record.slot,
      model_tier: record.model_tier,
      model: record.model,
      latency_ms: record.latency_ms,
      request_bytes: record.request_bytes,
      response_bytes: record.response_bytes,
      status: record.status,
      prompt_tokens: record.prompt_tokens,
      completion_tokens: record.completion_tokens,
      total_tokens: record.total_tokens,
    }));
    return {
      schema_version: "checkback.mvtec-pilot-result.v1",
      case_id: caseItem.case_id,
      attempt,
      scene_id: caseItem.scene_id,
      category: caseItem.category,
      truth_class: caseItem.truth_class,
      current_transform: caseItem.current_transform,
      case_pass: safetyStopReason === null,
      safety_stop_reason: safetyStopReason,
      images: {
        baseline_bytes: baseline.bytes,
        current_bytes: current.bytes,
        baseline_width: baseline.width,
        baseline_height: baseline.height,
        current_width: current.width,
        current_height: current.height,
      },
      primary: {
        scene_match: primary.scene.match,
        overlap: primary.scene.overlap,
        quality_blocking_count: primary.quality_issues.filter(
          (issue) => issue.severity === "blocking",
        ).length,
        change_count: primary.changes.length,
        high_missing_candidate_count: candidates.length,
      },
      verification: {
        path: verification.diagnostics.path,
        shadow_agreement: verification.diagnostics.shadow_agreement,
        active_fast_eligible:
          verification.diagnostics.active_fast_eligible,
        active_fallback_reason:
          verification.diagnostics.active_fallback_reason ?? null,
        terminal_reason: verification.diagnostics.terminal_reason ?? null,
        flash_counts: flashCounts,
        plus_counts: plusCounts,
        flash_decisions: flashDecisions,
        plus_decisions: plusDecisions,
      },
      timings: {
        preprocessing_ms: round(
          baseline.preprocessing_ms + current.preprocessing_ms,
        ),
        actual_shadow_model_ms: round(actualShadowMs),
        current_safe_model_ms: round(safePathMs),
        simulated_active_model_ms: round(simulatedActiveMs),
        case_total_ms: round(performance.now() - caseStartedAt),
      },
      calls: sanitizedCalls,
    };
  } finally {
    if (baseline) {
      baseline.buffer.fill(0);
      baseline.dataUrl = "";
    }
    if (current) {
      current.buffer.fill(0);
      current.dataUrl = "";
    }
  }
}

async function main() {
  if (values["dry-run"] === values.execute) {
    fail("pilot_choose_exactly_one_mode");
  }
  const maxCases = parsePositiveInteger(
    values["max-cases"],
    "pilot_max_cases_invalid",
  );
  if (maxCases > 15) fail("pilot_max_cases_too_large");
  const { manifest, assets } = validateManifest(
    readJson(MANIFEST_PATH, 4 * 1024 * 1024),
  );
  const dryRun = values["dry-run"];
  const priorResults = dryRun ? [] : readJsonLines(RESULTS_PATH, 4 * 1024 * 1024);
  const completed = validateExistingResults(priorResults, manifest);
  const priorStop = priorResults.find((result) => result.safety_stop_reason);
  const tokenEvents = dryRun
    ? []
    : readJsonLines(TOKEN_LEDGER_PATH, 4 * 1024 * 1024);
  const initialTokenSummary = summarizePilotTokenEvents(tokenEvents);
  if (initialTokenSummary.pending.length > 0) {
    fail("pilot_pending_call_requires_manual_stop");
  }
  if (priorStop) {
    process.stdout.write(
      JSON.stringify({
        mode: "live",
        status: "already_safety_stopped",
        stop_reason: priorStop.safety_stop_reason,
        completed_cases: completed.size,
        token_summary: initialTokenSummary,
      }) + "\n",
    );
    return;
  }
  const configuration = dryRun
    ? { apiKey: "offline-rehearsal-key-000000000000000000000000", baseURL: PINNED_QWEN_BASE_URL }
    : loadQwenConfiguration();
  const tokenStore = new TokenStore(tokenEvents, !dryRun);
  const pendingCases = manifest.cases
    .filter((item) => !completed.has(item.case_id))
    .slice(0, maxCases);
  const invocationResults = [];
  let stopReason = null;
  for (const caseItem of pendingCases) {
    const priorAttempts = tokenEvents
      .filter(
        (event) =>
          event.event === "reserve" && event.case_id === caseItem.case_id,
      )
      .map((event) => event.attempt ?? 1);
    const attempt =
      priorAttempts.length === 0 ? 1 : Math.max(...priorAttempts) + 1;
    if (attempt > 1 && !values["allow-settled-case-retry"]) {
      fail("pilot_settled_case_retry_requires_flag");
    }
    const result = await runCase({
      caseItem,
      assets,
      tokenStore,
      apiKey: configuration.apiKey,
      baseURL: configuration.baseURL,
      dryRun,
      attempt,
    });
    invocationResults.push(result);
    if (!dryRun) appendJsonLine(RESULTS_PATH, result);
    if (result.safety_stop_reason) {
      stopReason = result.safety_stop_reason;
      break;
    }
  }
  const tokenSummary = tokenStore.summary();
  process.stdout.write(
    JSON.stringify({
      mode: dryRun ? "dry_run_no_network" : "live",
      status: stopReason ? "safety_stopped" : "batch_complete",
      processed_cases: invocationResults.length,
      completed_cases: dryRun
        ? invocationResults.length
        : completed.size + invocationResults.length,
      provider_calls: invocationResults.reduce(
        (total, result) => total + result.calls.length,
        0,
      ),
      stop_reason: stopReason,
      token_summary: tokenSummary,
    }) + "\n",
  );
}

await main().catch((error) => {
  const tokenEvents = existsSync(TOKEN_LEDGER_PATH)
    ? readJsonLines(TOKEN_LEDGER_PATH, 4 * 1024 * 1024)
    : [];
  let tokenSummary = null;
  try {
    tokenSummary = summarizePilotTokenEvents(tokenEvents);
  } catch {
    tokenSummary = { ledger_valid: false };
  }
  process.stderr.write(
    JSON.stringify({
      success: false,
      error: safeError(error),
      token_summary: tokenSummary,
    }) + "\n",
  );
  process.exitCode = 1;
});
