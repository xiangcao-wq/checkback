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
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import OpenAI from "openai";
import sharp from "sharp";
import {
  analyzeImagePairWithScout,
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
  CHECKBACK_MISSING_SCOUT_PROMPT_VERSION,
  MISSING_SCOUT_MAX_TOKENS,
} from "../app/lib/qwen-missing-scout.ts";
import { QWEN_VERIFIER_MAX_TOKENS } from "../app/lib/qwen-verifier-prompt.ts";
import { validateVerificationCandidates } from "../app/lib/verification-policy.ts";
import {
  ADAPTIVE_FLASH_MODEL,
  ADAPTIVE_PLUS_MODEL,
  createAdaptiveFinalReservation,
  createAdaptiveInitialReservations,
  createAdaptiveSettlement,
  summarizeAdaptiveTokenEvents,
} from "../evaluation/pilot/adaptive-token-budget.ts";
import {
  QWEN_PRICING_CHECKED_DATE,
  QWEN_PRICING_CURRENCY,
  QWEN_PRICING_SOURCE_URL,
  estimateQwenCallCost,
} from "../evaluation/pilot/model-pricing.ts";
import { summarizePilotTokenEvents } from "../evaluation/pilot/token-budget.ts";

const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PILOT_ROOT = resolve(WEB_ROOT, ".shadow-private", "mvtec-loco", "pilot");
const ASSET_ROOT = resolve(PILOT_ROOT, "assets");
const MANIFEST_PATH = resolve(PILOT_ROOT, "pilot-manifest.json");
const PHASE22_LEDGER_PATH = resolve(PILOT_ROOT, "live-run-v1", "token-ledger.jsonl");
const FIRST_ADAPTIVE_RUN_ROOT = resolve(PILOT_ROOT, "adaptive-live-run-v1");
const FIRST_ADAPTIVE_TOKEN_LEDGER_PATH = resolve(
  FIRST_ADAPTIVE_RUN_ROOT,
  "token-ledger.jsonl",
);
const FIRST_ADAPTIVE_RESULTS_PATH = resolve(
  FIRST_ADAPTIVE_RUN_ROOT,
  "results.jsonl",
);
const RUN_ROOT = resolve(PILOT_ROOT, "adaptive-live-run-v2");
const TOKEN_LEDGER_PATH = resolve(RUN_ROOT, "token-ledger.jsonl");
const RESULTS_PATH = resolve(RUN_ROOT, "results.jsonl");
const ENV_PATH = resolve(WEB_ROOT, ".env.local");
const PINNED_QWEN_BASE_URL =
  "https://llm-2th4ful6vems5zkd.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";
const PINNED_ASSET_REVISION = "464875d33af84257cac350ebcf2c4210343f85a3";
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_PREPARED_BYTES = 430 * 1024;
const MAX_INPUT_PIXELS = 32_000_000;
const NATIVE_FETCH = globalThis.fetch.bind(globalThis);

const SELECTED_CASES = [
  {
    case_id: "case-0022",
    scene_id: "scene-0022",
    category: "pushpins",
    truth_class: "observable_missing",
    baseline_asset_id: "asset-0027",
    current_asset_id: "asset-0033",
    current_transform: "none",
  },
  {
    case_id: "case-0008",
    scene_id: "scene-0008",
    category: "pushpins",
    truth_class: "hard_negative",
    baseline_asset_id: "asset-0027",
    current_asset_id: "asset-0028",
    current_transform: "none",
  },
  {
    case_id: "case-0014",
    scene_id: "scene-0014",
    category: "splicing_connectors",
    truth_class: "hard_negative",
    baseline_asset_id: "asset-0053",
    current_asset_id: "asset-0054",
    current_transform: "none",
  },
];

const { values } = parseArgs({
  options: {
    "dry-run": { type: "boolean", default: false },
    execute: { type: "boolean", default: false },
    "confirm-phase23-retest": { type: "boolean", default: false },
  },
  strict: true,
});

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function round(value, digits = 1) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function safeError(error) {
  const candidates = [];
  let current = error;
  for (let depth = 0; depth < 4 && current; depth += 1) {
    if (typeof current === "object" && "code" in current) {
      candidates.push(String(current.code));
    }
    if (current instanceof Error) candidates.push(current.message);
    current = typeof current === "object" && "cause" in current ? current.cause : null;
  }
  return {
    name: error instanceof Error ? error.name : "UnknownError",
    code:
      candidates.find((item) => /^[a-z0-9_.:-]{1,128}$/i.test(item)) ??
      "adaptive_pilot_unclassified_error",
  };
}

function positiveInteger(value, code) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) fail(code);
  return parsed;
}

function readJson(path, maxBytes) {
  const bytes = readFileSync(path);
  try {
    if (bytes.byteLength < 2 || bytes.byteLength > maxBytes) {
      fail("adaptive_pilot_json_size_invalid");
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
    if (bytes.byteLength > maxBytes) fail("adaptive_pilot_jsonl_size_invalid");
    const text = bytes.toString("utf8");
    if (text && !text.endsWith("\n")) fail("adaptive_pilot_jsonl_truncated");
    return text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } finally {
    bytes.fill(0);
  }
}

function appendJsonLines(path, valuesToWrite) {
  mkdirSync(dirname(path), { recursive: true });
  const bytes = Buffer.from(
    valuesToWrite.map((value) => JSON.stringify(value)).join("\n") + "\n",
    "utf8",
  );
  const descriptor = openSync(path, "a", 0o600);
  try {
    appendFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    bytes.fill(0);
    closeSync(descriptor);
  }
}

function loadQwenConfiguration() {
  const bytes = readFileSync(ENV_PATH);
  try {
    if (bytes.byteLength > 64 * 1024) fail("adaptive_pilot_env_too_large");
    const required = new Map();
    for (const rawLine of bytes.toString("utf8").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const match = /^([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
      if (!match || !["DASHSCOPE_API_KEY", "DASHSCOPE_BASE_URL"].includes(match[1])) {
        continue;
      }
      if (required.has(match[1])) fail("adaptive_pilot_configuration_duplicate");
      let value = match[2].trim();
      if (
        value.length >= 2 &&
        ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'")))
      ) {
        value = value.slice(1, -1);
      }
      required.set(match[1], value);
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
      fail("adaptive_pilot_configuration_invalid");
    }
    return { apiKey, baseURL };
  } finally {
    bytes.fill(0);
  }
}

function loadSelectedManifest() {
  const manifest = readJson(MANIFEST_PATH, 4 * 1024 * 1024);
  if (
    manifest?.schema_version !== "checkback.mvtec-end-to-end-pilot-manifest.v1" ||
    manifest.asset_revision !== PINNED_ASSET_REVISION ||
    manifest.source_license !== "CC-BY-NC-SA-4.0" ||
    manifest.noncommercial_evaluation_only !== true ||
    !Array.isArray(manifest.cases) ||
    !Array.isArray(manifest.assets)
  ) {
    fail("adaptive_pilot_manifest_contract_invalid");
  }
  const assets = new Map(manifest.assets.map((asset) => [asset.asset_id, asset]));
  for (const expected of SELECTED_CASES) {
    const actual = manifest.cases.find((item) => item.case_id === expected.case_id);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      fail("adaptive_pilot_case_revision_changed");
    }
    for (const assetId of [expected.baseline_asset_id, expected.current_asset_id]) {
      const asset = assets.get(assetId);
      if (
        !asset ||
        !/^asset-[0-9]{4}$/.test(asset.asset_id) ||
        !/^assets\/asset-[0-9]{4}\.png$/.test(asset.local_relpath) ||
        !/^[a-f0-9]{64}$/.test(asset.sha256) ||
        !Number.isInteger(asset.expected_bytes) ||
        asset.expected_bytes < 1 ||
        asset.expected_bytes > MAX_SOURCE_BYTES
      ) {
        fail("adaptive_pilot_asset_contract_invalid");
      }
    }
  }
  return { assets };
}

function loadPriorUsage() {
  const phase22Events = readJsonLines(PHASE22_LEDGER_PATH, 4 * 1024 * 1024);
  const phase22Summary = summarizePilotTokenEvents(phase22Events);
  if (
    phase22Summary.event_count !== 74 ||
    phase22Summary.call_count !== 37 ||
    phase22Summary.pending.length !== 0 ||
    phase22Summary.settled.plus !== 120_167 ||
    phase22Summary.settled.flash !== 24_805
  ) {
    fail("adaptive_pilot_prior_ledger_revision_changed");
  }
  const phase22Usage = {
    plus: phase22Summary.settled.plus,
    flash: phase22Summary.settled.flash,
  };
  const firstEvents = readJsonLines(
    FIRST_ADAPTIVE_TOKEN_LEDGER_PATH,
    4 * 1024 * 1024,
  );
  const firstSummary = summarizeAdaptiveTokenEvents(
    firstEvents,
    phase22Usage,
  );
  const firstResults = readJsonLines(
    FIRST_ADAPTIVE_RESULTS_PATH,
    4 * 1024 * 1024,
  );
  if (
    firstSummary.event_count !== 6 ||
    firstSummary.call_count !== 3 ||
    firstSummary.pending.length !== 0 ||
    firstSummary.new_settled.plus !== 8_997 ||
    firstSummary.new_settled.flash !== 3_327 ||
    firstResults.length !== 1 ||
    firstResults[0]?.schema_version !== "checkback.adaptive-pilot-result.v1" ||
    firstResults[0]?.case_id !== "case-0022" ||
    firstResults[0]?.safety_stop_reason !== "verification_unresolved" ||
    !Array.isArray(firstResults[0]?.calls) ||
    firstResults[0].calls.length !== 3
  ) {
    fail("adaptive_pilot_first_run_revision_changed");
  }
  return {
    plus: firstSummary.charged_or_reserved_including_prior.plus,
    flash: firstSummary.charged_or_reserved_including_prior.flash,
  };
}

function assetPath(asset) {
  const path = resolve(PILOT_ROOT, asset.local_relpath);
  const rel = relative(ASSET_ROOT, path);
  if (!rel || rel.startsWith("..") || isAbsolute(rel)) {
    fail("adaptive_pilot_asset_path_invalid");
  }
  return path;
}

async function prepareAsset(asset) {
  const startedAt = performance.now();
  const source = readFileSync(assetPath(asset));
  try {
    if (source.byteLength !== asset.expected_bytes || sha256(source) !== asset.sha256) {
      fail("adaptive_pilot_asset_integrity_mismatch");
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
      fail("adaptive_pilot_asset_dimensions_invalid");
    }
    let maxSide = 1600;
    let quality = 82;
    for (let attempt = 0; attempt < 9; attempt += 1) {
      const scale = Math.min(1, maxSide / Math.max(metadata.width, metadata.height));
      const prepared = await sharp(source, {
        failOn: "error",
        limitInputPixels: MAX_INPUT_PIXELS,
        sequentialRead: true,
      })
        .rotate()
        .resize(
          Math.max(1, Math.round(metadata.width * scale)),
          Math.max(1, Math.round(metadata.height * scale)),
          { fit: "fill" },
        )
        .jpeg({
          quality,
          chromaSubsampling: "4:2:0",
          progressive: false,
          optimizeCoding: true,
        })
        .toBuffer();
      if (prepared.byteLength <= MAX_PREPARED_BYTES) {
        const output = await sharp(prepared).metadata();
        if (
          output.format !== "jpeg" ||
          output.exif ||
          output.icc ||
          output.iptc ||
          output.xmp
        ) {
          prepared.fill(0);
          fail("adaptive_pilot_prepared_image_invalid");
        }
        return {
          buffer: prepared,
          dataUrl: "data:image/jpeg;base64," + prepared.toString("base64"),
          sha256: sha256(prepared),
          bytes: prepared.byteLength,
          width: output.width,
          height: output.height,
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
    fail("adaptive_pilot_prepared_image_too_large");
  } finally {
    source.fill(0);
  }
}

class AdaptiveTokenStore {
  constructor(events, priorUsage, persist) {
    this.events = events;
    this.priorUsage = priorUsage;
    this.persist = persist;
    summarizeAdaptiveTokenEvents(this.events, this.priorUsage);
  }

  reserveInitial(caseId) {
    const reservations = createAdaptiveInitialReservations(
      this.events,
      this.priorUsage,
      caseId,
    );
    if (this.persist) appendJsonLines(TOKEN_LEDGER_PATH, reservations);
    this.events.push(...reservations);
    return reservations;
  }

  reserveFinal(caseId) {
    const reservation = createAdaptiveFinalReservation(
      this.events,
      this.priorUsage,
      caseId,
    );
    if (this.persist) appendJsonLines(TOKEN_LEDGER_PATH, [reservation]);
    this.events.push(reservation);
    return reservation;
  }

  settle(callId, usage) {
    const settlement = createAdaptiveSettlement(this.events, this.priorUsage, {
      call_id: callId,
      ...usage,
    });
    if (this.persist) appendJsonLines(TOKEN_LEDGER_PATH, [settlement]);
    this.events.push(settlement);
    return this.summary();
  }

  summary() {
    return summarizeAdaptiveTokenEvents(this.events, this.priorUsage);
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
    fail("adaptive_pilot_request_image_type_invalid");
  }
  const encoded = dataUrl.slice(prefix.length);
  const decoded = Buffer.from(encoded, "base64");
  try {
    if (
      decoded.byteLength !== expected.bytes ||
      sha256(decoded) !== expected.sha256 ||
      decoded.toString("base64") !== encoded
    ) {
      fail("adaptive_pilot_request_image_mismatch");
    }
  } finally {
    decoded.fill(0);
  }
}

function requestSlot(body) {
  if (body.model === ADAPTIVE_PLUS_MODEL && body.max_tokens === 4000) return "primary";
  if (
    body.model === ADAPTIVE_FLASH_MODEL &&
    body.max_tokens === MISSING_SCOUT_MAX_TOKENS
  ) {
    return "scout";
  }
  if (
    body.model === ADAPTIVE_PLUS_MODEL &&
    body.max_tokens === QWEN_VERIFIER_MAX_TOKENS
  ) {
    return "final";
  }
  fail("adaptive_pilot_request_model_or_slot_invalid");
}

function fakeCandidateIds(body) {
  const content = body.messages?.[1]?.content;
  if (!Array.isArray(content)) fail("adaptive_pilot_fake_verifier_content_invalid");
  const prefix = "Missing candidates to verify: ";
  const entry = content.find(
    (item) => typeof item?.text === "string" && item.text.startsWith(prefix),
  );
  if (!entry) fail("adaptive_pilot_fake_verifier_candidates_missing");
  const candidates = JSON.parse(entry.text.slice(prefix.length));
  if (!Array.isArray(candidates) || candidates.length < 1) {
    fail("adaptive_pilot_fake_verifier_candidates_invalid");
  }
  return candidates.map((candidate) => candidate.id);
}

function fakeCompletion(slot, truthClass, body) {
  let content;
  let promptTokens;
  let completionTokens;
  if (slot === "primary") {
    content = JSON.stringify({
      scene: { match: "same", overlap: "high", reason: "offline rehearsal" },
      quality_issues: [],
      changes: [],
      checked_item_count: 1,
      summary: "offline rehearsal",
    });
    promptTokens = 4_800;
    completionTokens = 200;
  } else if (slot === "scout") {
    content = JSON.stringify({
      comparison: "usable",
      reason: "offline rehearsal",
      candidates:
        truthClass === "observable_missing"
          ? [
              {
                label: "fixture item",
                baseline_location: "reference region",
                certainty: "high",
                baseline_visible: true,
                expected_region_visible: true,
                evidence: "offline rehearsal",
              },
            ]
          : [],
    });
    promptTokens = 4_200;
    completionTokens = 180;
  } else {
    content = JSON.stringify({
      verifications: fakeCandidateIds(body).map((id) => ({
        id,
        verdict: "confirmed_missing",
        certainty: "high",
        current_location: null,
        evidence: "offline rehearsal",
      })),
    });
    promptTokens = 4_300;
    completionTokens = 180;
  }
  return {
    id: "offline-rehearsal",
    object: "chat.completion",
    created: 0,
    model: body.model,
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

function createControlledFetch({
  apiKey,
  baseURL,
  caseItem,
  expectedImages,
  tokenStore,
  callRecords,
  dryRun,
}) {
  const endpoint = baseURL.replace(/\/$/, "") + "/chat/completions";
  const expectedSlots = new Set(["primary", "scout"]);

  const controlledFetch = async (input, init) => {
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
        fail("adaptive_pilot_request_transport_invalid");
      }
      const keyBytes = Buffer.from(apiKey, "utf8");
      try {
        if (bodyBytes.indexOf(keyBytes) !== -1) {
          fail("adaptive_pilot_credential_in_request_body");
        }
      } finally {
        keyBytes.fill(0);
      }
      let body;
      try {
        body = JSON.parse(bodyBytes.toString("utf8"));
      } catch {
        fail("adaptive_pilot_request_json_invalid");
      }
      const slot = requestSlot(body);
      if (
        !expectedSlots.delete(slot) ||
        body.response_format?.type !== "json_object" ||
        body.enable_thinking !== false ||
        body.vl_high_resolution_images !== true ||
        !Array.isArray(body.messages) ||
        body.messages.length !== 2
      ) {
        fail("adaptive_pilot_request_shape_invalid");
      }
      const images = collectDataUrls(body);
      if (images.length !== 2) fail("adaptive_pilot_request_image_count_invalid");
      validateEmbeddedImage(images[0], expectedImages[0]);
      validateEmbeddedImage(images[1], expectedImages[1]);

      const callId = `adaptive-${caseItem.case_id}-${slot}`;
      const pending = tokenStore.summary().pending;
      if (!pending.some((event) => event.call_id === callId)) {
        fail("adaptive_pilot_request_without_reservation");
      }
      const startedAt = performance.now();
      let status;
      let responseHeaders;
      if (dryRun) {
        responseBytes = Buffer.from(
          JSON.stringify(fakeCompletion(slot, caseItem.truth_class, body)),
          "utf8",
        );
        status = 200;
        responseHeaders = new Headers({ "content-type": "application/json" });
      } else {
        const response = await NATIVE_FETCH(webRequest.url, {
          method: "POST",
          headers: webRequest.headers,
          body: bodyBytes,
          redirect: "error",
          signal: webRequest.signal,
        });
        status = response.status;
        const declaredLength = Number(response.headers.get("content-length"));
        if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
          fail("adaptive_pilot_response_too_large");
        }
        responseBytes = Buffer.from(await response.arrayBuffer());
        responseHeaders = new Headers(response.headers);
      }
      if (
        status !== 200 ||
        responseBytes.byteLength < 2 ||
        responseBytes.byteLength > MAX_RESPONSE_BYTES
      ) {
        fail("adaptive_pilot_provider_response_invalid");
      }
      let completion;
      try {
        completion = JSON.parse(responseBytes.toString("utf8"));
      } catch {
        fail("adaptive_pilot_provider_response_json_invalid");
      }
      const usage = {
        prompt_tokens: positiveInteger(
          completion?.usage?.prompt_tokens,
          "adaptive_pilot_prompt_tokens_missing",
        ),
        completion_tokens: positiveInteger(
          completion?.usage?.completion_tokens,
          "adaptive_pilot_completion_tokens_missing",
        ),
        total_tokens: positiveInteger(
          completion?.usage?.total_tokens,
          "adaptive_pilot_total_tokens_missing",
        ),
      };
      tokenStore.settle(callId, usage);
      const cost = estimateQwenCallCost(body.model, usage);
      callRecords.push({
        slot,
        model_tier: slot === "scout" ? "flash" : "plus",
        model: body.model,
        latency_ms: round(performance.now() - startedAt),
        request_bytes: bodyBytes.byteLength,
        response_bytes: responseBytes.byteLength,
        status,
        ...usage,
        public_list_equivalent_cny: cost.public_list_equivalent_cny,
        current_advertised_equivalent_cny:
          cost.current_advertised_equivalent_cny,
      });

      responseHeaders.delete("content-encoding");
      responseHeaders.delete("content-length");
      return new Response(responseBytes, { status, headers: responseHeaders });
    } finally {
      bodyBytes.fill(0);
      responseBytes?.fill(0);
    }
  };

  return {
    fetch: controlledFetch,
    allowFinal() {
      if (expectedSlots.size !== 0) fail("adaptive_pilot_observers_not_complete");
      expectedSlots.add("final");
    },
    assertComplete() {
      if (expectedSlots.size !== 0) fail("adaptive_pilot_expected_call_missing");
    },
  };
}

function verdictCounts(verification) {
  const counts = {
    confirmed_missing: 0,
    visible_same_place: 0,
    visible_elsewhere: 0,
    not_comparable: 0,
  };
  for (const decision of verification?.verifications ?? []) {
    counts[decision.verdict] += 1;
  }
  return counts;
}

function sumCalls(calls) {
  return calls.reduce(
    (total, call) => ({
      prompt_tokens: total.prompt_tokens + call.prompt_tokens,
      completion_tokens: total.completion_tokens + call.completion_tokens,
      total_tokens: total.total_tokens + call.total_tokens,
      public_list_equivalent_cny:
        total.public_list_equivalent_cny + call.public_list_equivalent_cny,
      current_advertised_equivalent_cny:
        total.current_advertised_equivalent_cny +
        call.current_advertised_equivalent_cny,
    }),
    {
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
      public_list_equivalent_cny: 0,
      current_advertised_equivalent_cny: 0,
    },
  );
}

async function runCase({
  caseItem,
  assets,
  tokenStore,
  apiKey,
  baseURL,
  dryRun,
}) {
  const caseStartedAt = performance.now();
  let baseline;
  let current;
  try {
    baseline = await prepareAsset(assets.get(caseItem.baseline_asset_id));
    current = await prepareAsset(assets.get(caseItem.current_asset_id));
    const callRecords = [];
    tokenStore.reserveInitial(caseItem.case_id);
    const fetchController = createControlledFetch({
      apiKey,
      baseURL,
      caseItem,
      expectedImages: [baseline, current],
      tokenStore,
      callRecords,
      dryRun,
    });
    const client = new OpenAI({
      apiKey,
      baseURL,
      maxRetries: DEFAULT_QWEN_MAX_RETRIES,
      timeout: DEFAULT_QWEN_PRIMARY_TIMEOUT_MS,
      logLevel: "off",
      fetch: fetchController.fetch,
    });
    const runtime = {
      provider: "qwen",
      model: ADAPTIVE_PLUS_MODEL,
      client,
      qwenMissingScout: {
        mode: "active",
        model: ADAPTIVE_FLASH_MODEL,
        timeoutMs: DEFAULT_QWEN_FAST_VERIFICATION_TIMEOUT_MS,
        promptVersion: CHECKBACK_MISSING_SCOUT_PROMPT_VERSION,
      },
      qwenVerification: {
        mode: "off",
        fastModel: ADAPTIVE_FLASH_MODEL,
        fallbackModel: ADAPTIVE_PLUS_MODEL,
        promptVersion: CHECKBACK_VERIFIER_PROMPT_VERSION,
        promptSha256: CHECKBACK_VERIFIER_PROMPT_SHA256,
        fastTimeoutMs: DEFAULT_QWEN_FAST_VERIFICATION_TIMEOUT_MS,
        fallbackTimeoutMs: DEFAULT_QWEN_VERIFICATION_FALLBACK_TIMEOUT_MS,
      },
    };

    const observer = await analyzeImagePairWithScout(
      runtime,
      baseline.dataUrl,
      current.dataUrl,
    );
    fetchController.assertComplete();
    const observerSlots = new Set(callRecords.map((record) => record.slot));
    if (
      callRecords.length !== 2 ||
      !observerSlots.has("primary") ||
      !observerSlots.has("scout")
    ) {
      fail("adaptive_pilot_observer_call_contract_invalid");
    }

    const analysis = observer.analysis;
    const candidates =
      analysis?.changes.filter(
        (change) =>
          change.type === "missing" &&
          (change.certainty === "high" ||
            (change.origin === "scout" && change.certainty === "medium")) &&
          change.baseline_visible &&
          change.expected_region_visible,
      ) ?? [];
    const candidateFailure = validateVerificationCandidates(candidates);
    const shouldCallFinal = candidates.length > 0 && candidateFailure === null;
    if (shouldCallFinal) {
      tokenStore.reserveFinal(caseItem.case_id);
      fetchController.allowFinal();
    }
    const verification = analysis
      ? await verifyMissingCandidates(
          runtime,
          baseline.dataUrl,
          current.dataUrl,
          analysis,
          { qwenModeOverride: "off" },
        )
      : {
          verification: null,
          diagnostics: {
            path: "qwen_unresolved",
            provider_calls: 0,
            terminal_reason: "invalid_output",
          },
        };
    fetchController.assertComplete();
    if (
      verification.diagnostics.provider_calls !== (shouldCallFinal ? 1 : 0) ||
      callRecords.length !== (shouldCallFinal ? 3 : 2)
    ) {
      fail("adaptive_pilot_final_call_contract_invalid");
    }
    if (tokenStore.summary().pending.length !== 0) {
      fail("adaptive_pilot_pending_call_after_case");
    }

    const counts = verdictCounts(verification.verification);
    const highConfirmedMissing =
      verification.verification?.verifications.filter(
        (item) => item.verdict === "confirmed_missing" && item.certainty === "high",
      ).length ?? 0;
    const verificationAmbiguous =
      verification.verification?.verifications.some(
        (item) => item.certainty !== "high" || item.verdict === "not_comparable",
      ) ?? false;
    const blockingCount =
      analysis?.quality_issues.filter((issue) => issue.severity === "blocking").length ??
      1;
    let safetyStopReason = null;
    if (!analysis || observer.diagnostics.path !== "parallel" || blockingCount > 0) {
      safetyStopReason = "observer_unresolved";
    } else if (
      candidateFailure ||
      verification.diagnostics.path === "qwen_unresolved" ||
      (candidates.length > 0 && !verification.verification) ||
      verificationAmbiguous
    ) {
      safetyStopReason = "verification_unresolved";
    } else if (
      caseItem.truth_class === "observable_missing" &&
      highConfirmedMissing < 1
    ) {
      safetyStopReason = "missed_known_missing";
    } else if (
      caseItem.truth_class !== "observable_missing" &&
      highConfirmedMissing > 0
    ) {
      safetyStopReason = "false_missing";
    }

    const finalRecord = callRecords.find((record) => record.slot === "final");
    const cost = sumCalls(callRecords);
    return {
      schema_version: "checkback.adaptive-pilot-result.v1",
      run_revision: "adaptive-live-run-v2",
      attempt: caseItem.case_id === "case-0022" ? 2 : 1,
      case_id: caseItem.case_id,
      scene_id: caseItem.scene_id,
      category: caseItem.category,
      truth_class: caseItem.truth_class,
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
      observer: {
        path: observer.diagnostics.path,
        comparison: observer.diagnostics.comparison,
        scene_match: analysis?.scene.match ?? null,
        overlap: analysis?.scene.overlap ?? null,
        blocking_quality_count: blockingCount,
        primary_change_count: analysis?.changes.filter(
          (change) => change.origin !== "scout",
        ).length ?? 0,
        scout_candidate_count: observer.diagnostics.scout_candidate_count,
        scout_added_candidate_count: observer.diagnostics.added_candidate_count,
        merged_verifiable_candidate_count: candidates.length,
      },
      verification: {
        path: verification.diagnostics.path,
        terminal_reason: verification.diagnostics.terminal_reason ?? null,
        verdict_counts: counts,
        high_confirmed_missing_count: highConfirmedMissing,
      },
      timings: {
        preprocessing_ms: round(
          baseline.preprocessing_ms + current.preprocessing_ms,
        ),
        observer_wall_ms: observer.diagnostics.observer_ms,
        final_model_ms: finalRecord?.latency_ms ?? 0,
        model_wall_ms: round(
          observer.diagnostics.observer_ms + (finalRecord?.latency_ms ?? 0),
        ),
        case_total_ms: round(performance.now() - caseStartedAt),
      },
      calls: callRecords,
      usage_and_cost: {
        ...cost,
        public_list_equivalent_cny: round(cost.public_list_equivalent_cny, 8),
        current_advertised_equivalent_cny: round(
          cost.current_advertised_equivalent_cny,
          8,
        ),
      },
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

function validateExistingResults(results) {
  const selected = new Set(SELECTED_CASES.map((item) => item.case_id));
  const completed = new Set();
  for (const result of results) {
    if (
      result?.schema_version !== "checkback.adaptive-pilot-result.v1" ||
      result.run_revision !== "adaptive-live-run-v2" ||
      result.attempt !== (result.case_id === "case-0022" ? 2 : 1) ||
      !selected.has(result.case_id) ||
      completed.has(result.case_id) ||
      typeof result.case_pass !== "boolean" ||
      !Array.isArray(result.calls) ||
      result.calls.length < 2 ||
      result.calls.length > 3
    ) {
      fail("adaptive_pilot_existing_result_invalid");
    }
    completed.add(result.case_id);
  }
  return completed;
}

function aggregateResults(results) {
  const calls = results.flatMap((result) => result.calls);
  const totals = sumCalls(calls);
  const checks = results.length;
  const byPath = {};
  for (const result of results) {
    const key = result.calls.length === 2 ? "two_call" : "three_call";
    const bucket = byPath[key] ?? { checks: 0, calls: [] };
    bucket.checks += 1;
    bucket.calls.push(...result.calls);
    byPath[key] = bucket;
  }
  const pathAverages = Object.fromEntries(
    Object.entries(byPath).map(([key, bucket]) => {
      const pathTotals = sumCalls(bucket.calls);
      return [
        key,
        {
          checks: bucket.checks,
          average_total_tokens: round(pathTotals.total_tokens / bucket.checks, 3),
          average_public_list_equivalent_cny: round(
            pathTotals.public_list_equivalent_cny / bucket.checks,
            8,
          ),
          average_current_advertised_equivalent_cny: round(
            pathTotals.current_advertised_equivalent_cny / bucket.checks,
            8,
          ),
        },
      ];
    }),
  );
  const perModel = {};
  for (const call of calls) {
    const bucket = perModel[call.model] ?? {
      calls: 0,
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
      public_list_equivalent_cny: 0,
      current_advertised_equivalent_cny: 0,
    };
    bucket.calls += 1;
    bucket.prompt_tokens += call.prompt_tokens;
    bucket.completion_tokens += call.completion_tokens;
    bucket.total_tokens += call.total_tokens;
    bucket.public_list_equivalent_cny += call.public_list_equivalent_cny;
    bucket.current_advertised_equivalent_cny +=
      call.current_advertised_equivalent_cny;
    perModel[call.model] = bucket;
  }
  for (const bucket of Object.values(perModel)) {
    bucket.public_list_equivalent_cny = round(
      bucket.public_list_equivalent_cny,
      8,
    );
    bucket.current_advertised_equivalent_cny = round(
      bucket.current_advertised_equivalent_cny,
      8,
    );
  }
  return {
    completed_checks: checks,
    passing_checks: results.filter((result) => result.case_pass).length,
    provider_calls: calls.length,
    average_calls_per_check: checks ? round(calls.length / checks, 3) : null,
    average_prompt_tokens_per_check: checks
      ? round(totals.prompt_tokens / checks, 3)
      : null,
    average_completion_tokens_per_check: checks
      ? round(totals.completion_tokens / checks, 3)
      : null,
    average_total_tokens_per_check: checks
      ? round(totals.total_tokens / checks, 3)
      : null,
    average_public_list_equivalent_cny_per_check: checks
      ? round(totals.public_list_equivalent_cny / checks, 8)
      : null,
    average_current_advertised_equivalent_cny_per_check: checks
      ? round(totals.current_advertised_equivalent_cny / checks, 8)
      : null,
    average_model_wall_ms_per_check: checks
      ? round(
          results.reduce((sum, result) => sum + result.timings.model_wall_ms, 0) /
            checks,
        )
      : null,
    totals: {
      ...totals,
      public_list_equivalent_cny: round(totals.public_list_equivalent_cny, 8),
      current_advertised_equivalent_cny: round(
        totals.current_advertised_equivalent_cny,
        8,
      ),
    },
    path_averages: pathAverages,
    per_model: perModel,
  };
}

async function main() {
  const dryRun = values["dry-run"];
  if (dryRun === values.execute) fail("adaptive_pilot_choose_exactly_one_mode");
  if (
    values.execute !== values["confirm-phase23-retest"] ||
    (dryRun && values["confirm-phase23-retest"])
  ) {
    fail("adaptive_pilot_live_confirmation_invalid");
  }
  const { assets } = loadSelectedManifest();
  const priorUsage = loadPriorUsage();
  const existingResults = dryRun
    ? []
    : readJsonLines(RESULTS_PATH, 4 * 1024 * 1024);
  const completed = validateExistingResults(existingResults);
  const priorStop = existingResults.find((result) => result.safety_stop_reason);
  const tokenEvents = dryRun
    ? []
    : readJsonLines(TOKEN_LEDGER_PATH, 4 * 1024 * 1024);
  const initialSummary = summarizeAdaptiveTokenEvents(tokenEvents, priorUsage);
  if (initialSummary.pending.length > 0) {
    fail("adaptive_pilot_pending_call_requires_manual_stop");
  }
  if (priorStop) {
    process.stdout.write(
      JSON.stringify({
        mode: "live",
        run_revision: "adaptive-live-run-v2",
        status: "already_safety_stopped",
        stop_reason: priorStop.safety_stop_reason,
        metrics: aggregateResults(existingResults),
        token_summary: initialSummary,
      }) + "\n",
    );
    return;
  }
  const configuration = dryRun
    ? {
        apiKey: "offline-rehearsal-key-000000000000000000000000",
        baseURL: PINNED_QWEN_BASE_URL,
      }
    : loadQwenConfiguration();
  const tokenStore = new AdaptiveTokenStore(tokenEvents, priorUsage, !dryRun);
  const invocationResults = [];
  let stopReason = null;
  for (const caseItem of SELECTED_CASES) {
    if (completed.has(caseItem.case_id)) continue;
    const result = await runCase({
      caseItem,
      assets,
      tokenStore,
      apiKey: configuration.apiKey,
      baseURL: configuration.baseURL,
      dryRun,
    });
    invocationResults.push(result);
    if (!dryRun) appendJsonLines(RESULTS_PATH, [result]);
    if (result.safety_stop_reason) {
      stopReason = result.safety_stop_reason;
      break;
    }
  }
  const allResults = dryRun
    ? invocationResults
    : [...existingResults, ...invocationResults];
  process.stdout.write(
    JSON.stringify({
      mode: dryRun ? "dry_run_no_network" : "live",
      run_revision: "adaptive-live-run-v2",
      status: stopReason ? "safety_stopped" : "batch_complete",
      processed_checks: invocationResults.length,
      stop_reason: stopReason,
      metrics: aggregateResults(allResults),
      token_summary: tokenStore.summary(),
      pricing: {
        source_url: QWEN_PRICING_SOURCE_URL,
        checked_date: QWEN_PRICING_CHECKED_DATE,
        currency: QWEN_PRICING_CURRENCY,
        note: "equivalent cost before account-specific free quota or contract adjustments",
      },
    }) + "\n",
  );
}

await main().catch((error) => {
  let tokenSummary = null;
  try {
    const priorUsage = loadPriorUsage();
    const events = readJsonLines(TOKEN_LEDGER_PATH, 4 * 1024 * 1024);
    tokenSummary = summarizeAdaptiveTokenEvents(events, priorUsage);
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
