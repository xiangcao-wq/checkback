import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { request as httpsRequest, Agent as HttpsAgent } from "node:https";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";
import OpenAI from "openai";
import sharp from "sharp";
import { analyzeImagePair } from "../app/lib/vision-provider.ts";

const MAX_IMAGE_BYTES = 430 * 1024;
const MAX_IMAGE_EDGE = 4096;
const MAX_IMAGE_PIXELS = 16_000_000;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 90_000;
const PINNED_QWEN_BASE_URL =
  "https://llm-2th4ful6vems5zkd.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";
const PINNED_QWEN_MODEL = "qwen3.7-plus";
const PINNED_PRIMARY_SYSTEM_PROMPT_SHA256 =
  "b60b285e9d0f1250974db6b0cea75539aea5e690fc3df0c50bb78e70a8081767";
const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const { values } = parseArgs({
  options: {
    baseline: { type: "string" },
    current: { type: "string" },
    "dry-run": { type: "boolean", default: false },
    "execute-once": { type: "boolean", default: false },
  },
  strict: true,
});

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function sha256Utf8(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function round(value) {
  return value === null || value === undefined ? null : Math.round(value * 10) / 10;
}

export async function preprocessImage(path) {
  const startedAt = performance.now();
  const original = readFileSync(path);
  let sanitized = null;
  let handedOff = false;
  try {
    if (original.byteLength < 1 || original.byteLength > MAX_IMAGE_BYTES) {
      fail("probe_image_size_invalid");
    }
    const image = sharp(original, {
      failOn: "error",
      limitInputPixels: MAX_IMAGE_PIXELS,
      sequentialRead: true,
    });
    const metadata = await image.metadata();
    if (
      metadata.format !== "jpeg" ||
      !metadata.width ||
      !metadata.height ||
      metadata.width > MAX_IMAGE_EDGE ||
      metadata.height > MAX_IMAGE_EDGE ||
      metadata.width * metadata.height > MAX_IMAGE_PIXELS
    ) {
      fail("probe_image_dimensions_invalid");
    }
    sanitized = await image
      .rotate()
      .jpeg({
        quality: 90,
        chromaSubsampling: "4:4:4",
        progressive: false,
        optimizeCoding: true,
      })
      .toBuffer();
    if (sanitized.byteLength < 1 || sanitized.byteLength > MAX_IMAGE_BYTES) {
      fail("probe_sanitized_image_size_invalid");
    }
    const sanitizedMetadata = await sharp(sanitized).metadata();
    if (
      sanitizedMetadata.exif ||
      sanitizedMetadata.icc ||
      sanitizedMetadata.iptc ||
      sanitizedMetadata.xmp
    ) {
      fail("probe_sanitized_image_metadata_present");
    }
    const prepared = {
      sanitized,
      dataUrl: "data:image/jpeg;base64," + sanitized.toString("base64"),
      metrics: {
        original_bytes: original.byteLength,
        sanitized_bytes: sanitized.byteLength,
        sanitized_sha256: sha256(sanitized),
        width: sanitizedMetadata.width,
        height: sanitizedMetadata.height,
        preprocessing_ms: round(performance.now() - startedAt),
      },
    };
    handedOff = true;
    return prepared;
  } finally {
    original.fill(0);
    if (sanitized && !handedOff) sanitized.fill(0);
  }
}
export function hasExactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort())
  );
}

export function collectDataUrls(value, output = []) {
  if (typeof value === "string") {
    if (value.startsWith("data:")) output.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectDataUrls(item, output);
  } else if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) collectDataUrls(item, output);
  }
  return output;
}

export function validateEmbeddedImage(dataUrl, expected) {
  const prefix = "data:image/jpeg;base64,";
  if (typeof dataUrl !== "string" || !dataUrl.startsWith(prefix)) {
    fail("probe_embedded_image_type_invalid");
  }
  const encoded = dataUrl.slice(prefix.length);
  if (
    encoded.length < 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)
  ) {
    fail("probe_embedded_image_base64_invalid");
  }
  const decoded = Buffer.from(encoded, "base64");
  try {
    if (
      decoded.toString("base64") !== encoded ||
      decoded.byteLength !== expected.bytes ||
      sha256(decoded) !== expected.sha256
    ) {
      fail("probe_embedded_image_not_authorized_pair");
    }
  } finally {
    decoded.fill(0);
  }
}

function validateCanonicalRequest(bodyBytes, { expectedModel, expectedImages, apiKey }) {
  let body;
  try {
    body = JSON.parse(bodyBytes.toString("utf8"));
  } catch {
    fail("probe_request_json_invalid");
  }
  const content = body?.messages?.[1]?.content;
  const images = Array.isArray(content)
    ? [content[1]?.image_url?.url, content[3]?.image_url?.url]
    : [];
  if (
    !hasExactKeys(body, [
      "model",
      "max_tokens",
      "response_format",
      "enable_thinking",
      "vl_high_resolution_images",
      "messages",
    ]) ||
    body.model !== expectedModel ||
    body.max_tokens !== 4000 ||
    !hasExactKeys(body.response_format, ["type"]) ||
    body.response_format.type !== "json_object" ||
    body.enable_thinking !== false ||
    body.vl_high_resolution_images !== true ||
    !Array.isArray(body.messages) ||
    body.messages.length !== 2 ||
    !hasExactKeys(body.messages[0], ["role", "content"]) ||
    body.messages[0].role !== "system" ||
    typeof body.messages[0].content !== "string" ||
    sha256Utf8(body.messages[0].content) !== PINNED_PRIMARY_SYSTEM_PROMPT_SHA256 ||
    !hasExactKeys(body.messages[1], ["role", "content"]) ||
    body.messages[1].role !== "user" ||
    !Array.isArray(content) ||
    content.length !== 4 ||
    !hasExactKeys(content[0], ["type", "text"]) ||
    content[0].type !== "text" ||
    content[0].text !== "Image A: organized reference state." ||
    !hasExactKeys(content[1], ["type", "image_url"]) ||
    content[1].type !== "image_url" ||
    !hasExactKeys(content[1].image_url, ["url"]) ||
    !hasExactKeys(content[2], ["type", "text"]) ||
    content[2].type !== "text" ||
    content[2].text !== "Image B: current state to check." ||
    !hasExactKeys(content[3], ["type", "image_url"]) ||
    content[3].type !== "image_url" ||
    !hasExactKeys(content[3].image_url, ["url"]) ||
    images.length !== 2 ||
    collectDataUrls(body).length !== 2
  ) {
    fail("probe_request_shape_invalid");
  }
  validateEmbeddedImage(images[0], expectedImages[0]);
  validateEmbeddedImage(images[1], expectedImages[1]);
  const keyBytes = Buffer.from(apiKey, "utf8");
  try {
    if (bodyBytes.indexOf(keyBytes) !== -1) fail("probe_credential_in_request_body");
  } finally {
    keyBytes.fill(0);
  }
  return {
    request_body_bytes: bodyBytes.byteLength,
    request_body_sha256: sha256(bodyBytes),
    embedded_image_count: images.length,
    exact_authorized_pair: true,
  };
}
function responseHeadersForEvidence(headers) {
  const evidence = {};
  for (const name of [
    "x-request-id",
    "request-id",
    "x-dashscope-request-id",
    "date",
    "content-type",
    "content-length",
    "server-timing",
  ]) {
    const value = headers[name];
    if (typeof value === "string" && value.length <= 256) evidence[name] = value;
  }
  return evidence;
}

function decodedResponseBody(body, encoding) {
  if (!encoding || encoding === "identity") return body;
  if (encoding === "gzip") {
    return gunzipSync(body, { maxOutputLength: MAX_RESPONSE_BYTES });
  }
  if (encoding === "deflate") {
    return inflateSync(body, { maxOutputLength: MAX_RESPONSE_BYTES });
  }
  if (encoding === "br") {
    return brotliDecompressSync(body, { maxOutputLength: MAX_RESPONSE_BYTES });
  }
  fail("probe_response_encoding_unsupported");
}

export function createInstrumentedFetch({
  allowedBaseUrl,
  expectedModel,
  expectedImages,
  apiKey,
  dryRun,
  capture,
  validateRequest = validateCanonicalRequest,
  dryRunContent = null,
  requestTimeoutMs = REQUEST_TIMEOUT_MS,
}) {
  const base = new URL(allowedBaseUrl);
  const expectedPath = base.pathname.replace(/\/$/, "") + "/chat/completions";
  const agent = new HttpsAgent({ keepAlive: false, maxSockets: 1 });

  return async (input, init) => {
    capture.transport_calls += 1;
    if (capture.transport_calls !== 1) fail("probe_more_than_one_transport_call");
    const webRequest = new Request(input, init);
    const url = new URL(webRequest.url);
    if (
      url.protocol !== "https:" ||
      url.origin !== base.origin ||
      url.pathname !== expectedPath ||
      url.search !== "" ||
      url.hash !== "" ||
      url.username !== "" ||
      url.password !== ""
    ) {
      fail("probe_endpoint_not_allowlisted");
    }
    const expectedAuthorization = `Bearer ${apiKey}`;
    if (
      webRequest.method !== "POST" ||
      webRequest.headers.get("authorization") !== expectedAuthorization ||
      webRequest.headers.get("content-type") !== "application/json"
    ) {
      fail("probe_sdk_request_headers_invalid");
    }

    const bodyBytes = Buffer.from(await webRequest.arrayBuffer());
    try {
      capture.request = validateRequest(bodyBytes, {
        expectedModel,
        expectedImages,
        apiKey,
      });
      capture.endpoint = { origin: url.origin, path: url.pathname };
      capture.fetch_invoked_ms = round(performance.now() - capture.analysis_started_at);

      if (dryRun) {
        const fakeAnalysis = dryRunContent ?? JSON.stringify({
          scene: { match: "same", overlap: "high", reason: "dry-run" },
          quality_issues: [],
          changes: [],
          checked_item_count: 0,
          summary: "dry-run",
        });
        const fakeCompletion = JSON.stringify({
          id: "dry-run",
          object: "chat.completion",
          created: 0,
          model: expectedModel,
          choices: [
            {
              index: 0,
              message: { role: "assistant", content: fakeAnalysis },
              finish_reason: "stop",
            },
          ],
        });
        agent.destroy();
        return new Response(fakeCompletion, {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      const headers = {
        accept: "application/json",
        authorization: expectedAuthorization,
        "content-type": "application/json",
        "content-length": String(bodyBytes.byteLength),
        "accept-encoding": "identity",
        connection: "close",
        "user-agent": "CheckBack-Qwen-Latency-Probe/1.0",
      };
      const startedAt = performance.now();
      const marks = {
        socket_assigned_ms: null,
        dns_lookup_ms: null,
        tcp_connected_ms: null,
        tls_connected_ms: null,
        local_request_write_finished_ms: null,
        response_headers_ms: null,
        response_finished_ms: null,
      };
      const snapshotTransport = () => {
        capture.transport = {
          ...marks,
          response_headers_after_local_write_ms:
            marks.response_headers_ms === null ||
            marks.local_request_write_finished_ms === null
              ? null
              : round(
                  marks.response_headers_ms - marks.local_request_write_finished_ms,
                ),
          response_download_ms:
            marks.response_finished_ms === null || marks.response_headers_ms === null
              ? null
              : round(marks.response_finished_ms - marks.response_headers_ms),
        };
      };
      const currentFailureStage = () => {
        if (marks.response_headers_ms !== null) return "response_body";
        if (marks.local_request_write_finished_ms !== null) return "response_wait";
        if (marks.tls_connected_ms !== null) return "request_upload";
        if (marks.tcp_connected_ms !== null) return "tls_handshake";
        if (marks.dns_lookup_ms !== null) return "tcp_connect";
        if (marks.socket_assigned_ms !== null) return "dns_or_connect";
        return "request_setup";
      };

      return await new Promise((resolvePromise, rejectPromise) => {
        let settled = false;
        let nodeRequest;
        const chunks = [];
        let responseBytes = 0;
        const onAbort = () => nodeRequest?.destroy(new Error("probe_aborted"));
        const cleanup = () => {
          webRequest.signal.removeEventListener("abort", onAbort);
          agent.destroy();
        };
        const wipeChunks = () => {
          for (const chunk of chunks) chunk.fill(0);
          chunks.length = 0;
        };
        const finishError = (error) => {
          if (settled) return;
          settled = true;
          snapshotTransport();
          capture.transport_failure_stage = currentFailureStage();
          wipeChunks();
          cleanup();
          rejectPromise(error);
        };

        try {
          nodeRequest = httpsRequest(
            url,
            {
              method: "POST",
              headers,
              agent,
              timeout: requestTimeoutMs,
              maxHeaderSize: 32 * 1024,
            },
            (nodeResponse) => {
              marks.response_headers_ms = round(performance.now() - startedAt);
              capture.response = {
                status: nodeResponse.statusCode ?? 0,
                wire_body_bytes: null,
                decoded_body_bytes: null,
                headers: responseHeadersForEvidence(nodeResponse.headers),
              };
              nodeResponse.on("data", (chunk) => {
                const copy = Buffer.from(chunk);
                responseBytes += copy.byteLength;
                if (responseBytes > MAX_RESPONSE_BYTES) {
                  copy.fill(0);
                  nodeResponse.destroy(new Error("probe_response_too_large"));
                  return;
                }
                chunks.push(copy);
              });
              nodeResponse.on("error", finishError);
              nodeResponse.on("end", () => {
                if (settled) return;
                marks.response_finished_ms = round(performance.now() - startedAt);
                let wireBody;
                let decodedBody;
                try {
                  wireBody = Buffer.concat(chunks);
                  decodedBody = decodedResponseBody(
                    wireBody,
                    typeof nodeResponse.headers["content-encoding"] === "string"
                      ? nodeResponse.headers["content-encoding"].toLowerCase()
                      : "identity",
                  );
                  if (decodedBody.byteLength > MAX_RESPONSE_BYTES) {
                    fail("probe_decoded_response_too_large");
                  }
                  capture.response = {
                    status: nodeResponse.statusCode ?? 0,
                    wire_body_bytes: wireBody.byteLength,
                    decoded_body_bytes: decodedBody.byteLength,
                    headers: responseHeadersForEvidence(nodeResponse.headers),
                  };
                  snapshotTransport();
                  if (
                    (nodeResponse.statusCode ?? 0) >= 300 &&
                    (nodeResponse.statusCode ?? 0) < 400
                  ) {
                    fail("probe_redirect_rejected");
                  }
                  const responseHeaders = new Headers();
                  for (const [name, value] of Object.entries(nodeResponse.headers)) {
                    if (
                      name === "content-encoding" ||
                      name === "content-length" ||
                      value === undefined
                    ) {
                      continue;
                    }
                    if (Array.isArray(value)) {
                      for (const item of value) responseHeaders.append(name, item);
                    } else {
                      responseHeaders.set(name, String(value));
                    }
                  }
                  const responseBody = Buffer.from(decodedBody);
                  let webResponse;
                  try {
                    webResponse = new Response(responseBody, {
                      status: nodeResponse.statusCode ?? 500,
                      statusText: nodeResponse.statusMessage,
                      headers: responseHeaders,
                    });
                  } finally {
                    responseBody.fill(0);
                  }
                  capture.fetch_response_ready_at = performance.now();
                  settled = true;
                  wipeChunks();
                  cleanup();
                  resolvePromise(webResponse);
                } catch (error) {
                  finishError(error);
                } finally {
                  if (wireBody) wireBody.fill(0);
                  if (decodedBody && decodedBody !== wireBody) decodedBody.fill(0);
                }
              });
            },
          );
          capture.network_requests_started += 1;
        } catch (error) {
          finishError(error);
          return;
        }
        nodeRequest.on("socket", (socket) => {
          marks.socket_assigned_ms = round(performance.now() - startedAt);
          socket.once("lookup", () => {
            marks.dns_lookup_ms = round(performance.now() - startedAt);
          });
          socket.once("connect", () => {
            marks.tcp_connected_ms = round(performance.now() - startedAt);
          });
          socket.once("secureConnect", () => {
            marks.tls_connected_ms = round(performance.now() - startedAt);
          });
        });
        nodeRequest.on("finish", () => {
          marks.local_request_write_finished_ms = round(performance.now() - startedAt);
          bodyBytes.fill(0);
        });
        nodeRequest.on("timeout", () => nodeRequest.destroy(new Error("probe_timeout")));
        nodeRequest.on("error", finishError);
        if (webRequest.signal.aborted) {
          nodeRequest.destroy(new Error("probe_aborted"));
          return;
        }
        webRequest.signal.addEventListener("abort", onAbort, { once: true });
        try {
          nodeRequest.end(bodyBytes);
        } catch (error) {
          finishError(error);
        }
      });
    } finally {
      bodyBytes.fill(0);
    }
  };
}
export function writeExclusiveJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeFileSync(descriptor, JSON.stringify(value, null, 2) + "\n", "utf8");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function boundedErrorCode(value) {
  return typeof value === "string" && value.length > 0
    ? value.slice(0, 128)
    : null;
}

export function sanitizedError(error) {
  const cause =
    typeof error === "object" && error !== null && "cause" in error
      ? error.cause
      : null;
  const directCode =
    typeof error === "object" && error !== null && "code" in error
      ? boundedErrorCode(error.code)
      : null;
  const causeCode =
    typeof cause === "object" && cause !== null && "code" in cause
      ? boundedErrorCode(cause.code)
      : null;
  const directStatus =
    typeof error === "object" && error !== null && "status" in error
      ? Number(error.status) || null
      : null;
  const causeStatus =
    typeof cause === "object" && cause !== null && "status" in cause
      ? Number(cause.status) || null
      : null;
  return {
    name: error instanceof Error ? error.name : "UnknownError",
    code: directCode ?? causeCode,
    status: directStatus ?? causeStatus,
  };
}

async function main() {
  if (!values.baseline || !values.current) fail("probe_two_image_paths_required");
  if (values["dry-run"] === values["execute-once"]) {
    fail("probe_choose_exactly_one_mode");
  }
  const apiKey = process.env.DASHSCOPE_API_KEY?.trim();
  const baseURL = process.env.DASHSCOPE_BASE_URL?.trim();
  const model = process.env.QWEN_VISION_MODEL?.trim();
  if (!apiKey || !baseURL || !model) fail("probe_qwen_configuration_missing");
  const parsedBase = new URL(baseURL);
  if (
    baseURL !== PINNED_QWEN_BASE_URL ||
    model !== PINNED_QWEN_MODEL ||
    parsedBase.protocol !== "https:" ||
    parsedBase.username !== "" ||
    parsedBase.password !== "" ||
    parsedBase.search !== "" ||
    parsedBase.hash !== ""
  ) {
    fail("probe_pinned_qwen_configuration_mismatch");
  }

  const processStartedAt = performance.now();
  let baseline = null;
  let current = null;
  try {
    baseline = await preprocessImage(resolve(values.baseline));
    current = await preprocessImage(resolve(values.current));
    const pairMaterial = Buffer.from(
      baseline.metrics.sanitized_sha256 + "\0" + current.metrics.sanitized_sha256,
      "utf8",
    );
    let pairId;
    try {
      pairId = sha256(pairMaterial);
    } finally {
      pairMaterial.fill(0);
    }
    const outputBase = resolve(
      WEB_ROOT,
      `evaluation/live-diagnostics/authorized-pair-${pairId}/call-1`,
    );
    const reservationPath = outputBase + ".reservation.json";
    const resultPath = outputBase + ".result.json";
    if (values["execute-once"] && (existsSync(reservationPath) || existsSync(resultPath))) {
      fail("probe_call_slot_already_consumed");
    }

    const capture = {
      transport_calls: 0,
      network_requests_started: 0,
      transport_failure_stage: null,
      analysis_started_at: 0,
      fetch_response_ready_at: null,
      endpoint: null,
      request: null,
      response: null,
      transport: null,
    };
    const runId = `qwen_probe_${Date.now()}_${pairId.slice(0, 12)}`;
    if (values["execute-once"]) {
      writeExclusiveJson(reservationPath, {
        schema_version: "checkback.qwen-latency-reservation.v1",
        run_id: runId,
        pair_commitment_sha256: pairId,
        call_slot: 1,
        authorized_pair_transmission_limit: 5,
        probe_supported_call_slots: [1],
        state: "reserved_before_network",
        created_at: new Date().toISOString(),
        endpoint_origin: parsedBase.origin,
        endpoint_path: "/compatible-mode/v1/chat/completions",
        model,
        max_retries: 0,
      });
    }

    let analysis = null;
    let error = null;
    capture.analysis_started_at = performance.now();
    try {
      const client = new OpenAI({
        apiKey,
        baseURL,
        maxRetries: 0,
        timeout: REQUEST_TIMEOUT_MS,
        logLevel: "off",
        fetch: createInstrumentedFetch({
          allowedBaseUrl: baseURL,
          expectedModel: model,
          expectedImages: [
            {
              bytes: baseline.metrics.sanitized_bytes,
              sha256: baseline.metrics.sanitized_sha256,
            },
            {
              bytes: current.metrics.sanitized_bytes,
              sha256: current.metrics.sanitized_sha256,
            },
          ],
          apiKey,
          dryRun: values["dry-run"],
          capture,
        }),
      });
      const runtime = { provider: "qwen", model, client };
      analysis = await analyzeImagePair(runtime, baseline.dataUrl, current.dataUrl);
      if (!analysis) fail("probe_model_output_schema_invalid");
    } catch (caught) {
      error = sanitizedError(caught);
    }
    const analysisFinishedAt = performance.now();

    const highMissingCandidates = analysis
      ? analysis.changes.filter(
          (change) =>
            change.type === "missing" &&
            change.certainty === "high" &&
            change.baseline_visible &&
            change.expected_region_visible,
        ).length
      : null;
    const analysisExcerpt = analysis
      ? {
          scene: analysis.scene,
          checked_item_count: analysis.checked_item_count,
          summary: analysis.summary,
          change_count: analysis.changes.length,
          changes: analysis.changes.map((change) => ({
            label: change.label,
            type: change.type,
            certainty: change.certainty,
            action: change.action,
          })),
        }
      : null;
    const analysisBytes = analysis
      ? Buffer.from(JSON.stringify(analysis), "utf8")
      : null;
    let analysisSha256 = null;
    if (analysisBytes) {
      try {
        analysisSha256 = sha256(analysisBytes);
      } finally {
        analysisBytes.fill(0);
      }
    }
    const result = {
      schema_version: "checkback.qwen-latency-result.v1",
      run_id: runId,
      pair_commitment_sha256: pairId,
      mode: values["dry-run"] ? "dry_run_no_network" : "live_single_primary_call",
      success: error === null,
      call_slot: values["dry-run"] ? 0 : 1,
      authorized_pair_transmission_limit: 5,
      fetch_adapter_calls: capture.transport_calls,
      network_requests_started: capture.network_requests_started,
      retry_count: 0,
      endpoint: capture.endpoint,
      model,
      images: {
        baseline: {
          original_bytes: baseline.metrics.original_bytes,
          sanitized_bytes: baseline.metrics.sanitized_bytes,
          width: baseline.metrics.width,
          height: baseline.metrics.height,
          metadata_reencoded: true,
        },
        current: {
          original_bytes: current.metrics.original_bytes,
          sanitized_bytes: current.metrics.sanitized_bytes,
          width: current.metrics.width,
          height: current.metrics.height,
          metadata_reencoded: true,
        },
      },
      request: capture.request,
      response: capture.response,
      transport_failure_stage: capture.transport_failure_stage,
      timings: {
        combined_local_preprocessing_ms: round(
          baseline.metrics.preprocessing_ms + current.metrics.preprocessing_ms,
        ),
        sdk_request_build_copy_and_validation_ms: capture.fetch_invoked_ms ?? null,
        ...capture.transport,
        sdk_response_parse_and_schema_validation_ms:
          capture.fetch_response_ready_at === null
            ? null
            : round(analysisFinishedAt - capture.fetch_response_ready_at),
        primary_call_ms: round(analysisFinishedAt - capture.analysis_started_at),
        probe_through_analysis_ms: round(analysisFinishedAt - processStartedAt),
      },
      timing_caveat:
        "local_request_write_finished_ms means bytes reached the local socket buffer; response_headers_after_local_write_ms is not pure model time.",
      product_followup: {
        high_confidence_missing_candidates: highMissingCandidates,
        product_would_send_second_pair_request:
          highMissingCandidates === null ? null : highMissingCandidates > 0,
        second_request_executed: false,
      },
      analysis_sha256: analysisSha256,
      analysis_excerpt: analysisExcerpt,
      error,
      completed_at: new Date().toISOString(),
    };

    if (values["execute-once"]) writeExclusiveJson(resultPath, result);
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    if (error) process.exitCode = 1;
  } finally {
    if (baseline) {
      baseline.sanitized.fill(0);
      baseline.dataUrl = "";
    }
    if (current) {
      current.sanitized.fill(0);
      current.dataUrl = "";
    }
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main().catch((error) => {
    process.stderr.write(JSON.stringify({ success: false, error: sanitizedError(error) }) + "\n");
    process.exitCode = 1;
  });
}
