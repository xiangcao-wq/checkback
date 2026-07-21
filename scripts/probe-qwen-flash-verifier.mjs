import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import OpenAI from "openai";
import { MissingVerificationSchema } from "../app/lib/checkback-analysis.ts";
import {
  CHECKBACK_VERIFIER_PROMPT_SHA256,
  CHECKBACK_VERIFIER_PROMPT_VERSION,
  DEFAULT_QWEN_FAST_VERIFICATION_MODEL,
} from "../app/lib/qwen-model-config.ts";
import {
  QWEN_ENABLE_THINKING,
  QWEN_HIGH_RESOLUTION_IMAGES,
  QWEN_JSON_RESPONSE_FORMAT,
  QWEN_VERIFIER_BASELINE_LABEL,
  QWEN_VERIFIER_CANDIDATE_PREFIX,
  QWEN_VERIFIER_CURRENT_LABEL,
  QWEN_VERIFIER_MAX_TOKENS,
  QWEN_VERIFIER_SYSTEM_PROMPT,
  buildQwenVerifierUserContent,
  serializeQwenVerifierCandidates,
} from "../app/lib/qwen-verifier-prompt.ts";
import { validateVerificationBatch } from "../app/lib/verification-policy.ts";
import {
  collectDataUrls,
  createInstrumentedFetch,
  hasExactKeys,
  preprocessImage,
  round,
  sanitizedError,
  sha256,
  sha256Utf8,
  validateEmbeddedImage,
  writeExclusiveJson,
} from "./probe-qwen-latency.mjs";

const PINNED_QWEN_BASE_URL =
  "https://llm-2th4ful6vems5zkd.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";
const PINNED_PRIMARY_ENV_MODEL = "qwen3.7-plus";
const PINNED_FLASH_MODEL = "qwen3.6-flash-2026-04-16";
const PINNED_PAIR_COMMITMENT =
  "d7909bab1505b7d12637ba45e96cf7eaf4c7291f653f8ded03f885af9bee11cd";
const PINNED_CALL_1_RESULT_SHA256 =
  "00afaffbafd1dd1885ddfd5f7149b93d646b48ae4c39047cb85ad27a0c425398";
const PINNED_CALL_1_ANALYSIS_SHA256 =
  "e5dff842cb2a978d432ffb961d737a3c55e7f873f6359b1ca859c33c2300407f";
const PINNED_VERIFIER_SYSTEM_PROMPT_SHA256 =
  "4a51225e81c0475c685716748283234036a12dcb8d6e8d0255ce509504cffc21";
const PINNED_VERIFIER_FINGERPRINT_SHA256 =
  "30e5793cbf214c1d4c29ad467c642b382841170f42e84af7a925519069feb49b";
const PINNED_CANDIDATE_SHA256 =
  "2f37c286284b5a35fb3d128dcb523830041836f4ea0024e672f1eae55cf2de36";
const VERIFIER_TIMEOUT_MS = 20_000;
const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const RECONSTRUCTED_CANDIDATES = Object.freeze([
  Object.freeze({
    id: "primary-e5dff842-change-0",
    label: "黑色圆形音箱",
    baseline_location: "桌面右下角",
  }),
]);
const RECONSTRUCTED_CANDIDATES_JSON =
  serializeQwenVerifierCandidates(RECONSTRUCTED_CANDIDATES);

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

function validatePinnedVerifierConfiguration() {
  if (
    DEFAULT_QWEN_FAST_VERIFICATION_MODEL !== PINNED_FLASH_MODEL ||
    CHECKBACK_VERIFIER_PROMPT_VERSION !== "checkback-verifier-v1" ||
    CHECKBACK_VERIFIER_PROMPT_SHA256 !== PINNED_VERIFIER_FINGERPRINT_SHA256 ||
    sha256Utf8(QWEN_VERIFIER_SYSTEM_PROMPT) !==
      PINNED_VERIFIER_SYSTEM_PROMPT_SHA256 ||
    sha256Utf8(RECONSTRUCTED_CANDIDATES_JSON) !== PINNED_CANDIDATE_SHA256 ||
    QWEN_VERIFIER_MAX_TOKENS !== 2200 ||
    QWEN_JSON_RESPONSE_FORMAT !== "json_object" ||
    QWEN_ENABLE_THINKING !== false ||
    QWEN_HIGH_RESOLUTION_IMAGES !== true
  ) {
    fail("flash_probe_pinned_verifier_configuration_mismatch");
  }
}

function validateCallOneEvidence(path, pairCommitment) {
  const bytes = readFileSync(path);
  try {
    if (sha256(bytes) !== PINNED_CALL_1_RESULT_SHA256) {
      fail("flash_probe_call_1_artifact_hash_mismatch");
    }
    let value;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch {
      fail("flash_probe_call_1_artifact_json_invalid");
    }
    const change = value?.analysis_excerpt?.changes?.[0];
    if (
      value?.schema_version !== "checkback.qwen-latency-result.v1" ||
      value?.success !== true ||
      value?.call_slot !== 1 ||
      value?.authorized_pair_transmission_limit !== 5 ||
      value?.pair_commitment_sha256 !== pairCommitment ||
      value?.model !== PINNED_PRIMARY_ENV_MODEL ||
      value?.network_requests_started !== 1 ||
      value?.retry_count !== 0 ||
      value?.request?.exact_authorized_pair !== true ||
      value?.response?.status !== 200 ||
      value?.analysis_sha256 !== PINNED_CALL_1_ANALYSIS_SHA256 ||
      value?.product_followup?.high_confidence_missing_candidates !== 1 ||
      value?.product_followup?.product_would_send_second_pair_request !== true ||
      value?.product_followup?.second_request_executed !== false ||
      value?.analysis_excerpt?.changes?.length !== 1 ||
      change?.label !== RECONSTRUCTED_CANDIDATES[0].label ||
      change?.type !== "missing" ||
      change?.certainty !== "high" ||
      typeof value?.analysis_excerpt?.summary !== "string" ||
      !value.analysis_excerpt.summary.includes("桌面右下角")
    ) {
      fail("flash_probe_call_1_evidence_invalid");
    }
    return {
      result_sha256: PINNED_CALL_1_RESULT_SHA256,
      analysis_sha256: value.analysis_sha256,
    };
  } finally {
    bytes.fill(0);
  }
}

function validateVerifierRequest(bodyBytes, { expectedModel, expectedImages, apiKey }) {
  let body;
  try {
    body = JSON.parse(bodyBytes.toString("utf8"));
  } catch {
    fail("flash_probe_request_json_invalid");
  }
  const content = body?.messages?.[1]?.content;
  const images = Array.isArray(content)
    ? [content[2]?.image_url?.url, content[4]?.image_url?.url]
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
    body.max_tokens !== QWEN_VERIFIER_MAX_TOKENS ||
    !hasExactKeys(body.response_format, ["type"]) ||
    body.response_format.type !== QWEN_JSON_RESPONSE_FORMAT ||
    body.enable_thinking !== QWEN_ENABLE_THINKING ||
    body.vl_high_resolution_images !== QWEN_HIGH_RESOLUTION_IMAGES ||
    !Array.isArray(body.messages) ||
    body.messages.length !== 2 ||
    !hasExactKeys(body.messages[0], ["role", "content"]) ||
    body.messages[0].role !== "system" ||
    body.messages[0].content !== QWEN_VERIFIER_SYSTEM_PROMPT ||
    !hasExactKeys(body.messages[1], ["role", "content"]) ||
    body.messages[1].role !== "user" ||
    !Array.isArray(content) ||
    content.length !== 5 ||
    !hasExactKeys(content[0], ["type", "text"]) ||
    content[0].type !== "text" ||
    content[0].text !==
      QWEN_VERIFIER_CANDIDATE_PREFIX + RECONSTRUCTED_CANDIDATES_JSON ||
    !hasExactKeys(content[1], ["type", "text"]) ||
    content[1].type !== "text" ||
    content[1].text !== QWEN_VERIFIER_BASELINE_LABEL ||
    !hasExactKeys(content[2], ["type", "image_url"]) ||
    content[2].type !== "image_url" ||
    !hasExactKeys(content[2].image_url, ["url"]) ||
    !hasExactKeys(content[3], ["type", "text"]) ||
    content[3].type !== "text" ||
    content[3].text !== QWEN_VERIFIER_CURRENT_LABEL ||
    !hasExactKeys(content[4], ["type", "image_url"]) ||
    content[4].type !== "image_url" ||
    !hasExactKeys(content[4].image_url, ["url"]) ||
    images.length !== 2 ||
    collectDataUrls(body).length !== 2
  ) {
    fail("flash_probe_request_shape_invalid");
  }
  validateEmbeddedImage(images[0], expectedImages[0]);
  validateEmbeddedImage(images[1], expectedImages[1]);
  const keyBytes = Buffer.from(apiKey, "utf8");
  try {
    if (bodyBytes.indexOf(keyBytes) !== -1) {
      fail("flash_probe_credential_in_request_body");
    }
  } finally {
    keyBytes.fill(0);
  }
  return {
    request_body_bytes: bodyBytes.byteLength,
    request_body_sha256: sha256(bodyBytes),
    embedded_image_count: images.length,
    content_part_count: content.length,
    exact_authorized_pair: true,
    candidate_payload_sha256: PINNED_CANDIDATE_SHA256,
    candidate_source: "reconstructed_from_sanitized_primary_evidence",
    exact_original_candidate_payload: false,
  };
}

function verifierExcerpt(value) {
  if (!value) return null;
  return {
    verifications: value.verifications.map((item) => ({
      id: item.id,
      verdict: item.verdict,
      certainty: item.certainty,
      current_location_present: Boolean(item.current_location?.trim()),
    })),
  };
}

async function main() {
  if (!values.baseline || !values.current) {
    fail("flash_probe_two_image_paths_required");
  }
  if (values["dry-run"] === values["execute-once"]) {
    fail("flash_probe_choose_exactly_one_mode");
  }
  validatePinnedVerifierConfiguration();

  const apiKey = process.env.DASHSCOPE_API_KEY?.trim();
  const baseURL = process.env.DASHSCOPE_BASE_URL?.trim();
  const primaryModel = process.env.QWEN_VISION_MODEL?.trim();
  if (!apiKey || !baseURL || !primaryModel) {
    fail("flash_probe_qwen_configuration_missing");
  }
  const parsedBase = new URL(baseURL);
  if (
    baseURL !== PINNED_QWEN_BASE_URL ||
    primaryModel !== PINNED_PRIMARY_ENV_MODEL ||
    parsedBase.protocol !== "https:" ||
    parsedBase.username !== "" ||
    parsedBase.password !== "" ||
    parsedBase.search !== "" ||
    parsedBase.hash !== ""
  ) {
    fail("flash_probe_pinned_qwen_configuration_mismatch");
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
    let pairCommitment;
    try {
      pairCommitment = sha256(pairMaterial);
    } finally {
      pairMaterial.fill(0);
    }
    if (pairCommitment !== PINNED_PAIR_COMMITMENT) {
      fail("flash_probe_authorized_pair_mismatch");
    }

    const outputDirectory = resolve(
      WEB_ROOT,
      `evaluation/live-diagnostics/authorized-pair-${pairCommitment}`,
    );
    const callOnePath = resolve(outputDirectory, "call-1.result.json");
    const callOneEvidence = validateCallOneEvidence(callOnePath, pairCommitment);
    const outputBase = resolve(outputDirectory, "call-2");
    const reservationPath = outputBase + ".reservation.json";
    const resultPath = outputBase + ".result.json";
    if (
      values["execute-once"] &&
      (existsSync(reservationPath) || existsSync(resultPath))
    ) {
      fail("flash_probe_call_slot_already_consumed");
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
    const runId = `qwen_flash_verifier_probe_${Date.now()}_${pairCommitment.slice(0, 12)}`;
    if (values["execute-once"]) {
      writeExclusiveJson(reservationPath, {
        schema_version: "checkback.qwen-flash-verifier-reservation.v1",
        run_id: runId,
        pair_commitment_sha256: pairCommitment,
        call_slot: 2,
        authorized_pair_transmission_limit: 5,
        previous_consumed_call_slot: 1,
        probe_supported_call_slots: [2],
        state: "reserved_before_network",
        created_at: new Date().toISOString(),
        endpoint_origin: parsedBase.origin,
        endpoint_path: "/compatible-mode/v1/chat/completions",
        model: PINNED_FLASH_MODEL,
        max_retries: 0,
        timeout_ms: VERIFIER_TIMEOUT_MS,
        candidate_source: "reconstructed_from_sanitized_primary_evidence",
        candidate_payload_sha256: PINNED_CANDIDATE_SHA256,
        exact_original_candidate_payload: false,
        source_primary_result_sha256: callOneEvidence.result_sha256,
        source_primary_analysis_sha256: callOneEvidence.analysis_sha256,
      });
    }

    let verification = null;
    let providerMetadata = null;
    let error = null;
    capture.analysis_started_at = performance.now();
    try {
      const dryRunContent = JSON.stringify({
        verifications: [
          {
            id: RECONSTRUCTED_CANDIDATES[0].id,
            verdict: "confirmed_missing",
            certainty: "high",
            current_location: null,
            evidence: "dry-run",
          },
        ],
      });
      const client = new OpenAI({
        apiKey,
        baseURL,
        maxRetries: 0,
        timeout: VERIFIER_TIMEOUT_MS,
        logLevel: "off",
        fetch: createInstrumentedFetch({
          allowedBaseUrl: baseURL,
          expectedModel: PINNED_FLASH_MODEL,
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
          validateRequest: validateVerifierRequest,
          dryRunContent,
          requestTimeoutMs: VERIFIER_TIMEOUT_MS,
        }),
      });
      const completion = await client.chat.completions.create(
        {
          model: PINNED_FLASH_MODEL,
          max_tokens: QWEN_VERIFIER_MAX_TOKENS,
          response_format: { type: QWEN_JSON_RESPONSE_FORMAT },
          enable_thinking: QWEN_ENABLE_THINKING,
          vl_high_resolution_images: QWEN_HIGH_RESOLUTION_IMAGES,
          messages: [
            { role: "system", content: QWEN_VERIFIER_SYSTEM_PROMPT },
            {
              role: "user",
              content: buildQwenVerifierUserContent(
                RECONSTRUCTED_CANDIDATES_JSON,
                baseline.dataUrl,
                current.dataUrl,
              ),
            },
          ],
        },
        { maxRetries: 0, timeout: VERIFIER_TIMEOUT_MS },
      );
      const content = completion.choices[0]?.message?.content;
      if (typeof content !== "string") {
        fail("flash_probe_model_output_missing");
      }
      let parsedJson;
      try {
        parsedJson = JSON.parse(content);
      } catch {
        fail("flash_probe_model_output_json_invalid");
      }
      const parsed = MissingVerificationSchema.safeParse(parsedJson);
      if (!parsed.success) {
        fail("flash_probe_model_output_schema_invalid");
      }
      verification = parsed.data;
      providerMetadata = {
        finish_reason: completion.choices[0]?.finish_reason ?? null,
        prompt_tokens: completion.usage?.prompt_tokens ?? null,
        completion_tokens: completion.usage?.completion_tokens ?? null,
        total_tokens: completion.usage?.total_tokens ?? null,
      };
    } catch (caught) {
      error = sanitizedError(caught);
    }
    const verificationFinishedAt = performance.now();

    const validationReason = verification
      ? validateVerificationBatch(RECONSTRUCTED_CANDIDATES, verification, true)
      : null;
    const conflictsWithPrimary =
      verification?.verifications.some(
        (item) => item.verdict !== "confirmed_missing",
      ) ?? false;
    const activeFallbackReason =
      validationReason ?? (conflictsWithPrimary ? "conflicts_with_primary" : null);
    const activeFastEligible =
      error === null && verification !== null && activeFallbackReason === null;
    const decisionConsistentWithPrimary = verification
      ? verification.verifications.every(
          (item) => item.verdict === "confirmed_missing",
        )
      : null;
    const verificationBytes = verification
      ? Buffer.from(JSON.stringify(verification), "utf8")
      : null;
    let verificationSha256 = null;
    if (verificationBytes) {
      try {
        verificationSha256 = sha256(verificationBytes);
      } finally {
        verificationBytes.fill(0);
      }
    }
    const modelCallMs = round(
      verificationFinishedAt - capture.analysis_started_at,
    );
    const result = {
      schema_version: "checkback.qwen-flash-verifier-result.v1",
      run_id: runId,
      pair_commitment_sha256: pairCommitment,
      mode: values["dry-run"]
        ? "dry_run_no_network_flash_verifier"
        : "live_single_flash_verifier_call",
      success: error === null,
      verifier_output_valid: verification !== null && validationReason === null,
      call_slot: values["dry-run"] ? 0 : 2,
      authorized_pair_transmission_limit: 5,
      cumulative_pair_transmissions_after_call: values["dry-run"] ? 1 : 2,
      fetch_adapter_calls: capture.transport_calls,
      network_requests_started: capture.network_requests_started,
      retry_count: 0,
      endpoint: capture.endpoint,
      model: PINNED_FLASH_MODEL,
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
      provider_metadata: providerMetadata,
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
            : round(verificationFinishedAt - capture.fetch_response_ready_at),
        verifier_call_ms: modelCallMs,
        probe_through_verification_ms: round(
          verificationFinishedAt - processStartedAt,
        ),
      },
      timing_caveat:
        "local_request_write_finished_ms means bytes reached the local socket buffer; response_headers_after_local_write_ms is not pure model time.",
      verifier_context: {
        prompt_version: CHECKBACK_VERIFIER_PROMPT_VERSION,
        prompt_fingerprint_sha256: CHECKBACK_VERIFIER_PROMPT_SHA256,
        system_prompt_sha256: PINNED_VERIFIER_SYSTEM_PROMPT_SHA256,
        candidate_source: "reconstructed_from_sanitized_primary_evidence",
        candidate_payload_sha256: PINNED_CANDIDATE_SHA256,
        exact_original_candidate_payload: false,
        candidates: RECONSTRUCTED_CANDIDATES,
        source_primary_result_sha256: callOneEvidence.result_sha256,
        source_primary_analysis_sha256: callOneEvidence.analysis_sha256,
      },
      decision: {
        validation_reason: validationReason,
        decision_consistent_with_primary: decisionConsistentWithPrimary,
        active_fast_eligible: activeFastEligible,
        active_fallback_reason: activeFallbackReason,
        plus_fallback_would_be_required: !activeFastEligible,
        plus_request_executed: false,
      },
      verification_sha256: verificationSha256,
      verification_excerpt: verifierExcerpt(verification),
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

await main().catch((error) => {
  process.stderr.write(
    JSON.stringify({ success: false, error: sanitizedError(error) }) + "\n",
  );
  process.exitCode = 1;
});
