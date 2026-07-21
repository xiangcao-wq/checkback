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
const PINNED_VERIFIER_SYSTEM_PROMPT_SHA256 =
  "4a51225e81c0475c685716748283234036a12dcb8d6e8d0255ce509504cffc21";
const PINNED_VERIFIER_FINGERPRINT_SHA256 =
  "30e5793cbf214c1d4c29ad467c642b382841170f42e84af7a925519069feb49b";
const PINNED_CANDIDATE_SHA256 =
  "1bad77d71ebb63a00ea5067d9ab8d4e6bae42ad4e64fbceeb9953f6dd20bbb8f";
const VERIFIER_TIMEOUT_MS = 20_000;
const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const PRIOR_ARTIFACTS = Object.freeze([
  Object.freeze({
    name: "call-1.reservation.json",
    sha256: "efc1799d3ac0862a17b14bd7af956394d61f3b74d7e44fa0e578865171846b58",
    slot: 1,
    kind: "reservation",
    model: PINNED_PRIMARY_ENV_MODEL,
  }),
  Object.freeze({
    name: "call-1.result.json",
    sha256: "00afaffbafd1dd1885ddfd5f7149b93d646b48ae4c39047cb85ad27a0c425398",
    slot: 1,
    kind: "result",
    model: PINNED_PRIMARY_ENV_MODEL,
  }),
  Object.freeze({
    name: "call-2.reservation.json",
    sha256: "433c0f659a22e81a8287750f0b50ef0f9117c68a781fec3a5398504d405b8864",
    slot: 2,
    kind: "reservation",
    model: PINNED_FLASH_MODEL,
  }),
  Object.freeze({
    name: "call-2.result.json",
    sha256: "21676a16561068e244a68c1ac227377d7910cbc0721fa58014c45b9f73bde043",
    slot: 2,
    kind: "result",
    model: PINNED_FLASH_MODEL,
  }),
]);

const CHALLENGE_CANDIDATES = Object.freeze([
  Object.freeze({
    id: "challenge-speaker-missing",
    label: "独立放置的黑色圆形音箱",
    baseline_location: "桌面下半部中央偏右，机器人小车右侧",
  }),
  Object.freeze({
    id: "challenge-controller-present",
    label: "白色游戏手柄",
    baseline_location: "桌面上半部中央，斜放在键盘和线缆上",
  }),
  Object.freeze({
    id: "challenge-keyboard-present",
    label: "白色机械键盘（带橙色按键）",
    baseline_location: "桌面上半部，从左侧延伸到中央",
  }),
  Object.freeze({
    id: "challenge-power-box-present",
    label: "带蓝色指示灯的黑色长方形电源盒",
    baseline_location: "桌面中部偏右，竖向摆放",
  }),
]);

const EXPECTED_VERDICTS = Object.freeze({
  "challenge-speaker-missing": "confirmed_missing",
  "challenge-controller-present": "visible_same_place",
  "challenge-keyboard-present": "visible_same_place",
  "challenge-power-box-present": "visible_same_place",
});
const CONTROL_IDS = new Set(CHALLENGE_CANDIDATES.slice(1).map((item) => item.id));
const CHALLENGE_CANDIDATES_JSON =
  serializeQwenVerifierCandidates(CHALLENGE_CANDIDATES);
const GROUND_TRUTH_SHA256 = sha256Utf8(
  JSON.stringify(
    CHALLENGE_CANDIDATES.map((candidate) => ({
      id: candidate.id,
      expected_verdict: EXPECTED_VERDICTS[candidate.id],
    })),
  ),
);

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

function privacySafeError(error) {
  const sanitized = sanitizedError(error);
  const safeLocalCode =
    typeof sanitized.code === "string" &&
    /^(?:flash_challenge|probe)_[a-z0-9_]{1,96}$/.test(sanitized.code);
  const safeNames = new Set([
    "AbortError",
    "APIConnectionError",
    "APIConnectionTimeoutError",
    "APIError",
    "Error",
    "TypeError",
    "UnknownError",
  ]);
  return {
    name: safeNames.has(sanitized.name) ? sanitized.name : "ExternalError",
    code:
      sanitized.code === null
        ? null
        : safeLocalCode
          ? "local_probe_error"
          : "external_error_redacted",
    status:
      Number.isInteger(sanitized.status) &&
      sanitized.status >= 400 &&
      sanitized.status <= 599
        ? sanitized.status
        : null,
  };
}

function validatePinnedConfiguration() {
  if (
    DEFAULT_QWEN_FAST_VERIFICATION_MODEL !== PINNED_FLASH_MODEL ||
    CHECKBACK_VERIFIER_PROMPT_VERSION !== "checkback-verifier-v1" ||
    CHECKBACK_VERIFIER_PROMPT_SHA256 !== PINNED_VERIFIER_FINGERPRINT_SHA256 ||
    sha256Utf8(QWEN_VERIFIER_SYSTEM_PROMPT) !==
      PINNED_VERIFIER_SYSTEM_PROMPT_SHA256 ||
    sha256Utf8(CHALLENGE_CANDIDATES_JSON) !== PINNED_CANDIDATE_SHA256 ||
    Object.keys(EXPECTED_VERDICTS).length !== CHALLENGE_CANDIDATES.length ||
    QWEN_VERIFIER_MAX_TOKENS !== 2200 ||
    QWEN_JSON_RESPONSE_FORMAT !== "json_object" ||
    QWEN_ENABLE_THINKING !== false ||
    QWEN_HIGH_RESOLUTION_IMAGES !== true
  ) {
    fail("flash_challenge_pinned_configuration_mismatch");
  }
}

function validatePriorArtifact(value, specification, pairCommitment) {
  const commonValid =
    value?.pair_commitment_sha256 === pairCommitment &&
    value?.call_slot === specification.slot &&
    value?.authorized_pair_transmission_limit === 5 &&
    value?.model === specification.model;
  if (!commonValid) fail("flash_challenge_prior_artifact_invariant_mismatch");

  if (specification.kind === "reservation") {
    if (
      value?.state !== "reserved_before_network" ||
      value?.max_retries !== 0 ||
      value?.probe_supported_call_slots?.length !== 1 ||
      value.probe_supported_call_slots[0] !== specification.slot
    ) {
      fail("flash_challenge_prior_reservation_invalid");
    }
    return;
  }

  if (
    value?.success !== true ||
    value?.network_requests_started !== 1 ||
    value?.retry_count !== 0 ||
    value?.request?.exact_authorized_pair !== true ||
    value?.response?.status !== 200
  ) {
    fail("flash_challenge_prior_result_invalid");
  }
  if (
    specification.slot === 2 &&
    (value?.cumulative_pair_transmissions_after_call !== 2 ||
      value?.decision?.plus_request_executed !== false)
  ) {
    fail("flash_challenge_call_2_result_invalid");
  }
}

function validatePriorLedger(directory, pairCommitment) {
  const validated = {};
  for (const specification of PRIOR_ARTIFACTS) {
    const path = resolve(directory, specification.name);
    const bytes = readFileSync(path);
    try {
      if (sha256(bytes) !== specification.sha256) {
        fail("flash_challenge_prior_artifact_hash_mismatch");
      }
      let value;
      try {
        value = JSON.parse(bytes.toString("utf8"));
      } catch {
        fail("flash_challenge_prior_artifact_json_invalid");
      }
      validatePriorArtifact(value, specification, pairCommitment);
      validated[specification.name] = specification.sha256;
    } finally {
      bytes.fill(0);
    }
  }
  return validated;
}

function validateChallengeRequest(
  bodyBytes,
  { expectedModel, expectedImages, apiKey },
) {
  let body;
  try {
    body = JSON.parse(bodyBytes.toString("utf8"));
  } catch {
    fail("flash_challenge_request_json_invalid");
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
      QWEN_VERIFIER_CANDIDATE_PREFIX + CHALLENGE_CANDIDATES_JSON ||
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
    fail("flash_challenge_request_shape_invalid");
  }
  validateEmbeddedImage(images[0], expectedImages[0]);
  validateEmbeddedImage(images[1], expectedImages[1]);
  const keyBytes = Buffer.from(apiKey, "utf8");
  try {
    if (bodyBytes.indexOf(keyBytes) !== -1) {
      fail("flash_challenge_credential_in_request_body");
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
    candidate_count: CHALLENGE_CANDIDATES.length,
  };
}

function scoreChallenge(verification, validationReason, providerError) {
  const byId = new Map(
    verification?.verifications.map((item) => [item.id, item]) ?? [],
  );
  const candidateResults = CHALLENGE_CANDIDATES.map((candidate, index) => {
    const actual = byId.get(candidate.id) ?? null;
    const expected = EXPECTED_VERDICTS[candidate.id];
    const controlRejectedMissing =
      CONTROL_IDS.has(candidate.id) &&
      actual?.certainty === "high" &&
      (actual.verdict === "visible_same_place" ||
        actual.verdict === "visible_elsewhere");
    return {
      candidate_index: index,
      role: index === 0 ? "true_missing" : "present_control",
      expected_verdict: expected,
      actual_verdict: actual?.verdict ?? null,
      certainty: actual?.certainty ?? null,
      current_location_present: Boolean(actual?.current_location?.trim()),
      false_missing_rejected: index === 0 ? null : controlRejectedMissing,
      exact_match:
        actual?.certainty === "high" && actual?.verdict === expected,
    };
  });
  const speaker = candidateResults[0];
  const controls = candidateResults.slice(1);
  const trueMissingPass =
    speaker.actual_verdict === "confirmed_missing" &&
    speaker.certainty === "high";
  const falsePositiveCount =
    verification?.verifications.filter(
      (item) =>
        CONTROL_IDS.has(item.id) && item.verdict === "confirmed_missing",
    ).length ?? 0;
  const allControlsRejectMissing = controls.every(
    (item) => item.false_missing_rejected === true,
  );
  const safetyPass =
    providerError === null &&
    verification !== null &&
    validationReason === null &&
    trueMissingPass &&
    allControlsRejectMissing &&
    falsePositiveCount === 0;
  const exactGroundTruthPass =
    safetyPass && candidateResults.every((item) => item.exact_match);
  return {
    batch_pass: exactGroundTruthPass,
    safety_pass: safetyPass,
    exact_ground_truth_pass: exactGroundTruthPass,
    one_vote_veto_applied: true,
    true_missing_pass: trueMissingPass,
    present_control_count: controls.length,
    present_controls_rejecting_missing: controls.filter(
      (item) => item.false_missing_rejected,
    ).length,
    severe_false_positive_count: falsePositiveCount,
    unresolved_or_low_confidence_count: candidateResults.filter(
      (item) =>
        item.actual_verdict === null ||
        item.actual_verdict === "not_comparable" ||
        item.certainty !== "high",
    ).length,
    candidate_results: candidateResults,
  };
}

function sanitizedResponse(value) {
  if (!value) return null;
  return {
    status: value.status,
    wire_body_bytes: value.wire_body_bytes,
    decoded_body_bytes: value.decoded_body_bytes,
  };
}

async function main() {
  if (!values.baseline || !values.current) {
    fail("flash_challenge_two_image_paths_required");
  }
  if (values["dry-run"] === values["execute-once"]) {
    fail("flash_challenge_choose_exactly_one_mode");
  }
  validatePinnedConfiguration();

  if (process.env.OPENAI_CUSTOM_HEADERS?.trim()) {
    fail("flash_challenge_custom_headers_forbidden");
  }
  const apiKey = process.env.DASHSCOPE_API_KEY?.trim();
  const baseURL = process.env.DASHSCOPE_BASE_URL?.trim();
  const primaryModel = process.env.QWEN_VISION_MODEL?.trim();
  if (!apiKey || !baseURL || !primaryModel) {
    fail("flash_challenge_qwen_configuration_missing");
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
    fail("flash_challenge_pinned_qwen_configuration_mismatch");
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
      fail("flash_challenge_authorized_pair_mismatch");
    }

    const outputDirectory = resolve(
      WEB_ROOT,
      `evaluation/live-diagnostics/authorized-pair-${pairCommitment}`,
    );
    const priorArtifacts = validatePriorLedger(outputDirectory, pairCommitment);
    const outputBase = resolve(outputDirectory, "call-3");
    const reservationPath = outputBase + ".reservation.json";
    const resultPath = outputBase + ".result.json";
    if (
      values["execute-once"] &&
      (existsSync(reservationPath) || existsSync(resultPath))
    ) {
      fail("flash_challenge_call_slot_already_consumed");
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
    const runId = `qwen_flash_false_positive_${Date.now()}_${pairCommitment.slice(0, 12)}`;
    if (values["execute-once"]) {
      writeExclusiveJson(reservationPath, {
        schema_version: "checkback.qwen-flash-false-positive-reservation.v1",
        run_id: runId,
        pair_commitment_sha256: pairCommitment,
        call_slot: 3,
        authorized_pair_transmission_limit: 5,
        previous_consumed_call_slot: 2,
        probe_supported_call_slots: [3],
        state: "reserved_before_network",
        created_at: new Date().toISOString(),
        endpoint_origin: parsedBase.origin,
        endpoint_path: "/compatible-mode/v1/chat/completions",
        model: PINNED_FLASH_MODEL,
        max_retries: 0,
        timeout_ms: VERIFIER_TIMEOUT_MS,
        candidate_source: "human_audited_false_positive_challenge_v1",
        candidate_payload_sha256: PINNED_CANDIDATE_SHA256,
        ground_truth_sha256: GROUND_TRUTH_SHA256,
        candidate_count: CHALLENGE_CANDIDATES.length,
        prior_artifact_sha256: priorArtifacts,
      });
    }

    let verification = null;
    let providerMetadata = null;
    let error = null;
    capture.analysis_started_at = performance.now();
    try {
      const dryRunContent = JSON.stringify({
        verifications: CHALLENGE_CANDIDATES.map((candidate) => ({
          id: candidate.id,
          verdict: EXPECTED_VERDICTS[candidate.id],
          certainty: "high",
          current_location: null,
          evidence: "dry-run",
        })),
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
          validateRequest: validateChallengeRequest,
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
                CHALLENGE_CANDIDATES_JSON,
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
        fail("flash_challenge_model_output_missing");
      }
      let parsedJson;
      try {
        parsedJson = JSON.parse(content);
      } catch {
        fail("flash_challenge_model_output_json_invalid");
      }
      const parsed = MissingVerificationSchema.safeParse(parsedJson);
      if (!parsed.success) {
        fail("flash_challenge_model_output_schema_invalid");
      }
      verification = parsed.data;
      providerMetadata = {
        finish_reason: completion.choices[0]?.finish_reason ?? null,
        prompt_tokens: completion.usage?.prompt_tokens ?? null,
        completion_tokens: completion.usage?.completion_tokens ?? null,
        total_tokens: completion.usage?.total_tokens ?? null,
      };
    } catch (caught) {
      error = privacySafeError(caught);
    }
    const verificationFinishedAt = performance.now();

    const validationReason = verification
      ? validateVerificationBatch(CHALLENGE_CANDIDATES, verification, true)
      : null;
    const scoredChallenge = scoreChallenge(
      verification,
      validationReason,
      error,
    );
    const executionContractPass = values["dry-run"]
      ? capture.transport_calls === 1 && capture.network_requests_started === 0
      : capture.transport_calls === 1 &&
        capture.network_requests_started === 1 &&
        capture.response?.status === 200;
    const challengeScore = {
      ...scoredChallenge,
      execution_contract_pass: executionContractPass,
      batch_pass: scoredChallenge.batch_pass && executionContractPass,
    };
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
    const result = {
      schema_version: "checkback.qwen-flash-false-positive-result.v1",
      run_id: runId,
      pair_commitment_sha256: pairCommitment,
      mode: values["dry-run"]
        ? "dry_run_no_network_false_positive_challenge"
        : "live_single_flash_false_positive_challenge",
      success: challengeScore.batch_pass,
      provider_success: error === null,
      verifier_output_valid: verification !== null && validationReason === null,
      call_slot: values["dry-run"] ? 0 : 3,
      authorized_pair_transmission_limit: 5,
      cumulative_pair_transmissions_after_call: values["dry-run"] ? 2 : 3,
      fetch_adapter_calls: capture.transport_calls,
      network_requests_started: capture.network_requests_started,
      retry_count: 0,
      endpoint: capture.endpoint,
      model: PINNED_FLASH_MODEL,
      request: capture.request,
      response: sanitizedResponse(capture.response),
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
        verifier_call_ms: round(
          verificationFinishedAt - capture.analysis_started_at,
        ),
        probe_through_verification_ms: round(
          verificationFinishedAt - processStartedAt,
        ),
      },
      timing_caveat:
        "local_request_write_finished_ms means bytes reached the local socket buffer; response_headers_after_local_write_ms is not pure model time.",
      challenge_context: {
        prompt_version: CHECKBACK_VERIFIER_PROMPT_VERSION,
        prompt_fingerprint_sha256: CHECKBACK_VERIFIER_PROMPT_SHA256,
        system_prompt_sha256: PINNED_VERIFIER_SYSTEM_PROMPT_SHA256,
        candidate_source: "human_audited_false_positive_challenge_v1",
        candidate_payload_sha256: PINNED_CANDIDATE_SHA256,
        ground_truth_sha256: GROUND_TRUTH_SHA256,
        candidate_count: CHALLENGE_CANDIDATES.length,
        prior_artifact_sha256: priorArtifacts,
      },
      decision: {
        validation_reason: validationReason,
        plus_fallback_would_be_required: !challengeScore.batch_pass,
        plus_request_executed: false,
        active_mode_enabled: false,
        deployment_changed: false,
      },
      verification_sha256: verificationSha256,
      challenge_score: challengeScore,
      error,
      completed_at: new Date().toISOString(),
    };

    if (values["execute-once"]) writeExclusiveJson(resultPath, result);
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    if (!challengeScore.batch_pass) process.exitCode = 1;
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
    JSON.stringify({ success: false, error: privacySafeError(error) }) + "\n",
  );
  process.exitCode = 1;
});
