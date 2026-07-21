import { AnalysisModeSchema } from "../../lib/analysis-mode";
import { normalizeCheckbackReport } from "../../lib/checkback-analysis";
import { adaptReportForMode } from "../../lib/mode-report";
import { localeFromAcceptLanguage, parseAppLocale } from "../../lib/locale";
import {
  acquireAnalysisPermit,
  validateAnalysisRequest,
  type GuardRejection,
} from "../../lib/request-guard";
import {
  MAX_ANALYSIS_FORM_BYTES,
  parseRequestFormData,
} from "../../lib/request-form-data";
import {
  analyzeImagePairWithScout,
  getVisionRuntime,
  verifyMissingCandidates,
} from "../../lib/vision-provider";

const MAX_IMAGE_BYTES = 430 * 1024;
const MAX_IMAGE_EDGE = 4096;
const MAX_IMAGE_PIXELS = 16_000_000;
const JPEG_START_OF_FRAME_MARKERS = new Set([
  0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
]);

type PreparedImageResult =
  | { bytes: Uint8Array; error?: never }
  | { error: string; bytes?: never };

function isImageFile(value: FormDataEntryValue | null): value is File {
  return Boolean(
    value &&
      typeof value !== "string" &&
      typeof value.arrayBuffer === "function" &&
      typeof value.size === "number",
  );
}

function validateImage(file: File, label: string): string | null {
  if (file.type !== "image/jpeg") return label + "不是有效的 JPEG 图片，请重新拍摄";
  if (file.size <= 0) return label + "为空，请重新拍摄";
  if (file.size > MAX_IMAGE_BYTES) return label + "还未完成移动端压缩，请重新拍摄";
  return null;
}

function readUint16(bytes: Uint8Array, offset: number) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function readJpegDimensions(bytes: Uint8Array) {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;

  let offset = 2;
  while (offset + 3 < bytes.length) {
    if (bytes[offset] !== 0xff) {
      offset += 1;
      continue;
    }

    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    if (offset >= bytes.length) return null;
    const marker = bytes[offset];
    offset += 1;

    if (marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 1 >= bytes.length) return null;

    const length = readUint16(bytes, offset);
    if (length < 2 || offset + length > bytes.length) return null;
    if (JPEG_START_OF_FRAME_MARKERS.has(marker)) {
      if (length < 7) return null;
      const height = readUint16(bytes, offset + 3);
      const width = readUint16(bytes, offset + 5);
      return width > 0 && height > 0 ? { width, height } : null;
    }
    offset += length;
  }

  return null;
}

function stripJpegMetadata(bytes: Uint8Array) {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;

  const chunks: Uint8Array[] = [bytes.slice(0, 2)];
  let totalLength = 2;
  let offset = 2;

  while (offset < bytes.length) {
    const markerStart = offset;
    if (bytes[offset] !== 0xff) return null;
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    if (offset >= bytes.length) return null;

    const marker = bytes[offset];
    offset += 1;
    if (marker === 0xda) {
      const tail = bytes.slice(markerStart);
      chunks.push(tail);
      totalLength += tail.length;
      break;
    }
    if (marker === 0xd9) {
      const end = bytes.slice(markerStart, offset);
      chunks.push(end);
      totalLength += end.length;
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      const standalone = bytes.slice(markerStart, offset);
      chunks.push(standalone);
      totalLength += standalone.length;
      continue;
    }
    if (offset + 1 >= bytes.length) return null;

    const length = readUint16(bytes, offset);
    if (length < 2 || offset + length > bytes.length) return null;
    const segmentEnd = offset + length;
    const containsMetadata = marker === 0xe1 || marker === 0xed || marker === 0xfe;
    if (!containsMetadata) {
      const segment = bytes.slice(markerStart, segmentEnd);
      chunks.push(segment);
      totalLength += segment.length;
    }
    offset = segmentEnd;
  }

  if (chunks.length < 2) return null;
  const sanitized = new Uint8Array(totalLength);
  let cursor = 0;
  for (const chunk of chunks) {
    sanitized.set(chunk, cursor);
    cursor += chunk.length;
  }
  return sanitized;
}

async function prepareImage(file: File, label: string): Promise<PreparedImageResult> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const dimensions = readJpegDimensions(bytes);
  if (!dimensions) return { error: label + "内容不是有效的 JPEG 图片" };
  if (
    dimensions.width > MAX_IMAGE_EDGE ||
    dimensions.height > MAX_IMAGE_EDGE ||
    dimensions.width * dimensions.height > MAX_IMAGE_PIXELS
  ) {
    return { error: label + "尺寸过大，请重新拍摄" };
  }

  const sanitized = stripJpegMetadata(bytes);
  if (!sanitized) return { error: label + "内容损坏，请重新拍摄" };
  return { bytes: sanitized };
}

function bytesToBase64(bytes: Uint8Array): string {
  const chunkSize = 0x8000;
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function imageToDataUrl(bytes: Uint8Array) {
  return "data:image/jpeg;base64," + bytesToBase64(bytes);
}

function json(payload: unknown, status = 200, headers?: HeadersInit) {
  return Response.json(payload, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

function guardResponse(rejection: GuardRejection) {
  return json(
    { code: rejection.code, message: rejection.message },
    rejection.status,
    rejection.retryAfter ? { "Retry-After": String(rejection.retryAfter) } : undefined,
  );
}

function mapServiceError(error: unknown) {
  const status =
    typeof error === "object" && error !== null && "status" in error
      ? Number((error as { status?: unknown }).status)
      : 0;

  if (status === 401 || status === 403) {
    return json(
      {
        code: "SERVICE_CONFIGURATION_ERROR",
        message: "检查服务暂时不可用，照片已经保留，请稍后重试",
      },
      503,
    );
  }
  if (status === 429) {
    return json({ code: "SERVICE_BUSY", message: "现在检查的人有点多，请稍后重试" }, 429);
  }
  if (status === 400) {
    return json({ code: "IMAGE_REJECTED", message: "照片无法分析，请重新拍摄清晰画面" }, 400);
  }
  if (error instanceof Error && /timeout|timed out|abort/i.test(error.message)) {
    return json({ code: "ANALYSIS_TIMEOUT", message: "这次检查时间比平时长，请直接重试" }, 504);
  }
  return json({ code: "ANALYSIS_FAILED", message: "暂时无法可靠完成这次检查，请重试" }, 502);
}

export async function POST(request: Request) {
  const locale =
    parseAppLocale(request.headers.get("x-checkback-locale")) ??
    localeFromAcceptLanguage(request.headers.get("accept-language")) ??
    "zh-CN";
  const startedAt = Date.now();
  const analysisId = crypto.randomUUID();

  try {
    const requestRejection = validateAnalysisRequest(request);
    if (requestRejection) return guardResponse(requestRejection);

    const runtime = getVisionRuntime();
    if (!runtime) {
      return json(
        {
          code: "SERVICE_NOT_CONFIGURED",
          message: "检查服务尚未配置，照片已经保留，请联系管理员",
        },
        503,
      );
    }

    const permit = acquireAnalysisPermit(request);
    if (!permit.ok) return guardResponse(permit);

    try {
      const parsedFormData = await parseRequestFormData(request, MAX_ANALYSIS_FORM_BYTES);
      if (!parsedFormData.ok) {
        if (parsedFormData.reason === "too_large") {
          return json(
            { code: "REQUEST_TOO_LARGE", message: "两张照片合计过大，请重新拍摄后重试" },
            413,
          );
        }
        if (parsedFormData.reason === "aborted") {
          return json({ code: "REQUEST_ABORTED", message: "检查已取消" }, 499);
        }
        return json(
          { code: "INVALID_FORM_DATA", message: "照片请求格式不正确，请从 CheckBack 页面重试" },
          400,
        );
      }
    const { formData } = parsedFormData;
    const baseline = formData.get("baseline");
    const current = formData.get("current");
    const modeValue = formData.get("mode");
    const parsedMode = AnalysisModeSchema.safeParse(
      typeof modeValue === "string" ? modeValue : "restoration",
    );
    if (!parsedMode.success) {
      return json(
        { code: "INVALID_MODE", message: "\u68c0\u67e5\u6a21\u5f0f\u65e0\u6548\uff0c\u8bf7\u91cd\u65b0\u9009\u62e9\u533a\u57df" },
        400,
      );
    }
    const analysisMode = parsedMode.data;

    if (!isImageFile(baseline) || !isImageFile(current)) {
      return json({ code: "MISSING_IMAGES", message: "需要标准照片和当前照片才能检查" }, 400);
    }

    const validationError =
      validateImage(baseline, "标准照片") ?? validateImage(current, "当前照片");
    if (validationError) {
      return json({ code: "INVALID_IMAGE", message: validationError }, 400);
    }

    const requestParseMs = Date.now() - startedAt;
    const imagePrepareStartedAt = Date.now();
    const [preparedBaseline, preparedCurrent] = await Promise.all([
      prepareImage(baseline, "标准照片"),
      prepareImage(current, "当前照片"),
    ]);
    const imagePrepareMs = Date.now() - imagePrepareStartedAt;
    if ("error" in preparedBaseline) {
      return json({ code: "INVALID_IMAGE", message: preparedBaseline.error }, 400);
    }
    if ("error" in preparedCurrent) {
      return json({ code: "INVALID_IMAGE", message: preparedCurrent.error }, 400);
    }

      const dataUrlStartedAt = Date.now();
      const baselineDataUrl = imageToDataUrl(preparedBaseline.bytes);
      const currentDataUrl = imageToDataUrl(preparedCurrent.bytes);
      const dataUrlMs = Date.now() - dataUrlStartedAt;
      const preprocessingMs = Date.now() - startedAt;
      const observerStartedAt = Date.now();
      const analysisResult = await analyzeImagePairWithScout(
        runtime,
        baselineDataUrl,
        currentDataUrl,
        request.signal,
        analysisMode,
        locale,
      );
      const observerAiMs = Date.now() - observerStartedAt;
      const raw = analysisResult.analysis;
      const scoutDiagnostics = analysisResult.diagnostics;
      const primaryAiMs = scoutDiagnostics.primary_ms;

      if (!raw) {
        return json(
          { code: "UNRELIABLE_OUTPUT", message: "这次没有得到可靠结论，请重新拍摄后重试" },
          422,
        );
      }

      const verificationStartedAt = Date.now();
      const verificationResult = await verifyMissingCandidates(
        runtime,
        baselineDataUrl,
        currentDataUrl,
        raw,
        {
          ...(scoutDiagnostics.enabled ? { qwenModeOverride: "off" as const } : {}),
          signal: request.signal,
        },
      );
      const verificationAiMs = Date.now() - verificationStartedAt;
      const reportStartedAt = Date.now();
      const report = adaptReportForMode(
        normalizeCheckbackReport(raw, verificationResult.verification, {
          analysisId,
          processingMs: 0,
        }, locale),
        raw,
        analysisMode,
        locale,
      );
      const reportAssemblyMs = Date.now() - reportStartedAt;
      const totalMs = Date.now() - startedAt;
      report.processing_ms = totalMs;
      const verificationDiagnostics = verificationResult.diagnostics;
      const verificationPlusRole =
        scoutDiagnostics.enabled &&
        verificationDiagnostics.provider_calls > 0
          ? "adaptive_final"
          :
        runtime.qwenVerification?.mode === "shadow" &&
        verificationDiagnostics.provider_calls > 1
          ? "shadow_control"
          : runtime.qwenVerification?.mode === "active" &&
              verificationDiagnostics.provider_calls > 1
            ? "active_fallback"
            : runtime.qwenVerification?.mode === "off" &&
                verificationDiagnostics.provider_calls > 0
              ? "primary_verifier"
              : "none";
      const diagnostics = {
        request_parse_ms: requestParseMs,
        image_prepare_ms: imagePrepareMs,
        data_url_ms: dataUrlMs,
        preprocessing_ms: preprocessingMs,
        report_assembly_ms: reportAssemblyMs,
        primary_ai_ms: primaryAiMs,
        observer_ai_ms: observerAiMs,
        missing_scout_ms: scoutDiagnostics.scout_ms,
        observer_provider_calls: scoutDiagnostics.provider_calls,
        missing_scout_provider_calls: scoutDiagnostics.enabled ? 1 : 0,
        dual_observer_enabled: Number(scoutDiagnostics.enabled),
        missing_scout_candidate_count: scoutDiagnostics.scout_candidate_count,
        missing_scout_merged_count: scoutDiagnostics.merged_candidate_count,
        missing_scout_added_count: scoutDiagnostics.added_candidate_count,
        missing_scout_path: scoutDiagnostics.path,
        missing_scout_comparison: scoutDiagnostics.comparison,
        missing_scout_terminal_reason: scoutDiagnostics.terminal_reason ?? null,
        missing_scout_model: runtime.qwenMissingScout?.model ?? null,
        missing_scout_prompt_version: runtime.qwenMissingScout?.promptVersion ?? null,
        verification_ai_ms: verificationAiMs,
        fast_verifier_ms: verificationDiagnostics.fast_ms,
        verification_fallback_ms: verificationDiagnostics.fallback_ms,
        verification_provider_calls: verificationDiagnostics.provider_calls,
        verification_fallback_used: verificationPlusRole === "active_fallback" ? 1 : 0,
        verification_plus_role: verificationPlusRole,
        verification_shadow_agreement:
          verificationDiagnostics.shadow_agreement === null
            ? -1
            : Number(verificationDiagnostics.shadow_agreement),
        verification_active_fast_eligible:
          verificationDiagnostics.active_fast_eligible === null
            ? -1
            : Number(verificationDiagnostics.active_fast_eligible),
        verifier_path: verificationDiagnostics.path,
        verifier_fallback_reason: verificationDiagnostics.fallback_reason ?? null,
        verifier_active_fallback_reason: verificationDiagnostics.active_fallback_reason ?? null,
        verifier_primary_model: runtime.provider === "qwen" ? runtime.model : null,
        verifier_fast_model: runtime.qwenVerification?.fastModel ?? null,
        verifier_plus_model: runtime.qwenVerification?.fallbackModel ?? null,
        verifier_prompt_version: runtime.qwenVerification?.promptVersion ?? null,
        verifier_prompt_sha256: runtime.qwenVerification?.promptSha256 ?? null,
        verifier_terminal_reason: verificationDiagnostics.terminal_reason ?? null,
        total_ms: totalMs,
      };
      const serverTiming = [
        "request_parse;dur=" + requestParseMs,
        "image_prepare;dur=" + imagePrepareMs,
        "data_url;dur=" + dataUrlMs,
        "preprocessing;dur=" + preprocessingMs,
        "primary_ai;dur=" + primaryAiMs,
        "observer_ai;dur=" + observerAiMs,
        "missing_scout;dur=" + scoutDiagnostics.scout_ms,
        "verification_ai;dur=" + verificationAiMs,
        "verification_fast;dur=" + verificationDiagnostics.fast_ms,
        "verification_fallback;dur=" + verificationDiagnostics.fallback_ms,
        "report_assembly;dur=" + reportAssemblyMs,
        "total;dur=" + totalMs,
      ].join(", ");

      return json({ report, diagnostics }, 200, { "Server-Timing": serverTiming });
    } finally {
      permit.release();
    }
  } catch (error) {
    return mapServiceError(error);
  }
}
