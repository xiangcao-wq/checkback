/* eslint-disable @next/next/no-img-element */
"use client";

import {
  Camera,
  CheckCircle,
  CaretDown,
  GlobeHemisphereWest,
  ImagesSquare,
  MapPinArea,
  PencilSimple,
  Scan,
  ShieldCheck,
  Warning,
  X,
} from "@phosphor-icons/react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AnalysisMode } from "./lib/analysis-mode";
import type { CheckbackReport, ReportItem } from "./lib/checkback-analysis";
import {
  createArea as createStoredArea,
  initializeAreaWorkspace,
  saveCheckHistory,
  setActiveArea as persistActiveArea,
  analysisModeMeta,
  displayAreaName,
  type CheckArea,
} from "./lib/area-store";
import {
  ensureCurrentBaselineVersion,
  loadBaselineImage,
  saveBaselineImage,
} from "./lib/area-baseline-store";
import {
  persistPerformanceSample,
  type PerformanceSample,
} from "./lib/performance-history";
import { WorkspacePanel } from "./workspace-panel";
import { useAppLocale } from "./locale-provider";
import { localize, type AppLocale } from "./lib/locale";

type Phase = "loading" | "baseline" | "camera" | "analyzing" | "result" | "error";
type CameraState = "idle" | "starting" | "live" | "unavailable";
type AnalysisStage = "preparing" | "uploading" | "analyzing";
type PhotoPurpose = "baseline" | "current";

type AnalysisDiagnostics = {
  request_parse_ms?: number;
  image_prepare_ms?: number;
  data_url_ms?: number;
  report_assembly_ms?: number;
  preprocessing_ms: number;
  primary_ai_ms: number;
  observer_ai_ms?: number;
  missing_scout_ms?: number;
  observer_provider_calls?: number;
  missing_scout_provider_calls?: number;
  dual_observer_enabled?: number;
  missing_scout_candidate_count?: number;
  missing_scout_merged_count?: number;
  missing_scout_added_count?: number;
  verification_ai_ms: number;
  fast_verifier_ms?: number;
  verification_fallback_ms?: number;
  verification_provider_calls?: number;
  verification_fallback_used?: number;
  verification_plus_role?:
    | "none"
    | "primary_verifier"
    | "adaptive_final"
    | "shadow_control"
    | "active_fallback";
  verification_shadow_agreement?: number;
  verification_active_fast_eligible?: number;
  verifier_active_fallback_reason?: string | null;
  verifier_primary_model?: string | null;
  verifier_fast_model?: string | null;
  verifier_plus_model?: string | null;
  verifier_prompt_version?: string | null;
  verifier_prompt_sha256?: string | null;
  verifier_path?: string;
  verifier_fallback_reason?: string | null;
  verifier_terminal_reason?: string | null;
  total_ms: number;
};

type AnalysisResponseBody = {
  code?: string;
  report?: CheckbackReport;
  message?: string;
  diagnostics?: AnalysisDiagnostics;
};

function analysisErrorMessage(code: string | undefined, locale: AppLocale, serverMessage?: string) {
  const messages: Record<string, [string, string]> = {
    SERVICE_CONFIGURATION_ERROR: ["检查服务暂时不可用，照片已经保留，请稍后重试", "The check service is temporarily unavailable. Your photo is still here; try again later"],
    SERVICE_NOT_CONFIGURED: ["检查服务尚未配置，请联系管理员", "The check service is not configured. Please contact the administrator"],
    SERVICE_BUSY: ["现在检查的人有点多，请稍后重试", "The check service is busy. Please try again shortly"],
    CLIENT_RATE_LIMIT: ["这台设备的检查次数已达到临时上限，请稍后再试", "This device has reached the temporary check limit. Please try again later"],
    DAILY_LIMIT: ["今天的体验额度已用完，请联系作品提交者", "Today's check allowance has been used. Please contact the administrator"],
    CONCURRENT_LIMIT: ["当前正在检查的人较多，请稍后重试", "Several checks are running right now. Please try again shortly"],
    ANALYSIS_DISABLED: ["检查服务暂时关闭，请稍后再试", "The check service is temporarily paused. Please try again later"],
    UNTRUSTED_ORIGIN: ["请从 CheckBack 页面发起检查", "Please start the check from the CheckBack page"],
    REQUEST_TOO_LARGE: ["两张照片合计过大，请重新拍摄后重试", "The two photos are too large. Retake them and try again"],
    INVALID_FORM_DATA: ["照片请求格式不正确，请重试", "The photo request format is invalid. Please try again"],
    INVALID_MODE: ["检查模式无效，请重新选择区域", "The check mode is invalid. Select the area again"],
    MISSING_IMAGES: ["需要标准照片和当前照片才能检查", "A reference photo and a current photo are required"],
    INVALID_IMAGE: ["照片无法处理，请重新拍摄清晰画面", "The photo could not be processed. Retake a clear image"],
    IMAGE_REJECTED: ["照片无法分析，请重新拍摄清晰画面", "The photo could not be analyzed. Retake a clear image"],
    ANALYSIS_TIMEOUT: ["这次检查时间比平时长，请直接重试", "This check took longer than usual. Please try again"],
    UNRELIABLE_OUTPUT: ["这次没有得到可靠结论，请重新拍摄后重试", "No reliable conclusion was produced. Retake the photo and try again"],
    ANALYSIS_FAILED: ["暂时无法可靠完成这次检查，请重试", "The check could not be completed reliably. Please try again"],
    REQUEST_ABORTED: ["检查已取消", "Check canceled"],
  };
  const message = code ? messages[code] : undefined;
  if (message) return localize(locale, message[0], message[1]);
  return locale === "en" ? "The check did not finish. Please try again" : serverMessage || "这次检查没有完成，请重试";
}

type AnalysisRequestResult = {
  status: number;
  body: AnalysisResponseBody;
  uploadMs: number;
  serverWaitMs: number;
  responseHeadersMs: number;
  responseDownloadMs: number;
  responseParseMs: number;
  responseBytes: number;
  requestMs: number;
};

type PhotoPreparationOptions = {
  alreadyPrepared?: boolean;
  preparationVisible?: boolean;
  startedAt?: number;
};

const ITEM_LABELS: Record<ReportItem["type"], string> = {
  missing: "缺少",
  misplaced: "放错位置",
  added: "新增物品",
  occluded: "被遮挡",
  uncovered: "未拍到",
  uncertain: "暂不确定",
};

const ITEM_LABELS_EN: Record<ReportItem["type"], string> = {
  missing: "Missing",
  misplaced: "Misplaced",
  added: "Added item",
  occluded: "Occluded",
  uncovered: "Out of frame",
  uncertain: "Uncertain",
};

function useObjectUrl(file: File | null) {
  const url = useMemo(() => (file ? URL.createObjectURL(file) : ""), [file]);

  useEffect(() => {
    return () => {
      if (url) URL.revokeObjectURL(url);
    };
  }, [url]);

  return url;
}

const MAX_PROCESSED_IMAGE_BYTES = 430 * 1024;

function fileFromBlob(blob: Blob, prefix: string) {
  return new File([blob], prefix + "-" + Date.now() + ".jpg", {
    type: "image/jpeg",
    lastModified: Date.now(),
  });
}

function canvasToJpeg(canvas: HTMLCanvasElement, quality: number) {
  return new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/jpeg", quality));
}

function throwIfAborted(locale: AppLocale, signal?: AbortSignal) {
  if (signal?.aborted) {
    throw new DOMException(localize(locale, "操作已取消", "Operation canceled"), "AbortError");
  }
}

async function preparePhoto(file: File, prefix: string, locale: AppLocale, signal?: AbortSignal) {
  throwIfAborted(locale, signal);
  const imageUrl = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.src = imageUrl;
    await image.decode();
    throwIfAborted(locale, signal);

    let maxSide = 1600;
    let quality = 0.82;
    let lastBlob: Blob | null = null;

    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d");
    if (!context) throw new Error(localize(locale, "无法处理照片", "Could not process the photo"));
    let drawnWidth = 0;
    let drawnHeight = 0;

    for (let attempt = 0; attempt < 9; attempt += 1) {
      const scale = Math.min(1, maxSide / Math.max(image.naturalWidth, image.naturalHeight));
      const width = Math.max(1, Math.round(image.naturalWidth * scale));
      const height = Math.max(1, Math.round(image.naturalHeight * scale));
      if (width !== drawnWidth || height !== drawnHeight) {
        canvas.width = width;
        canvas.height = height;
        context.drawImage(image, 0, 0, width, height);
        drawnWidth = width;
        drawnHeight = height;
      }

      lastBlob = await canvasToJpeg(canvas, quality);
      throwIfAborted(locale, signal);
      if (!lastBlob) throw new Error(localize(locale, "无法处理照片", "Could not process the photo"));
      if (lastBlob.size <= MAX_PROCESSED_IMAGE_BYTES) {
        return fileFromBlob(lastBlob, prefix);
      }

      if (quality > 0.58) quality -= 0.08;
      else {
        maxSide = Math.round(maxSide * 0.8);
        quality = 0.72;
      }
    }

    if (!lastBlob || lastBlob.size > MAX_PROCESSED_IMAGE_BYTES) {
      throw new Error(localize(locale, "照片内容过于复杂，请换个角度重拍", "The photo is too complex to process. Try another angle"));
    }
    return fileFromBlob(lastBlob, prefix);
  } finally {
    URL.revokeObjectURL(imageUrl);
  }
}

function waitForPaint() {
  return new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
}

function submitAnalysis(
  formData: FormData,
  locale: AppLocale,
  handlers: {
    onCreated: (request: XMLHttpRequest) => void;
    onUploadProgress: (percent: number | null) => void;
    onUploadComplete: () => void;
  },
) {
  return new Promise<AnalysisRequestResult>((resolve, reject) => {
    const requestStartedAt = performance.now();
    let uploadStartedAt = requestStartedAt;
    let uploadCompletedAt = requestStartedAt;
    let responseHeadersAt: number | null = null;
    const xhr = new XMLHttpRequest();

    xhr.open("POST", "/api/analyze");
    xhr.withCredentials = true;
    xhr.timeout = 400_000;
    xhr.setRequestHeader("Accept", "application/json");
    xhr.setRequestHeader("X-CheckBack-Locale", locale);
    handlers.onCreated(xhr);

    xhr.upload.addEventListener("loadstart", () => {
      uploadStartedAt = performance.now();
      handlers.onUploadProgress(0);
    });
    xhr.upload.addEventListener("progress", (event) => {
      const percent =
        event.lengthComputable && event.total > 0
          ? Math.min(100, Math.round((event.loaded / event.total) * 100))
          : null;
      handlers.onUploadProgress(percent);
    });
    xhr.upload.addEventListener("load", () => {
      uploadCompletedAt = performance.now();
      handlers.onUploadProgress(100);
      handlers.onUploadComplete();
    });
    xhr.addEventListener("readystatechange", () => {
      if (xhr.readyState >= XMLHttpRequest.HEADERS_RECEIVED && responseHeadersAt === null) {
        responseHeadersAt = performance.now();
      }
    });
    xhr.addEventListener("load", () => {
      const responseCompletedAt = performance.now();
      const parseStartedAt = performance.now();
      let body: AnalysisResponseBody = {};
      try {
        body = JSON.parse(xhr.responseText) as AnalysisResponseBody;
      } catch {
        body = {};
      }
      const responseParsedAt = performance.now();
      const headersAt = responseHeadersAt ?? responseCompletedAt;
      resolve({
        status: xhr.status,
        body,
        uploadMs: Math.max(0, uploadCompletedAt - uploadStartedAt),
        serverWaitMs: Math.max(0, headersAt - uploadCompletedAt),
        responseHeadersMs: Math.max(0, headersAt - requestStartedAt),
        responseDownloadMs: Math.max(0, responseCompletedAt - headersAt),
        responseParseMs: Math.max(0, responseParsedAt - parseStartedAt),
        responseBytes: new Blob([xhr.responseText]).size,
        requestMs: responseParsedAt - requestStartedAt,
      });
    });
    xhr.addEventListener("error", () => reject(new Error(localize(locale, "网络连接中断，请检查网络后重试", "The connection was interrupted. Check your network and try again"))));
    xhr.addEventListener("timeout", () => reject(new Error(localize(locale, "这次检查时间比平时长，请直接重试", "This check is taking longer than usual. Please try again"))));
    xhr.addEventListener("abort", () => reject(new Error(localize(locale, "检查已取消", "Check canceled"))));

    xhr.send(formData);
  });
}

function savePerformanceSample(sample: PerformanceSample) {
  try {
    persistPerformanceSample(window.localStorage, window.sessionStorage, sample);
  } catch {
    // Performance diagnostics must never interrupt a check.
  }
}

const INITIAL_AREA: CheckArea = {
  id: "default",
  name: "\u529e\u516c\u684c",
  mode: "restoration",
  createdAt: 0,
  updatedAt: 0,
};

export default function Home() {
  const { locale, toggleLocale } = useAppLocale();
  const l = useCallback((chinese: string, english: string) => localize(locale, chinese, english), [locale]);
  const [phase, setPhase] = useState<Phase>("loading");
  const [cameraState, setCameraState] = useState<CameraState>("idle");
  const [baseline, setBaseline] = useState<File | null>(null);
  const [current, setCurrent] = useState<File | null>(null);
  const [operationBusy, setOperationBusy] = useState(false);
  const [report, setReport] = useState<CheckbackReport | null>(null);
  const [message, setMessage] = useState("");
  const [toast, setToast] = useState("");
  const [analysisStage, setAnalysisStage] = useState<AnalysisStage>("preparing");
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [analysisElapsed, setAnalysisElapsed] = useState(0);
  const [areas, setAreas] = useState<CheckArea[]>([INITIAL_AREA]);
  const [activeArea, setActiveArea] = useState<CheckArea>(INITIAL_AREA);
  const [workspaceOpen, setWorkspaceOpen] = useState(false);

  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pendingPhotoPurposeRef = useRef<{
    purpose: PhotoPurpose;
    modeEpoch: number;
  } | null>(null);
  const photoModeEpochRef = useRef(0);
  const streamRef = useRef<MediaStream | null>(null);
  const cameraGenerationRef = useRef(0);
  const analysisRequestRef = useRef<{
    operationId: number;
    request: XMLHttpRequest;
  } | null>(null);
  const operationSequenceRef = useRef(0);
  const operationBusyRef = useRef(false);
  const photoOperationRef = useRef<{
    operationId: number;
    controller: AbortController;
  } | null>(null);

  const baselineUrl = useObjectUrl(baseline);
  const currentUrl = useObjectUrl(current);
  const isReplacingBaseline = phase === "baseline" && Boolean(baseline);
  const capturingStandard = phase === "baseline";

  const invalidatePendingPhotoIntent = useCallback(() => {
    photoModeEpochRef.current += 1;
    pendingPhotoPurposeRef.current = null;
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, []);

  const stopCamera = useCallback(() => {
    cameraGenerationRef.current += 1;
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    if (videoRef.current) videoRef.current.srcObject = null;
    setCameraState("idle");
  }, []);

  const startCamera = useCallback(async () => {
    stopCamera();
    const generation = cameraGenerationRef.current;
    if (!navigator.mediaDevices?.getUserMedia) {
      setCameraState("unavailable");
      setMessage(l("请使用手机相机拍摄", "Please use your phone camera"));
      return;
    }

    setCameraState("starting");
    setMessage("");
    let openedStream: MediaStream | null = null;
    try {
      openedStream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: {
          facingMode: { ideal: "environment" },
          width: { ideal: 1920 },
          height: { ideal: 1440 },
        },
      });
      if (cameraGenerationRef.current !== generation) {
        openedStream.getTracks().forEach((track) => track.stop());
        return;
      }

      streamRef.current = openedStream;
      const video = videoRef.current;
      if (video) {
        video.srcObject = openedStream;
        await video.play();
      }
      if (cameraGenerationRef.current !== generation) {
        openedStream.getTracks().forEach((track) => track.stop());
        if (streamRef.current === openedStream) streamRef.current = null;
        if (video?.srcObject === openedStream) video.srcObject = null;
        return;
      }
      setCameraState("live");
    } catch {
      openedStream?.getTracks().forEach((track) => track.stop());
      if (streamRef.current === openedStream) streamRef.current = null;
      if (videoRef.current?.srcObject === openedStream) {
        videoRef.current.srcObject = null;
      }
      if (cameraGenerationRef.current !== generation) return;
      setCameraState("unavailable");
      setMessage(l("相机没有打开，点击快门改用系统相机", "The camera did not open. Use the shutter to open your system camera"));
    }
  }, [l, stopCamera]);

  useEffect(() => {
    let mounted = true;
    void (async () => {
      try {
        const workspace = await initializeAreaWorkspace();
        const stored = await loadBaselineImage(workspace.activeArea.id);
        if (!mounted) return;
        setAreas(workspace.areas);
        setActiveArea(workspace.activeArea);
        setBaseline(stored);
        setPhase(stored ? "camera" : "baseline");
      } catch {
        if (!mounted) return;
        setMessage(l("本地区域数据不可用，请重新拍摄", "Local area data is unavailable. Please capture a new reference"));
        setPhase("baseline");
      }
    })();
    return () => {
      mounted = false;
    };
  }, [l]);

  useEffect(() => {
    if (phase === "baseline" || phase === "camera") return;
    const task = window.setTimeout(stopCamera, 0);
    return () => window.clearTimeout(task);
  }, [phase, stopCamera]);

  useEffect(() => {
    return () => stopCamera();
  }, [l, stopCamera]);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(""), 2600);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const beginPhotoOperation = useCallback(() => {
    if (operationBusyRef.current) return null;
    operationBusyRef.current = true;
    setOperationBusy(true);
    operationSequenceRef.current += 1;
    const operationId = operationSequenceRef.current;
    photoOperationRef.current = {
      operationId,
      controller: new AbortController(),
    };
    return operationId;
  }, []);

  const isPhotoOperationActive = useCallback((operationId: number) => {
    const operation = photoOperationRef.current;
    return (
      operationSequenceRef.current === operationId &&
      operation?.operationId === operationId &&
      !operation.controller.signal.aborted
    );
  }, []);

  const finishPhotoOperation = useCallback((operationId: number) => {
    if (operationSequenceRef.current === operationId) {
      if (photoOperationRef.current?.operationId === operationId) {
        photoOperationRef.current = null;
      }
      operationBusyRef.current = false;
      setOperationBusy(false);
    }
  }, []);

  useEffect(() => {
    return () => {
      photoOperationRef.current?.controller.abort();
      photoOperationRef.current = null;
      operationSequenceRef.current += 1;
      operationBusyRef.current = false;
      photoModeEpochRef.current += 1;
      pendingPhotoPurposeRef.current = null;
      analysisRequestRef.current?.request.abort();
    };
  }, []);

  useEffect(() => {
    if (phase !== "analyzing" || analysisStage !== "analyzing") return;
    const startedAt = performance.now();
    const updateElapsed = () => {
      setAnalysisElapsed(Math.floor((performance.now() - startedAt) / 1000));
    };
    updateElapsed();
    const interval = window.setInterval(updateElapsed, 1000);
    return () => window.clearInterval(interval);
  }, [analysisStage, phase]);

  const analyze = useCallback(
    async (
      photo: File,
      metrics: { flowStartedAt: number; preparationMs: number; sourceBytes: number },
      operationId: number,
    ) => {
      if (!baseline || !isPhotoOperationActive(operationId)) {
        finishPhotoOperation(operationId);
        return;
      }
      setPhase("analyzing");
      setAnalysisStage("uploading");
      setUploadProgress(0);
      setAnalysisElapsed(0);
      setMessage("");
      setReport(null);
      await waitForPaint();
      if (!isPhotoOperationActive(operationId)) {
        finishPhotoOperation(operationId);
        return;
      }

      try {
        const formData = new FormData();
        formData.append("baseline", baseline);
        formData.append("current", photo);
        formData.append("mode", activeArea.mode);
        const result = await submitAnalysis(formData, locale, {
          onCreated: (request) => {
            if (!isPhotoOperationActive(operationId)) {
              request.abort();
              return;
            }
            analysisRequestRef.current = { operationId, request };
          },
          onUploadProgress: (percent) => {
            if (isPhotoOperationActive(operationId)) {
              setUploadProgress(percent);
            }
          },
          onUploadComplete: () => {
            if (!isPhotoOperationActive(operationId)) return;
            setUploadProgress(100);
            setAnalysisElapsed(0);
            setAnalysisStage("analyzing");
          },
        });
        if (!isPhotoOperationActive(operationId)) return;
        if (result.status < 200 || result.status >= 300 || !result.body.report) {
          throw new Error(analysisErrorMessage(result.body.code, locale, result.body.message));
        }

        const diagnostics = result.body.diagnostics;
        savePerformanceSample({
          source_bytes: metrics.sourceBytes,
          upload_bytes: baseline.size + photo.size,
          preparation_ms: Math.round(metrics.preparationMs),
          upload_ms: Math.round(result.uploadMs),
          server_wait_ms: Math.round(result.serverWaitMs),
          response_headers_ms: Math.round(result.responseHeadersMs),
          response_download_ms: Math.round(result.responseDownloadMs),
          response_parse_ms: Math.round(result.responseParseMs),
          response_bytes: result.responseBytes,
          request_ms: Math.round(result.requestMs),
          server_total_ms: result.body.report.processing_ms,
          request_parse_ms: diagnostics?.request_parse_ms ?? 0,
          image_prepare_ms: diagnostics?.image_prepare_ms ?? 0,
          data_url_ms: diagnostics?.data_url_ms ?? 0,
          preprocessing_ms: diagnostics?.preprocessing_ms ?? 0,
          report_assembly_ms: diagnostics?.report_assembly_ms ?? 0,
          primary_ai_ms: diagnostics?.primary_ai_ms ?? 0,
          observer_ai_ms: diagnostics?.observer_ai_ms ?? 0,
          missing_scout_ms: diagnostics?.missing_scout_ms ?? 0,
          observer_provider_calls: diagnostics?.observer_provider_calls ?? 0,
          missing_scout_provider_calls: diagnostics?.missing_scout_provider_calls ?? 0,
          dual_observer_enabled: diagnostics?.dual_observer_enabled ?? 0,
          missing_scout_candidate_count: diagnostics?.missing_scout_candidate_count ?? 0,
          missing_scout_merged_count: diagnostics?.missing_scout_merged_count ?? 0,
          missing_scout_added_count: diagnostics?.missing_scout_added_count ?? 0,
          verification_ai_ms: diagnostics?.verification_ai_ms ?? 0,
          fast_verifier_ms: diagnostics?.fast_verifier_ms ?? 0,
          verification_fallback_ms: diagnostics?.verification_fallback_ms ?? 0,
          verification_provider_calls: diagnostics?.verification_provider_calls ?? 0,
          verification_fallback_used: diagnostics?.verification_fallback_used ?? 0,
          verification_shadow_agreement:
            diagnostics?.verification_shadow_agreement ?? -1,
          verification_active_fast_eligible:
            diagnostics?.verification_active_fast_eligible ?? -1,
          total_ms: Math.round(performance.now() - metrics.flowStartedAt),
        });
        const completedReport = result.body.report;
        try {
          const baselineVersionId = await ensureCurrentBaselineVersion(activeArea.id);
          await saveCheckHistory({
            area: activeArea,
            baselineVersionId,
            current: photo,
            report: completedReport,
          });
        } catch {
          setToast(l("检查完成，但这次历史没有保存", "Check complete, but this result was not saved to history"));
        }
        if (activeArea.mode === "inventory") {
          try {
            await saveBaselineImage(photo, undefined, activeArea.id);
            setBaseline(photo);
          } catch {
            setToast(l("盘点历史已保存，但下次盘点参考没有更新", "Inventory history was saved, but the next reference was not updated"));
          }
        }
        setReport(completedReport);
        setPhase("result");
      } catch (error) {
        if (!isPhotoOperationActive(operationId)) return;
        setMessage(error instanceof Error ? error.message : l("这次检查没有完成，请重试", "The check did not finish. Please try again"));
        setPhase("error");
      } finally {
        if (analysisRequestRef.current?.operationId === operationId) {
          analysisRequestRef.current = null;
        }
        finishPhotoOperation(operationId);
      }
    },
    [activeArea, baseline, finishPhotoOperation, isPhotoOperationActive, l, locale],
  );

  const acceptPhoto = useCallback(
    async (
      photo: File,
      purpose: PhotoPurpose,
      options: PhotoPreparationOptions,
      operationId: number,
    ) => {
      const operation = photoOperationRef.current;
      if (
        operation?.operationId !== operationId ||
        !isPhotoOperationActive(operationId)
      ) {
        finishPhotoOperation(operationId);
        return;
      }
      if (!photo.type.startsWith("image/")) {
        setMessage(l("请选择一张照片", "Please choose a photo"));
        finishPhotoOperation(operationId);
        return;
      }

      const checkingCurrent = purpose === "current";
      const replacingExisting = purpose === "baseline" && Boolean(baseline);
      const flowStartedAt = options.startedAt ?? performance.now();
      if (checkingCurrent) {
        if (options.alreadyPrepared) setCurrent(photo);
        if (!options.preparationVisible) {
          setAnalysisStage("preparing");
          setUploadProgress(null);
          setAnalysisElapsed(0);
          setMessage("");
          setReport(null);
          setPhase("analyzing");
          await waitForPaint();
          if (!isPhotoOperationActive(operationId)) {
            finishPhotoOperation(operationId);
            return;
          }
        }
      }

      let prepared: File;
      try {
        prepared = options.alreadyPrepared
          ? photo
          : await preparePhoto(
              photo,
              purpose === "current" ? "checkback-current" : "checkback-standard",
              locale,
              operation.controller.signal,
            );
      } catch (error) {
        if (!isPhotoOperationActive(operationId)) {
          finishPhotoOperation(operationId);
          return;
        }
        const failureMessage = error instanceof Error ? error.message : l("照片处理失败，请重拍", "Photo processing failed. Please retake it");
        setMessage(failureMessage);
        if (checkingCurrent) setPhase("error");
        else setToast(failureMessage);
        finishPhotoOperation(operationId);
        return;
      }

      if (!isPhotoOperationActive(operationId)) {
        finishPhotoOperation(operationId);
        return;
      }

      if (purpose === "baseline") {
        try {
          await saveBaselineImage(prepared, operation.controller.signal, activeArea.id);
          if (!isPhotoOperationActive(operationId)) return;
          setBaseline(prepared);
          setCurrent(null);
          setMessage("");
          setToast(replacingExisting ? l("标准照片已更新", "Reference photo updated") : l("标准照片已保存", "Reference photo saved"));
          setPhase("camera");
        } catch {
          if (!isPhotoOperationActive(operationId)) return;
          const saveMessage = replacingExisting
            ? l("更新失败，原标准照片已保留", "Update failed. The previous reference was kept")
            : l("标准照片没有保存成功，请重试", "The reference photo was not saved. Please try again");
          setMessage(saveMessage);
          setToast(saveMessage);
        } finally {
          finishPhotoOperation(operationId);
        }
        return;
      }

      const preparationMs = performance.now() - flowStartedAt;
      setCurrent(prepared);
      await analyze(prepared, {
        flowStartedAt,
        preparationMs,
        sourceBytes: photo.size,
      }, operationId);
    },
    [activeArea.id, analyze, baseline, finishPhotoOperation, isPhotoOperationActive, l, locale],
  );

  const openPhotoPicker = useCallback((purpose: PhotoPurpose) => {
    if (operationBusyRef.current) return;
    pendingPhotoPurposeRef.current = {
      purpose,
      modeEpoch: photoModeEpochRef.current,
    };
    fileInputRef.current?.click();
  }, []);

  const captureFrame = useCallback(async () => {
    const purpose: PhotoPurpose = capturingStandard ? "baseline" : "current";
    const checkingCurrent = purpose === "current";
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (cameraState !== "live" || !video || !canvas || !video.videoWidth) {
      openPhotoPicker(purpose);
      return;
    }
    const operationId = beginPhotoOperation();
    if (operationId === null) return;
    const captureStartedAt = performance.now();

    const maxSide = 1600;
    const scale = Math.min(1, maxSide / Math.max(video.videoWidth, video.videoHeight));
    canvas.width = Math.round(video.videoWidth * scale);
    canvas.height = Math.round(video.videoHeight * scale);
    const context = canvas.getContext("2d");
    if (!context) {
      finishPhotoOperation(operationId);
      openPhotoPicker(purpose);
      return;
    }
    context.drawImage(video, 0, 0, canvas.width, canvas.height);
    if (checkingCurrent) {
      setAnalysisStage("preparing");
      setUploadProgress(null);
      setAnalysisElapsed(0);
      setMessage("");
      setReport(null);
      setPhase("analyzing");
      await waitForPaint();
      if (!isPhotoOperationActive(operationId)) {
        finishPhotoOperation(operationId);
        return;
      }
    }
    const blob = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob(resolve, "image/jpeg", 0.82),
    );
    if (!isPhotoOperationActive(operationId)) {
      finishPhotoOperation(operationId);
      return;
    }
    if (!blob) {
      setMessage(l("没有拍到照片，请再试一次", "No photo was captured. Please try again"));
      finishPhotoOperation(operationId);
      if (checkingCurrent) setPhase("error");
      else setToast(l("没有拍到照片，请再试一次", "No photo was captured. Please try again"));
      return;
    }
    const photo = fileFromBlob(
      blob,
      purpose === "current" ? "checkback-current" : "checkback-standard",
    );
    await acceptPhoto(photo, purpose, {
      alreadyPrepared: blob.size <= MAX_PROCESSED_IMAGE_BYTES,
      preparationVisible: checkingCurrent,
      startedAt: captureStartedAt,
    }, operationId);
  }, [
    acceptPhoto,
    beginPhotoOperation,
    cameraState,
    capturingStandard,
    finishPhotoOperation,
    isPhotoOperationActive,
    openPhotoPicker,
    l,
  ]);

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const intent = pendingPhotoPurposeRef.current;
    pendingPhotoPurposeRef.current = null;
    const photo = event.target.files?.[0];
    event.target.value = "";
    if (
      !photo ||
      !intent ||
      intent.modeEpoch !== photoModeEpochRef.current
    ) {
      return;
    }
    const operationId = beginPhotoOperation();
    if (operationId === null) return;
    await acceptPhoto(photo, intent.purpose, {}, operationId);
  };

  const cancelAnalysis = useCallback(() => {
    if (phase !== "analyzing") return;

    invalidatePendingPhotoIntent();
    photoOperationRef.current?.controller.abort();
    photoOperationRef.current = null;
    analysisRequestRef.current?.request.abort();
    analysisRequestRef.current = null;
    operationSequenceRef.current += 1;
    operationBusyRef.current = false;
    setOperationBusy(false);
    setCurrent(null);
    setReport(null);
    setMessage("");
    setUploadProgress(null);
    setAnalysisElapsed(0);
    setPhase(baseline ? "camera" : "baseline");
    setToast(l("检查已取消", "Check canceled"));
  }, [baseline, invalidatePendingPhotoIntent, l, phase]);

  const returnToCamera = () => {
    invalidatePendingPhotoIntent();
    setCurrent(null);
    setReport(null);
    setMessage("");
    setPhase(baseline ? "camera" : "baseline");
  };

  const beginBaselineReplacement = () => {
    if (!baseline || operationBusyRef.current || phase === "analyzing") return;
    invalidatePendingPhotoIntent();
    setCurrent(null);
    setReport(null);
    setMessage("");
    setPhase("baseline");
  };

  const cancelBaselineReplacement = () => {
    if (!baseline || operationBusyRef.current) return;
    invalidatePendingPhotoIntent();
    setCurrent(null);
    setReport(null);
    setMessage("");
    setPhase("camera");
  };

  const selectArea = async (area: CheckArea) => {
    if (area.id === activeArea.id || operationBusyRef.current || phase === "analyzing") return;
    const previousBaseline = baseline;
    invalidatePendingPhotoIntent();
    stopCamera();
    setPhase("loading");
    setCurrent(null);
    setReport(null);
    setMessage("");
    try {
      await persistActiveArea(area.id);
      const stored = await loadBaselineImage(area.id);
      setActiveArea(area);
      setAreas((currentAreas) => [
        area,
        ...currentAreas.filter((item) => item.id !== area.id),
      ]);
      setBaseline(stored);
      setPhase(stored ? "camera" : "baseline");
      setToast(l(`已切换到${displayAreaName(area, locale)} · ${analysisModeMeta(area.mode, locale).shortLabel}`, `Switched to ${displayAreaName(area, locale)} · ${analysisModeMeta(area.mode, locale).shortLabel}`));
    } catch {
      setBaseline(previousBaseline);
      setPhase(previousBaseline ? "camera" : "baseline");
      setToast(l("区域切换失败，请重试", "Could not switch areas. Please try again"));
    }
  };

  const addArea = async (input: { name: string; mode: AnalysisMode }) => {
    if (operationBusyRef.current || phase === "analyzing") return;
    invalidatePendingPhotoIntent();
    stopCamera();
    setPhase("loading");
    setCurrent(null);
    setReport(null);
    setMessage("");
    try {
      const area = await createStoredArea(input);
      setAreas((currentAreas) => [area, ...currentAreas]);
      setActiveArea(area);
      setBaseline(null);
      setPhase("baseline");
      setToast(l(`已创建${area.name}，请先拍摄参考照片`, `${area.name} created. Capture a reference photo first`));
    } catch (error) {
      setPhase(baseline ? "camera" : "baseline");
      throw error;
    }
  };

  const modeMeta = analysisModeMeta(activeArea.mode, locale);
  const activeAreaName = displayAreaName(activeArea, locale);
  const referenceLabel = activeArea.mode === "inventory"
    ? l("盘点参考", "Inventory reference")
    : l("标准照片", "Reference photo");
  const referenceEmpty = activeArea.mode === "inventory"
    ? l("先拍柜内物资作为盘点参考", "Capture the cabinet contents as your inventory reference")
    : l("先拍整理好的区域", "Capture the organized area first");

  const primaryLabel =
    operationBusy && capturingStandard
      ? l("正在保存", "Saving")
      : phase === "baseline"
        ? isReplacingBaseline
          ? activeArea.mode === "inventory" ? l("保存新参考", "Save new reference") : l("保存新标准", "Save new reference")
          : activeArea.mode === "inventory" ? l("保存盘点参考", "Save inventory reference") : l("保存标准", "Save reference")
        : phase === "analyzing"
          ? activeArea.mode === "inventory" ? l("正在盘点", "Counting inventory") : l("正在检查", "Checking")
          : phase === "result"
          ? report?.status === "issues"
            ? l("整理后复查", "Check again after fixing")
            : l("再检查一次", "Check again")
          : phase === "error"
            ? l("重新拍摄", "Retake photo")
            : activeArea.mode === "inventory" ? l("拍下并盘点", "Capture and count") : l("拍下并检查", "Capture and check");

  const onPrimaryAction = () => {
    if (phase === "result" || phase === "error") returnToCamera();
    else void captureFrame();
  };

  const liveStatus =
    operationBusy && capturingStandard
      ? isReplacingBaseline
        ? l("正在保存新标准照片，原标准照片仍会保留", "Saving the new reference; the previous photo is still kept")
        : l("正在保存标准照片", "Saving reference photo")
      : phase === "loading"
        ? l("正在读取标准照片", "Loading reference photo")
        : phase === "analyzing"
          ? analysisStage === "preparing"
            ? l("正在优化照片", "Optimizing photos")
            : analysisStage === "uploading"
              ? l("正在上传照片", "Uploading photos")
              : l("照片已上传，AI 正在检查", "Photos uploaded. AI is checking")
          : phase === "result"
            ? report?.headline || l("检查完成", "Check complete")
            : message;

  return (
    <main className="app-stage">
      <section className="camera-shell" aria-label={l("CheckBack 桌面检查相机", "CheckBack visual inspection camera")}>
        <header className="app-header">
          <h1>CheckBack</h1>
          <button
            className="area-trigger"
            type="button"
            onClick={() => setWorkspaceOpen(true)}
            disabled={operationBusy || phase === "loading" || phase === "analyzing"}
            aria-label={l(`当前区域${activeAreaName}，${modeMeta.shortLabel}，打开区域面板`, `Current area: ${activeAreaName}, ${modeMeta.shortLabel}. Open area panel`)}
            aria-haspopup="dialog"
            aria-expanded={workspaceOpen}
          >
            <span className="area-trigger__icon" aria-hidden="true">
              <MapPinArea size={17} weight="duotone" />
            </span>
            <span className="area-trigger__copy">
              <span className="area-trigger__name">{activeAreaName}</span>
              <small className="area-trigger__mode">
                <span className="area-trigger__status-dot" aria-hidden="true" />
                {modeMeta.shortLabel}
              </small>
            </span>
            <span className="area-trigger__chevron" aria-hidden="true">
              <CaretDown size={12} weight="bold" />
            </span>
          </button>
          <div className="header-tools">
            <button
              className="locale-switch"
              type="button"
              onClick={toggleLocale}
              aria-label={l("切换到英文", "Switch to Chinese")}
              title={l("切换到英文", "Switch to Chinese")}
            >
              <GlobeHemisphereWest size={15} weight="duotone" aria-hidden="true" />
              <span>{locale === "en" ? "EN" : "中"}</span>
            </button>
            <Link className="header-privacy-link" href="/privacy" aria-label={l("查看照片处理与隐私说明", "View photo processing and privacy information")}>
              <ShieldCheck size={16} weight="duotone" aria-hidden="true" />
            </Link>
          </div>
        </header>

        <section className="reference-slot" aria-label={referenceLabel}>
          {baselineUrl ? (
            <img
              className="reference-image"
              src={baselineUrl}
              alt={isReplacingBaseline
                ? l("当前" + referenceLabel + "，尚未替换", "Current " + referenceLabel + ", not replaced yet")
                : l(activeAreaName + "的" + referenceLabel, activeAreaName + " " + referenceLabel)}
            />
          ) : (
            <div className="reference-empty">
              <Camera size={24} weight="duotone" aria-hidden="true" />
              <span>{referenceEmpty}</span>
            </div>
          )}
          {baseline && (
            <>
              <span className="slot-label">{referenceLabel}</span>
              <button
                className="reference-action"
                type="button"
                onClick={
                  isReplacingBaseline ? cancelBaselineReplacement : beginBaselineReplacement
                }
                disabled={operationBusy || phase === "loading" || phase === "analyzing"}
                aria-label={(isReplacingBaseline ? l("取消更换", "Cancel replacing ") : l("更换", "Replace ")) + referenceLabel}
              >
                {isReplacingBaseline ? (
                  <X size={14} weight="bold" aria-hidden="true" />
                ) : (
                  <PencilSimple size={14} weight="bold" aria-hidden="true" />
                )}
                <span>{isReplacingBaseline ? l("取消", "Cancel") : l("更换", "Replace")}</span>
              </button>
            </>
          )}
          <span
            className={"ready-light " + (cameraState === "live" ? "is-live" : "")}
            aria-hidden="true"
          />
        </section>

        <section
          className="viewfinder"
          aria-label={capturingStandard
            ? l(activeAreaName + (isReplacingBaseline ? "新" + referenceLabel : referenceLabel) + "取景", activeAreaName + " " + referenceLabel + " viewfinder")
            : l(activeAreaName + modeMeta.shortLabel + "取景", activeAreaName + " " + modeMeta.shortLabel + " viewfinder")}
          aria-busy={phase === "analyzing" || operationBusy}
        >
          {(phase === "baseline" || phase === "camera") && (
            <>
              <video ref={videoRef} className="camera-feed" muted playsInline />
              {cameraState !== "live" && (
                <button
                  className="camera-fallback"
                  type="button"
                  onClick={() => {
                    if (cameraState === "idle") void startCamera();
                    else openPhotoPicker(capturingStandard ? "baseline" : "current");
                  }}
                  disabled={operationBusy || cameraState === "starting"}
                >
                  <Camera size={34} weight="duotone" aria-hidden="true" />
                  <strong>
                    {cameraState === "starting"
                      ? l("正在打开相机", "Opening camera")
                      : cameraState === "idle"
                        ? l("打开相机", "Open camera")
                        : l("使用手机相机", "Use phone camera")}
                  </strong>
                  <span>
                    {message ||
                      (cameraState === "idle"
                        ? l("点击后才会请求相机权限", "Camera permission is requested only after you tap")
                        : l("拍摄或选择一张清晰照片", "Capture or choose a clear photo"))}
                  </span>
                </button>
              )}
              <div className="viewfinder-caption">
                <span>
                  {isReplacingBaseline ? l("更新参考", "Update reference") : capturingStandard ? l("建立参考", "Set reference") : modeMeta.shortLabel}
                </span>
                <p>
                  {isReplacingBaseline
                    ? l(`准备完成后，拍下新${referenceLabel}`, `When ready, capture a new ${referenceLabel}`)
                    : capturingStandard
                      ? l(`拍下${activeAreaName}的${referenceLabel}`, `Capture the ${referenceLabel} for ${activeAreaName}`)
                      : modeMeta.cameraHint}
                </p>
              </div>
            </>
          )}

          {phase === "loading" && (
            <div className="center-state">
              <Scan size={34} weight="duotone" aria-hidden="true" />
              <strong>{l("正在准备", "Getting ready")}</strong>
            </div>
          )}

          {phase === "analyzing" && (
            <>
              {currentUrl && <img className="captured-frame" src={currentUrl} alt={l("刚拍摄的当前桌面", "Current scene just captured")} />}
              <AnalysisProgressView
                stage={analysisStage}
                uploadPercent={uploadProgress}
                elapsedSeconds={analysisElapsed}
                onCancel={cancelAnalysis}
              />
            </>
          )}

          {phase === "result" && report && (
            <ResultView report={report} currentUrl={currentUrl} mode={activeArea.mode} />
          )}

          {phase === "error" && (
            <>
              {currentUrl && <img className="captured-frame" src={currentUrl} alt={l("本次检查照片", "Photo for this check")} />}
              <div className="result-panel error-panel" role="alert">
                <span className="result-icon"><Warning size={24} weight="fill" aria-hidden="true" /></span>
                <p className="result-kicker">{l("检查未完成", "Check incomplete")}</p>
                <h2>{l("照片还在，可以直接重试", "Your photo is still here. You can retry now")}</h2>
                <p>{message}</p>
              </div>
            </>
          )}
        </section>

        <footer className="control-deck">
          <button
            className="shutter-button"
            type="button"
            onClick={onPrimaryAction}
            disabled={operationBusy || phase === "loading" || phase === "analyzing"}
          >
            <span>{primaryLabel}</span>
          </button>
          <button
            className="deck-button"
            type="button"
            onClick={() => openPhotoPicker(capturingStandard ? "baseline" : "current")}
            disabled={operationBusy || phase === "loading" || phase === "analyzing"}
            aria-label={
              capturingStandard
                ? isReplacingBaseline
                  ? l("从手机照片中选择新" + referenceLabel, "Choose a new " + referenceLabel + " from your photos")
                  : activeArea.mode === "inventory" ? l("从手机照片中选择盘点参考", "Choose an inventory reference from your photos") : l("从手机照片中选择标准照片", "Choose a reference photo from your photos")
                : l("从手机照片中选择" + activeAreaName + "的当前照片", "Choose a current photo for " + activeAreaName)
            }
          >
            <ImagesSquare size={24} weight="duotone" aria-hidden="true" />
          </button>
        </footer>

        <input
          ref={fileInputRef}
          hidden
          type="file"
          accept="image/jpeg,image/png,image/webp"
          capture="environment"
          disabled={operationBusy || phase === "loading" || phase === "analyzing"}
          onChange={handleFileChange}
        />
        <canvas ref={canvasRef} className="visually-hidden" />
        <p className="visually-hidden" aria-live="polite" aria-atomic="true">{liveStatus}</p>
        {toast && <div className="toast" role="status">{toast}</div>}
        <WorkspacePanel
          open={workspaceOpen}
          activeArea={activeArea}
          areas={areas}
          disabled={operationBusy || phase === "loading" || phase === "analyzing"}
          onClose={() => setWorkspaceOpen(false)}
          onSelectArea={selectArea}
          onCreateArea={addArea}
        />
      </section>
    </main>
  );
}

function AnalysisProgressView({
  stage,
  uploadPercent,
  elapsedSeconds,
  onCancel,
}: {
  stage: AnalysisStage;
  uploadPercent: number | null;
  elapsedSeconds: number;
  onCancel: () => void;
}) {
  const { locale } = useAppLocale();
  const l = (chinese: string, english: string) => localize(locale, chinese, english);
  const stages: Array<{ id: AnalysisStage; label: string }> = [
    { id: "preparing", label: l("处理", "Prepare") },
    { id: "uploading", label: l("上传", "Upload") },
    { id: "analyzing", label: l("分析", "Analyze") },
  ];
  const currentIndex = stages.findIndex((item) => item.id === stage);
  const title =
    stage === "preparing"
      ? l("正在优化照片", "Optimizing photos")
      : stage === "uploading"
        ? uploadPercent === null
          ? l("正在上传照片", "Uploading photos")
          : l("正在上传 ", "Uploading ") + uploadPercent + "%"
        : l("AI 正在逐项比对", "AI is comparing each item");
  const detail =
    stage === "preparing"
      ? l("压缩到适合识别的清晰度", "Compressing to a clear recognition-ready size")
      : stage === "uploading"
        ? l("加密发送标准照片和当前照片", "Securely sending the reference and current photos")
        : elapsedSeconds >= 3
          ? l("已分析 ", "Analyzing for ") + elapsedSeconds + l(" 秒，疑似缺少会自动复核", " seconds; possible missing items are verified automatically")
          : l("对齐视角、确认位置并复核异常", "Aligning views, checking positions, and verifying changes");
  const valueText =
    stage === "preparing"
      ? l("正在优化照片", "Optimizing photos")
      : stage === "uploading" && uploadPercent !== null
        ? l("照片已上传 ", "Photos uploaded ") + uploadPercent + "%"
        : stage === "uploading"
          ? l("正在上传照片", "Uploading photos")
          : l("照片上传完成，AI 正在逐项比对", "Upload complete. AI is comparing each item");
  const meterStyle =
    stage === "uploading" && uploadPercent !== null
      ? { transform: "scaleX(" + uploadPercent / 100 + ")" }
      : undefined;

  return (
    <div
      className="analysis-state"
      aria-labelledby="analysis-progress-title"
      aria-describedby="analysis-progress-detail"
    >
      <Scan className="scan-icon" size={38} weight="duotone" aria-hidden="true" />
      <strong id="analysis-progress-title">{title}</strong>
      <span id="analysis-progress-detail" className="analysis-copy">{detail}</span>
      <div
        className={
          "analysis-meter is-" +
          stage +
          (stage === "uploading" && uploadPercent === null ? " is-indeterminate" : "")
        }
        role="progressbar"
        aria-label={l("照片检查进度", "Photo check progress")}
        aria-describedby="analysis-progress-detail"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={
          stage === "uploading" && uploadPercent !== null ? uploadPercent : undefined
        }
        aria-valuetext={valueText}
      >
        <div className="analysis-meter-track" aria-hidden="true">
          <span className="analysis-meter-fill" style={meterStyle} />
        </div>
      </div>
      <div className="analysis-steps" aria-hidden="true">
        {stages.map((item, index) => {
          const state = index < currentIndex ? "is-done" : index === currentIndex ? "is-active" : "";
          return (
            <span className={"analysis-step " + state} key={item.id}>
              {item.label}
            </span>
          );
        })}
      </div>
      <button className="analysis-cancel" type="button" onClick={onCancel}>
        {l("取消检查", "Cancel check")}
      </button>
    </div>
  );
}

function ResultView({
  report,
  currentUrl,
  mode,
}: {
  report: CheckbackReport;
  currentUrl: string;
  mode: AnalysisMode;
}) {
  const { locale } = useAppLocale();
  const l = (chinese: string, english: string) => localize(locale, chinese, english);
  const isClear = report.status === "clear";
  const isInventory = mode === "inventory";

  return (
    <>
      {currentUrl && <img className="captured-frame" src={currentUrl} alt={l("完成检查的当前桌面", "Current scene after the completed check")} />}
      <div className={"result-panel result-" + report.status}>
        <span className="result-icon">
          {isClear ? (
            <CheckCircle size={26} weight="fill" aria-hidden="true" />
          ) : (
            <Warning size={25} weight="fill" aria-hidden="true" />
          )}
        </span>
        <p className="result-kicker">
          {isInventory && isClear ? l("盘点完成", "Inventory complete") : isClear ? l("检查完成", "Check complete") : report.status === "issues" ? l("需要处理", "Action needed") : l("需要补拍", "More photos needed")}
          <span className="result-duration"> · {(report.processing_ms / 1000).toFixed(1)} {l("秒", "sec")}</span>
        </p>
        <h2>{isInventory ? report.headline : isClear ? l("可以放心离开", "Everything is in place") : report.headline}</h2>
        <p>{report.summary}</p>
        {report.items.length > 0 && (
          <section className="result-details" aria-labelledby="result-details-title">
            <h3 id="result-details-title">
              {isInventory ? l("当前库存明细", "Current inventory") : isClear ? l("其他变化（无需处理）", "Other changes (no action needed)") : l("全部检查明细", "All check details")}
            </h3>
            <ul className="issue-list">
              {report.items.map((item) => (
                <li key={item.id}>
                  <span>{isInventory && item.type === "added" ? l("盘点项", "Inventory item") : (locale === "en" ? ITEM_LABELS_EN : ITEM_LABELS)[item.type]}</span>
                  <div>
                    <strong>{item.label}</strong>
                    <p className="issue-action">{item.action}</p>
                    <dl className="issue-evidence">
                      <div>
                        <dt>{l("标准位置", "Reference position")}</dt>
                        <dd>{item.baseline_location}</dd>
                      </div>
                      {item.current_location && (
                        <div>
                          <dt>{l("当前位置", "Current position")}</dt>
                          <dd>{item.current_location}</dd>
                        </div>
                      )}
                      <div>
                        <dt>{l("判断依据", "Evidence")}</dt>
                        <dd>{item.evidence}</dd>
                      </div>
                    </dl>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </>
  );
}
