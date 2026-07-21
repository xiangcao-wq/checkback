import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

async function dispatch(request) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", process.pid + "-" + Date.now() + "-" + Math.random());
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

test("server-renders the mobile camera product shell", async () => {
  const response = await dispatch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
  );
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<html lang="zh-CN"/i);
  assert.match(html, /<title>CheckBack — 拍下并检查<\/title>/i);
  assert.match(html, /CheckBack 桌面检查相机/);
  assert.match(html, /先拍整理好的区域/);
  assert.match(html, /当前区域办公桌，归位检查，打开区域面板/);
  assert.match(html, /正在准备/);
  assert.doesNotMatch(html, /演示|DEMO_REPORTS|codex-preview|Your site is taking shape/i);
});

test("browser language takes priority over the detected country", async () => {
  const response = await dispatch(
    new Request("http://localhost/", {
      headers: {
        accept: "text/html",
        "accept-language": "en-US,en;q=0.9",
        "x-checkback-country": "CN",
      },
    }),
  );
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<html lang="en"/i);
  assert.match(html, /<title>CheckBack — Capture and check<\/title>/i);
  assert.match(html, /CheckBack visual inspection camera/);
  assert.match(html, /Capture the organized area first/);
  assert.match(
    html,
    /Current area: Office desk, Restore check\. Open area panel/,
  );
});

test("locale endpoint falls back to the locally detected country", async () => {
  const response = await dispatch(
    new Request("http://localhost/api/locale", {
      headers: {
        "accept-language": "fr-FR,fr;q=0.9",
        "x-checkback-country": "US",
      },
    }),
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "private, no-store");
  assert.deepEqual(await response.json(), {
    country: "US",
    locale: "en",
    source: "country",
  });
});

test("implements a real one-action camera and analysis flow", async () => {
  const [
    page,
    css,
    layout,
    route,
    provider,
    qwenModelConfig,
    qwenVerifierPrompt,
    verificationPolicy,
    baselineStore,
    performanceHistory,
    workspacePanel,
    packageJson,
    envExample,
    selfHostEnvExample,
  ] = await Promise.all([
      readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
      readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
      readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
      readFile(new URL("../app/api/analyze/route.ts", import.meta.url), "utf8"),
      readFile(new URL("../app/lib/vision-provider.ts", import.meta.url), "utf8"),
      readFile(new URL("../app/lib/qwen-model-config.ts", import.meta.url), "utf8"),
      readFile(new URL("../app/lib/qwen-verifier-prompt.ts", import.meta.url), "utf8"),
      readFile(new URL("../app/lib/verification-policy.ts", import.meta.url), "utf8"),
      readFile(new URL("../app/lib/area-baseline-store.ts", import.meta.url), "utf8"),
      readFile(new URL("../app/lib/performance-history.ts", import.meta.url), "utf8"),
      readFile(new URL("../app/workspace-panel.tsx", import.meta.url), "utf8"),
      readFile(new URL("../package.json", import.meta.url), "utf8"),
      readFile(new URL("../.env.example", import.meta.url), "utf8"),
      readFile(
        new URL("../deploy/self-host/checkback.env.example", import.meta.url),
        "utf8",
      ),
    ]);

  assert.match(page, /"use client";/);
  assert.doesNotMatch(workspacePanel, /:\s*"\{copy\.[A-Za-z]+\}"/);
  assert.match(workspacePanel, /viewHistory: "查看历史"/);
  assert.match(workspacePanel, /newArea: "新建区域"/);
  assert.match(workspacePanel, /createAction: "创建并拍摄标准照片"/);
  assert.match(page, /navigator\.mediaDevices\.getUserMedia/);
  assert.doesNotMatch(
    page,
    /phase === "baseline" \|\| phase === "camera"\) void startCamera/,
  );
  assert.match(page, /点击后才会请求相机权限/);
  assert.match(page, /facingMode:\s*\{ ideal: "environment" \}/);
  assert.match(page, /canvas\.toBlob/);
  assert.match(page, /MAX_PROCESSED_IMAGE_BYTES = 430 \* 1024/);
  assert.match(page, /preparePhoto/);
  assert.match(page, /capture="environment"/);
  assert.match(page, /new XMLHttpRequest\(\)/);
  assert.match(page, /xhr\.upload\.addEventListener\("progress"/);
  assert.match(page, /role="progressbar"/);
  assert.match(page, /aria-valuenow=/);
  assert.match(page, /className="analysis-cancel"/);
  assert.match(page, /onCancel=\{cancelAnalysis\}/);
  assert.match(page, /检查已取消/);
  assert.match(page, /aria-busy=/);
  assert.match(page, /persistPerformanceSample\(window\.localStorage, window\.sessionStorage/);
  assert.match(performanceHistory, /PERFORMANCE_HISTORY_LIMIT = 20/);
  assert.match(performanceHistory, /checkback:performance-history-v1/);
  assert.match(performanceHistory, /checkback:last-performance/);
  assert.match(performanceHistory, /MAX_RAW_STORAGE_BYTES = 64 \* 1024/);
  assert.match(page, /operationBusyRef/);
  assert.match(page, /operationSequenceRef/);
  assert.match(page, /analysisRequestRef/);
  assert.match(page, /is-indeterminate/);
  assert.doesNotMatch(page, /fetch\("\/api\/analyze"/);
  assert.match(page, /type PhotoPurpose = "baseline" \| "current"/);
  assert.match(page, /pendingPhotoPurposeRef/);
  assert.match(page, /photoModeEpochRef/);
  assert.match(page, /intent\.modeEpoch !== photoModeEpochRef\.current/);
  assert.doesNotMatch(page, /pendingPhotoPurposeRef\.current \?\?/);
  assert.match(page, /cameraGenerationRef/);
  assert.match(page, /cameraGenerationRef\.current !== generation/);
  assert.match(page, /openedStream\.getTracks\(\)\.forEach\(\(track\) => track\.stop\(\)\)/);
  assert.match(page, /controller: new AbortController\(\)/);
  assert.match(page, /photoOperationRef\.current\?\.controller\.abort\(\)/);
  assert.match(page, /preparePhoto\([\s\S]*?operation\.controller\.signal/);
  assert.match(page, /const isReplacingBaseline = phase === "baseline" && Boolean\(baseline\)/);
  assert.match(
    page,
    /aria-label=\{\(isReplacingBaseline \? l\("取消更换", "Cancel replacing "\)/,
  );
  assert.match(page, /\+ referenceLabel\}/);
  assert.match(page, /isReplacingBaseline \? l\("更新参考", "Update reference"\)/);
  assert.match(page, /原标准照片已保留/);
  assert.match(page, /await saveBaselineImage\(prepared, operation\.controller\.signal, activeArea\.id\);\s*if \(!isPhotoOperationActive\(operationId\)\) return;\s*setBaseline\(prepared\);/);
  assert.match(page, /"从手机照片中选择标准照片"/);
  assert.match(page, /"从手机照片中选择新" \+ referenceLabel/);
  assert.doesNotMatch(page, /window\.confirm|clearBaselineImage/);
  assert.match(page, /saveBaselineImage/);
  assert.match(page, /拍下并检查/);
  assert.match(page, /aria-live="polite"/);
  assert.match(page, /ref=\{fileInputRef\}\s*hidden\s*type="file"/);
  assert.match(page, /formData\.append\("mode", activeArea\.mode\)/);
  assert.match(page, /saveCheckHistory/);
  assert.match(page, /<WorkspacePanel/);
  assert.match(page, /analysisModeMeta/);
  assert.doesNotMatch(page, /DEMO_REPORTS|runDemo|beginDemo|演示检查|Scene\s*\(/i);

  assert.match(baselineStore, /openCheckbackDatabase/);
  assert.match(baselineStore, /BASELINE_VERSION_STORE/);
  assert.match(baselineStore, /signal\?: AbortSignal/);
  assert.match(baselineStore, /transaction\.abort\(\)/);
  assert.match(baselineStore, /transaction\.onabort/);
  assert.match(baselineStore, /removeEventListener\("abort"/);
  assert.match(route, /getVisionRuntime/);
  assert.match(route, /照片已经保留/);
  assert.match(route, /Server-Timing/);
  assert.match(route, /primary_ai_ms/);
  assert.match(route, /verification_ai_ms/);
  assert.match(route, /request_parse_ms/);
  assert.match(route, /image_prepare_ms/);
  assert.match(route, /data_url_ms/);
  assert.match(route, /report_assembly_ms/);
  assert.match(route, /report\.processing_ms = totalMs/);
  assert.match(route, /parseRequestFormData\(request, MAX_ANALYSIS_FORM_BYTES\)/);
  assert.match(route, /analyzeImagePairWithScout\([\s\S]*?request\.signal/);
  assert.match(route, /fast_verifier_ms/);
  assert.match(route, /verification_fallback_ms/);
  assert.match(route, /verification_provider_calls/);
  assert.match(route, /verifier_path/);
  assert.match(route, /verification_active_fast_eligible/);
  assert.match(route, /verification_plus_role/);
  assert.match(route, /verifier_prompt_version/);
  assert.match(route, /verifier_prompt_sha256/);
  assert.match(route, /verifier_active_fallback_reason/);
  assert.doesNotMatch(route, /演示/);
  assert.match(provider, /process\.env\.DASHSCOPE_API_KEY/);
  assert.match(provider, /vl_high_resolution_images:\s*true/);
  assert.match(provider, /enable_thinking:\s*false/);
  assert.match(provider, /verifyMissingCandidates/);
  assert.match(provider, /CHECKBACK_FAST_VERIFIER_MODE/);
  assert.match(provider, /DEFAULT_QWEN_FAST_VERIFICATION_MODEL/);
  assert.match(qwenModelConfig, /qwen3\.6-flash-2026-04-16/);
  assert.match(qwenModelConfig, /CHECKBACK_VERIFIER_PROMPT_VERSION/);
  assert.match(qwenVerifierPrompt, /QWEN_VERIFIER_FINGERPRINT_SOURCE/);
  assert.match(qwenVerifierPrompt, /QWEN_JSON_ONLY_SUFFIX/);
  assert.match(qwenVerifierPrompt, /buildQwenVerifierUserContent/);
  assert.match(qwenVerifierPrompt, /serializeQwenVerifierCandidates/);
  assert.match(provider, /runQwenVerificationPolicy/);
  assert.match(provider, /maxRetries:\s*DEFAULT_QWEN_MAX_RETRIES/);
  assert.match(qwenModelConfig, /DEFAULT_QWEN_MAX_RETRIES\s*=\s*0/);
  assert.match(qwenModelConfig, /DEFAULT_QWEN_PRIMARY_TIMEOUT_MS\s*=\s*90_000/);
  assert.match(
    qwenModelConfig,
    /DEFAULT_QWEN_FAST_VERIFICATION_TIMEOUT_MS\s*=\s*20_000/,
  );
  assert.match(provider, /Simplified Chinese/);
  assert.match(verificationPolicy, /parseFastVerifierMode/);
  assert.match(verificationPolicy, /duplicate_candidate_id/);
  assert.match(verificationPolicy, /too_many_candidates/);
  assert.match(verificationPolicy, /qwen_fast_fallback/);
  assert.match(page, /fast_verifier_ms/);
  assert.match(page, /verification_active_fast_eligible/);
  assert.match(page, /verifier_prompt_version/);
  assert.doesNotMatch(page, /DASHSCOPE_API_KEY|OPENAI_API_KEY/);

  assert.match(css, /env\(safe-area-inset-bottom\)/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
  assert.match(css, /@media \(min-width: 600px\)/);
  assert.match(css, /min-height:\s*100svh/);
  assert.match(css, /min-height:\s*56px/);
  assert.match(css, /\.reference-action\s*\{/);
  assert.match(css, /\.reference-action[\s\S]*?min-height:\s*44px/);
  assert.match(css, /\.reference-action:focus-visible[\s\S]*?var\(--amber-dark\)/);
  assert.match(css, /@media \(orientation: landscape\) and \(max-height: 500px\)/);
  assert.doesNotMatch(css, /reference-image-button/);
  assert.match(css, /\.analysis-meter/);
  assert.match(css, /@keyframes meter-sweep/);
  assert.match(css, /analysis-meter\.is-analyzing/);
  assert.match(css, /analysis-meter.is-indeterminate/);
  assert.doesNotMatch(css, /linear-gradient|radial-gradient/);

  assert.match(layout, /lang=\{locale\}/);
  assert.match(layout, /width:\s*"device-width"/);
  assert.match(layout, /viewportFit:\s*"cover"/);
  assert.doesNotMatch(layout, /analysis\.css|accessibility\.css/);
  assert.match(packageJson, /"@phosphor-icons\/react":/);
  assert.match(packageJson, /"openai":/);
  assert.match(packageJson, /"zod":/);
  assert.match(envExample, /^AI_VISION_PROVIDER=qwen$/m);
  assert.match(envExample, /^DASHSCOPE_API_KEY=$/m);
  assert.match(envExample, /^CHECKBACK_FAST_VERIFIER_MODE=off$/m);
  assert.match(envExample, /^QWEN_FAST_VERIFICATION_MODEL=qwen3\.6-flash-2026-04-16$/m);
  assert.match(envExample, /^OPENAI_API_KEY=$/m);
  assert.match(selfHostEnvExample, /^CHECKBACK_FAST_VERIFIER_MODE=off$/m);
  assert.match(
    selfHostEnvExample,
    /^QWEN_FAST_VERIFICATION_MODEL=qwen3\.6-flash-2026-04-16$/m,
  );

  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
});

test("returns a recoverable configuration response when the server key is absent", async () => {
  const response = await dispatch(
    new Request("http://localhost/api/analyze", { method: "POST", body: new FormData() }),
  );
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assert.equal(body.code, "SERVICE_NOT_CONFIGURED");
  assert.match(body.message, /尚未配置/);
  assert.doesNotMatch(body.message, /演示/);
});
