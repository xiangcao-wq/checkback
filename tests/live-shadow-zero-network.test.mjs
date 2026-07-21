import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import test from "node:test";

function recursiveFiles(root) {
  const output = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) output.push(...recursiveFiles(path));
    else output.push(path);
  }
  return output;
}

test("Phase 19A execution closure has an explicit offline import allowlist", () => {
  const root = process.cwd();
  const liveRoot = join(root, "evaluation", "live-shadow");
  const files = [
    ...recursiveFiles(liveRoot).filter((path) => path.endsWith(".ts")),
    join(root, "scripts", "rehearse-live-shadow-safety.mjs"),
  ];
  const allowedImports = new Set([
    "node:crypto",
    "node:fs",
    "node:os",
    "node:path",
    "node:sqlite",
    "zod",
  ]);
  const forbidden = [
    /\bfetch\s*\(/,
    /\bWebSocket\b/,
    /\bprocess\.(?:env|getBuiltinModule|binding|dlopen)\b/,
    /\bcreateRequire\b/,
    /\bchild_process\b/,
    /\bworker_threads\b/,
    /\bimport\s*\(/,
    /\b(?:require|eval)\s*\(/,
    /\bnew\s+Function\b/,
    /https?:\/\//,
    /\b(?:DASHSCOPE_API_KEY|QWEN_API_KEY|OPENAI_API_KEY)\b/,
    /sk-[A-Za-z0-9._-]{12,}/,
    /data:image\//,
  ];
  for (const path of files) {
    const source = readFileSync(path, "utf8");
    const specifiers = [
      ...source.matchAll(/\bfrom\s+["']([^"']+)["']/g),
      ...source.matchAll(/^\s*import\s+["']([^"']+)["']/gm),
    ].map((match) => match[1]);
    for (const specifier of specifiers) {
      if (specifier.startsWith(".")) {
        const target = resolve(dirname(path), specifier);
        assert.equal(
          target === liveRoot || target.startsWith(`${liveRoot}${sep}`),
          true,
          `${relative(root, path)} imports outside live-shadow: ${specifier}`,
        );
      } else {
        assert.equal(
          allowedImports.has(specifier),
          true,
          `${relative(root, path)} imports non-allowlisted ${specifier}`,
        );
      }
    }
    for (const pattern of forbidden) {
      assert.equal(
        pattern.test(source),
        false,
        `${relative(root, path)} contains forbidden ${pattern}`,
      );
    }
  }
  for (const path of recursiveFiles(join(root, "evaluation", "collector"))) {
    if (!path.endsWith(".ts")) continue;
    assert.equal(readFileSync(path, "utf8").includes("live-shadow"), false);
  }
  const apiRoot = join(root, "app", "api");
  for (const path of recursiveFiles(apiRoot)) {
    if (!/\.(?:ts|tsx|js|mjs)$/.test(path)) continue;
    assert.equal(readFileSync(path, "utf8").includes("live-shadow"), false);
  }
});
test("offline rehearsal succeeds under a dynamic network tripwire", () => {
  const allowedEnvironmentNames = ["SystemRoot", "WINDIR", "TEMP", "TMP", "PATH"];
  const environment = Object.fromEntries(
    allowedEnvironmentNames
      .filter((name) => typeof process.env[name] === "string")
      .map((name) => [name, process.env[name]]),
  );
  assert.equal(
    Object.keys(environment).some((name) => /KEY|TOKEN|SECRET|QWEN|DASHSCOPE/i.test(name)),
    false,
  );
  const swallowedAttempt = spawnSync(
    process.execPath,
    [
      "--import",
      "./tests/helpers/network-tripwire.mjs",
      "--eval",
      'try { fetch("https://blocked.invalid") } catch {}',
    ],
    {
      cwd: process.cwd(),
      env: environment,
      encoding: "utf8",
      windowsHide: true,
      timeout: 30_000,
    },
  );
  assert.equal(swallowedAttempt.error, undefined);
  assert.equal(swallowedAttempt.status, 97);
  const result = spawnSync(
    process.execPath,
    [
      "--import",
      "./tests/helpers/network-tripwire.mjs",
      "--experimental-strip-types",
      "scripts/rehearse-live-shadow-safety.mjs",
    ],
    {
      cwd: process.cwd(),
      env: environment,
      encoding: "utf8",
      windowsHide: true,
      timeout: 30_000,
    },
  );
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  const summary = JSON.parse(result.stdout.trim());
  assert.deepEqual(
    {
      mode: summary.mode,
      provider: summary.provider,
      network_calls: summary.network_calls,
      fake_send_attempts: summary.fake_send_attempts,
      completed_results: summary.completed_results,
      real_model_ready: summary.real_model_ready,
    },
    {
      mode: "offline_stub",
      provider: "fake_gateway",
      network_calls: 0,
      fake_send_attempts: 3,
      completed_results: 3,
      real_model_ready: false,
    },
  );
});
