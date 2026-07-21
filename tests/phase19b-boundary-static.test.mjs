import assert from "node:assert/strict";
import {
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import test from "node:test";

function filesUnder(root, suffix) {
  const output = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    if (statSync(path).isDirectory()) output.push(...filesUnder(path, suffix));
    else if (path.endsWith(suffix)) output.push(path);
  }
  return output;
}

test("Phase19B boundary has no network client or environment-secret primitive", () => {
  const files = filesUnder("evaluation/live-shadow-boundary", ".ts");
  assert.ok(files.length >= 10);
  const forbidden =
    /node:(?:http|https|http2|net|tls|dns|dgram)|\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(|\bprocess\.env\b|\b(?:axios|undici|got)\b|DASHSCOPE_API_KEY|OPENAI_API_KEY/;
  for (const path of files) {
    const source = readFileSync(path, "utf8");
    assert.doesNotMatch(source, forbidden, path);
  }
});

test("offline boundary remains disconnected from the production app and API", () => {
  const appFiles = filesUnder("app", ".ts").concat(filesUnder("app", ".tsx"));
  for (const path of appFiles) {
    const source = readFileSync(path, "utf8");
    assert.doesNotMatch(
      source,
      /evaluation\/live-shadow-boundary|live-shadow-boundary/,
      path,
    );
  }
});

test("boundary source contains no previously exposed secret-shaped literal", () => {
  const files = filesUnder("evaluation/live-shadow-boundary", ".ts").concat(
    filesUnder("tests", ".mjs").filter((path) => path.includes("phase19b")),
  );
  for (const path of files) {
    const source = readFileSync(path, "utf8");
    assert.doesNotMatch(source, /sk-[A-Za-z0-9._-]{20,}/, path);
  }
});
