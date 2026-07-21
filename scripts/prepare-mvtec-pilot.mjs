import { createHash } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import sharp from "sharp";
import {
  MVTEC_PILOT_CATEGORIES,
  buildMvtecPilotPlan,
} from "../evaluation/pilot/mvtec-pilot-plan.ts";

const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CACHE_ROOT = resolve(WEB_ROOT, ".shadow-private", "mvtec-loco");
const METADATA_ROOT = resolve(CACHE_ROOT, "metadata");
const PILOT_ROOT = resolve(CACHE_ROOT, "pilot");
const ASSET_ROOT = resolve(PILOT_ROOT, "assets");

const { values } = parseArgs({
  options: { verify: { type: "boolean", default: false } },
  strict: true,
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeDeterministicJson(path, value) {
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + "\n", "utf8");
  try {
    if (existsSync(path)) {
      const existing = readFileSync(path);
      try {
        if (!existing.equals(bytes)) {
          throw new Error(`deterministic_file_mismatch:${path}`);
        }
        return;
      } finally {
        existing.fill(0);
      }
    }
    mkdirSync(dirname(path), { recursive: true });
    const temporary = path + ".tmp";
    writeFileSync(temporary, bytes, { encoding: "utf8", mode: 0o600, flag: "wx" });
    renameSync(temporary, path);
  } finally {
    bytes.fill(0);
  }
}

function sourceUrl(revision, sourcePath) {
  return (
    "https://huggingface.co/datasets/zhaolutuan/0423/resolve/" +
    revision +
    "/" +
    sourcePath.split("/").map(encodeURIComponent).join("/") +
    "?download=true"
  );
}

const trees = Object.fromEntries(
  MVTEC_PILOT_CATEGORIES.map((category) => [
    category,
    {
      test: readJson(resolve(METADATA_ROOT, `tree-${category}-test.json`)),
      good: readJson(resolve(METADATA_ROOT, `tree-${category}-good.json`)),
    },
  ]),
);
const plan = buildMvtecPilotPlan(trees);
const downloadPlan = {
  schema_version: "checkback.mvtec-pilot-download-plan.v1",
  asset_revision: plan.asset_revision,
  source_license: plan.source_license,
  noncommercial_evaluation_only: true,
  assets: plan.assets.map((asset) => ({
    asset_id: asset.asset_id,
    category: asset.category,
    expected_bytes: asset.expected_bytes,
    source_oid: asset.source_oid,
    source_path: asset.source_path,
    source_url: sourceUrl(plan.asset_revision, asset.source_path),
    local_relpath: `assets/${asset.asset_id}.png`,
  })),
};

mkdirSync(ASSET_ROOT, { recursive: true });
writeDeterministicJson(resolve(PILOT_ROOT, "pilot-plan.json"), plan);
writeDeterministicJson(resolve(PILOT_ROOT, "download-plan.json"), downloadPlan);

if (!values.verify) {
  process.stdout.write(
    JSON.stringify({
      mode: "plan",
      cases: plan.cases.length,
      assets: plan.assets.length,
      categories: MVTEC_PILOT_CATEGORIES.length,
    }) + "\n",
  );
} else {
  const verifiedAssets = [];
  for (const asset of downloadPlan.assets) {
    const path = resolve(PILOT_ROOT, asset.local_relpath);
    if (!path.startsWith(ASSET_ROOT + "\\") && path !== ASSET_ROOT) {
      throw new Error(`asset_path_outside_cache:${asset.asset_id}`);
    }
    const bytes = readFileSync(path);
    try {
      if (bytes.byteLength !== asset.expected_bytes) {
        throw new Error(`asset_size_mismatch:${asset.asset_id}`);
      }
      const metadata = await sharp(bytes, {
        failOn: "error",
        limitInputPixels: 32_000_000,
        sequentialRead: true,
      }).metadata();
      if (
        metadata.format !== "png" ||
        !metadata.width ||
        !metadata.height ||
        metadata.width * metadata.height > 32_000_000
      ) {
        throw new Error(`asset_image_invalid:${asset.asset_id}`);
      }
      verifiedAssets.push({
        ...asset,
        sha256: sha256(bytes),
        width: metadata.width,
        height: metadata.height,
        channels: metadata.channels ?? null,
      });
    } finally {
      bytes.fill(0);
    }
  }
  const manifest = {
    schema_version: "checkback.mvtec-end-to-end-pilot-manifest.v1",
    asset_revision: plan.asset_revision,
    source_license: plan.source_license,
    noncommercial_evaluation_only: true,
    preprocessing_policy: "checkback-mobile-1600px-430k-v1",
    cases: plan.cases,
    assets: verifiedAssets,
  };
  const manifestPath = resolve(PILOT_ROOT, "pilot-manifest.json");
  if (existsSync(manifestPath)) unlinkSync(manifestPath);
  writeDeterministicJson(manifestPath, manifest);
  process.stdout.write(
    JSON.stringify({
      mode: "verify",
      cases: manifest.cases.length,
      assets: verifiedAssets.length,
      manifest_sha256: sha256(readFileSync(manifestPath)),
    }) + "\n",
  );
}
