import { posix } from "node:path";

export const MVTEC_PILOT_REVISION =
  "464875d33af84257cac350ebcf2c4210343f85a3";

export const MVTEC_PILOT_CATEGORIES = [
  "breakfast_box",
  "juice_bottle",
  "pushpins",
  "screw_bag",
  "splicing_connectors",
] as const;

export type MvtecPilotCategory = (typeof MVTEC_PILOT_CATEGORIES)[number];
export type MvtecPilotTruthClass =
  | "observable_missing"
  | "hard_negative"
  | "not_comparable";
export type MvtecPilotTransform =
  | "none"
  | "blur"
  | "occlusion"
  | "crop"
  | "darkness";

export const MVTEC_PILOT_MISSING_IDS: Readonly<
  Record<MvtecPilotCategory, readonly string[]>
> = Object.freeze({
  breakfast_box: Object.freeze(["0003", "0010", "0024", "0027"]),
  juice_bottle: Object.freeze(["0000", "0003", "0007", "0015"]),
  pushpins: Object.freeze(["0034", "0039", "0041", "0043"]),
  screw_bag: Object.freeze(["0065", "0067", "0068", "0069"]),
  splicing_connectors: Object.freeze(["0030", "0031", "0032", "0033"]),
});

const DIFFICULT_TRANSFORMS = Object.freeze([
  "blur",
  "occlusion",
  "crop",
  "darkness",
] as const);

export type HuggingFaceTreeEntry = {
  type: string;
  path: string;
  size: number;
  oid: string;
};

export type MvtecPilotAsset = {
  asset_id: string;
  category: MvtecPilotCategory;
  source_kind: "good" | "logical_anomaly";
  source_id: string;
  source_path: string;
  expected_bytes: number;
  source_oid: string;
};

export type MvtecPilotCase = {
  case_id: string;
  scene_id: string;
  category: MvtecPilotCategory;
  truth_class: MvtecPilotTruthClass;
  baseline_asset_id: string;
  current_asset_id: string;
  current_transform: MvtecPilotTransform;
};

export type MvtecPilotPlan = {
  schema_version: "checkback.mvtec-end-to-end-pilot-plan.v1";
  asset_revision: string;
  source_license: "CC-BY-NC-SA-4.0";
  noncommercial_evaluation_only: true;
  cases: MvtecPilotCase[];
  assets: MvtecPilotAsset[];
};

type CategoryTrees = Record<
  MvtecPilotCategory,
  { test: HuggingFaceTreeEntry[]; good: HuggingFaceTreeEntry[] }
>;

function assertFileEntries(
  category: MvtecPilotCategory,
  kind: "test" | "good",
  entries: HuggingFaceTreeEntry[],
) {
  const expectedPrefix =
    `MVTec-LOCO/${category}/` +
    (kind === "test" ? "test/logical_anomalies/" : "train/good/");
  if (!Array.isArray(entries) || entries.length < 5) {
    throw new Error(`mvtec_${category}_${kind}_tree_too_small`);
  }
  const paths = new Set<string>();
  for (const entry of entries) {
    if (
      entry?.type !== "file" ||
      typeof entry.path !== "string" ||
      !entry.path.startsWith(expectedPrefix) ||
      !/^\d{4}\.png$/.test(posix.basename(entry.path)) ||
      !Number.isInteger(entry.size) ||
      entry.size < 1 ||
      entry.size > 8 * 1024 * 1024 ||
      typeof entry.oid !== "string" ||
      !/^[a-f0-9]{40}$/.test(entry.oid) ||
      paths.has(entry.path)
    ) {
      throw new Error(`mvtec_${category}_${kind}_tree_invalid`);
    }
    paths.add(entry.path);
  }
}

function sourceId(path: string) {
  return posix.basename(path, ".png");
}

export function buildMvtecPilotPlan(
  trees: CategoryTrees,
  assetRevision = MVTEC_PILOT_REVISION,
): MvtecPilotPlan {
  if (!/^[a-f0-9]{40}$/.test(assetRevision)) {
    throw new Error("mvtec_asset_revision_invalid");
  }

  const assetByPath = new Map<string, MvtecPilotAsset>();
  const selectedByCategory = new Map<
    MvtecPilotCategory,
    {
      baseline: string;
      hardNegatives: string[];
      missing: string[];
      difficult: string[];
    }
  >();

  const registerAsset = (
    category: MvtecPilotCategory,
    sourceKind: "good" | "logical_anomaly",
    entry: HuggingFaceTreeEntry,
  ) => {
    const existing = assetByPath.get(entry.path);
    if (existing) return existing.asset_id;
    const asset: MvtecPilotAsset = {
      asset_id: `asset-${String(assetByPath.size + 1).padStart(4, "0")}`,
      category,
      source_kind: sourceKind,
      source_id: sourceId(entry.path),
      source_path: entry.path,
      expected_bytes: entry.size,
      source_oid: entry.oid,
    };
    assetByPath.set(entry.path, asset);
    return asset.asset_id;
  };

  for (const category of MVTEC_PILOT_CATEGORIES) {
    const categoryTrees = trees[category];
    if (!categoryTrees) throw new Error(`mvtec_${category}_trees_missing`);
    assertFileEntries(category, "test", categoryTrees.test);
    assertFileEntries(category, "good", categoryTrees.good);
    const testEntries = [...categoryTrees.test].sort((a, b) =>
      a.path.localeCompare(b.path),
    );
    const goodEntries = [...categoryTrees.good].sort((a, b) =>
      a.path.localeCompare(b.path),
    );
    const testById = new Map(testEntries.map((entry) => [sourceId(entry.path), entry]));
    const missingEntries = MVTEC_PILOT_MISSING_IDS[category].map((id) => {
      const entry = testById.get(id);
      if (!entry) throw new Error(`mvtec_${category}_missing_id_not_in_tree_${id}`);
      return entry;
    });
    const missingPaths = new Set(missingEntries.map((entry) => entry.path));
    const difficultEntries = testEntries
      .filter((entry) => !missingPaths.has(entry.path))
      .slice(-DIFFICULT_TRANSFORMS.length);
    if (difficultEntries.length !== DIFFICULT_TRANSFORMS.length) {
      throw new Error(`mvtec_${category}_difficult_cases_missing`);
    }

    selectedByCategory.set(category, {
      baseline: registerAsset(category, "good", goodEntries[0]),
      hardNegatives: goodEntries
        .slice(1, 5)
        .map((entry) => registerAsset(category, "good", entry)),
      missing: missingEntries.map((entry) =>
        registerAsset(category, "logical_anomaly", entry),
      ),
      difficult: difficultEntries.map((entry) =>
        registerAsset(category, "logical_anomaly", entry),
      ),
    });
  }

  const cases: MvtecPilotCase[] = [];
  const pushCase = (
    category: MvtecPilotCategory,
    truthClass: MvtecPilotTruthClass,
    baselineAssetId: string,
    currentAssetId: string,
    transform: MvtecPilotTransform,
  ) => {
    const ordinal = cases.length + 1;
    cases.push({
      case_id: `case-${String(ordinal).padStart(4, "0")}`,
      scene_id: `scene-${String(ordinal).padStart(4, "0")}`,
      category,
      truth_class: truthClass,
      baseline_asset_id: baselineAssetId,
      current_asset_id: currentAssetId,
      current_transform: transform,
    });
  };

  for (let sample = 0; sample < 4; sample += 1) {
    for (const category of MVTEC_PILOT_CATEGORIES) {
      const selected = selectedByCategory.get(category)!;
      pushCase(
        category,
        "observable_missing",
        selected.baseline,
        selected.missing[sample],
        "none",
      );
      pushCase(
        category,
        "hard_negative",
        selected.baseline,
        selected.hardNegatives[sample],
        "none",
      );
      pushCase(
        category,
        "not_comparable",
        selected.baseline,
        selected.difficult[sample],
        DIFFICULT_TRANSFORMS[sample],
      );
    }
  }

  const assets = [...assetByPath.values()];
  const truthCounts = Object.fromEntries(
    ["observable_missing", "hard_negative", "not_comparable"].map((truth) => [
      truth,
      cases.filter((item) => item.truth_class === truth).length,
    ]),
  );
  if (
    cases.length !== 60 ||
    assets.length !== 65 ||
    Object.values(truthCounts).some((count) => count !== 20) ||
    new Set(cases.map((item) => item.case_id)).size !== 60 ||
    new Set(assets.map((item) => item.asset_id)).size !== 65
  ) {
    throw new Error("mvtec_pilot_plan_contract_failed");
  }

  return {
    schema_version: "checkback.mvtec-end-to-end-pilot-plan.v1",
    asset_revision: assetRevision,
    source_license: "CC-BY-NC-SA-4.0",
    noncommercial_evaluation_only: true,
    cases,
    assets,
  };
}
