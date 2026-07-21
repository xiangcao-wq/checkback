import test from "node:test";
import assert from "node:assert/strict";
import {
  MVTEC_PILOT_CATEGORIES,
  MVTEC_PILOT_MISSING_IDS,
  buildMvtecPilotPlan,
} from "../evaluation/pilot/mvtec-pilot-plan.ts";

function treeEntry(path, index) {
  return {
    type: "file",
    path,
    size: 100_000 + index,
    oid: (index + 1).toString(16).padStart(40, "0"),
  };
}

function makeTrees() {
  return Object.fromEntries(
    MVTEC_PILOT_CATEGORIES.map((category, categoryIndex) => [
      category,
      {
        test: Array.from({ length: 180 }, (_, index) =>
          treeEntry(
            `MVTec-LOCO/${category}/test/logical_anomalies/${String(index).padStart(4, "0")}.png`,
            categoryIndex * 1_000 + index,
          ),
        ),
        good: Array.from({ length: 20 }, (_, index) =>
          treeEntry(
            `MVTec-LOCO/${category}/train/good/${String(index).padStart(4, "0")}.png`,
            10_000 + categoryIndex * 1_000 + index,
          ),
        ),
      },
    ]),
  );
}

test("builds a balanced, deterministic, non-overlapping 60-case pilot", () => {
  const plan = buildMvtecPilotPlan(makeTrees());
  assert.equal(plan.cases.length, 60);
  assert.equal(plan.assets.length, 65);
  assert.equal(new Set(plan.cases.map((item) => item.case_id)).size, 60);
  assert.equal(new Set(plan.assets.map((item) => item.asset_id)).size, 65);

  for (const truthClass of [
    "observable_missing",
    "hard_negative",
    "not_comparable",
  ]) {
    assert.equal(
      plan.cases.filter((item) => item.truth_class === truthClass).length,
      20,
    );
  }
  for (const category of MVTEC_PILOT_CATEGORIES) {
    assert.equal(plan.cases.filter((item) => item.category === category).length, 12);
    const missingAssets = plan.cases
      .filter(
        (item) =>
          item.category === category &&
          item.truth_class === "observable_missing",
      )
      .map((item) => plan.assets.find((asset) => asset.asset_id === item.current_asset_id)?.source_id);
    assert.deepEqual(missingAssets, [...MVTEC_PILOT_MISSING_IDS[category]]);
  }
  const firstRound = plan.cases.slice(0, 15);
  assert.equal(new Set(firstRound.map((item) => item.category)).size, 5);
  assert.equal(new Set(firstRound.map((item) => item.truth_class)).size, 3);
  for (const transform of ["blur", "occlusion", "crop", "darkness"]) {
    assert.equal(
      plan.cases.filter((item) => item.current_transform === transform).length,
      5,
    );
  }
});

test("fails closed when a frozen missing ID is absent from the source tree", () => {
  const trees = makeTrees();
  const missing = MVTEC_PILOT_MISSING_IDS.breakfast_box[0];
  trees.breakfast_box.test = trees.breakfast_box.test.filter(
    (entry) => !entry.path.endsWith(`/${missing}.png`),
  );
  assert.throws(
    () => buildMvtecPilotPlan(trees),
    new RegExp(`mvtec_breakfast_box_missing_id_not_in_tree_${missing}`),
  );
});
