import assert from "node:assert/strict";
import test from "node:test";
import { normalizeCheckbackReport } from "../app/lib/checkback-analysis.ts";

function rawWith(change) {
  return {
    scene: { match: "same", overlap: "high", reason: "共同锚点一致" },
    quality_issues: [],
    changes: change ? [change] : [],
    checked_item_count: 7,
    summary: "分析完成",
  };
}

const missing = {
  id: "glasses",
  label: "黑框眼镜",
  type: "missing",
  certainty: "high",
  baseline_location: "桌面左上角",
  current_location: null,
  baseline_visible: true,
  expected_region_visible: true,
  evidence: "当前图未找到",
  action: "寻找眼镜",
};

const meta = { analysisId: "test-analysis", processingMs: 1200 };

test("keeps missing only after an independent high-certainty confirmation", () => {
  const report = normalizeCheckbackReport(
    rawWith(missing),
    {
      verifications: [
        {
          id: "glasses",
          verdict: "confirmed_missing",
          certainty: "high",
          current_location: null,
          evidence: "对应区域完整可见，当前图其他位置也未出现",
        },
      ],
    },
    meta,
  );

  assert.equal(report.status, "issues");
  assert.equal(report.items[0].type, "missing");
  assert.equal(report.verified_missing_count, 1);
});

test("downgrades missing to uncovered when the expected region is absent", () => {
  const report = normalizeCheckbackReport(
    rawWith({ ...missing, expected_region_visible: false }),
    null,
    meta,
  );

  assert.equal(report.status, "incomplete");
  assert.equal(report.items[0].type, "uncovered");
  assert.equal(report.verified_missing_count, 0);
});

test("removes a first-pass false alarm when verification finds the item in place", () => {
  const report = normalizeCheckbackReport(
    rawWith(missing),
    {
      verifications: [
        {
          id: "glasses",
          verdict: "visible_same_place",
          certainty: "high",
          current_location: "桌面左上角",
          evidence: "当前图仍可见同一副眼镜",
        },
      ],
    },
    meta,
  );

  assert.equal(report.status, "clear");
  assert.equal(report.items.length, 0);
  assert.equal(report.verified_missing_count, 0);
});

test("does not present low-certainty misplaced items as confirmed issues", () => {
  const report = normalizeCheckbackReport(
    rawWith({
      ...missing,
      id: "charger",
      label: "充电器",
      type: "misplaced",
      certainty: "low",
      current_location: "键盘旁",
    }),
    null,
    meta,
  );

  assert.equal(report.status, "incomplete");
  assert.equal(report.items[0].type, "uncertain");
});

test("an unresolved missing verification cannot produce a clear result", () => {
  const report = normalizeCheckbackReport(rawWith(missing), null, meta);

  assert.equal(report.status, "incomplete");
  assert.equal(report.items.length, 1);
  assert.equal(report.items[0].type, "uncertain");
  assert.equal(report.verified_missing_count, 0);
});

test("treats added items as informational instead of requiring action", () => {
  const report = normalizeCheckbackReport(
    rawWith({
      ...missing,
      id: "cup",
      label: "水杯",
      type: "added",
      certainty: "low",
      current_location: "桌面右侧",
    }),
    null,
    meta,
  );

  assert.equal(report.status, "clear");
  assert.equal(report.items[0].type, "added");
  assert.match(report.summary, /新增物品，不影响本次结果/);
});

test("does not clear when the model only considers the scene a possible match", () => {
  const raw = rawWith(null);
  raw.scene.match = "possible";

  const report = normalizeCheckbackReport(raw, null, meta);

  assert.equal(report.status, "incomplete");
  assert.match(report.headline, /不能确认是同一个区域/);
});

test("does not clear when the shared photo area is only medium", () => {
  const raw = rawWith(null);
  raw.scene.overlap = "medium";

  const report = normalizeCheckbackReport(raw, null, meta);

  assert.equal(report.status, "incomplete");
  assert.match(report.headline, /覆盖不够完整/);
});

test("does not clear when no comparable item was checked", () => {
  const raw = rawWith(null);
  raw.checked_item_count = 0;

  const report = normalizeCheckbackReport(raw, null, meta);

  assert.equal(report.status, "incomplete");
  assert.match(report.headline, /没有检查到可比对的物品/);
});
