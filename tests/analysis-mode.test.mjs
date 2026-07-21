import assert from "node:assert/strict";
import test from "node:test";
import { AnalysisModeSchema } from "../app/lib/analysis-mode.ts";
import { normalizeCheckbackReport } from "../app/lib/checkback-analysis.ts";
import { adaptReportForMode } from "../app/lib/mode-report.ts";

function inventoryChange(id, label, location) {
  return {
    id,
    label,
    type: "added",
    certainty: "high",
    baseline_location: location,
    current_location: location,
    baseline_visible: true,
    expected_region_visible: true,
    evidence: "逐格清点，轮廓清晰",
    action: "记录当前数量",
  };
}

function inventoryRaw(overrides = {}) {
  return {
    scene: { match: "same", overlap: "high", reason: "同一个储物柜" },
    quality_issues: [],
    changes: [
      inventoryChange("screws", "螺丝 × 12", "上层左侧"),
      inventoryChange("tape", "胶带 × 5", "中层"),
    ],
    checked_item_count: 17,
    summary: "已盘点当前可见物资",
    ...overrides,
  };
}

function normalized(raw) {
  return normalizeCheckbackReport(raw, null, {
    analysisId: "inventory-test",
    processingMs: 1200,
  });
}

test("accepts only supported area analysis modes", () => {
  for (const mode of ["restoration", "inventory", "condition", "completeness"]) {
    assert.equal(AnalysisModeSchema.parse(mode), mode);
  }
  assert.equal(AnalysisModeSchema.safeParse("storage-cabinet").success, false);
});

test("turns an inventory snapshot into a count-first report", () => {
  const raw = inventoryRaw();
  const report = adaptReportForMode(normalized(raw), raw, "inventory");

  assert.equal(report.status, "clear");
  assert.match(report.headline, /2 类，共 17 件/);
  assert.match(report.summary, /库存快照已完成并保存/);
  assert.equal(report.items.length, 2);
});

test("does not claim a complete inventory when framing is blocked", () => {
  const raw = inventoryRaw({
    quality_issues: [
      { type: "framing", severity: "blocking", message: "柜子右侧没有拍全" },
    ],
  });
  const report = adaptReportForMode(normalized(raw), raw, "inventory");

  assert.equal(report.status, "incomplete");
  assert.match(report.summary, /不足以可靠完成库存盘点/);
});
