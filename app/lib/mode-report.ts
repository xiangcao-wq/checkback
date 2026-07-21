import type { AnalysisMode } from "./analysis-mode";
import type { CheckbackReport, RawCheckbackAnalysis } from "./checkback-analysis";
import { localize, type AppLocale } from "./locale.ts";

export function adaptReportForMode(
  report: CheckbackReport,
  raw: RawCheckbackAnalysis,
  mode: AnalysisMode,
  locale: AppLocale = "zh-CN",
): CheckbackReport {
  if (mode === "inventory") {
    const uncertainCount = report.items.filter((item) =>
      ["occluded", "uncovered", "uncertain"].includes(item.type),
    ).length;
    const countedGroups = report.items.filter((item) => item.type === "added").length;
    const usable =
      report.scene_match === "same" &&
      report.overlap === "high" &&
      !report.quality_issues.some((issue) => issue.severity === "blocking") &&
      raw.checked_item_count > 0;
    return {
      ...report,
      status: usable && uncertainCount === 0 ? "clear" : "incomplete",
      headline: usable
        ? localize(
            locale,
            `已盘点 ${countedGroups} 类，共 ${raw.checked_item_count} 件`,
            `Counted ${countedGroups} categor${countedGroups === 1 ? "y" : "ies"}, ${raw.checked_item_count} unit${raw.checked_item_count === 1 ? "" : "s"}`,
          )
        : report.headline,
      summary: usable
        ? uncertainCount > 0
          ? localize(
              locale,
              `已记录当前可见库存，另有 ${uncertainCount} 项因遮挡或画面范围暂时无法确认。`,
              `Visible inventory was recorded; ${uncertainCount} categor${uncertainCount === 1 ? "y is" : "ies are"} still uncertain because of occlusion or framing.`,
            )
          : localize(
              locale,
              "当前库存快照已完成并保存，可以在历史中查看之后的数量变化。",
              "The current inventory snapshot is complete and saved. Use history to review later quantity changes.",
            )
        : localize(
            locale,
            "当前照片不足以可靠完成库存盘点，请拍全柜内层板后重试。",
            "The current photo is not sufficient for a reliable count. Capture every shelf and try again.",
          ),
    };
  }

  if (mode === "condition") {
    return {
      ...report,
      headline:
        report.status === "clear"
          ? localize(locale, "空间状态符合标准", "Space matches the reference condition")
          : report.status === "issues" && locale !== "en"
            ? report.headline.replace("变化", "状态差异")
            : report.headline,
      summary:
        report.status === "clear"
          ? localize(
              locale,
              "当前空间与标准状态一致，没有发现需要处理的异常。",
              "The current space matches the reference condition; no issues need attention.",
            )
          : report.summary,
    };
  }

  if (mode === "completeness") {
    return {
      ...report,
      headline:
        report.status === "clear"
          ? localize(locale, "必备物品齐全", "All required items are present")
          : report.status === "issues"
            ? localize(
                locale,
                `发现 ${report.verified_missing_count} 件必备物品缺少或错位`,
                `${report.verified_missing_count} required item${report.verified_missing_count === 1 ? " is" : "s are"} missing or misplaced`,
              )
            : report.headline,
      summary:
        report.status === "clear"
          ? localize(
              locale,
              `已核对 ${report.checked_item_count} 件可见物品，没有发现必备物品缺少。`,
              `Checked ${report.checked_item_count} visible item${report.checked_item_count === 1 ? "" : "s"}; no required items are missing.`,
            )
          : report.summary,
    };
  }

  return report;
}
