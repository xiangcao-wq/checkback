import { z } from "zod";
import { localize, type AppLocale } from "./locale.ts";

export const ChangeTypeSchema = z.enum([
  "missing",
  "misplaced",
  "added",
  "occluded",
  "uncovered",
  "uncertain",
]);

export const CertaintySchema = z.enum(["high", "medium", "low"]);

export const QualityIssueSchema = z
  .object({
    type: z.enum(["blur", "darkness", "glare", "occlusion", "framing", "other"]),
    severity: z.enum(["blocking", "warning"]),
    message: z.string().min(1).max(160),
  })
  .strict();

export const RawChangeSchema = z
  .object({
    id: z.string().min(1).max(80),
    label: z.string().min(1).max(80),
    type: ChangeTypeSchema,
    certainty: CertaintySchema,
    baseline_location: z.string().min(1).max(160),
    current_location: z.string().max(160).nullable(),
    baseline_visible: z.boolean(),
    expected_region_visible: z.boolean(),
    origin: z.enum(["primary", "scout"]).optional(),
    evidence: z.string().min(1).max(300),
    action: z.string().min(1).max(160),
  })
  .strict();

export const RawCheckbackAnalysisSchema = z
  .object({
    scene: z
      .object({
        match: z.enum(["same", "possible", "different"]),
        overlap: z.enum(["high", "medium", "low"]),
        reason: z.string().min(1).max(240),
      })
      .strict(),
    quality_issues: z.array(QualityIssueSchema).max(8),
    changes: z.array(RawChangeSchema).max(30),
    checked_item_count: z.number().int().min(0).max(200),
    summary: z.string().min(1).max(360),
  })
  .strict();

export const MissingVerificationSchema = z
  .object({
    verifications: z
      .array(
        z
          .object({
            id: z.string().min(1).max(80),
            verdict: z.enum([
              "confirmed_missing",
              "visible_same_place",
              "visible_elsewhere",
              "not_comparable",
            ]),
            certainty: CertaintySchema,
            current_location: z.string().max(160).nullable(),
            evidence: z.string().min(1).max(300),
          })
          .strict(),
      )
      .max(20),
  })
  .strict();

export type RawCheckbackAnalysis = z.infer<typeof RawCheckbackAnalysisSchema>;
export type MissingVerification = z.infer<typeof MissingVerificationSchema>;
export type QualityIssue = z.infer<typeof QualityIssueSchema>;
export type Certainty = z.infer<typeof CertaintySchema>;
export type ChangeType = z.infer<typeof ChangeTypeSchema>;

export type ReportItem = {
  id: string;
  label: string;
  type: ChangeType;
  certainty: Certainty;
  baseline_location: string;
  current_location: string | null;
  evidence: string;
  action: string;
};

export type CheckbackReport = {
  status: "clear" | "issues" | "incomplete";
  headline: string;
  summary: string;
  scene_match: "same" | "possible" | "different";
  overlap: "high" | "medium" | "low";
  scene_reason: string;
  quality_issues: QualityIssue[];
  items: ReportItem[];
  checked_item_count: number;
  verified_missing_count: number;
  analysis_id: string;
  processing_ms: number;
};

function asReportItem(change: RawCheckbackAnalysis["changes"][number]): ReportItem {
  return {
    id: change.id,
    label: change.label,
    type: change.type,
    certainty: change.certainty,
    baseline_location: change.baseline_location,
    current_location: change.current_location,
    evidence: change.evidence,
    action: change.action,
  };
}

export function normalizeCheckbackReport(
  raw: RawCheckbackAnalysis,
  verification: MissingVerification | null,
  meta: { analysisId: string; processingMs: number },
  locale: AppLocale = "zh-CN",
): CheckbackReport {
  const verificationById = new Map(
    verification?.verifications.map((item) => [item.id, item]) ?? [],
  );

  const items: ReportItem[] = [];
  let verifiedMissingCount = 0;

  for (const change of raw.changes) {
    if (change.type !== "missing") {
      const item = asReportItem(change);
      if (item.type === "added") {
        item.action = localize(locale, "仅供参考，无需处理，不影响本次检查结果", "For reference only; no action is needed and this does not affect the result");
      } else if (item.type === "misplaced" && item.certainty === "low") {
        item.type = "uncertain";
      }
      items.push(item);
      continue;
    }

    const item = asReportItem(change);

    const scoutCandidate = change.origin === "scout";
    if (
      !change.baseline_visible || (change.certainty !== "high" && !scoutCandidate)
    ) {
      item.type = "uncertain";
      item.action = localize(locale, "请确认标准照片足够清晰，或重新拍摄当前照片", "Make sure the reference is clear, or retake the current photo");
      items.push(item);
      continue;
    }

    if (!change.expected_region_visible) {
      item.type = "uncovered";
      item.action = localize(locale, "请补拍这个物品原来所在的区域", "Capture the area where this item originally appeared");
      items.push(item);
      continue;
    }

    const checked = verificationById.get(change.id);
    if (!checked || checked.certainty !== "high") {
      item.type = "uncertain";
      item.action = localize(locale, "还不能可靠确认是否缺少，请补拍后重试", "Missing status is not reliable yet; capture more of the area and retry");
      items.push(item);
      continue;
    }

    if (checked.verdict === "confirmed_missing") {
      item.evidence = checked.evidence;
      verifiedMissingCount += 1;
      items.push(item);
      continue;
    }

    if (checked.verdict === "visible_elsewhere") {
      item.type = "misplaced";
      item.current_location = checked.current_location;
      item.evidence = checked.evidence;
      item.action = localize(locale, "把它放回标准照片中的位置", "Return it to the position shown in the reference photo");
      items.push(item);
      continue;
    }

    if (checked.verdict === "not_comparable") {
      item.type = "uncovered";
      item.evidence = checked.evidence;
      item.action = localize(locale, "请补拍这个物品原来所在的区域", "Capture the area where this item originally appeared");
      items.push(item);
    }
  }

  const hasBlockingQuality = raw.quality_issues.some((issue) => issue.severity === "blocking");
  const comparisonIncomplete =
    raw.scene.match !== "same" ||
    raw.scene.overlap !== "high" ||
    raw.checked_item_count === 0;
  const actionable = items.filter((item) =>
    ["missing", "misplaced"].includes(item.type),
  );
  const addedCount = items.filter((item) => item.type === "added").length;
  const unresolved = items.filter((item) =>
    ["occluded", "uncovered", "uncertain"].includes(item.type),
  );

  let status: CheckbackReport["status"] = "clear";
  if (comparisonIncomplete || hasBlockingQuality) status = "incomplete";
  else if (actionable.length > 0) status = "issues";
  else if (unresolved.length > 0) status = "incomplete";

  const misplacedCount = actionable.filter((item) => item.type === "misplaced").length;
  const addedNote = addedCount > 0
    ? localize(
        locale,
        "另记录 " + addedCount + " 件新增物品，不影响本次结果。",
        addedCount + " added item" + (addedCount === 1 ? " was" : "s were") + " recorded and do not affect this result. ",
      )
    : "";
  const headline =
    status === "clear"
      ? localize(locale, "没有发现需要处理的问题", "No issues need attention")
      : status === "issues"
        ? localize(
            locale,
            "发现 " + actionable.length + " 个需要处理的变化",
            "Found " + actionable.length + " change" + (actionable.length === 1 ? "" : "s") + " that need attention",
          )
        : raw.quality_issues.find((issue) => issue.severity === "blocking")?.message ??
          (raw.scene.match === "different"
            ? localize(locale, "这两张照片可能不是同一个区域", "These photos may show different areas")
            : raw.scene.match === "possible"
              ? localize(locale, "还不能确认是同一个区域，请按标准照片的角度补拍", "The area match is uncertain. Retake from the reference angle")
              : raw.scene.overlap !== "high"
                ? localize(locale, "当前照片覆盖不够完整，请把标准照片中的主要区域拍全", "The current photo does not cover enough of the reference area")
                : raw.checked_item_count === 0
                  ? localize(locale, "没有检查到可比对的物品，请拍清楚桌面后重试", "No comparable items were found. Capture the full area clearly and retry")
                  : localize(locale, "这次还不能完成检查", "This check could not be completed"));

  const summary =
    status === "clear"
      ? localize(
          locale,
          "已检查 " + raw.checked_item_count + " 件可见物品，没有发现需要处理的缺少或错位。" + addedNote,
          "Checked " + raw.checked_item_count + " visible item" + (raw.checked_item_count === 1 ? "" : "s") + "; no missing or misplaced items need attention. " + addedNote,
        )
      : status === "issues"
        ? localize(
            locale,
            verifiedMissingCount + " 件确认缺少，" + misplacedCount + " 件疑似放错位置；" + addedNote + "证据不足的项目不会算作缺少。",
            verifiedMissingCount + " confirmed missing; " + misplacedCount + " misplaced. " + addedNote + "Items without enough evidence are not counted as missing.",
          )
        : unresolved.length > 0
          ? localize(
              locale,
              unresolved.length + " 个项目暂时无法确认，我们没有把它们算作缺少。",
              unresolved.length + " item" + (unresolved.length === 1 ? " is" : "s are") + " still uncertain and are not counted as missing.",
            )
          : localize(
              locale,
              "当前照片不足以可靠完成比对，我们不会给出“可以离开”的结论。",
              "The current photo is not sufficient for a reliable comparison, so this check cannot be cleared.",
            );

  return {
    status,
    headline,
    summary,
    scene_match: raw.scene.match,
    overlap: raw.scene.overlap,
    scene_reason: raw.scene.reason,
    quality_issues: raw.quality_issues,
    items,
    checked_item_count: raw.checked_item_count,
    verified_missing_count: verifiedMissingCount,
    analysis_id: meta.analysisId,
    processing_ms: meta.processingMs,
  };
}
