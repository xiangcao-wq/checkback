/* eslint-disable @next/next/no-img-element */
"use client";

import {
  CaretLeft,
  Check,
  ClockCounterClockwise,
  Plus,
  X,
} from "@phosphor-icons/react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useAppLocale } from "./locale-provider";
import type { AnalysisMode } from "./lib/analysis-mode";
import type { ReportItem } from "./lib/checkback-analysis";
import {
  analysisModeMeta,
  displayAreaName,
  historyCurrentFile,
  loadCheckHistory,
  type CheckArea,
  type CheckHistoryRecord,
} from "./lib/area-store";
import { loadBaselineVersionImage } from "./lib/area-baseline-store";

type PanelView = "areas" | "create" | "history" | "detail";

type HistoryDetail = {
  record: CheckHistoryRecord;
  current: File;
  baseline: File | null;
};

const MODE_ORDER: AnalysisMode[] = [
  "restoration",
  "inventory",
  "condition",
  "completeness",
];

const ITEM_LABELS: Record<ReportItem["type"], string> = {
  missing: "缺少",
  misplaced: "放错位置",
  added: "记录项",
  occluded: "被遮挡",
  uncovered: "未拍到",
  uncertain: "暂不确定",
};

const ITEM_LABELS_EN: Record<ReportItem["type"], string> = {
  missing: "Missing",
  misplaced: "Misplaced",
  added: "Recorded",
  occluded: "Occluded",
  uncovered: "Out of frame",
  uncertain: "Uncertain",
};

function useObjectUrl(file: File | null) {
  const url = useMemo(() => (file ? URL.createObjectURL(file) : ""), [file]);
  useEffect(() => () => {
    if (url) URL.revokeObjectURL(url);
  }, [url]);
  return url;
}

function formatDate(value: number, locale: "zh-CN" | "en") {
  return new Intl.DateTimeFormat(locale === "en" ? "en-US" : "zh-CN", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function statusLabel(record: CheckHistoryRecord, locale: "zh-CN" | "en") {
  if (locale === "en") {
    if (record.mode === "inventory" && record.report.status === "clear") return "Inventory complete";
    if (record.report.status === "clear") return "Check passed";
    if (record.report.status === "issues") return "Action needed";
    return "Check incomplete";
  }
  if (record.mode === "inventory" && record.report.status === "clear") return "盘点完成";
  if (record.report.status === "clear") return "检查通过";
  if (record.report.status === "issues") return "需要处理";
  return "检查不完整";
}

export function WorkspacePanel({
  open,
  activeArea,
  areas,
  disabled,
  onClose,
  onSelectArea,
  onCreateArea,
}: {
  open: boolean;
  activeArea: CheckArea;
  areas: CheckArea[];
  disabled: boolean;
  onClose: () => void;
  onSelectArea: (area: CheckArea) => Promise<void>;
  onCreateArea: (input: { name: string; mode: AnalysisMode }) => Promise<void>;
}) {
  const [view, setView] = useState<PanelView>("areas");
  const [name, setName] = useState("");
  const [mode, setMode] = useState<AnalysisMode>("restoration");
  const [history, setHistory] = useState<CheckHistoryRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [detail, setDetail] = useState<HistoryDetail | null>(null);
  const [message, setMessage] = useState("");
  const currentUrl = useObjectUrl(detail?.current ?? null);
  const baselineUrl = useObjectUrl(detail?.baseline ?? null);
  const { locale } = useAppLocale();
  const en = locale === "en";
  const copy = en ? {
    historyReadError: "History is temporarily unavailable",
    historyBaselineError: "The reference photo for this record is unavailable",
    nameRequired: "Give this area an easy-to-recognize name",
    createFailed: "Could not create the area. Please try again",
    areasTitle: "Areas and tasks",
    createTitle: "New check area",
    historyDetails: "History details",
    back: "Back",
    current: "Current",
    close: "Close area panel",
    viewHistory: "View this area's history",
    newArea: "New area",
    areaName: "Area name",
    areaPlaceholder: "For example: Storage cabinet A",
    modeQuestion: "What do you mainly want to check?",
    createAction: "Create and capture reference photo",
    loadingHistory: "Loading history…",
    emptyHistory: "No check records yet",
    emptyHistoryHint: "Your first completed check will be saved here automatically",
    baselineAlt: "Reference photo used for this check",
    baselineCaption: "Reference at the time",
    currentAlt: "Current photo captured for this check",
    currentCaption: "Check photo",
    inventoryItem: "Inventory item",
  } : {
    historyReadError: "检查历史暂时无法读取",
    historyBaselineError: "这条记录的历史标准照片无法读取",
    nameRequired: "给这个区域起一个容易识别的名称",
    createFailed: "区域创建失败，请重试",
    areasTitle: "区域与任务",
    createTitle: "新建检查区域",
    historyDetails: "历史详情",
    back: "返回",
    current: "当前",
    close: "关闭区域面板",
    viewHistory: "查看历史",
    newArea: "新建区域",
    areaName: "区域名称",
    areaPlaceholder: "例如：储物柜 A",
    modeQuestion: "你主要想检查什么？",
    createAction: "创建并拍摄标准照片",
    loadingHistory: "正在读取历史…",
    emptyHistory: "还没有检查记录",
    emptyHistoryHint: "完成第一次检查后会自动保存在这里",
    baselineAlt: "这次检查使用的标准照片",
    baselineCaption: "当时的标准",
    currentAlt: "这次检查拍摄的当前照片",
    currentCaption: "检查照片",
    inventoryItem: "盘点项",
  };

  const resetAndClose = useCallback(() => {
    setView("areas");
    setDetail(null);
    setMessage("");
    onClose();
  }, [onClose]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") resetAndClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, resetAndClose]);

  if (!open) return null;

  const openHistory = async () => {
    setView("history");
    setHistoryLoading(true);
    setMessage("");
    try {
      setHistory(await loadCheckHistory(activeArea.id));
    } catch {
      setMessage(copy.historyReadError);
    } finally {
      setHistoryLoading(false);
    }
  };

  const openDetail = async (record: CheckHistoryRecord) => {
    setView("detail");
    setMessage("");
    const current = historyCurrentFile(record);
    setDetail({ record, current, baseline: null });
    if (!record.baselineVersionId) return;
    try {
      const baseline = await loadBaselineVersionImage(record.baselineVersionId);
      setDetail((value) => value?.record.id === record.id ? { ...value, baseline } : value);
    } catch {
      setMessage(copy.historyBaselineError);
    }
  };

  const create = async () => {
    if (!name.trim()) {
      setMessage(copy.nameRequired);
      return;
    }
    setMessage("");
    try {
      await onCreateArea({ name, mode });
      setName("");
      setMode("restoration");
      resetAndClose();
    } catch {
      setMessage(copy.createFailed);
    }
  };

  const activeAreaName = displayAreaName(activeArea, locale);
  const title =
    view === "areas"
      ? copy.areasTitle
      : view === "create"
        ? copy.createTitle
        : view === "history"
          ? en ? `${activeAreaName} history` : `${activeAreaName}的历史`
          : copy.historyDetails;

  return (
    <div className="workspace-overlay" role="presentation" onMouseDown={(event) => {
      if (event.target === event.currentTarget) resetAndClose();
    }}>
      <section className="workspace-sheet" role="dialog" aria-modal="true" aria-labelledby="workspace-title">
        <header className="workspace-header">
          {view !== "areas" ? (
            <button
              className="workspace-icon-button"
              type="button"
              onClick={() => {
                if (view === "detail") setView("history");
                else setView("areas");
              }}
              aria-label={copy.back}
            >
              <CaretLeft size={20} weight="bold" aria-hidden="true" />
            </button>
          ) : <span className="workspace-header-spacer" />}
          <div>
            <p>{copy.current}：{activeAreaName}</p>
            <h2 id="workspace-title">{title}</h2>
          </div>
          <button className="workspace-icon-button" type="button" onClick={resetAndClose} aria-label={copy.close}>
            <X size={20} weight="bold" aria-hidden="true" />
          </button>
        </header>

        <div className="workspace-content">
          {view === "areas" && (
            <>
              <div className="area-list">
                {areas.map((area) => {
                  const selected = area.id === activeArea.id;
                  const meta = analysisModeMeta(area.mode, locale);
                  return (
                    <button
                      className={`area-card${selected ? " is-active" : ""}`}
                      key={area.id}
                      type="button"
                      disabled={disabled || selected}
                      onClick={() => void onSelectArea(area).then(resetAndClose)}
                    >
                      <span className="area-card-mark" aria-hidden="true">
                        {selected ? <Check size={17} weight="bold" /> : area.name.slice(0, 1)}
                      </span>
                      <span>
                        <strong>{displayAreaName(area, locale)}</strong>
                        <small>{meta.shortLabel} · {meta.description}</small>
                      </span>
                    </button>
                  );
                })}
              </div>
              <div className="workspace-actions">
                <button type="button" onClick={() => void openHistory()}>
                  <ClockCounterClockwise size={19} weight="duotone" aria-hidden="true" />
                  {copy.viewHistory}
                </button>
                <button type="button" onClick={() => setView("create")}>
                  <Plus size={19} weight="bold" aria-hidden="true" />
                  {copy.newArea}
                </button>
              </div>
            </>
          )}

          {view === "create" && (
            <div className="area-create-form">
              <label>
                <span>{copy.areaName}</span>
                <input
                  autoFocus
                  maxLength={24}
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder={copy.areaPlaceholder}
                />
              </label>
              <fieldset>
                <legend>{copy.modeQuestion}</legend>
                <div className="mode-options">
                  {MODE_ORDER.map((value) => {
                    const meta = analysisModeMeta(value, locale);
                    return (
                      <button
                        className={mode === value ? "is-selected" : ""}
                        type="button"
                        key={value}
                        onClick={() => setMode(value)}
                      >
                        <strong>{meta.label}</strong>
                        <span>{meta.description}</span>
                      </button>
                    );
                  })}
                </div>
              </fieldset>
              <button className="workspace-primary" type="button" onClick={() => void create()}>
                {copy.createAction}
              </button>
            </div>
          )}

          {view === "history" && (
            <div className="history-list">
              {historyLoading ? (
                <p className="workspace-empty">{copy.loadingHistory}</p>
              ) : history.length === 0 ? (
                <div className="workspace-empty">
                  <ClockCounterClockwise size={28} weight="duotone" aria-hidden="true" />
                  <strong>{copy.emptyHistory}</strong>
                  <span>{copy.emptyHistoryHint}</span>
                </div>
              ) : history.map((record) => (
                <button type="button" key={record.id} onClick={() => void openDetail(record)}>
                  <span className={`history-status is-${record.report.status}`} />
                  <span>
                    <strong>{statusLabel(record, locale)}</strong>
                    <small>{formatDate(record.createdAt, locale)} · {record.report.headline}</small>
                  </span>
                  <CaretLeft className="history-caret" size={17} weight="bold" aria-hidden="true" />
                </button>
              ))}
            </div>
          )}

          {view === "detail" && detail && (
            <article className="history-detail">
              <div className="history-photos">
                {baselineUrl && <figure><img src={baselineUrl} alt={copy.baselineAlt} /><figcaption>{copy.baselineCaption}</figcaption></figure>}
                {currentUrl && <figure><img src={currentUrl} alt={copy.currentAlt} /><figcaption>{copy.currentCaption}</figcaption></figure>}
              </div>
              <p className="history-detail-meta">{formatDate(detail.record.createdAt, locale)} · {analysisModeMeta(detail.record.mode, locale).shortLabel}</p>
              <h3>{detail.record.report.headline}</h3>
              <p>{detail.record.report.summary}</p>
              {detail.record.report.items.length > 0 && (
                <ul className="history-item-list">
                  {detail.record.report.items.map((item) => (
                    <li key={item.id}>
                      <span>{detail.record.mode === "inventory" && item.type === "added" ? copy.inventoryItem : (en ? ITEM_LABELS_EN : ITEM_LABELS)[item.type]}</span>
                      <div><strong>{item.label}</strong><p>{item.evidence}</p></div>
                    </li>
                  ))}
                </ul>
              )}
            </article>
          )}
          {message && <p className="workspace-message" role="alert">{message}</p>}
        </div>
      </section>
    </div>
  );
}
