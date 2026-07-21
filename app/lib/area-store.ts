"use client";

import type { AnalysisMode } from "./analysis-mode";
import type { AppLocale } from "./locale";
import type { CheckbackReport } from "./checkback-analysis";
import {
  AREA_STORE,
  BASELINE_STORE,
  BASELINE_VERSION_STORE,
  HISTORY_STORE,
  SETTINGS_STORE,
  openCheckbackDatabase,
  requestValue,
} from "./local-database";

export const DEFAULT_AREA_ID = "default";
const ACTIVE_AREA_KEY = "active-area-id";
const MAX_HISTORY_PER_AREA = 30;

export type CheckArea = {
  id: string;
  name: string;
  mode: AnalysisMode;
  createdAt: number;
  updatedAt: number;
};

export type CheckHistoryRecord = {
  id: string;
  areaId: string;
  areaName: string;
  mode: AnalysisMode;
  baselineVersionId: string | null;
  createdAt: number;
  report: CheckbackReport;
  currentBlob: Blob;
  currentName: string;
  currentType: string;
};

export const ANALYSIS_MODE_META: Record<
  AnalysisMode,
  { label: string; shortLabel: string; description: string; cameraHint: string }
> = {
  restoration: {
    label: "物品归位",
    shortLabel: "归位检查",
    description: "检查缺少、错位、新增和未覆盖",
    cameraHint: "让主要物品和整个操作区域进入画面",
  },
  inventory: {
    label: "库存盘点",
    shortLabel: "库存盘点",
    description: "统计当前物资种类、数量和数量变化",
    cameraHint: "拍全柜内层板，让同类物资清晰可数",
  },
  condition: {
    label: "空间状态",
    shortLabel: "状态核验",
    description: "确认空间是否恢复到标准状态",
    cameraHint: "按标准照片范围拍全需要核验的空间",
  },
  completeness: {
    label: "必备物品",
    shortLabel: "完整性检查",
    description: "确认必需物品是否齐全",
    cameraHint: "拍全所有格位，避免物品相互遮挡",
  },
};

const ANALYSIS_MODE_META_EN: typeof ANALYSIS_MODE_META = {
  restoration: {
    label: "Restore items",
    shortLabel: "Restore check",
    description: "Find missing, misplaced, added, and uncovered items",
    cameraHint: "Keep the main items and the full work area in frame",
  },
  inventory: {
    label: "Inventory count",
    shortLabel: "Inventory",
    description: "Count current item categories, quantities, and changes",
    cameraHint: "Capture every shelf so matching items can be counted clearly",
  },
  condition: {
    label: "Space condition",
    shortLabel: "Condition check",
    description: "Confirm that the space has returned to its reference state",
    cameraHint: "Match the reference framing and capture the full space",
  },
  completeness: {
    label: "Required items",
    shortLabel: "Completeness",
    description: "Confirm that every required item is present",
    cameraHint: "Capture every compartment and avoid overlapping items",
  },
};

export function analysisModeMeta(mode: AnalysisMode, locale: AppLocale) {
  return locale === "en" ? ANALYSIS_MODE_META_EN[mode] : ANALYSIS_MODE_META[mode];
}

export function displayAreaName(area: Pick<CheckArea, "id" | "name">, locale: AppLocale) {
  if (area.id === DEFAULT_AREA_ID && (area.name === "办公桌" || area.name === "Office desk")) {
    return locale === "en" ? "Office desk" : "办公桌";
  }
  return area.name;
}

function defaultArea(): CheckArea {
  const now = Date.now();
  return {
    id: DEFAULT_AREA_ID,
    name: "办公桌",
    mode: "restoration",
    createdAt: now,
    updatedAt: now,
  };
}

export async function initializeAreaWorkspace(): Promise<{
  areas: CheckArea[];
  activeArea: CheckArea;
}> {
  const database = await openCheckbackDatabase();
  try {
    let areas = await requestValue(
      database.transaction(AREA_STORE, "readonly").objectStore(AREA_STORE).getAll(),
      "无法读取检查区域",
    ) as CheckArea[];

    if (areas.length === 0) {
      const area = defaultArea();
      await new Promise<void>((resolve, reject) => {
        const transaction = database.transaction([AREA_STORE, SETTINGS_STORE], "readwrite");
        transaction.objectStore(AREA_STORE).put(area);
        transaction.objectStore(SETTINGS_STORE).put(area.id, ACTIVE_AREA_KEY);
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error ?? new Error("无法创建默认区域"));
      });
      areas = [area];
    }

    areas.sort((left, right) => right.updatedAt - left.updatedAt);
    const activeAreaId = await requestValue(
      database.transaction(SETTINGS_STORE, "readonly")
        .objectStore(SETTINGS_STORE)
        .get(ACTIVE_AREA_KEY),
      "无法读取当前区域",
    ) as string | undefined;
    const activeArea = areas.find((area) => area.id === activeAreaId) ?? areas[0];
    if (activeArea.id !== activeAreaId) {
      const transaction = database.transaction(SETTINGS_STORE, "readwrite");
      transaction.objectStore(SETTINGS_STORE).put(activeArea.id, ACTIVE_AREA_KEY);
    }
    return { areas, activeArea };
  } finally {
    database.close();
  }
}

export async function createArea(input: { name: string; mode: AnalysisMode }): Promise<CheckArea> {
  const name = input.name.trim().slice(0, 24);
  if (!name) throw new Error("请输入区域名称");
  const now = Date.now();
  const area: CheckArea = {
    id: crypto.randomUUID(),
    name,
    mode: input.mode,
    createdAt: now,
    updatedAt: now,
  };
  const database = await openCheckbackDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction([AREA_STORE, SETTINGS_STORE], "readwrite");
      transaction.objectStore(AREA_STORE).add(area);
      transaction.objectStore(SETTINGS_STORE).put(area.id, ACTIVE_AREA_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("无法创建区域"));
    });
    return area;
  } finally {
    database.close();
  }
}

export async function setActiveArea(areaId: string): Promise<void> {
  const database = await openCheckbackDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction([AREA_STORE, SETTINGS_STORE], "readwrite");
      const areas = transaction.objectStore(AREA_STORE);
      const request = areas.get(areaId);
      request.onsuccess = () => {
        const area = request.result as CheckArea | undefined;
        if (!area) {
          transaction.abort();
          return;
        }
        areas.put({ ...area, updatedAt: Date.now() });
        transaction.objectStore(SETTINGS_STORE).put(areaId, ACTIVE_AREA_KEY);
      };
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("无法切换区域"));
      transaction.onabort = () => reject(new Error("区域不存在"));
    });
  } finally {
    database.close();
  }
}

export async function saveCheckHistory(input: {
  area: CheckArea;
  baselineVersionId: string | null;
  current: File;
  report: CheckbackReport;
}): Promise<CheckHistoryRecord> {
  const record: CheckHistoryRecord = {
    id: crypto.randomUUID(),
    areaId: input.area.id,
    areaName: input.area.name,
    mode: input.area.mode,
    baselineVersionId: input.baselineVersionId,
    createdAt: Date.now(),
    report: input.report,
    currentBlob: input.current,
    currentName: input.current.name,
    currentType: input.current.type,
  };
  const database = await openCheckbackDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(HISTORY_STORE, "readwrite");
      const store = transaction.objectStore(HISTORY_STORE);
      store.add(record);
      const existingRequest = store.index("by-area").getAll(input.area.id);
      existingRequest.onsuccess = () => {
        const existing = (existingRequest.result as CheckHistoryRecord[])
          .filter((item) => item.id !== record.id)
          .sort((left, right) => right.createdAt - left.createdAt);
        for (const stale of existing.slice(MAX_HISTORY_PER_AREA - 1)) {
          store.delete(stale.id);
        }
      };
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("无法保存检查历史"));
    });
    return record;
  } finally {
    database.close();
  }
}

export async function loadCheckHistory(areaId: string): Promise<CheckHistoryRecord[]> {
  const database = await openCheckbackDatabase();
  try {
    const records = await requestValue(
      database.transaction(HISTORY_STORE, "readonly")
        .objectStore(HISTORY_STORE)
        .index("by-area")
        .getAll(areaId),
      "无法读取检查历史",
    ) as CheckHistoryRecord[];
    return records.sort((left, right) => right.createdAt - left.createdAt);
  } finally {
    database.close();
  }
}

export function historyCurrentFile(record: CheckHistoryRecord): File {
  return new File([record.currentBlob], record.currentName || "checkback-history.jpg", {
    type: record.currentType || record.currentBlob.type,
    lastModified: record.createdAt,
  });
}

export async function clearAllCheckbackData(): Promise<void> {
  const database = await openCheckbackDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const storeNames = [
        AREA_STORE,
        BASELINE_STORE,
        BASELINE_VERSION_STORE,
        HISTORY_STORE,
        SETTINGS_STORE,
      ];
      const transaction = database.transaction(storeNames, "readwrite");
      for (const storeName of storeNames) transaction.objectStore(storeName).clear();
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("无法清除本地数据"));
    });
  } finally {
    database.close();
  }
}
