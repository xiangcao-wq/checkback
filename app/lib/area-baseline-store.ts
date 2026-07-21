"use client";

import { DEFAULT_AREA_ID } from "./area-store";
import {
  BASELINE_STORE,
  BASELINE_VERSION_STORE,
  openCheckbackDatabase,
  requestValue,
} from "./local-database";

type StoredBaseline = {
  blob: Blob;
  name: string;
  type: string;
  updatedAt: number;
  versionId?: string;
};

type StoredBaselineVersion = StoredBaseline & { id: string; areaId: string };

function createAbortError() {
  return new DOMException("标准照片保存已取消", "AbortError");
}

function asFile(record: StoredBaseline | undefined, fallbackName: string): File | null {
  if (!record?.blob) return null;
  return new File([record.blob], record.name || fallbackName, {
    type: record.type || record.blob.type,
    lastModified: record.updatedAt,
  });
}

export async function saveBaselineImage(
  file: File,
  signal?: AbortSignal,
  areaId = DEFAULT_AREA_ID,
): Promise<string> {
  if (signal?.aborted) throw createAbortError();
  const versionId = crypto.randomUUID();
  const baseline: StoredBaseline = {
    blob: file,
    name: file.name,
    type: file.type,
    updatedAt: Date.now(),
    versionId,
  };
  const database = await openCheckbackDatabase();
  try {
    if (signal?.aborted) throw createAbortError();
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(
        [BASELINE_STORE, BASELINE_VERSION_STORE],
        "readwrite",
      );
      let settled = false;
      const cleanup = () => signal?.removeEventListener("abort", abortTransaction);
      const settle = (callback: () => void) => {
        if (settled) return;
        settled = true;
        cleanup();
        callback();
      };
      const abortTransaction = () => {
        if (settled) return;
        try {
          transaction.abort();
        } catch (error) {
          if (error instanceof DOMException && error.name === "InvalidStateError") return;
          settle(() => reject(createAbortError()));
        }
      };

      transaction.objectStore(BASELINE_STORE).put(baseline, areaId);
      transaction.objectStore(BASELINE_VERSION_STORE).put({
        ...baseline,
        id: versionId,
        areaId,
      } satisfies StoredBaselineVersion);
      transaction.oncomplete = () => settle(resolve);
      transaction.onerror = () =>
        settle(() => reject(transaction.error ?? new Error("无法保存标准照片")));
      transaction.onabort = () =>
        settle(() =>
          reject(
            signal?.aborted
              ? createAbortError()
              : transaction.error ?? new Error("无法保存标准照片"),
          ),
        );
      signal?.addEventListener("abort", abortTransaction, { once: true });
    });
    return versionId;
  } finally {
    database.close();
  }
}

export async function loadBaselineImage(areaId = DEFAULT_AREA_ID): Promise<File | null> {
  const database = await openCheckbackDatabase();
  try {
    const record = await requestValue(
      database.transaction(BASELINE_STORE, "readonly").objectStore(BASELINE_STORE).get(areaId),
      "无法读取标准照片",
    ) as StoredBaseline | undefined;
    return asFile(record, "checkback-standard.jpg");
  } finally {
    database.close();
  }
}

export async function ensureCurrentBaselineVersion(areaId: string): Promise<string | null> {
  const database = await openCheckbackDatabase();
  try {
    const existing = await requestValue(
      database.transaction(BASELINE_STORE, "readonly").objectStore(BASELINE_STORE).get(areaId),
      "无法读取标准照片版本",
    ) as StoredBaseline | undefined;
    if (!existing?.blob) return null;
    if (existing.versionId) return existing.versionId;

    const versionId = crypto.randomUUID();
    const upgraded = { ...existing, versionId };
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(
        [BASELINE_STORE, BASELINE_VERSION_STORE],
        "readwrite",
      );
      transaction.objectStore(BASELINE_STORE).put(upgraded, areaId);
      transaction.objectStore(BASELINE_VERSION_STORE).put({
        ...upgraded,
        id: versionId,
        areaId,
      } satisfies StoredBaselineVersion);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("无法保存标准照片版本"));
    });
    return versionId;
  } finally {
    database.close();
  }
}

export async function loadBaselineVersionImage(versionId: string): Promise<File | null> {
  const database = await openCheckbackDatabase();
  try {
    const record = await requestValue(
      database.transaction(BASELINE_VERSION_STORE, "readonly")
        .objectStore(BASELINE_VERSION_STORE)
        .get(versionId),
      "无法读取历史标准照片",
    ) as StoredBaselineVersion | undefined;
    return asFile(record, "checkback-history-standard.jpg");
  } finally {
    database.close();
  }
}
