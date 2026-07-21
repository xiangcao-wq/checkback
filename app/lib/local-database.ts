"use client";

export const CHECKBACK_DB_NAME = "checkback-local";
export const CHECKBACK_DB_VERSION = 2;

export const BASELINE_STORE = "baseline-images";
export const BASELINE_VERSION_STORE = "baseline-versions";
export const AREA_STORE = "areas";
export const HISTORY_STORE = "check-history";
export const SETTINGS_STORE = "settings";

export function openCheckbackDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(CHECKBACK_DB_NAME, CHECKBACK_DB_VERSION);

    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(BASELINE_STORE)) {
        database.createObjectStore(BASELINE_STORE);
      }
      if (!database.objectStoreNames.contains(BASELINE_VERSION_STORE)) {
        const versions = database.createObjectStore(BASELINE_VERSION_STORE, {
          keyPath: "id",
        });
        versions.createIndex("by-area", "areaId", { unique: false });
      }
      if (!database.objectStoreNames.contains(AREA_STORE)) {
        database.createObjectStore(AREA_STORE, { keyPath: "id" });
      }
      if (!database.objectStoreNames.contains(HISTORY_STORE)) {
        const history = database.createObjectStore(HISTORY_STORE, { keyPath: "id" });
        history.createIndex("by-area", "areaId", { unique: false });
      }
      if (!database.objectStoreNames.contains(SETTINGS_STORE)) {
        database.createObjectStore(SETTINGS_STORE);
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("无法打开本地数据存储"));
  });
}

export function requestValue<T>(request: IDBRequest<T>, fallbackMessage: string): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error(fallbackMessage));
  });
}
