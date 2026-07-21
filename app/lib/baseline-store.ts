"use client";

const DB_NAME = "checkback-local";
const STORE_NAME = "baseline-images";
const RECORD_KEY = "default";

type StoredBaseline = {
  blob: Blob;
  name: string;
  type: string;
  updatedAt: number;
};

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);

    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        database.createObjectStore(STORE_NAME);
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("无法打开本地照片存储"));
  });
}

function createAbortError() {
  return new DOMException("标准照片保存已取消", "AbortError");
}

export async function saveBaselineImage(file: File, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) throw createAbortError();

  const database = await openDatabase();
  try {
    if (signal?.aborted) throw createAbortError();

    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
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

      try {
        transaction.objectStore(STORE_NAME).put(
          {
            blob: file,
            name: file.name,
            type: file.type,
            updatedAt: Date.now(),
          } satisfies StoredBaseline,
          RECORD_KEY,
        );
      } catch (error) {
        settle(() => reject(error));
      }
    });
  } finally {
    database.close();
  }
}

export async function loadBaselineImage(): Promise<File | null> {
  const database = await openDatabase();
  try {
    return await new Promise<File | null>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).get(RECORD_KEY);
      request.onsuccess = () => {
        const record = request.result as StoredBaseline | undefined;
        if (!record?.blob) {
          resolve(null);
          return;
        }
        resolve(
          new File([record.blob], record.name || "checkback-standard.jpg", {
            type: record.type || record.blob.type,
            lastModified: record.updatedAt,
          }),
        );
      };
      request.onerror = () => reject(request.error ?? new Error("无法读取标准照片"));
    });
  } finally {
    database.close();
  }
}

export async function clearBaselineImage(): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).delete(RECORD_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("无法清除标准照片"));
    });
  } finally {
    database.close();
  }
}
