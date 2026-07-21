export const MAX_ANALYSIS_FORM_BYTES = 1024 * 1024;

export type RequestFormDataResult =
  | { ok: true; formData: FormData }
  | { ok: false; reason: "invalid" | "too_large" | "aborted" };

function declaredBodyTooLarge(request: Request, maxBytes: number) {
  const value = request.headers.get("content-length");
  if (!value) return false;
  const length = Number(value);
  return Number.isFinite(length) && length > maxBytes;
}

export async function parseRequestFormData(
  request: Request,
  maxBytes = MAX_ANALYSIS_FORM_BYTES,
): Promise<RequestFormDataResult> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    return { ok: false, reason: "invalid" };
  }
  if (request.signal.aborted) {
    return { ok: false, reason: "aborted" };
  }
  if (declaredBodyTooLarge(request, maxBytes)) {
    return { ok: false, reason: "too_large" };
  }

  const reader = request.body?.getReader();
  if (!reader) return { ok: false, reason: "invalid" };

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  const cancelOnAbort = () => {
    void reader.cancel(request.signal.reason).catch(() => undefined);
  };
  request.signal.addEventListener("abort", cancelOnAbort, { once: true });

  try {
    while (true) {
      if (request.signal.aborted) {
        return { ok: false, reason: "aborted" };
      }

      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel("analysis request body too large").catch(() => undefined);
        return { ok: false, reason: "too_large" };
      }
      chunks.push(value);
    }

    if (request.signal.aborted) {
      return { ok: false, reason: "aborted" };
    }

    const body = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }

    const headers = new Headers(request.headers);
    headers.delete("content-length");
    const boundedRequest = new Request(request.url, {
      method: request.method,
      headers,
      body,
    });
    return { ok: true, formData: await boundedRequest.formData() };
  } catch {
    return {
      ok: false,
      reason: request.signal.aborted ? "aborted" : "invalid",
    };
  } finally {
    request.signal.removeEventListener("abort", cancelOnAbort);
    reader.releaseLock();
  }
}
