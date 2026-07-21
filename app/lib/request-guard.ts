type ClientWindow = {
  startedAt: number;
  count: number;
};

type GuardState = {
  day: string;
  dailyCount: number;
  active: number;
  clients: Map<string, ClientWindow>;
};

export type GuardRejection = {
  ok: false;
  status: 403 | 429 | 503;
  code: string;
  message: string;
  retryAfter?: number;
};

export type GuardPermit = {
  ok: true;
  release: () => void;
};

const shared = globalThis as typeof globalThis & {
  __checkbackGuardState?: GuardState;
};

function getState(): GuardState {
  const day = new Date().toISOString().slice(0, 10);
  if (!shared.__checkbackGuardState) {
    shared.__checkbackGuardState = {
      day,
      dailyCount: 0,
      active: 0,
      clients: new Map(),
    };
  }

  if (shared.__checkbackGuardState.day !== day) {
    shared.__checkbackGuardState.day = day;
    shared.__checkbackGuardState.dailyCount = 0;
    shared.__checkbackGuardState.clients.clear();
  }

  return shared.__checkbackGuardState;
}

function readInteger(name: string, fallback: number, minimum: number, maximum: number) {
  const value = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(value) ? Math.min(maximum, Math.max(minimum, value)) : fallback;
}

function clientAddress(request: Request) {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return (forwarded || request.headers.get("x-real-ip")?.trim() || "unknown").slice(0, 64);
}

export function validateAnalysisRequest(request: Request): GuardRejection | null {
  const enabled = (process.env.CHECKBACK_ANALYSIS_ENABLED ?? "true").trim().toLowerCase();
  if (enabled === "false" || enabled === "0") {
    return {
      ok: false,
      status: 503,
      code: "ANALYSIS_DISABLED",
      message: "检查服务暂时关闭，请稍后再试",
    };
  }

  const expectedOrigin = process.env.CHECKBACK_PUBLIC_ORIGIN?.trim();
  if (!expectedOrigin) return null;

  const fetchSite = request.headers.get("sec-fetch-site")?.trim().toLowerCase();
  const origin = request.headers.get("origin")?.trim();
  if (fetchSite === "cross-site" || origin !== expectedOrigin) {
    return {
      ok: false,
      status: 403,
      code: "UNTRUSTED_ORIGIN",
      message: "请从 CheckBack 页面发起检查",
    };
  }

  return null;
}

export function acquireAnalysisPermit(request: Request): GuardPermit | GuardRejection {
  const state = getState();
  const now = Date.now();
  const windowMs = readInteger("CHECKBACK_RATE_WINDOW_MS", 60 * 60 * 1000, 60_000, 86_400_000);
  const clientLimit = readInteger("CHECKBACK_RATE_LIMIT", 12, 1, 1_000);
  const dailyLimit = readInteger("CHECKBACK_DAILY_LIMIT", 120, 1, 100_000);
  const concurrentLimit = readInteger("CHECKBACK_MAX_CONCURRENT", 3, 1, 32);
  const address = clientAddress(request);

  for (const [key, value] of state.clients) {
    if (now - value.startedAt >= windowMs) state.clients.delete(key);
  }

  const current = state.clients.get(address);
  if (current && now - current.startedAt < windowMs && current.count >= clientLimit) {
    return {
      ok: false,
      status: 429,
      code: "CLIENT_RATE_LIMIT",
      message: "这台设备的检查次数已达到临时上限，请稍后再试",
      retryAfter: Math.max(1, Math.ceil((windowMs - (now - current.startedAt)) / 1000)),
    };
  }

  if (state.dailyCount >= dailyLimit) {
    return {
      ok: false,
      status: 429,
      code: "DAILY_LIMIT",
      message: "今天的体验额度已用完，请联系作品提交者",
      retryAfter: 3600,
    };
  }

  if (state.active >= concurrentLimit) {
    return {
      ok: false,
      status: 429,
      code: "CONCURRENCY_LIMIT",
      message: "当前正在检查的人较多，请稍后重试",
      retryAfter: 15,
    };
  }

  if (!current || now - current.startedAt >= windowMs) {
    state.clients.set(address, { startedAt: now, count: 1 });
  } else {
    current.count += 1;
  }
  state.dailyCount += 1;
  state.active += 1;

  let released = false;
  return {
    ok: true,
    release: () => {
      if (released) return;
      released = true;
      state.active = Math.max(0, state.active - 1);
    },
  };
}
