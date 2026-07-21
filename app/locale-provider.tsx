"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import {
  APP_LOCALE_COOKIE,
  APP_LOCALE_STORAGE_KEY,
  type AppLocale,
} from "./lib/locale";

type LocaleContextValue = {
  locale: AppLocale;
  setLocale: (locale: AppLocale) => void;
  toggleLocale: () => void;
};

const LocaleContext = createContext<LocaleContextValue | null>(null);

export function LocaleProvider({
  initialLocale,
  children,
}: {
  initialLocale: AppLocale;
  children: React.ReactNode;
}) {
  const [locale, setLocaleState] = useState<AppLocale>(initialLocale);

  const setLocale = useCallback((nextLocale: AppLocale) => {
    setLocaleState(nextLocale);
    try {
      window.localStorage.setItem(APP_LOCALE_STORAGE_KEY, nextLocale);
    } catch {
      // A cookie remains the durable preference when local storage is unavailable.
    }
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${APP_LOCALE_COOKIE}=${encodeURIComponent(nextLocale)}; Path=/; Max-Age=31536000; SameSite=Lax${secure}`;
  }, []);

  const toggleLocale = useCallback(() => {
    setLocale(locale === "en" ? "zh-CN" : "en");
  }, [locale, setLocale]);

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dataset.locale = locale;
    document.title = locale === "en" ? "CheckBack ? Capture and check" : "CheckBack ? ?????";
  }, [locale]);

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key !== APP_LOCALE_STORAGE_KEY) return;
      if (event.newValue === "en" || event.newValue === "zh-CN") {
        setLocaleState(event.newValue);
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const value = useMemo(
    () => ({ locale, setLocale, toggleLocale }),
    [locale, setLocale, toggleLocale],
  );
  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

export function useAppLocale() {
  const context = useContext(LocaleContext);
  if (!context) throw new Error("useAppLocale must be used inside LocaleProvider");
  return context;
}
