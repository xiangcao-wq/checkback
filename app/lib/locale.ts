export const APP_LOCALE_COOKIE = "checkback_locale";
export const APP_LOCALE_STORAGE_KEY = "checkback-locale";

export type AppLocale = "zh-CN" | "en";

const CHINESE_COUNTRIES = new Set(["CN", "HK", "MO", "TW"]);

export function parseAppLocale(value: string | null | undefined): AppLocale | null {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return null;
  if (normalized === "zh" || normalized === "zh-cn" || normalized.startsWith("zh-")) {
    return "zh-CN";
  }
  if (normalized === "en" || normalized.startsWith("en-")) return "en";
  return null;
}

export function localeFromAcceptLanguage(value: string | null | undefined): AppLocale | null {
  if (!value) return null;
  const preferences = value
    .split(",")
    .map((entry, index) => {
      const [language, ...parameters] = entry.trim().split(";");
      const qualityParameter = parameters.find((parameter) => parameter.trim().startsWith("q="));
      const parsedQuality = qualityParameter
        ? Number.parseFloat(qualityParameter.trim().slice(2))
        : 1;
      return {
        locale: parseAppLocale(language),
        quality: Number.isFinite(parsedQuality) ? parsedQuality : 0,
        index,
      };
    })
    .filter((entry): entry is { locale: AppLocale; quality: number; index: number } =>
      entry.locale !== null && entry.quality > 0,
    )
    .sort((left, right) => right.quality - left.quality || left.index - right.index);
  return preferences[0]?.locale ?? null;
}

export function normalizeCountryCode(value: string | null | undefined): string | null {
  const normalized = value?.trim().toUpperCase();
  return normalized && /^[A-Z]{2}$/.test(normalized) && normalized !== "ZZ"
    ? normalized
    : null;
}

export function localeFromCountry(value: string | null | undefined): AppLocale | null {
  const country = normalizeCountryCode(value);
  if (!country) return null;
  return CHINESE_COUNTRIES.has(country) ? "zh-CN" : "en";
}

export function resolveAppLocale(input: {
  savedLocale?: string | null;
  acceptLanguage?: string | null;
  countryCode?: string | null;
}): { locale: AppLocale; source: "saved" | "browser" | "country" | "default" } {
  const saved = parseAppLocale(input.savedLocale);
  if (saved) return { locale: saved, source: "saved" };

  const browser = localeFromAcceptLanguage(input.acceptLanguage);
  if (browser) return { locale: browser, source: "browser" };

  const country = localeFromCountry(input.countryCode);
  if (country) return { locale: country, source: "country" };

  return { locale: "zh-CN", source: "default" };
}

export function localize(locale: AppLocale, chinese: string, english: string) {
  return locale === "en" ? english : chinese;
}
