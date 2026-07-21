import assert from "node:assert/strict";
import test from "node:test";

import { adaptReportForMode } from "../app/lib/mode-report.ts";
import { normalizeCheckbackReport } from "../app/lib/checkback-analysis.ts";

import {
  localeFromAcceptLanguage,
  localeFromCountry,
  normalizeCountryCode,
  parseAppLocale,
  resolveAppLocale,
} from "../app/lib/locale.ts";

test("locale parsing accepts supported Chinese and English variants", () => {
  assert.equal(parseAppLocale("zh-TW"), "zh-CN");
  assert.equal(parseAppLocale("en-US"), "en");
  assert.equal(parseAppLocale("fr-FR"), null);
});

test("browser language honors quality order among supported locales", () => {
  assert.equal(localeFromAcceptLanguage("fr-FR, en-US;q=0.8, zh-CN;q=0.6"), "en");
  assert.equal(localeFromAcceptLanguage("zh-CN, en;q=0.5"), "zh-CN");
  assert.equal(localeFromAcceptLanguage("de-DE, fr;q=0.8"), null);
});

test("country fallback maps US to English and Chinese regions to Chinese", () => {
  assert.equal(localeFromCountry("US"), "en");
  assert.equal(localeFromCountry("CN"), "zh-CN");
  assert.equal(localeFromCountry("HK"), "zh-CN");
  assert.equal(normalizeCountryCode("zz"), null);
});

test("locale priority is saved choice, browser, country, then Chinese default", () => {
  assert.deepEqual(
    resolveAppLocale({ savedLocale: "en", acceptLanguage: "zh-CN", countryCode: "CN" }),
    { locale: "en", source: "saved" },
  );
  assert.deepEqual(
    resolveAppLocale({ acceptLanguage: "zh-CN", countryCode: "US" }),
    { locale: "zh-CN", source: "browser" },
  );
  assert.deepEqual(
    resolveAppLocale({ acceptLanguage: "fr-FR", countryCode: "US" }),
    { locale: "en", source: "country" },
  );
  assert.deepEqual(resolveAppLocale({}), { locale: "zh-CN", source: "default" });
});

test("inventory reports are assembled in the requested English locale", () => {
  const raw = {
    scene: { match: "same", overlap: "high", reason: "Same cabinet" },
    quality_issues: [],
    changes: [
      {
        id: "cans",
        label: "Canned food x 3",
        type: "added",
        certainty: "high",
        baseline_location: "Upper shelf",
        current_location: "Upper shelf",
        baseline_visible: true,
        expected_region_visible: true,
        evidence: "Three cans are clearly visible",
        action: "Record quantity",
      },
    ],
    checked_item_count: 3,
    summary: "Three cans counted",
  };
  const normalized = normalizeCheckbackReport(
    raw,
    null,
    { analysisId: "analysis-en", processingMs: 0 },
    "en",
  );
  const report = adaptReportForMode(normalized, raw, "inventory", "en");
  assert.equal(report.headline, "Counted 1 category, 3 units");
  assert.match(report.summary, /inventory snapshot is complete/i);
});
