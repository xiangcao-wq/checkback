import type { Metadata, Viewport } from "next";
import { cookies, headers } from "next/headers";
import "./globals.css";
import "./workspace-panel.css";
import { LocaleProvider } from "./locale-provider";
import { APP_LOCALE_COOKIE, resolveAppLocale } from "./lib/locale";

async function requestLocale() {
  const [cookieStore, requestHeaders] = await Promise.all([cookies(), headers()]);
  return resolveAppLocale({
    savedLocale: cookieStore.get(APP_LOCALE_COOKIE)?.value,
    acceptLanguage: requestHeaders.get("accept-language"),
    countryCode: requestHeaders.get("x-checkback-country"),
  });
}

export async function generateMetadata(): Promise<Metadata> {
  const { locale } = await requestLocale();
  return locale === "en"
    ? {
        title: "CheckBack — Capture and check",
        description: "Compare a reference photo with the current scene to find missing, misplaced, or unseen items.",
        applicationName: "CheckBack",
        keywords: ["visual inspection", "inventory", "AI vision", "photo comparison", "CheckBack"],
      }
    : {
        title: "CheckBack — 拍下并检查",
        description: "用标准照片和当前照片自动检查物品是否缺少、放错位置或没有拍到。",
        applicationName: "CheckBack",
        keywords: ["桌面检查", "物品归位", "AI 视觉", "照片对比", "CheckBack"],
      };
}

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#d9d8d2" },
    { media: "(prefers-color-scheme: dark)", color: "#272a27" },
  ],
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const { locale } = await requestLocale();
  return (
    <html lang={locale} data-locale={locale}>
      <body>
        <LocaleProvider initialLocale={locale}>{children}</LocaleProvider>
      </body>
    </html>
  );
}
