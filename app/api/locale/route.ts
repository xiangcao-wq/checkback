import { cookies, headers } from "next/headers";
import {
  APP_LOCALE_COOKIE,
  normalizeCountryCode,
  resolveAppLocale,
} from "../../lib/locale";

export async function GET() {
  const [cookieStore, requestHeaders] = await Promise.all([cookies(), headers()]);
  const country = normalizeCountryCode(requestHeaders.get("x-checkback-country"));
  const resolution = resolveAppLocale({
    savedLocale: cookieStore.get(APP_LOCALE_COOKIE)?.value,
    acceptLanguage: requestHeaders.get("accept-language"),
    countryCode: country,
  });
  return Response.json(
    { country, ...resolution },
    {
      headers: {
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
      },
    },
  );
}
