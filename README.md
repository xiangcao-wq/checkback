# CheckBack

CheckBack is an AI-assisted visual inspection app for keeping shared spaces in a
known-good state. A user records a reference photo, captures the current scene,
and receives a focused report of what is missing, misplaced, or unexpectedly
present. Different area types adapt the workflow: desks use restore checks,
while cabinets and storage areas focus on inventory counts.

The camera-first home screen stays fast and uncluttered. A compact area island
opens the multi-area panel for switching locations, adding areas, and reviewing
local inspection history. The interface supports Chinese and English, including
locale-aware AI results, with an automatic self-hosted country/language fallback
and a manual language switch.

## Core features

- Reference-versus-current visual checks for desks and work surfaces
- Inventory-oriented checks for cabinets and storage areas
- Multiple named areas without replacing the camera-first home screen
- Local history and performance records for completed checks
- Chinese and English UI plus locale-aware model instructions and reports
- Server-side provider credentials with guarded uploads and request limits
- Self-hosted Nginx configuration with local GeoIP language detection

## Demo flow

1. Open the area island and select or create an area.
2. Capture a clean reference image for that area.
3. Capture the current scene and run the check.
4. Review missing, misplaced, extra, or inventory-count findings.
5. Open History from the area panel to revisit completed checks.

## How Codex and GPT-5.6 were used

Codex was used throughout the project to turn the product concept into a tested
application: implementing the camera workflow, multi-area data model, adaptive
desk/cabinet modes, bilingual interface, self-hosted deployment configuration,
security guards, and the regression suite. Codex was also used to reproduce UI
issues in a real browser, interpret visual feedback, and iteratively refine the
compact header and area-island interaction.

GPT-5.6 is available through the OpenAI vision provider as a server-side analysis
model. It compares the reference and current images, follows the selected area's
inspection mode, and returns structured, locale-aware findings for the UI. The
provider layer also supports a Qwen deployment, so evaluators can run the app with
either provider without changing client code. API keys never ship to the browser.

## Prerequisites

- Node.js `>=22.13.0`

## Quick Start

```bash
npm install
npm run dev
npm run build
```


## AI vision provider setup

The browser sends the baseline and current photos to the server-side
`/api/analyze` route. The active provider API key must stay on the server and must never
be exposed through a `NEXT_PUBLIC_` environment variable.

For local development, copy `.env.example` to `.env.local` and set:

```dotenv
AI_VISION_PROVIDER=qwen
DASHSCOPE_API_KEY=your_dashscope_api_key
DASHSCOPE_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
QWEN_VISION_MODEL=qwen3.7-plus-2026-05-26

# Keep off until isolated shadow evaluation passes.
CHECKBACK_FAST_VERIFIER_MODE=off
QWEN_FAST_VERIFICATION_MODEL=qwen3.6-flash-2026-04-16
QWEN_FAST_VERIFICATION_TIMEOUT_MS=20000
QWEN_VERIFICATION_FALLBACK_MODEL=qwen3.7-plus-2026-05-26
QWEN_VERIFICATION_FALLBACK_TIMEOUT_MS=90000

# Optional OpenAI fallback
OPENAI_API_KEY=your_api_key
OPENAI_VISION_MODEL=gpt-5.6-sol
```

For the hosted site, configure the same keys as Sites runtime environment
variables and mark `DASHSCOPE_API_KEY` or `OPENAI_API_KEY` as secrets. Redeploy after
changing hosted runtime values.

Fast verification is fail-closed and supports three modes:

- `off` (default): use the existing Plus verifier only.
- `shadow`: call Flash and Plus but return only the Plus result. Use only in isolated
  evaluation because the same photos are sent for a third model call.
- `active`: accept Flash only when every candidate independently confirms the Plus primary
  missing verdict with high certainty. Any disagreement, malformed output, incomplete ID set,
  or uncertainty runs the pinned Plus fallback.

Do not enable `shadow` or `active` in production until the labeled accuracy and latency
gates pass. This app does not use `wrangler.jsonc`.

## Architecture

- application routes and UI live under `app/`
- `vite.config.ts` simulates declared bindings for local development
- `db/schema.ts` starts intentionally empty
- `examples/d1/` contains an optional D1 example surface
- `drizzle.config.ts` supports local migration generation when needed

## Workspace Auth Headers

OpenAI workspace sites can read the current user's email from
`oai-authenticated-user-email`.

SIWC-authenticated workspace sites may also receive
`oai-authenticated-user-full-name` when the user's SIWC profile has a non-empty
`name` claim. The full-name value is percent-encoded UTF-8 and is accompanied by
`oai-authenticated-user-full-name-encoding: percent-encoded-utf-8`.

Treat the full name as optional and fall back to email when it is absent:

```tsx
import { headers } from "next/headers";

export default async function Home() {
  const requestHeaders = await headers();
  const email = requestHeaders.get("oai-authenticated-user-email");
  const encodedFullName = requestHeaders.get("oai-authenticated-user-full-name");
  const fullName =
    encodedFullName &&
    requestHeaders.get("oai-authenticated-user-full-name-encoding") ===
      "percent-encoded-utf-8"
      ? decodeURIComponent(encodedFullName)
      : null;

  const displayName = fullName ?? email;
  // ...
}
```

## Optional Dispatch-Owned ChatGPT Sign-In

Import the ready-to-use helpers from `app/chatgpt-auth.ts` when the site needs
optional or required ChatGPT sign-in:

- Use `getChatGPTUser()` for optional signed-in UI.
- Use `requireChatGPTUser(returnTo)` for server-rendered pages that should send
  anonymous visitors through Sign in with ChatGPT.
- Use `chatGPTSignInPath(returnTo)` and `chatGPTSignOutPath(returnTo)` for
  browser links or actions.
- Pass a same-origin relative `returnTo` path for the destination after sign-in
  or sign-out. The helper validates and safely encodes it.
- Mark protected pages with `export const dynamic = "force-dynamic"` because
  they depend on per-request identity headers.

Dispatch owns `/signin-with-chatgpt`, `/signout-with-chatgpt`, `/callback`, the
OAuth cookies, and identity header injection. Do not implement app routes for
those reserved paths. Routes that do not import and call the helper remain
anonymous-compatible.

SIWC establishes identity only; it does not prove workspace membership. Use the
Sites hosting platform's access policy controls for workspace-wide restrictions,
or enforce explicit server-side membership or allowlist checks.

Use SIWC for account pages, user-specific dashboards, saved records, and write
actions tied to the current ChatGPT user. Leave public content anonymous.

## Self-hosted language detection

CheckBack resolves the initial interface language in this order: the saved manual
choice, the browser's `Accept-Language`, the locally detected IP country, then
Simplified Chinese. China, Hong Kong, Macao, and Taiwan resolve to Chinese; other
known countries resolve to English. The compact header switch saves the user's
choice in a cookie and local storage.

The self-hosted Nginx configuration performs the country lookup against a local
MMDB file and forwards only `X-CheckBack-Country` to the app. The visitor IP is
not sent to a third-party geolocation service or stored for language detection.

Install the pinned and SHA-256-verified country database before enabling the
provided Nginx configuration:

```bash
sudo ./deploy/self-host/install-geoip.sh
sudo nginx -t
sudo systemctl reload nginx
```

`deploy/self-host/nginx-checkback.conf` expects the Nginx GeoIP2 module and the
database at `/etc/checkback/geoip/iptoasn-country.mmdb`. Adapt the domain and
certificate paths when using the file on another server. The competition demo
is public by default; add an access policy only for private deployments.

## Useful Commands

- `npm run dev`: start local development
- `npm run build`: verify the vinext build output
- `npm test`: build the app and run the complete regression suite
- `npm run eval:shadow`: generate the offline verifier-only synthetic safety report
- `npm run eval:shadow -- path\to\suite.json`: inspect another suite without enforcing gates
- `npm run eval:shadow:gate -- path\to\holdout-suite.json`: enforce frozen holdout gates
- `npm run db:generate`: generate Drizzle migrations after schema changes

## Shadow Evaluation

The offline evaluator, strict anonymous fixture format, metrics, and limitations are documented
in `evaluation/README.md`. The consent text and controlled live-run checklist are in
`evaluation/LIVE_SHADOW_PROTOCOL.md`. Running the evaluator never enables Shadow or calls a model.

## Learn More

- [vinext Documentation](https://github.com/cloudflare/vinext)
- [Drizzle D1 Guide](https://orm.drizzle.team/docs/get-started/d1-new)
