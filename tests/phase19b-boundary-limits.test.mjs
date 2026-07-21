import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  MAX_CANONICAL_PROVIDER_REQUEST_BODY_BYTES,
  MAX_PREPROCESSED_MEDIA_PART_BYTES,
} from "../evaluation/live-shadow-boundary/boundary-limits.ts";
import { issueVaultSealTicketsFromAuthorizedPair } from "../evaluation/live-shadow-boundary/vault-binding-authorizer.ts";
import {
  createLiveContractFixture,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

test("two maximum-size Base64 images leave bounded JSON and prompt headroom", () => {
  const base64PairBytes =
    Math.ceil(MAX_PREPROCESSED_MEDIA_PART_BYTES / 3) * 4 * 2;
  assert.equal(MAX_PREPROCESSED_MEDIA_PART_BYTES, 10 * 1024 * 1024);
  assert.ok(base64PairBytes < MAX_CANONICAL_PROVIDER_REQUEST_BODY_BYTES);
  assert.ok(
    MAX_CANONICAL_PROVIDER_REQUEST_BODY_BYTES - base64PairBytes >
      5 * 1024 * 1024,
  );
});

test("Authority refuses one media part above the joint boundary", () => {
  const fixture = createLiveContractFixture({ count: 1 });
  const authorityKeys = generateKeyPairSync("ed25519");
  const oversized = Buffer.alloc(MAX_PREPROCESSED_MEDIA_PART_BYTES + 1, 0x41);
  try {
    assert.throws(
      () =>
        issueVaultSealTicketsFromAuthorizedPair({
          signed_consent: fixture.signedConsent,
          consent_public_key: fixture.consentKeys.publicKey,
          execution_plan: fixture.plan,
          runtime_manifest: fixture.runtime,
          authority_pair_secret: fixture.authoritySecret,
          authority_signing_private_key: authorityKeys.privateKey,
          expected_custody_id: fixtureId("custody", "limit-test"),
          before_plaintext: oversized,
          after_plaintext: fixture.mediaPairs[0].after_bytes,
          now_ms: 10_001,
          expires_at_ms: 11_000,
        }),
      /vault_media_part_too_large/,
    );
  } finally {
    oversized.fill(0);
  }
});

test("IPC and request rebuilder consume the shared limits", () => {
  const ipc = readFileSync(
    "evaluation/live-shadow-boundary/ipc-contracts.ts",
    "utf8",
  );
  const rebuilder = readFileSync(
    "evaluation/live-shadow-boundary/gateway-request-rebuilder.ts",
    "utf8",
  );
  assert.match(ipc, /MAX_CANONICAL_PROVIDER_REQUEST_BODY_BYTES/);
  assert.match(rebuilder, /MAX_PREPROCESSED_MEDIA_PART_BYTES/);
  assert.doesNotMatch(rebuilder, /MAX_IMAGE_BYTES = 16 \* 1024 \* 1024/);
});
