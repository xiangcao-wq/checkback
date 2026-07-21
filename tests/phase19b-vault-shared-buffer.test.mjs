import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  createVaultObjectBindingFromAuthorization,
  issueVaultSealTicketsFromAuthorizedPair,
} from "../evaluation/live-shadow-boundary/vault-binding-authorizer.ts";
import {
  createLiveContractFixture,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

test("Authority and Vault operate on stable snapshots of shared byte views", () => {
  const fixture = createLiveContractFixture({ count: 1 });
  const authorityKeys = generateKeyPairSync("ed25519");
  const custodyId = fixtureId("custody", "shared-view-vault");
  const beforeShared = new Uint8Array(
    new SharedArrayBuffer(fixture.mediaPairs[0].before_bytes.byteLength),
  );
  const afterShared = new Uint8Array(
    new SharedArrayBuffer(fixture.mediaPairs[0].after_bytes.byteLength),
  );
  beforeShared.set(fixture.mediaPairs[0].before_bytes);
  afterShared.set(fixture.mediaPairs[0].after_bytes);

  const tickets = issueVaultSealTicketsFromAuthorizedPair({
    signed_consent: fixture.signedConsent,
    consent_public_key: fixture.consentKeys.publicKey,
    execution_plan: fixture.plan,
    runtime_manifest: fixture.runtime,
    authority_pair_secret: fixture.authoritySecret,
    authority_signing_private_key: authorityKeys.privateKey,
    expected_custody_id: custodyId,
    before_plaintext: beforeShared,
    after_plaintext: afterShared,
    now_ms: 10_001,
    expires_at_ms: 11_000,
  });
  beforeShared.fill(0x5a);
  afterShared.fill(0x5a);

  const prepared = createVaultObjectBindingFromAuthorization({
    signed_seal_ticket: tickets.reference,
    authority_public_key: authorityKeys.publicKey,
    expected_custody_id: custodyId,
    plaintext: fixture.mediaPairs[0].before_bytes,
    now_ms: 10_002,
  });
  try {
    assert.deepEqual(
      prepared.plaintext_snapshot,
      fixture.mediaPairs[0].before_bytes,
    );
    fixture.mediaPairs[0].before_bytes.fill(0x33);
    assert.notDeepEqual(
      prepared.plaintext_snapshot,
      fixture.mediaPairs[0].before_bytes,
    );
  } finally {
    prepared.plaintext_snapshot.fill(0);
    beforeShared.fill(0);
    afterShared.fill(0);
  }
});
