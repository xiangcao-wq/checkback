import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  VaultSignedSealTicketSchema,
  createVaultObjectBindingFromAuthorization,
  issueVaultSealTicketsFromAuthorizedPair,
  verifyVaultSealTicket,
} from "../evaluation/live-shadow-boundary/vault-binding-authorizer.ts";
import {
  createLiveContractFixture,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

function issueFixture(overrides = {}) {
  const fixture = createLiveContractFixture({ count: 1 });
  const authorityKeys = generateKeyPairSync("ed25519");
  const custodyId = fixtureId("custody", "phase19b-authorized-vault");
  const tickets = issueVaultSealTicketsFromAuthorizedPair({
    signed_consent: fixture.signedConsent,
    consent_public_key: fixture.consentKeys.publicKey,
    execution_plan: fixture.plan,
    runtime_manifest: fixture.runtime,
    authority_pair_secret: fixture.authoritySecret,
    authority_signing_private_key: authorityKeys.privateKey,
    expected_custody_id: custodyId,
    before_plaintext: fixture.mediaPairs[0].before_bytes,
    after_plaintext: fixture.mediaPairs[0].after_bytes,
    now_ms: 10_001,
    expires_at_ms: 11_000,
    ...overrides,
  });
  return { fixture, authorityKeys, custodyId, tickets };
}

test("Authority tickets bind the exact authorized pair, part, and raw-media deadline", () => {
  const { fixture, authorityKeys, custodyId, tickets } = issueFixture();
  assert.equal(tickets.reference.payload.pair_ticket_id, tickets.comparison.payload.pair_ticket_id);
  assert.notEqual(tickets.reference.payload.ticket_id, tickets.comparison.payload.ticket_id);
  assert.equal(tickets.reference.payload.binding.part, "reference");
  assert.equal(tickets.comparison.payload.binding.part, "comparison");
  assert.equal(
    tickets.reference.payload.binding.delete_by_ms,
    fixture.consent.local_media_delete_by_ms,
  );
  assert.notEqual(
    tickets.reference.payload.binding.delete_by_ms,
    fixture.consent.sanitized_record_delete_by_ms,
  );

  const verified = createVaultObjectBindingFromAuthorization({
    signed_seal_ticket: tickets.reference,
    authority_public_key: authorityKeys.publicKey,
    expected_custody_id: custodyId,
    plaintext: fixture.mediaPairs[0].before_bytes,
    now_ms: 10_002,
  });
  try {
    assert.deepEqual(verified.binding, tickets.reference.payload.binding);
    assert.deepEqual(
      verified.plaintext_snapshot,
      fixture.mediaPairs[0].before_bytes,
    );
    assert.notEqual(verified.plaintext_snapshot, fixture.mediaPairs[0].before_bytes);
    assert.deepEqual(
      verifyVaultSealTicket(authorityKeys.publicKey, tickets.reference),
      tickets.reference,
    );
  } finally {
    verified.plaintext_snapshot.fill(0);
  }
});

test("same-length substitution and before/after swapping fail closed", () => {
  const { fixture, authorityKeys, custodyId, tickets } = issueFixture();
  const substitute = Buffer.alloc(
    fixture.mediaPairs[0].before_bytes.byteLength,
    0x5a,
  );
  try {
    assert.throws(
      () =>
        createVaultObjectBindingFromAuthorization({
          signed_seal_ticket: tickets.reference,
          authority_public_key: authorityKeys.publicKey,
          expected_custody_id: custodyId,
          plaintext: substitute,
          now_ms: 10_002,
        }),
      /vault_seal_ticket_plaintext_mismatch/,
    );
    assert.throws(
      () =>
        createVaultObjectBindingFromAuthorization({
          signed_seal_ticket: tickets.comparison,
          authority_public_key: authorityKeys.publicKey,
          expected_custody_id: custodyId,
          plaintext: fixture.mediaPairs[0].before_bytes,
          now_ms: 10_002,
        }),
      /vault_seal_ticket_plaintext_mismatch/,
    );
  } finally {
    substitute.fill(0);
  }
});

test("ticket signature, custody, and exclusive validity window are enforced", () => {
  const { fixture, authorityKeys, custodyId, tickets } = issueFixture();
  assert.throws(
    () =>
      createVaultObjectBindingFromAuthorization({
        signed_seal_ticket: tickets.reference,
        authority_public_key: authorityKeys.publicKey,
        expected_custody_id: fixtureId("custody", "wrong"),
        plaintext: fixture.mediaPairs[0].before_bytes,
        now_ms: 10_002,
      }),
    /vault_seal_ticket_custody_mismatch/,
  );
  assert.throws(
    () =>
      createVaultObjectBindingFromAuthorization({
        signed_seal_ticket: tickets.reference,
        authority_public_key: authorityKeys.publicKey,
        expected_custody_id: custodyId,
        plaintext: fixture.mediaPairs[0].before_bytes,
        now_ms: tickets.reference.payload.expires_at_ms,
      }),
    /vault_seal_ticket_outside_validity_window/,
  );
  assert.throws(
    () =>
      verifyVaultSealTicket(authorityKeys.publicKey, {
        ...tickets.reference,
        payload: {
          ...tickets.reference.payload,
          plaintext_commitment_sha256: "0".repeat(64),
        },
      }),
    /vault_seal_ticket_signature_invalid/,
  );
  assert.throws(() =>
    VaultSignedSealTicketSchema.parse({
      ...tickets.reference,
      trusted: true,
    }),
  );
});

test("Authority refuses an altered pair and an execution plan from the future", () => {
  const fixture = createLiveContractFixture({ count: 1 });
  const authorityKeys = generateKeyPairSync("ed25519");
  const custodyId = fixtureId("custody", "phase19b-refusal-vault");
  const alteredAfter = Buffer.from(fixture.mediaPairs[0].after_bytes);
  alteredAfter[0] ^= 0x20;
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
          expected_custody_id: custodyId,
          before_plaintext: fixture.mediaPairs[0].before_bytes,
          after_plaintext: alteredAfter,
          now_ms: 10_001,
          expires_at_ms: 11_000,
        }),
      /vault_media_pair_not_authorized/,
    );
    assert.throws(
      () =>
        issueVaultSealTicketsFromAuthorizedPair({
          signed_consent: fixture.signedConsent,
          consent_public_key: fixture.consentKeys.publicKey,
          execution_plan: { ...fixture.plan, created_at_ms: 10_100 },
          runtime_manifest: fixture.runtime,
          authority_pair_secret: fixture.authoritySecret,
          authority_signing_private_key: authorityKeys.privateKey,
          expected_custody_id: custodyId,
          before_plaintext: fixture.mediaPairs[0].before_bytes,
          after_plaintext: fixture.mediaPairs[0].after_bytes,
          now_ms: 10_001,
          expires_at_ms: 11_000,
        }),
      /vault_execution_plan_outside_validity_window/,
    );
  } finally {
    alteredAfter.fill(0);
  }
});
