import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  authorizeLiveExecution,
  LiveConsentGrantSchema,
  LiveDispatchIntentSchema,
  LiveRuntimeManifestSchema,
  signLocalAnchorReceipt,
  verifyLiveConsent,
  verifyLocalAnchorReceipt,
} from "../evaluation/live-shadow/contracts.ts";
import { sha256Canonical } from "../evaluation/live-shadow/crypto.ts";
import { CollectorConsentGrantSchema } from "../evaluation/collector/contracts.ts";
import {
  createLiveContractFixture,
  fixtureHash,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

test("live.v1 consent is signed by a pinned Ed25519 authority", () => {
  const fixture = createLiveContractFixture();
  assert.deepEqual(
    verifyLiveConsent(fixture.consentKeys.publicKey, fixture.signedConsent),
    fixture.signedConsent,
  );
  const other = generateKeyPairSync("ed25519");
  assert.throws(
    () => verifyLiveConsent(other.publicKey, fixture.signedConsent),
    /consent_signer_key_mismatch/,
  );
});

test("live.v1 stays separate from the rehearsal consent schema", () => {
  const fixture = createLiveContractFixture();
  assert.throws(() => CollectorConsentGrantSchema.parse(fixture.consent));
  assert.throws(() =>
    LiveConsentGrantSchema.parse({
      ...fixture.consent,
      run_mode: "rehearsal",
      provider_id: "fake_local",
    }),
  );
});

test("live.v1 requires high-entropy identifiers and exact 3N caps", () => {
  const fixture = createLiveContractFixture();
  assert.throws(() =>
    LiveConsentGrantSchema.parse({
      ...fixture.consent,
      authorization_id: "authorization-0001",
    }),
  );
  assert.throws(() =>
    LiveConsentGrantSchema.parse({
      ...fixture.consent,
      max_provider_calls: fixture.consent.max_provider_calls + 1,
    }),
  );
  assert.throws(() =>
    LiveConsentGrantSchema.parse({
      ...fixture.consent,
      call_slots: ["primary", "plus", "flash"],
    }),
  );
});

test("live.v1 rejects duplicate or mismatched media scopes", () => {
  const fixture = createLiveContractFixture();
  const duplicate = fixture.consent.media_scopes.map((item) => ({ ...item }));
  duplicate[1].media_scope_id = duplicate[0].media_scope_id;
  assert.throws(() =>
    LiveConsentGrantSchema.parse({ ...fixture.consent, media_scopes: duplicate }),
  );
  const executions = fixture.consent.authorized_executions.map((item) => ({
    ...item,
  }));
  executions[0].pair_commitment_hmac_sha256 = fixtureHash("wrong-pair");
  assert.throws(() =>
    LiveConsentGrantSchema.parse({
      ...fixture.consent,
      authorized_executions: executions,
    }),
  );
});

test("live runtime pins HTTPS, redirects, proxy policy, retries, and Bailian host", () => {
  const fixture = createLiveContractFixture();
  assert.deepEqual(LiveRuntimeManifestSchema.parse(fixture.runtime), fixture.runtime);
  for (const runtime of [
    { ...fixture.runtime, max_retries: 1 },
    {
      ...fixture.runtime,
      endpoint: { ...fixture.runtime.endpoint, redirect_policy: "follow" },
    },
    {
      ...fixture.runtime,
      endpoint: { ...fixture.runtime.endpoint, host: "127.0.0.1" },
    },
  ]) {
    assert.throws(() => LiveRuntimeManifestSchema.parse(runtime));
  }
});

test("execution authorization binds the exact signed consent and runtime", () => {
  const fixture = createLiveContractFixture();
  const authorized = authorizeLiveExecution({
    signed_consent: fixture.signedConsent,
    runtime_manifest: fixture.runtime,
    execution_plan: fixture.plan,
    consent_public_key: fixture.consentKeys.publicKey,
    now_ms: fixture.consent.not_before_ms,
  });
  assert.equal(authorized.plan.execution_id, fixture.plan.execution_id);
  assert.throws(() =>
    authorizeLiveExecution({
      signed_consent: fixture.signedConsent,
      runtime_manifest: {
        ...fixture.runtime,
        models: { ...fixture.runtime.models, plus: "drifted-model" },
      },
      execution_plan: fixture.plan,
      consent_public_key: fixture.consentKeys.publicKey,
      now_ms: fixture.consent.not_before_ms,
    }),
  );
});

test("execution authorization fails at the exact expiry boundary", () => {
  const fixture = createLiveContractFixture();
  assert.throws(
    () =>
      authorizeLiveExecution({
        signed_consent: fixture.signedConsent,
        runtime_manifest: fixture.runtime,
        execution_plan: fixture.plan,
        consent_public_key: fixture.consentKeys.publicKey,
        now_ms: fixture.consent.expires_at_ms,
      }),
    /authorization_outside_validity_window/,
  );
});

test("dispatch intents bind slot ordinal, runtime, and request commitment", () => {
  const fixture = createLiveContractFixture();
  const intent = {
    schema_version: "checkback.live-shadow.dispatch-intent.v1",
    authority_registry_id: fixture.registryId,
    anchor_realm_id: fixture.realmId,
    authorization_id: fixture.consent.authorization_id,
    authorization_fingerprint_sha256: sha256Canonical(fixture.signedConsent),
    execution_id: fixture.plan.execution_id,
    media_scope_id: fixture.plan.media_scope_id,
    pair_commitment_hmac_sha256:
      fixture.plan.pair_commitment_hmac_sha256,
    slot: "flash",
    ordinal: 2,
    operation_id: fixtureId("op", "operation-a"),
    request_commitment_hmac_sha256: fixtureHash("synthetic-request"),
    runtime_manifest_sha256: sha256Canonical(fixture.runtime),
    created_at_ms: fixture.consent.not_before_ms,
    expires_at_ms: fixture.consent.expires_at_ms,
  };
  assert.deepEqual(LiveDispatchIntentSchema.parse(intent), intent);
  assert.throws(() =>
    LiveDispatchIntentSchema.parse({ ...intent, ordinal: 3 }),
  );
});

test("local anchor receipts are explicitly offline and signature-bound", () => {
  const fixture = createLiveContractFixture();
  const payload = {
    schema_version: "checkback.live-shadow.anchor-receipt.v1",
    anchor_mode: "offline_local_stub",
    anchor_realm_id: fixture.realmId,
    anchor_key_id: fixture.runtime.anchor_key_id,
    authority_registry_id: fixture.registryId,
    global_sequence: 1,
    registry_sequence: 1,
    previous_registry_head_sha256: "0".repeat(64),
    registry_head_sha256: fixtureHash("head-1"),
    event_type: "register_registry",
    object_key_sha256: fixtureHash("registry-object"),
    session_id: null,
    fencing_token: 0,
    recorded_at_ms: fixture.consent.created_at_ms,
  };
  const receipt = signLocalAnchorReceipt(fixture.anchorKeys.privateKey, payload);
  assert.deepEqual(
    verifyLocalAnchorReceipt(fixture.anchorKeys.publicKey, receipt),
    receipt,
  );
  assert.throws(() =>
    verifyLocalAnchorReceipt(fixture.anchorKeys.publicKey, {
      ...receipt,
      payload: { ...receipt.payload, global_sequence: 2 },
    }),
  );
});
