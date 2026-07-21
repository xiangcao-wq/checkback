import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  canonicalJson,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
} from "../evaluation/live-shadow/crypto.ts";
import {
  remoteAnchorRequestTimeStatus,
  SignedRemoteAnchorReceiptSchema,
  signRemoteAnchorReceipt,
  verifyRemoteAnchorReceipt,
} from "../evaluation/live-shadow-boundary/remote-anchor-contracts.ts";
import {
  RemoteAnchorClient,
  RemoteAnchorClientError,
} from "../evaluation/live-shadow-boundary/remote-anchor-client.ts";
import {
  RemoteAnchorServiceSimulator,
} from "../evaluation/live-shadow-boundary/remote-anchor-service-simulator.ts";
import {
  fixtureHash,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

class DirectSimulatorTransport {
  mode = "direct_offline_simulator";
  calls = 0;
  #service;

  constructor(service) {
    this.#service = service;
  }

  async exchangeOnce(requestBytes) {
    this.calls += 1;
    return this.#service.handle(requestBytes);
  }
}

function createHarness() {
  let now = 10_000;
  const anchorKeys = generateKeyPairSync("ed25519");
  const authorityA = generateKeyPairSync("ed25519");
  const authorityB = generateKeyPairSync("ed25519");
  const realmId = fixtureId("realm", "phase19b-remote-realm");
  const anchorEpochId = fixtureId("anchorepoch", "phase19b-anchor-epoch");
  const timeEpochId = fixtureId("timeepoch", "phase19b-time-epoch");
  const registryA = fixtureId("registry", "phase19b-registry-a");
  const registryB = fixtureId("registry", "phase19b-registry-b");
  const enrollmentA = fixtureId("enrollment", "phase19b-enrollment-a");
  const enrollmentB = fixtureId("enrollment", "phase19b-enrollment-b");
  const clock = () => ({
    unix_ms: String(now),
    source_id: "offline-trusted-clock-fixture",
    epoch_id: timeEpochId,
    max_error_ms: "0",
  });
  const service = new RemoteAnchorServiceSimulator({
    realm_id: realmId,
    anchor_epoch_id: anchorEpochId,
    anchor_private_key: anchorKeys.privateKey,
    anchor_public_key: anchorKeys.publicKey,
    time_source_id: "offline-trusted-clock-fixture",
    time_epoch_id: timeEpochId,
    max_error_ms: 0,
    clock,
    enrollments: [
      {
        enrollment_id: enrollmentA,
        authority_registry_id: registryA,
        authority_public_key: authorityA.publicKey,
      },
      {
        enrollment_id: enrollmentB,
        authority_registry_id: registryB,
        authority_public_key: authorityB.publicKey,
      },
    ],
  });
  function makeClient(authority, registryId, profile = "offline_simulator") {
    return new RemoteAnchorClient({
      realm_id: realmId,
      authority_registry_id: registryId,
      authority_private_key: authority.privateKey,
      authority_public_key: authority.publicKey,
      anchor_public_key: anchorKeys.publicKey,
      expected_service_profile: profile,
      anchor_epoch_id: anchorEpochId,
      time_source_id: "offline-trusted-clock-fixture",
      time_epoch_id: timeEpochId,
      max_trusted_time_error_ms: 0,
    });
  }
  const clientA = makeClient(authorityA, registryA);
  const clientB = makeClient(authorityB, registryB);
  const transport = new DirectSimulatorTransport(service);
  return {
    anchorKeys,
    authorityA,
    authorityB,
    realmId,
    registryA,
    registryB,
    enrollmentA,
    enrollmentB,
    service,
    clientA,
    clientB,
    transport,
    get now() {
      return now;
    },
    setNow(value) {
      now = value;
    },
    makeClient,
    close() {
      clientA.close();
      clientB.close();
      service.close();
    },
  };
}

function prepare(harness, client, seed, body, checkpoint, overrides = {}) {
  const issuedAt = overrides.issued_at_ms ?? harness.now;
  const expiresAt = overrides.expires_at_ms ?? issuedAt + 30_000;
  return client.prepare({
    request_id:
      overrides.request_id ?? fixtureId("anchorreq", `${seed}-request`),
    idempotency_key:
      overrides.idempotency_key ?? fixtureId("anchorop", `${seed}-operation`),
    request_nonce_hex:
      overrides.request_nonce_hex ?? fixtureHash(`${seed}-nonce`),
    issued_at_ms: String(issuedAt),
    expires_at_ms: String(expiresAt),
    expected_checkpoint: checkpoint,
    body,
  });
}

async function exchangeAndDispose(client, transport, prepared) {
  try {
    return await client.exchangeOnce(prepared, transport);
  } finally {
    client.disposePrepared(prepared);
  }
}

async function register(harness, client, enrollmentId, seed) {
  const prepared = prepare(
    harness,
    client,
    `${seed}-register`,
    { operation: "register_registry", enrollment_id: enrollmentId },
    null,
  );
  const receipt = await exchangeAndDispose(client, harness.transport, prepared);
  assert.equal(receipt.payload.decision, "committed");
  return receipt.payload.checkpoint_after;
}

async function acquire(harness, client, checkpoint, sessionId, seed, lease = "5000") {
  const prepared = prepare(
    harness,
    client,
    `${seed}-acquire`,
    { operation: "acquire_session", session_id: sessionId, requested_lease_ms: lease },
    checkpoint,
  );
  return exchangeAndDispose(client, harness.transport, prepared);
}

test("remote anchor registers only an enrolled authority and exact replay is byte-stable", async () => {
  const harness = createHarness();
  try {
    const prepared = prepare(
      harness,
      harness.clientA,
      "stable",
      {
        operation: "register_registry",
        enrollment_id: harness.enrollmentA,
      },
      null,
    );
    const requestBytes = harness.clientA.copyPreparedBytes(prepared);
    const firstBytes = harness.service.handle(requestBytes);
    const secondBytes = harness.service.handle(requestBytes);
    assert.deepEqual(secondBytes, firstBytes);
    const first = harness.clientA.verifyResponse(prepared, firstBytes);
    const second = harness.clientA.verifyResponse(prepared, secondBytes);
    assert.deepEqual(second, first);
    assert.equal(first.payload.decision, "committed");
    assert.equal(first.payload.service_profile, "offline_simulator");
    assert.equal(first.payload.checkpoint_after.registry_sequence, "1");
    assert.deepEqual(harness.service.snapshot(), {
      mode: "offline_remote_anchor_simulator",
      service_profile: "offline_simulator",
      network_calls: 0,
      global_sequence: "1",
      registered_registries: 1,
      authorizations: 0,
      executions: 0,
      call_slots: 0,
      consumed_slots: 0,
      terminal_requests: 1,
      replay_quarantines: 0,
      fatal: false,
    });
    requestBytes.fill(0);
    firstBytes.fill(0);
    secondBytes.fill(0);
    harness.clientA.disposePrepared(prepared);
  } finally {
    harness.close();
  }
});

test("remote anchor rejects non-canonical bytes and a tampered authority signature", () => {
  const harness = createHarness();
  try {
    const prepared = prepare(
      harness,
      harness.clientA,
      "canonical",
      {
        operation: "register_registry",
        enrollment_id: harness.enrollmentA,
      },
      null,
    );
    const bytes = harness.clientA.copyPreparedBytes(prepared);
    const padded = Buffer.concat([bytes, Buffer.from(" ", "utf8")]);
    assert.throws(
      () => harness.service.handle(padded),
      /remote_anchor_request_not_canonical/,
    );
    const envelope = JSON.parse(bytes.toString("utf8"));
    envelope.signature_base64 =
      (envelope.signature_base64[0] === "A" ? "B" : "A") +
      envelope.signature_base64.slice(1);
    assert.throws(
      () =>
        harness.service.handle(
          Buffer.from(canonicalJson(envelope), "utf8"),
        ),
      /remote_anchor_authority_signature_invalid/,
    );
    assert.equal(harness.service.snapshot().registered_registries, 0);
    bytes.fill(0);
    padded.fill(0);
    harness.clientA.disposePrepared(prepared);
  } finally {
    harness.close();
  }
});

test("nonce or idempotency reuse with a changed request quarantines the authority", async () => {
  const harness = createHarness();
  try {
    const checkpoint = await register(
      harness,
      harness.clientA,
      harness.enrollmentA,
      "conflict",
    );
    const nonce = fixtureHash("reused-nonce");
    const first = prepare(
      harness,
      harness.clientA,
      "conflict-observe-a",
      { operation: "get_checkpoint" },
      checkpoint,
      { request_nonce_hex: nonce },
    );
    await exchangeAndDispose(harness.clientA, harness.transport, first);
    const second = prepare(
      harness,
      harness.clientA,
      "conflict-observe-b",
      { operation: "get_checkpoint" },
      checkpoint,
      { request_nonce_hex: nonce },
    );
    await assert.rejects(
      () => harness.clientA.exchangeOnce(second, harness.transport),
      /remote_anchor_transport_outcome_unknown/,
    );
    harness.clientA.disposePrepared(second);
    assert.equal(harness.service.snapshot().replay_quarantines, 1);
    const third = prepare(
      harness,
      harness.clientA,
      "conflict-after",
      { operation: "get_checkpoint" },
      checkpoint,
    );
    await assert.rejects(
      () => harness.clientA.exchangeOnce(third, harness.transport),
      /remote_anchor_transport_outcome_unknown/,
    );
    harness.clientA.disposePrepared(third);
  } finally {
    harness.close();
  }
});

test("request expiry is a signed stable rejection even after its TTL", async () => {
  const harness = createHarness();
  try {
    const prepared = prepare(
      harness,
      harness.clientA,
      "expired",
      {
        operation: "register_registry",
        enrollment_id: harness.enrollmentA,
      },
      null,
      { issued_at_ms: 9_000, expires_at_ms: 9_500 },
    );
    const first = await harness.clientA.exchangeOnce(prepared, harness.transport);
    assert.equal(first.payload.decision, "rejected");
    assert.equal(first.payload.error_code, "remote_anchor_request_expired");
    harness.setNow(20_000);
    const replay = await harness.clientA.exchangeOnce(prepared, harness.transport);
    assert.deepEqual(replay, first);
    assert.equal(harness.service.snapshot().global_sequence, "0");
    harness.clientA.disposePrepared(prepared);
  } finally {
    harness.close();
  }
});

test("trusted clock rollback makes the simulator fatal for new requests", async () => {
  const harness = createHarness();
  try {
    const checkpoint = await register(
      harness,
      harness.clientA,
      harness.enrollmentA,
      "clock",
    );
    harness.setNow(9_999);
    const prepared = prepare(
      harness,
      harness.clientA,
      "clock-rollback",
      { operation: "get_checkpoint" },
      checkpoint,
      { issued_at_ms: 9_999, expires_at_ms: 20_000 },
    );
    await assert.rejects(
      () => harness.clientA.exchangeOnce(prepared, harness.transport),
      /remote_anchor_transport_outcome_unknown/,
    );
    harness.clientA.disposePrepared(prepared);
    assert.equal(harness.service.snapshot().fatal, true);
  } finally {
    harness.close();
  }
});

test("session leases fence clones and a later session receives a higher token", async () => {
  const harness = createHarness();
  try {
    const checkpoint = await register(
      harness,
      harness.clientA,
      harness.enrollmentA,
      "lease",
    );
    const sessionA = fixtureId("session", "lease-a");
    const acquired = await acquire(
      harness,
      harness.clientA,
      checkpoint,
      sessionA,
      "lease-a",
      "1000",
    );
    assert.equal(acquired.payload.checkpoint_after.fencing_token, "1");
    const sessionB = fixtureId("session", "lease-b");
    const blocked = await acquire(
      harness,
      harness.clientA,
      acquired.payload.checkpoint_after,
      sessionB,
      "lease-b-blocked",
      "1000",
    );
    assert.equal(blocked.payload.decision, "rejected");
    assert.equal(
      blocked.payload.error_code,
      "remote_anchor_session_already_active",
    );
    harness.setNow(11_001);
    const reacquired = await acquire(
      harness,
      harness.clientA,
      acquired.payload.checkpoint_after,
      sessionB,
      "lease-b-after-expiry",
      "5000",
    );
    assert.equal(reacquired.payload.decision, "committed");
    assert.equal(reacquired.payload.checkpoint_after.fencing_token, "2");
  } finally {
    harness.close();
  }
});

async function claimAuthorization(harness, client, checkpoint, sessionId, seed) {
  const authorization = {
    authorization_id: fixtureId("auth", "phase19b-shared-auth"),
    authorization_fingerprint_sha256: fixtureHash("phase19b-shared-fingerprint"),
    signed_consent_sha256: fixtureHash("phase19b-consent"),
    runtime_manifest_sha256: fixtureHash("phase19b-runtime"),
    expires_at_ms: 100_000,
    execution_id: fixtureId("exec", "phase19b-execution"),
    media_scope_id: fixtureId("scope", "phase19b-scope"),
    pair_commitment_hmac_sha256: fixtureHash("phase19b-pair"),
  };
  const prepared = prepare(
    harness,
    client,
    `${seed}-claim`,
    {
      operation: "claim_authorization",
      session_id: sessionId,
      fencing_token: checkpoint.fencing_token,
      authorization_id: authorization.authorization_id,
      authorization_fingerprint_sha256:
        authorization.authorization_fingerprint_sha256,
      signed_consent_sha256: authorization.signed_consent_sha256,
      runtime_manifest_sha256: authorization.runtime_manifest_sha256,
      expires_at_ms: String(authorization.expires_at_ms),
      executions: [
        {
          execution_id: authorization.execution_id,
          media_scope_id: authorization.media_scope_id,
          pair_commitment_hmac_sha256:
            authorization.pair_commitment_hmac_sha256,
        },
      ],
    },
    checkpoint,
  );
  const receipt = await exchangeAndDispose(client, harness.transport, prepared);
  return { receipt, authorization };
}

test("authorization and execution IDs are globally one-shot across authorities", async () => {
  const harness = createHarness();
  try {
    const checkpointA = await register(
      harness,
      harness.clientA,
      harness.enrollmentA,
      "global-a",
    );
    const sessionA = fixtureId("session", "global-a");
    const acquiredA = await acquire(
      harness,
      harness.clientA,
      checkpointA,
      sessionA,
      "global-a",
    );
    const claimedA = await claimAuthorization(
      harness,
      harness.clientA,
      acquiredA.payload.checkpoint_after,
      sessionA,
      "global-a",
    );
    assert.equal(claimedA.receipt.payload.decision, "committed");

    const checkpointB = await register(
      harness,
      harness.clientB,
      harness.enrollmentB,
      "global-b",
    );
    const sessionB = fixtureId("session", "global-b");
    const acquiredB = await acquire(
      harness,
      harness.clientB,
      checkpointB,
      sessionB,
      "global-b",
    );
    const claimedB = await claimAuthorization(
      harness,
      harness.clientB,
      acquiredB.payload.checkpoint_after,
      sessionB,
      "global-b",
    );
    assert.equal(claimedB.receipt.payload.decision, "rejected");
    assert.equal(
      claimedB.receipt.payload.error_code,
      "remote_anchor_authorization_already_claimed",
    );
    assert.equal(harness.service.snapshot().authorizations, 1);
  } finally {
    harness.close();
  }
});

test("slot consumption is ordered, non-idempotent across requests, and exact replay is stable", async () => {
  const harness = createHarness();
  try {
    const registered = await register(
      harness,
      harness.clientA,
      harness.enrollmentA,
      "slots",
    );
    const sessionId = fixtureId("session", "slots");
    const acquired = await acquire(
      harness,
      harness.clientA,
      registered,
      sessionId,
      "slots",
    );
    const claimed = await claimAuthorization(
      harness,
      harness.clientA,
      acquired.payload.checkpoint_after,
      sessionId,
      "slots",
    );
    const auth = claimed.authorization;
    const checkpoint = claimed.receipt.payload.checkpoint_after;
    function intent(slot, ordinal, operationSeed) {
      return {
        schema_version: "checkback.live-shadow.dispatch-intent.v1",
        authority_registry_id: harness.registryA,
        anchor_realm_id: harness.realmId,
        authorization_id: auth.authorization_id,
        authorization_fingerprint_sha256:
          auth.authorization_fingerprint_sha256,
        execution_id: auth.execution_id,
        media_scope_id: auth.media_scope_id,
        pair_commitment_hmac_sha256:
          auth.pair_commitment_hmac_sha256,
        slot,
        ordinal,
        operation_id: fixtureId("op", operationSeed),
        request_commitment_hmac_sha256: fixtureHash(`${operationSeed}-request`),
        runtime_manifest_sha256: auth.runtime_manifest_sha256,
        created_at_ms: harness.now,
        expires_at_ms: auth.expires_at_ms,
      };
    }
    const outOfOrder = prepare(
      harness,
      harness.clientA,
      "slots-plus-first",
      {
        operation: "consume_slot",
        session_id: sessionId,
        fencing_token: checkpoint.fencing_token,
        intent: intent("plus", 3, "plus-first"),
      },
      checkpoint,
    );
    const rejected = await exchangeAndDispose(
      harness.clientA,
      harness.transport,
      outOfOrder,
    );
    assert.equal(rejected.payload.error_code, "remote_anchor_slot_order_invalid");

    const primary = prepare(
      harness,
      harness.clientA,
      "slots-primary",
      {
        operation: "consume_slot",
        session_id: sessionId,
        fencing_token: checkpoint.fencing_token,
        intent: intent("primary", 1, "primary"),
      },
      checkpoint,
    );
    const proof = await harness.clientA.exchangeCommittedConsumeForIpc(
      primary,
      harness.transport,
    );
    const first = proof.receipt;
    try {
      assert.equal(proof.request.payload.operation, "consume_slot");
      assert.equal(proof.request_sha256, sha256Canonical(proof.request));
      assert.equal(proof.receipt_sha256, sha256Bytes(proof.receipt_bytes));
      assert.equal(
        proof.receipt.payload.object_key_sha256,
        sha256Canonical(proof.request.payload.body.intent),
      );
      assert.equal(proof.anchor_time_ms, harness.now);
    } finally {
      proof.receipt_bytes.fill(0);
    }
    const replay = await harness.clientA.exchangeOnce(primary, harness.transport);
    assert.deepEqual(replay, first);
    assert.equal(first.payload.decision, "committed");
    harness.clientA.disposePrepared(primary);

    const duplicate = prepare(
      harness,
      harness.clientA,
      "slots-primary-second-request",
      {
        operation: "consume_slot",
        session_id: sessionId,
        fencing_token: first.payload.checkpoint_after.fencing_token,
        intent: intent("primary", 1, "primary-second"),
      },
      first.payload.checkpoint_after,
    );
    const duplicateReceipt = await exchangeAndDispose(
      harness.clientA,
      harness.transport,
      duplicate,
    );
    assert.equal(
      duplicateReceipt.payload.error_code,
      "remote_anchor_slot_or_operation_consumed",
    );
    assert.equal(harness.service.snapshot().consumed_slots, 1);
  } finally {
    harness.close();
  }
});

test("a production-profile client rejects the offline simulator receipt", async () => {
  const harness = createHarness();
  const productionClient = harness.makeClient(
    harness.authorityA,
    harness.registryA,
    "production_external",
  );
  try {
    const prepared = prepare(
      harness,
      productionClient,
      "production-profile",
      {
        operation: "register_registry",
        enrollment_id: harness.enrollmentA,
      },
      null,
    );
    await assert.rejects(
      () => productionClient.exchangeOnce(prepared, harness.transport),
      /remote_anchor_receipt_binding_invalid/,
    );
    productionClient.disposePrepared(prepared);
    assert.equal(harness.service.snapshot().global_sequence, "0");
  } finally {
    productionClient.close();
    harness.close();
  }
});

test("tampered or wrong-key anchor receipts are rejected after a single exchange", async () => {
  const harness = createHarness();
  try {
    const prepared = prepare(
      harness,
      harness.clientA,
      "tampered-receipt",
      {
        operation: "register_registry",
        enrollment_id: harness.enrollmentA,
      },
      null,
    );
    let calls = 0;
    const tamperingTransport = {
      mode: "tampering-offline",
      async exchangeOnce(bytes) {
        calls += 1;
        const response = harness.service.handle(bytes);
        const parsed = SignedRemoteAnchorReceiptSchema.parse(
          JSON.parse(response.toString("utf8")),
        );
        parsed.payload.object_key_sha256 = fixtureHash("forged-object-key");
        return Buffer.from(canonicalJson(parsed), "utf8");
      },
    };
    await assert.rejects(
      () => harness.clientA.exchangeOnce(prepared, tamperingTransport),
      (error) =>
        error instanceof RemoteAnchorClientError &&
        error.code === "remote_anchor_receipt_verification_failed" &&
        error.outcomeMayBeCommitted === true,
    );
    assert.equal(calls, 1);
    harness.clientA.disposePrepared(prepared);

    const wrongAnchorKeys = generateKeyPairSync("ed25519");
    const wrongClient = new RemoteAnchorClient({
      realm_id: harness.realmId,
      authority_registry_id: harness.registryA,
      authority_private_key: harness.authorityA.privateKey,
      authority_public_key: harness.authorityA.publicKey,
      anchor_public_key: wrongAnchorKeys.publicKey,
      expected_service_profile: "offline_simulator",
      anchor_epoch_id: fixtureId("anchorepoch", "phase19b-anchor-epoch"),
      time_source_id: "offline-trusted-clock-fixture",
      time_epoch_id: fixtureId("timeepoch", "phase19b-time-epoch"),
      max_trusted_time_error_ms: 0,
    });
    const observe = prepare(
      harness,
      wrongClient,
      "wrong-anchor-key",
      { operation: "get_checkpoint" },
      null,
    );
    await assert.rejects(
      () => wrongClient.exchangeOnce(observe, harness.transport),
      (error) =>
        error instanceof RemoteAnchorClientError &&
        error.code === "remote_anchor_receipt_verification_failed" &&
        error.outcomeMayBeCommitted === true,
    );
    wrongClient.disposePrepared(observe);
    wrongClient.close();
  } finally {
    harness.close();
  }
});

test("transport uncertainty performs one call and is classified may-be-committed", async () => {
  const harness = createHarness();
  try {
    const prepared = prepare(
      harness,
      harness.clientA,
      "transport-unknown",
      {
        operation: "register_registry",
        enrollment_id: harness.enrollmentA,
      },
      null,
    );
    let calls = 0;
    const failingTransport = {
      mode: "throwing-offline",
      async exchangeOnce() {
        calls += 1;
        throw new Error("simulated_response_loss");
      },
    };
    await assert.rejects(
      () => harness.clientA.exchangeOnce(prepared, failingTransport),
      (error) =>
        error instanceof RemoteAnchorClientError &&
        error.code === "remote_anchor_transport_outcome_unknown" &&
        error.outcomeMayBeCommitted === true,
    );
    assert.equal(calls, 1);
    assert.equal(harness.service.snapshot().terminal_requests, 0);
    harness.clientA.disposePrepared(prepared);
  } finally {
    harness.close();
  }
});

test("verified remote receipts bind the expected anchor and authority key IDs", async () => {
  const harness = createHarness();
  try {
    const prepared = prepare(
      harness,
      harness.clientA,
      "receipt-bindings",
      {
        operation: "register_registry",
        enrollment_id: harness.enrollmentA,
      },
      null,
    );
    const bytes = harness.clientA.copyPreparedBytes(prepared);
    const response = harness.service.handle(bytes);
    const receipt = verifyRemoteAnchorReceipt(
      harness.anchorKeys.publicKey,
      JSON.parse(response.toString("utf8")),
    );
    assert.equal(receipt.payload.anchor_key_id, publicKeyId(harness.anchorKeys.publicKey));
    assert.equal(
      receipt.payload.authority_key_id,
      publicKeyId(harness.authorityA.publicKey),
    );
    bytes.fill(0);
    response.fill(0);
    harness.clientA.disposePrepared(prepared);
  } finally {
    harness.close();
  }
});

test("remote anchor rejects a non-canonical Base64 signature spelling", () => {
  const harness = createHarness();
  try {
    const prepared = prepare(
      harness,
      harness.clientA,
      "base64-pad-bits",
      {
        operation: "register_registry",
        enrollment_id: harness.enrollmentA,
      },
      null,
    );
    const bytes = harness.clientA.copyPreparedBytes(prepared);
    const envelope = JSON.parse(bytes.toString("utf8"));
    const alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const signature = envelope.signature_base64;
    const lastIndex = alphabet.indexOf(signature[85]);
    assert.equal(lastIndex & 15, 0);
    const alternate = alphabet[(lastIndex & 48) | 1];
    envelope.signature_base64 =
      signature.slice(0, 85) + alternate + signature.slice(86);
    assert.deepEqual(
      Buffer.from(envelope.signature_base64, "base64"),
      Buffer.from(signature, "base64"),
    );
    assert.throws(() =>
      harness.service.handle(Buffer.from(canonicalJson(envelope), "utf8")),
    );
    assert.equal(harness.service.snapshot().terminal_requests, 0);
    bytes.fill(0);
    harness.clientA.disposePrepared(prepared);
  } finally {
    harness.close();
  }
});
test("an exact old receipt cannot roll the client checkpoint backward", async () => {
  const harness = createHarness();
  try {
    const registration = prepare(
      harness,
      harness.clientA,
      "old-receipt-registration",
      {
        operation: "register_registry",
        enrollment_id: harness.enrollmentA,
      },
      null,
    );
    const oldReceipt = await harness.clientA.exchangeOnce(
      registration,
      harness.transport,
    );
    const sessionId = fixtureId("session", "old-receipt-session");
    const acquired = await acquire(
      harness,
      harness.clientA,
      oldReceipt.payload.checkpoint_after,
      sessionId,
      "old-receipt-session",
    );
    assert.equal(acquired.payload.checkpoint_after.registry_sequence, "2");
    await assert.rejects(
      () => harness.clientA.exchangeOnce(registration, harness.transport),
      (error) =>
        error instanceof RemoteAnchorClientError &&
        error.code === "remote_anchor_receipt_sequence_rollback" &&
        error.outcomeMayBeCommitted === true,
    );
    harness.clientA.disposePrepared(registration);
  } finally {
    harness.close();
  }
});
test("same-sequence checkpoint forks are rejected even when signed by the trusted anchor", async () => {
  const harness = createHarness();
  try {
    const currentCheckpoint = await register(
      harness,
      harness.clientA,
      harness.enrollmentA,
      "signed-fork",
    );
    const observe = prepare(
      harness,
      harness.clientA,
      "signed-fork-observe",
      { operation: "get_checkpoint" },
      currentCheckpoint,
    );
    const requestBytes = harness.clientA.copyPreparedBytes(observe);
    const request = JSON.parse(requestBytes.toString("utf8"));
    const forkHead = fixtureHash("signed-fork-head");
    const forgedReceipt = signRemoteAnchorReceipt(
      harness.anchorKeys.privateKey,
      {
        schema_version: "checkback.live-shadow.remote-anchor-receipt.v1",
        anchor_mode: "remote_service",
        service_profile: "offline_simulator",
        anchor_realm_id: harness.realmId,
        anchor_epoch_id: fixtureId(
          "anchorepoch",
          "phase19b-anchor-epoch",
        ),
        anchor_key_id: publicKeyId(harness.anchorKeys.publicKey),
        authority_registry_id: harness.registryA,
        authority_key_id: publicKeyId(harness.authorityA.publicKey),
        request_id: request.payload.request_id,
        idempotency_key: request.payload.idempotency_key,
        request_nonce_sha256: sha256Bytes(
          request.payload.request_nonce_hex,
        ),
        signed_request_sha256: sha256Bytes(requestBytes),
        operation: "get_checkpoint",
        decision: "observed",
        error_code: null,
        anchor_time: {
          unix_ms: String(harness.now),
          source_id: "offline-trusted-clock-fixture",
          epoch_id: fixtureId("timeepoch", "phase19b-time-epoch"),
          max_error_ms: "0",
        },
        global_sequence: null,
        previous_registry_head_sha256: null,
        registry_head_sha256: forkHead,
        object_key_sha256: fixtureHash("signed-fork-object"),
        checkpoint_after: {
          ...currentCheckpoint,
          registry_head_sha256: forkHead,
        },
      },
    );
    const forgedBytes = Buffer.from(canonicalJson(forgedReceipt), "utf8");
    assert.throws(
      () => harness.clientA.verifyResponse(observe, forgedBytes),
      (error) =>
        error instanceof RemoteAnchorClientError &&
        error.code === "remote_anchor_checkpoint_fork" &&
        error.outcomeMayBeCommitted === true,
    );
    requestBytes.fill(0);
    forgedBytes.fill(0);
    harness.clientA.disposePrepared(observe);
  } finally {
    harness.close();
  }
});
test("trusted-time error interval uses one shared conservative upper bound", () => {
  const base = {
    schema_version: "checkback.live-shadow.remote-anchor-request.v1",
    anchor_realm_id: fixtureId("realm", "time-window"),
    expected_service_profile: "offline_simulator",
    authority_registry_id: fixtureId("registry", "time-window"),
    authority_key_id: fixtureHash("time-window-authority"),
    request_id: fixtureId("anchorreq", "time-window"),
    idempotency_key: fixtureId("anchorop", "time-window"),
    request_nonce_hex: fixtureHash("time-window-nonce"),
    operation: "get_checkpoint",
    issued_at_ms: "1005",
    expires_at_ms: "1006",
    expected_checkpoint: null,
    body: { operation: "get_checkpoint" },
  };
  const time = {
    unix_ms: "1000",
    source_id: "shared-time-window",
    epoch_id: fixtureId("timeepoch", "shared-time-window"),
    max_error_ms: "5",
  };
  assert.equal(remoteAnchorRequestTimeStatus(base, time), "active");
  assert.equal(
    remoteAnchorRequestTimeStatus({ ...base, issued_at_ms: "1006" }, time),
    "future",
  );
  assert.equal(
    remoteAnchorRequestTimeStatus({ ...base, expires_at_ms: "1005" }, time),
    "expired",
  );
});