import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { spawn } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { GatewayLedgerError, PersistentGatewayLedger } from "../evaluation/live-shadow-boundary/gateway-ledger.ts";
import {
  createIpcAttachmentDescriptor,
  createIpcDispatchContext,
  encodeCanonicalAttachmentFrame,
  signIpcAuthorityDispatchTicket,
  signIpcChallenge,
  signIpcChallengeRequest,
  signIpcDispatchCommand,
  verifyIpcDispatchCommand,
} from "../evaluation/live-shadow-boundary/ipc-contracts.ts";
import {
  disposeRebuiltGatewayRequest,
  GATEWAY_PROVIDER_REQUEST_TEMPLATE_SHA256,
} from "../evaluation/live-shadow-boundary/gateway-request-rebuilder.ts";
import { canonicalJson, publicKeyId, sha256Bytes, sha256Canonical } from "../evaluation/live-shadow/crypto.ts";
import {
  remoteAnchorSignedRequestSha256,
  signRemoteAnchorReceipt,
  signRemoteAnchorRequest,
} from "../evaluation/live-shadow-boundary/remote-anchor-contracts.ts";
import { createLiveContractFixture, fixtureHash, fixtureId } from "./helpers/live-shadow-fixture.mjs";

function hash(label) {
  return sha256Bytes(`phase19b-gateway-ledger-v2:${label}`);
}

function identifier(prefix, label) {
  return `${prefix}_${hash(label)}`;
}

function expectCode(action, code) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof GatewayLedgerError);
    assert.equal(error.code, code);
    return true;
  });
}

function withDirectory(label, callback) {
  const directory = mkdtempSync(join(tmpdir(), `checkback-${label}-`));
  try {
    return callback(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function checkpointWal(path) {
  const db = new DatabaseSync(path, { readOnly: false });
  try {
    db.exec("PRAGMA journal_mode=WAL");
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } finally {
    db.close();
  }
}

function createHarness(label) {
  const fixture = createLiveContractFixture({
    count: 3,
    request_template_sha256: GATEWAY_PROVIDER_REQUEST_TEMPLATE_SHA256,
  });
  const collectorKeys = generateKeyPairSync("ed25519");
  const gatewayKeys = generateKeyPairSync("ed25519");
  const authorityKeys = generateKeyPairSync("ed25519");
  const state = { now: 9_000, counter: 0 };
  const profile = {
    gateway_instance_id: identifier("gateway", `instance:${label}`),
    runtime_policy_sha256: fixture.runtime.runtime_policy_sha256,
    gateway_key_id: publicKeyId(gatewayKeys.publicKey),
    gateway_build_sha256: fixture.runtime.gateway_build_sha256,
  };
  const secret = Buffer.from(hash(`secret:${label}`), "hex");

  function makePreChallenge(operationLabel, options = {}) {
    const base = 10_000 + state.counter++ * 1_000;
    const operationId = identifier("op", `${label}:${operationLabel}`);
    const intent = {
      schema_version: "checkback.live-shadow.dispatch-intent.v1",
      authority_registry_id: fixture.registryId,
      anchor_realm_id: fixture.realmId,
      authorization_id: fixture.consent.authorization_id,
      authorization_fingerprint_sha256: fixture.plan.authorization_fingerprint_sha256,
      execution_id: fixture.plan.execution_id,
      media_scope_id: fixture.plan.media_scope_id,
      pair_commitment_hmac_sha256: fixture.plan.pair_commitment_hmac_sha256,
      slot: "flash",
      ordinal: 2,
      operation_id: operationId,
      request_commitment_hmac_sha256: fixtureHash(`request-commit:${label}:${operationLabel}`),
      runtime_manifest_sha256: fixture.plan.runtime_manifest_sha256,
      created_at_ms: base,
      expires_at_ms: base + 8_000,
    };
    const requestBytes = Buffer.from(canonicalJson({
      model: fixture.runtime.models.flash,
      max_tokens: 2_200,
      response_format: { type: "json_object" },
      enable_thinking: false,
      vl_high_resolution_images: true,
      stream: false,
      messages: [
        { role: "system", content: "verifier-prompt-fixture" },
        { role: "user", content: [
          { type: "text", text: "Synthetic reference" },
          { type: "image_url", image_url: { url: "data:image/jpeg;base64,UjE=" } },
          { type: "text", text: "Synthetic comparison" },
          { type: "image_url", image_url: { url: "data:image/jpeg;base64,QzE=" } },
        ] },
      ],
    }), "utf8");
    const requestBody = createIpcAttachmentDescriptor("request_body", requestBytes);
    const policy = {
      schema_version: "checkback.live-shadow-boundary.gateway-policy.v1",
      provider_id: "aliyun_bailian_openai_compatible",
      transport: "https",
      host: fixture.runtime.endpoint.host,
      port: 443,
      path: "/compatible-mode/v1/chat/completions",
      method: "POST",
      request_content_type: "application/json",
      redirect_policy: "deny",
      proxy_policy: "deny",
      max_network_attempts: 1,
      max_retries: 0,
      model_id: fixture.runtime.models.flash,
      connect_timeout_ms: options.connect_timeout_ms ?? 5_000,
      total_timeout_ms: fixture.runtime.timeouts_ms.flash,
      max_request_body_bytes: 1024 * 1024,
      max_response_body_bytes: 1024 * 1024,
      resolved_destination_policy_sha256: fixtureHash("destination-policy"),
      tls_policy_sha256: fixtureHash("tls-policy"),
      gateway_build_sha256: fixture.runtime.gateway_build_sha256,
      runtime_policy_sha256: fixture.runtime.runtime_policy_sha256,
    };
    const sessionId = fixtureId("session", `session:${label}:${operationLabel}`);
    const checkpointBefore = {
      registry_sequence: "10",
      registry_head_sha256: fixtureHash(`remote-head-before:${label}:${operationLabel}`),
      active_session_id: sessionId,
      fencing_token: "3",
      session_lease_expires_at_ms: String(base + 50_000),
    };
    const anchorRequest = signRemoteAnchorRequest(authorityKeys.privateKey, {
      schema_version: "checkback.live-shadow.remote-anchor-request.v1",
      anchor_realm_id: fixture.realmId,
      expected_service_profile: "offline_simulator",
      authority_registry_id: fixture.registryId,
      authority_key_id: publicKeyId(authorityKeys.publicKey),
      request_id: fixtureId("anchorreq", `request:${label}:${operationLabel}`),
      idempotency_key: fixtureId("anchorop", `operation:${label}:${operationLabel}`),
      request_nonce_hex: fixtureHash(`anchor-nonce:${label}:${operationLabel}`),
      operation: "consume_slot",
      issued_at_ms: String(base),
      expires_at_ms: String(base + 5_000),
      expected_checkpoint: checkpointBefore,
      body: { operation: "consume_slot", session_id: sessionId, fencing_token: "3", intent },
    });    const checkpointAfter = {
      registry_sequence: "11",
      registry_head_sha256: fixtureHash(`remote-head-after:${label}:${operationLabel}`),
      active_session_id: sessionId,
      fencing_token: "3",
      session_lease_expires_at_ms: String(base + 50_000),
    };
    const anchorReceiptEnvelope = signRemoteAnchorReceipt(fixture.anchorKeys.privateKey, {
      schema_version: "checkback.live-shadow.remote-anchor-receipt.v1",
      anchor_mode: "remote_service",
      service_profile: "offline_simulator",
      anchor_realm_id: fixture.realmId,
      anchor_epoch_id: fixtureId("anchorepoch", `epoch:${label}`),
      anchor_key_id: fixture.runtime.anchor_key_id,
      authority_registry_id: fixture.registryId,
      authority_key_id: publicKeyId(authorityKeys.publicKey),
      request_id: anchorRequest.payload.request_id,
      idempotency_key: anchorRequest.payload.idempotency_key,
      request_nonce_sha256: sha256Bytes(anchorRequest.payload.request_nonce_hex),
      signed_request_sha256: remoteAnchorSignedRequestSha256(anchorRequest),
      operation: "consume_slot",
      decision: "committed",
      error_code: null,
      anchor_time: {
        unix_ms: String(base + 50),
        source_id: "synthetic-trusted-clock",
        epoch_id: fixtureId("timeepoch", `time:${label}`),
        max_error_ms: "1",
      },
      global_sequence: "11",
      previous_registry_head_sha256: checkpointBefore.registry_head_sha256,
      registry_head_sha256: checkpointAfter.registry_head_sha256,
      object_key_sha256: sha256Canonical(intent),
      checkpoint_after: checkpointAfter,
    });
    const anchorReceiptBytes = Buffer.from(canonicalJson(anchorReceiptEnvelope), "utf8");
    const anchorReceipt = createIpcAttachmentDescriptor("anchor_receipt", anchorReceiptBytes);
    const authorityTicket = signIpcAuthorityDispatchTicket(authorityKeys.privateKey, {
      schema_version: "checkback.live-shadow-boundary.authority-dispatch-ticket.v1",
      expected_anchor_service_profile: "offline_simulator",
      collector_key_id: publicKeyId(collectorKeys.publicKey),
      gateway_key_id: publicKeyId(gatewayKeys.publicKey),
      authority_key_id: publicKeyId(authorityKeys.publicKey),
      anchor_key_id: fixture.runtime.anchor_key_id,
      dispatch_intent: intent,
      runtime_manifest: fixture.runtime,
      runtime_manifest_sha256: sha256Canonical(fixture.runtime),
      policy,
      policy_sha256: sha256Canonical(policy),
      remote_anchor_request_sha256: sha256Canonical(anchorRequest),
      remote_anchor_receipt_sha256: sha256Canonical(anchorReceiptEnvelope),
      anchor_receipt: anchorReceipt,
      request_body: requestBody,
      issued_at_ms: base + 60,
      expires_at_ms: base + 7_500,
    });
    const context = createIpcDispatchContext({
      signed_authority_ticket: authorityTicket,
      authority_public_key: authorityKeys.publicKey,
    });
    const challengeRequest = signIpcChallengeRequest(collectorKeys.privateKey, {
      schema_version: "checkback.live-shadow-boundary.challenge-request.v1",
      challenge_request_id: fixtureId("challenge_request", `request:${label}:${operationLabel}`),
      collector_nonce: fixtureId("nonce", `collector:${label}:${operationLabel}`),
      context,
      created_at_ms: base + 100,
      expires_at_ms: base + 7_000,
    });
    return {
      base, operationId, intent, policy, context, authorityTicket, anchorRequest,
      anchorReceiptEnvelope, anchorReceiptBytes, anchorReceipt, requestBytes,
      requestBody, challengeRequest,
    };
  }

  function finishCommand(pre, reservation, options = {}) {
    const gatewaySequence = options.gateway_sequence ?? reservation.gateway_sequence;
    const gatewayBootId = options.gateway_boot_id ?? reservation.gateway_boot_id;
    const challenge = signIpcChallenge(gatewayKeys.privateKey, {
      schema_version: "checkback.live-shadow-boundary.challenge.v1",
      challenge_id: fixtureId("challenge", `${label}:${pre.operationId}:${gatewaySequence}`),
      challenge_request_id: pre.challengeRequest.payload.challenge_request_id,
      challenge_request_sha256: sha256Canonical(pre.challengeRequest),
      gateway_boot_id: gatewayBootId,
      gateway_sequence: gatewaySequence,
      challenge_nonce: fixtureId("nonce", `gateway:${label}:${pre.operationId}:${gatewaySequence}`),
      use_policy: "single_use",
      max_dispatch_commands: 1,
      context: pre.context,
      issued_at_ms: pre.base + 200,
      expires_at_ms: pre.base + 6_900,
    });
    const command = signIpcDispatchCommand(collectorKeys.privateKey, {
      schema_version: "checkback.live-shadow-boundary.dispatch-command.v1",
      dispatch_command_id: fixtureId("command", `${label}:${pre.operationId}:${gatewaySequence}`),
      challenge_request_sha256: sha256Canonical(pre.challengeRequest),
      challenge_id: challenge.payload.challenge_id,
      challenge_sha256: sha256Canonical(challenge),
      gateway_boot_id: gatewayBootId,
      gateway_sequence: gatewaySequence,
      context: pre.context,
      authority_ticket: pre.authorityTicket,
      remote_anchor_request: pre.anchorRequest,
      remote_anchor_receipt: pre.anchorReceiptEnvelope,
      dispatch_intent: pre.intent,
      created_at_ms: pre.base + 300,
      expires_at_ms: pre.base + 6_500,
    });
    const trustedNow = pre.base + 350;
    const verified = verifyIpcDispatchCommand(collectorKeys.publicKey, command, {
      challenge_request: pre.challengeRequest,
      challenge,
      gateway_public_key: gatewayKeys.publicKey,
      authority_public_key: authorityKeys.publicKey,
      anchor_public_key: fixture.anchorKeys.publicKey,
      expected_anchor_service_profile: "offline_simulator",
      now_ms: trustedNow,
    });
    const frame = encodeCanonicalAttachmentFrame([
      { descriptor: pre.anchorReceipt, bytes: pre.anchorReceiptBytes },
      { descriptor: pre.requestBody, bytes: pre.requestBytes },
    ]);
    const compiledIdentity = {
      schema_version: "checkback.live-shadow-boundary.gateway-compiled-identity.v1",
      gateway_build_sha256: fixture.runtime.gateway_build_sha256,
      runtime_policy_sha256: fixture.runtime.runtime_policy_sha256,
      request_template_sha256: GATEWAY_PROVIDER_REQUEST_TEMPLATE_SHA256,
      response_schema_sha256: fixture.runtime.response_schema_sha256,
      preprocessing_config_sha256: fixture.runtime.preprocessing_config_sha256,
    };
    return { challenge, command, verified, frame, compiledIdentity, trustedNow };
  }

  return {
    fixture, collectorKeys, gatewayKeys, authorityKeys, profile, secret, state,
    makePreChallenge, finishCommand,
  };
}

function initialize(path, harness) {
  PersistentGatewayLedger.initialize({
    database_path: path,
    ledger_secret: harness.secret,
    profile: harness.profile,
    now: () => harness.state.now,
  });
}

function open(path, harness, bootLabel, extra = {}) {
  return PersistentGatewayLedger.openExisting({
    database_path: path,
    ledger_secret: harness.secret,
    profile: harness.profile,
    boot_session_id: identifier("boot", bootLabel),
    now: () => harness.state.now,
    ...extra,
  });
}

function reserveOnly(ledger, harness, label, options) {
  const pre = harness.makePreChallenge(label, options);
  harness.state.now = pre.base + 150;
  const adapter = ledger.createIpcAdapter({
    collector_public_key: harness.collectorKeys.publicKey,
    gateway_public_key: harness.gatewayKeys.publicKey,
    authority_public_key: harness.authorityKeys.publicKey,
    anchor_public_key: harness.fixture.anchorKeys.publicKey,
    expected_anchor_service_profile: "offline_simulator",
  });
  const reservation = adapter.reserveChallenge({
    challenge_request: pre.challengeRequest,
    trusted_now_ms: harness.state.now,
  });
  return { adapter, pre, reservation };
}

function reserveAndIssue(ledger, harness, label, options) {
  const prepared = reserveOnly(ledger, harness, label, options);
  const command = harness.finishCommand(prepared.pre, prepared.reservation);
  harness.state.now = command.trustedNow;
  const issued = prepared.adapter.issueVerifiedDispatch({
    verified_dispatch_command: command.verified,
    attachment_frame: command.frame,
    compiled_identity: command.compiledIdentity,
    trusted_now_ms: harness.state.now,
  });
  return { ...prepared, ...command, issued };
}

function claimBinding(item) {
  const operation = item.issued.operation;
  return {
    operation_id: operation.operation_id,
    gateway_sequence: operation.gateway_sequence,
    challenge_sha256: operation.challenge_sha256,
    dispatch_command_sha256: operation.dispatch_command_sha256,
    provider_request_body_sha256: operation.provider_request_body_sha256,
  };
}

const CHILD_SOURCE = String.raw`
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { PersistentGatewayLedger } from "./evaluation/live-shadow-boundary/gateway-ledger.ts";
const c = JSON.parse(readFileSync(process.argv.at(-1), "utf8"));
let ledger;
try {
  ledger = PersistentGatewayLedger.openExisting({
    database_path: c.database_path,
    ledger_secret: Buffer.from(c.ledger_secret_hex, "hex"),
    profile: c.profile,
    boot_session_id: c.boot_session_id,
    now: () => c.now_ms,
    mode: c.mode,
    expected_fencing_token: c.expected_fencing_token,
  });
  if (c.action === "claim") {
    ledger.claimBeforeSend(c.claim);
    process.stdout.write(JSON.stringify({ ok: true }));
  } else {
    const r = ledger.createIpcAdapter({
      collector_public_key: createPublicKey(c.collector_public_key_pem),
      gateway_public_key: createPublicKey(c.gateway_public_key_pem),
      authority_public_key: createPublicKey(c.authority_public_key_pem),
      anchor_public_key: createPublicKey(c.anchor_public_key_pem),
      expected_anchor_service_profile: c.expected_anchor_service_profile,
    }).reserveChallenge({
      challenge_request: c.challenge_request,
      trusted_now_ms: c.now_ms,
    });
    const cp = ledger.close();
    ledger = null;
    process.stdout.write(JSON.stringify({ ok: true, gateway_sequence: r.gateway_sequence, checkpoint_gateway_sequence: cp.gateway_sequence }));
  }
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, code: error.code ?? error.message }));
} finally {
  try { ledger?.close(); } catch {}
}
`;

function runChild(configPath) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      "--experimental-strip-types", "--input-type=module", "-e", CHILD_SOURCE, configPath,
    ], { cwd: process.cwd(), windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code !== 0) return reject(new Error(`gateway_child_exit_${code}:${stderr}`));
      resolve(JSON.parse(stdout));
    });
  });
}
test("stable profile accepts varying policy and adapter persists unambiguous hashes", () => {
  withDirectory("gateway-adapter", (directory) => {
    const path = join(directory, "gateway.sqlite");
    const h = createHarness("adapter");
    initialize(path, h);
    h.state.now = 9_001;
    const ledger = open(path, h, "adapter");
    let first;
    let second;
    try {
      assert.equal(typeof ledger.issue, "undefined");
      first = reserveAndIssue(ledger, h, "first", { connect_timeout_ms: 4_000 });
      second = reserveAndIssue(ledger, h, "second", { connect_timeout_ms: 6_000 });
      assert.notEqual(first.issued.operation.policy_sha256, second.issued.operation.policy_sha256);
      assert.equal(first.reservation.gateway_sequence, 1);
      assert.equal(second.reservation.gateway_sequence, 2);
      assert.equal(first.issued.operation.challenge_request_sha256, sha256Canonical(first.pre.challengeRequest));
      assert.equal(first.issued.operation.challenge_sha256, sha256Canonical(first.challenge));
      assert.equal(first.issued.operation.dispatch_command_sha256, sha256Canonical(first.command));
      assert.equal(first.issued.operation.provider_request_body_sha256, sha256Bytes(first.issued.provider_request.body_bytes));
      assert.equal(first.issued.operation.runtime_manifest_sha256, sha256Canonical(h.fixture.runtime));
      assert.equal(first.issued.operation.context_sha256, sha256Canonical(first.pre.context));
      assert.equal(ledger.getChallengeReservation(1).state, "consumed");
      const capability = ledger.claimBeforeSend(claimBinding(first));
      assert.equal(ledger.complete(capability, {
        outcome: "success",
        network_attempts: 1,
        retry_count: 0,
        redirect_count: 0,
        response_sha256: hash("response:adapter"),
      }).state, "terminal");
    } finally {
      if (first) disposeRebuiltGatewayRequest(first.issued.provider_request);
      if (second) disposeRebuiltGatewayRequest(second.issued.provider_request);
      ledger.close();
    }

    const db = new DatabaseSync(path, { readOnly: true });
    try {
      const columns = db.prepare("PRAGMA table_info(gateway_operations)").all().map((row) => row.name);
      for (const name of [
        "challenge_request_sha256", "challenge_sha256", "dispatch_command_sha256",
        "provider_request_body_sha256", "policy_sha256", "runtime_manifest_sha256",
      ]) assert.ok(columns.includes(name));
      assert.ok(!columns.includes("request_sha256"));
      const meta = Object.fromEntries(
        db.prepare("SELECT key,value FROM gateway_meta").all().map((row) => [row.key, row.value]),
      );
      assert.equal(meta.runtime_policy_sha256, h.profile.runtime_policy_sha256);
      assert.equal(meta.gateway_build_sha256, h.profile.gateway_build_sha256);
      assert.equal(meta.gateway_sequence, "2");
    } finally {
      db.close();
    }
  });
});

test("exact verified command and matching reservation are mandatory and single-use", () => {
  withDirectory("gateway-binding", (directory) => {
    const path = join(directory, "gateway.sqlite");
    const h = createHarness("binding");
    initialize(path, h);
    h.state.now = 9_001;
    const ledger = open(path, h, "binding");
    let issued;
    try {
      const prepared = reserveOnly(ledger, h, "exact");
      const correct = h.finishCommand(prepared.pre, prepared.reservation);
      h.state.now = correct.trustedNow;
      const wrongAuthority = generateKeyPairSync("ed25519");
      const wrongTrustAdapter = ledger.createIpcAdapter({
        collector_public_key: h.collectorKeys.publicKey,
        gateway_public_key: h.gatewayKeys.publicKey,
        authority_public_key: wrongAuthority.publicKey,
        anchor_public_key: h.fixture.anchorKeys.publicKey,
        expected_anchor_service_profile: "offline_simulator",
      });
      expectCode(() => wrongTrustAdapter.issueVerifiedDispatch({
        verified_dispatch_command: correct.verified,
        attachment_frame: correct.frame,
        compiled_identity: correct.compiledIdentity,
        trusted_now_ms: h.state.now,
      }), "gateway_ipc_profile_mismatch");
      assert.throws(() => prepared.adapter.issueVerifiedDispatch({
        verified_dispatch_command: structuredClone(correct.verified),
        attachment_frame: correct.frame,
        compiled_identity: correct.compiledIdentity,
        trusted_now_ms: h.state.now,
      }), /ipc_verified_dispatch_capability_required/);
      assert.equal(ledger.getChallengeReservation(prepared.reservation.gateway_sequence).state, "reserved");

      const wrong = h.finishCommand(prepared.pre, prepared.reservation, {
        gateway_sequence: prepared.reservation.gateway_sequence + 100,
      });
      h.state.now = wrong.trustedNow;
      expectCode(() => prepared.adapter.issueVerifiedDispatch({
        verified_dispatch_command: wrong.verified,
        attachment_frame: wrong.frame,
        compiled_identity: wrong.compiledIdentity,
        trusted_now_ms: h.state.now,
      }), "gateway_reservation_missing");

      h.state.now = correct.trustedNow;
      issued = prepared.adapter.issueVerifiedDispatch({
        verified_dispatch_command: correct.verified,
        attachment_frame: correct.frame,
        compiled_identity: correct.compiledIdentity,
        trusted_now_ms: h.state.now,
      });
      expectCode(() => prepared.adapter.issueVerifiedDispatch({
        verified_dispatch_command: correct.verified,
        attachment_frame: correct.frame,
        compiled_identity: correct.compiledIdentity,
        trusted_now_ms: h.state.now,
      }), "gateway_reservation_not_consumable");
    } finally {
      if (issued) disposeRebuiltGatewayRequest(issued.provider_request);
      ledger.close();
    }
  });
});

test("normal close and confirmed-dead recovery cancel reserved challenges", () => {
  withDirectory("gateway-reservation-lifecycle", (directory) => {
    const path = join(directory, "gateway.sqlite");
    const h = createHarness("reservation-lifecycle");
    initialize(path, h);
    h.state.now = 9_001;
    const first = open(path, h, "lifecycle-first");
    const reserved = reserveOnly(first, h, "reserved");
    first.close();

    h.state.now += 1;
    const second = open(path, h, "lifecycle-second");
    assert.equal(second.getChallengeReservation(reserved.reservation.gateway_sequence).state, "cancelled");
    const next = reserveOnly(second, h, "next");
    assert.equal(next.reservation.gateway_sequence, 2);
    second.close();

    h.state.now += 1;
    const dead = open(path, h, "lifecycle-dead");
    const deadReservation = reserveOnly(dead, h, "dead-reserved");
    h.state.now += 1;
    PersistentGatewayLedger.recoverConfirmedDead({
      database_path: path,
      ledger_secret: h.secret,
      profile: h.profile,
      dead_boot_session_id: identifier("boot", "lifecycle-dead"),
      recovery_id: identifier("recovery", "lifecycle-dead"),
      confirmation: "confirmed_dead",
      now: () => h.state.now,
    });
    expectCode(() => dead.close(), "gateway_stale_boot_session");
    h.state.now += 1;
    const recovered = open(path, h, "lifecycle-after-recovery");
    assert.equal(recovered.getChallengeReservation(deadReservation.reservation.gateway_sequence).state, "cancelled");
    recovered.close();
  });
});

test("claimed work recovers conservatively and expired claim cannot revive", () => {
  withDirectory("gateway-terminal-safety", (directory) => {
    const path = join(directory, "gateway.sqlite");
    const h = createHarness("terminal-safety");
    initialize(path, h);
    h.state.now = 9_001;
    const dead = open(path, h, "terminal-dead");
    const claimed = reserveAndIssue(dead, h, "claimed");
    disposeRebuiltGatewayRequest(claimed.issued.provider_request);
    dead.claimBeforeSend(claimBinding(claimed));
    h.state.now += 1;
    PersistentGatewayLedger.recoverConfirmedDead({
      database_path: path,
      ledger_secret: h.secret,
      profile: h.profile,
      dead_boot_session_id: identifier("boot", "terminal-dead"),
      recovery_id: identifier("recovery", "terminal-dead"),
      confirmation: "confirmed_dead",
      now: () => h.state.now,
    });
    expectCode(() => dead.close(), "gateway_stale_boot_session");

    h.state.now += 1;
    const next = open(path, h, "terminal-next");
    const expiring = reserveAndIssue(next, h, "expiring");
    disposeRebuiltGatewayRequest(expiring.issued.provider_request);
    assert.equal(next.getOperation(claimed.issued.operation.operation_id).state, "unknown_after_crash");
    h.state.now = expiring.command.payload.expires_at_ms;
    expectCode(() => next.claimBeforeSend(claimBinding(expiring)), "gateway_operation_expired");
    assert.equal(next.getOperation(expiring.issued.operation.operation_id).state, "expired_before_send");
    h.state.now -= 1;
    assert.equal(next.getOperation(expiring.issued.operation.operation_id).state, "expired_before_send");
    expectCode(() => next.claimBeforeSend(claimBinding(expiring)), "gateway_clock_rollback_detected");
    h.state.now = expiring.command.payload.expires_at_ms + 1;
    next.close();
  });
});
test("profile, projection, and external checkpoint reject substitution or rollback", () => {
  withDirectory("gateway-integrity", (directory) => {
    const h = createHarness("integrity");
    const wrongPath = join(directory, "wrong.sqlite");
    initialize(wrongPath, h);
    expectCode(() => PersistentGatewayLedger.openExisting({
      database_path: wrongPath,
      ledger_secret: Buffer.alloc(32, 7),
      profile: h.profile,
      boot_session_id: identifier("boot", "wrong-secret"),
    }), "gateway_identity_hmac_invalid");
    expectCode(() => PersistentGatewayLedger.openExisting({
      database_path: wrongPath,
      ledger_secret: h.secret,
      profile: { ...h.profile, runtime_policy_sha256: hash("wrong-runtime-policy") },
      boot_session_id: identifier("boot", "wrong-profile"),
    }), "gateway_identity_mismatch");

    const tamperPath = join(directory, "tamper.sqlite");
    initialize(tamperPath, h);
    const tamper = new DatabaseSync(tamperPath, { readOnly: false });
    try {
      tamper.prepare("UPDATE gateway_meta SET value='99' WHERE key='gateway_sequence'").run();
    } finally {
      tamper.close();
    }
    expectCode(() => open(tamperPath, h, "projection-tamper"), "gateway_projection_hmac_invalid");

    const path = join(directory, "rollback.sqlite");
    const snapshot = join(directory, "old.sqlite");
    const r = createHarness("rollback");
    initialize(path, r);
    r.state.now = 9_001;
    const first = open(path, r, "rollback-first");
    const one = reserveAndIssue(first, r, "one");
    disposeRebuiltGatewayRequest(one.issued.provider_request);
    first.close();
    checkpointWal(path);
    copyFileSync(path, snapshot);

    r.state.now += 1;
    const second = open(path, r, "rollback-second");
    const two = reserveAndIssue(second, r, "two");
    disposeRebuiltGatewayRequest(two.issued.provider_request);
    const latest = second.close();
    assert.equal(latest.gateway_sequence, 2);
    checkpointWal(path);
    copyFileSync(snapshot, path);
    r.state.now += 1;
    expectCode(() => open(path, r, "rollback-third", {
      minimum_checkpoint: latest,
    }), "gateway_checkpoint_rollback_detected");
  });
});

test("joined process is read-only and sequence stays unique across process boots", async () => {
  const directory = mkdtempSync(join(tmpdir(), "checkback-gateway-process-"));
  const path = join(directory, "gateway.sqlite");
  const h = createHarness("process");
  let primary;
  try {
    initialize(path, h);
    h.state.now = 9_001;
    primary = open(path, h, "process-primary");
    const issued = reserveAndIssue(primary, h, "primary");
    disposeRebuiltGatewayRequest(issued.issued.provider_request);
    const joinConfig = join(directory, "join.json");
    writeFileSync(joinConfig, JSON.stringify({
      database_path: path,
      ledger_secret_hex: h.secret.toString("hex"),
      profile: h.profile,
      boot_session_id: identifier("boot", "process-primary"),
      now_ms: h.state.now,
      mode: "join_active",
      expected_fencing_token: primary.checkpoint().fencing_token,
      action: "claim",
      claim: claimBinding(issued),
    }), { mode: 0o600 });
    assert.deepEqual(await runChild(joinConfig), {
      ok: false,
      code: "gateway_mutation_requires_owner",
    });

    const nextPre = h.makePreChallenge("child-reservation");
    const firstSequence = issued.reservation.gateway_sequence;
    primary.close();
    primary = null;
    const reserveConfig = join(directory, "reserve.json");
    writeFileSync(reserveConfig, JSON.stringify({
      database_path: path,
      ledger_secret_hex: h.secret.toString("hex"),
      profile: h.profile,
      boot_session_id: identifier("boot", "process-child"),
      now_ms: nextPre.base + 150,
      mode: "activate",
      action: "reserve",
      collector_public_key_pem: h.collectorKeys.publicKey.export({ type: "spki", format: "pem" }),
      gateway_public_key_pem: h.gatewayKeys.publicKey.export({ type: "spki", format: "pem" }),
      authority_public_key_pem: h.authorityKeys.publicKey.export({ type: "spki", format: "pem" }),
      anchor_public_key_pem: h.fixture.anchorKeys.publicKey.export({ type: "spki", format: "pem" }),
      expected_anchor_service_profile: "offline_simulator",
      challenge_request: nextPre.challengeRequest,
    }), { mode: 0o600 });
    const childReservation = await runChild(reserveConfig);
    assert.equal(childReservation.ok, true);
    assert.equal(childReservation.gateway_sequence, firstSequence + 1);
    assert.equal(childReservation.checkpoint_gateway_sequence, childReservation.gateway_sequence);
  } finally {
    try { primary?.close(); } catch {}
    rmSync(directory, { recursive: true, force: true });
  }
});

test("boundary stays offline and uses durable SQLite settings", () => {
  const source = readFileSync("evaluation/live-shadow-boundary/gateway-ledger.ts", "utf8");
  assert.doesNotMatch(source, /node:(?:http|https|http2|net|tls|dns|dgram)|process\.env|\bfetch\s*\(/);
  for (const pragma of [
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=FULL",
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=10000",
  ]) assert.match(source, new RegExp(pragma));
  assert.match(source, /gateway_challenge_reservations/);
  assert.doesNotMatch(source, /\brequest_sha256\b/);
});