import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import {
  createIpcAttachmentDescriptor,
  createIpcDispatchContext,
  encodeCanonicalAttachmentFrame,
  IPC_MAX_REQUEST_BODY_BYTES,
  IPC_SIGNATURE_DOMAINS,
  IpcAttachmentDescriptorSchema,
  IpcDispatchContextSchema,
  IpcGatewayResultPayloadSchema,
  parseCanonicalAttachmentFrame,
  parseVerifiedIpcDispatchAttachmentFrame,
  signIpcAuthorityDispatchTicket,
  signIpcChallenge,
  signIpcChallengeRequest,
  signIpcDispatchCommand,
  signIpcGatewayResult,
  verifyIpcChallenge,
  verifyIpcChallengeRequest,
  verifyIpcDispatchCommand,
  verifyIpcGatewayResult,
} from "../evaluation/live-shadow-boundary/ipc-contracts.ts";
import {
  disposeRebuiltGatewayRequest,
  GATEWAY_PROVIDER_REQUEST_TEMPLATE_SHA256,
  rebuildVerifiedGatewayRequest,
} from "../evaluation/live-shadow-boundary/gateway-request-rebuilder.ts";
import {
  canonicalJson,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
  signCanonicalEd25519,
} from "../evaluation/live-shadow/crypto.ts";
import {
  remoteAnchorSignedRequestSha256,
  signRemoteAnchorReceipt,
  signRemoteAnchorRequest,
} from "../evaluation/live-shadow-boundary/remote-anchor-contracts.ts";
import {
  createLiveContractFixture,
  fixtureHash,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

function createBundle(options = {}) {
  const fixture =
    options.fixture ??
    createLiveContractFixture({
      count: 1,
      request_template_sha256: GATEWAY_PROVIDER_REQUEST_TEMPLATE_SHA256,
    });
  const collectorKeys = options.collectorKeys ?? generateKeyPairSync("ed25519");
  const gatewayKeys = options.gatewayKeys ?? generateKeyPairSync("ed25519");
  const authorityKeys = options.authorityKeys ?? generateKeyPairSync("ed25519");
  const operationLabel = options.operationLabel ?? "operation-a";
  const operationId = fixtureId("op", operationLabel);
  const now = fixture.consent.created_at_ms;
  const intent = {
    schema_version: "checkback.live-shadow.dispatch-intent.v1",
    authority_registry_id: fixture.registryId,
    anchor_realm_id: fixture.realmId,
    authorization_id: fixture.consent.authorization_id,
    authorization_fingerprint_sha256:
      fixture.plan.authorization_fingerprint_sha256,
    execution_id: fixture.plan.execution_id,
    media_scope_id: fixture.plan.media_scope_id,
    pair_commitment_hmac_sha256:
      fixture.plan.pair_commitment_hmac_sha256,
    slot: "flash",
    ordinal: 2,
    operation_id: operationId,
    request_commitment_hmac_sha256: fixtureHash(`request-commit-${operationLabel}`),
    runtime_manifest_sha256: fixture.plan.runtime_manifest_sha256,
    created_at_ms: now,
    expires_at_ms: fixture.plan.expires_at_ms,
  };
  const requestBytes =
    options.requestBytes ??
    Buffer.from(
      canonicalJson({
        model: fixture.runtime.models.flash,
        max_tokens: 2200,
        response_format: { type: "json_object" },
        enable_thinking: false,
        vl_high_resolution_images: true,
        stream: false,
        messages: [
          { role: "system", content: "verifier-prompt-fixture" },
          {
            role: "user",
            content: [
              { type: "text", text: "Synthetic reference" },
              {
                type: "image_url",
                image_url: { url: "data:image/jpeg;base64,UjE=" },
              },
              { type: "text", text: "Synthetic comparison" },
              {
                type: "image_url",
                image_url: { url: "data:image/jpeg;base64,QzE=" },
              },
            ],
          },
        ],
      }),
      "utf8",
    );
  const responseBytes = Buffer.from(
    canonicalJson({ id: "synthetic-response", choices: [] }),
    "utf8",
  );
  const requestBody = createIpcAttachmentDescriptor("request_body", requestBytes);
  const responseBody = createIpcAttachmentDescriptor(
    "response_body",
    responseBytes,
  );
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
    connect_timeout_ms: 5_000,
    total_timeout_ms: fixture.runtime.timeouts_ms.flash,
    max_request_body_bytes: 1024 * 1024,
    max_response_body_bytes: 1024 * 1024,
    resolved_destination_policy_sha256: fixtureHash("destination-policy"),
    tls_policy_sha256: fixtureHash("tls-policy"),
    gateway_build_sha256: fixture.runtime.gateway_build_sha256,
    runtime_policy_sha256: fixture.runtime.runtime_policy_sha256,
  };
  const sessionId = fixtureId("session", `session-${operationLabel}`);
  const checkpointBefore = {
    registry_sequence: "10",
    registry_head_sha256: fixtureHash("remote-head-before"),
    active_session_id: sessionId,
    fencing_token: "3",
    session_lease_expires_at_ms: String(now + 50_000),
  };
  const anchorRequest = signRemoteAnchorRequest(authorityKeys.privateKey, {
    schema_version: "checkback.live-shadow.remote-anchor-request.v1",
    anchor_realm_id: fixture.realmId,
    expected_service_profile: "offline_simulator",
    authority_registry_id: fixture.registryId,
    authority_key_id: publicKeyId(authorityKeys.publicKey),
    request_id: fixtureId("anchorreq", `request-${operationLabel}`),
    idempotency_key: fixtureId("anchorop", `operation-${operationLabel}`),
    request_nonce_hex: fixtureHash(`anchor-nonce-${operationLabel}`),
    operation: "consume_slot",
    issued_at_ms: String(now),
    expires_at_ms: String(now + 5_000),
    expected_checkpoint: checkpointBefore,
    body: {
      operation: "consume_slot",
      session_id: sessionId,
      fencing_token: "3",
      intent,
    },
  });
  const checkpointAfter = {
    registry_sequence: "11",
    registry_head_sha256: fixtureHash("remote-head-after"),
    active_session_id: sessionId,
    fencing_token: "3",
    session_lease_expires_at_ms: String(now + 50_000),
  };
  const anchorReceiptEnvelope = signRemoteAnchorReceipt(
    fixture.anchorKeys.privateKey,
    {
      schema_version: "checkback.live-shadow.remote-anchor-receipt.v1",
      anchor_mode: "remote_service",
      service_profile: "offline_simulator",
      anchor_realm_id: fixture.realmId,
      anchor_epoch_id: fixtureId("anchorepoch", "anchor-epoch-a"),
      anchor_key_id: fixture.runtime.anchor_key_id,
      authority_registry_id: fixture.registryId,
      authority_key_id: publicKeyId(authorityKeys.publicKey),
      request_id: anchorRequest.payload.request_id,
      idempotency_key: anchorRequest.payload.idempotency_key,
      request_nonce_sha256: sha256Bytes(
        anchorRequest.payload.request_nonce_hex,
      ),
      signed_request_sha256: remoteAnchorSignedRequestSha256(anchorRequest),
      operation: "consume_slot",
      decision: "committed",
      error_code: null,
      anchor_time: {
        unix_ms: String(now + 50),
        source_id: "synthetic-trusted-clock",
        epoch_id: fixtureId("timeepoch", "time-epoch-a"),
        max_error_ms: "1",
      },
      global_sequence: "11",
      previous_registry_head_sha256:
        checkpointBefore.registry_head_sha256,
      registry_head_sha256: checkpointAfter.registry_head_sha256,
      object_key_sha256: sha256Canonical(intent),
      checkpoint_after: checkpointAfter,
    },
  );
  const anchorReceiptBytes = Buffer.from(
    canonicalJson(anchorReceiptEnvelope),
    "utf8",
  );
  const anchorReceipt = createIpcAttachmentDescriptor(
    "anchor_receipt",
    anchorReceiptBytes,
  );
  const authorityTicket = signIpcAuthorityDispatchTicket(
    authorityKeys.privateKey,
    {
      schema_version:
        "checkback.live-shadow-boundary.authority-dispatch-ticket.v1",
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
      issued_at_ms: now + 60,
      expires_at_ms: now + 9_000,
    },
  );
  const context = createIpcDispatchContext({
    signed_authority_ticket: authorityTicket,
    authority_public_key: authorityKeys.publicKey,
  });
  const challengeRequest = signIpcChallengeRequest(collectorKeys.privateKey, {
    schema_version: "checkback.live-shadow-boundary.challenge-request.v1",
    challenge_request_id: fixtureId(
      "challenge_request",
      `request-${operationLabel}`,
    ),
    collector_nonce: fixtureId("nonce", `collector-${operationLabel}`),
    context,
    created_at_ms: now + 100,
    expires_at_ms: now + 20_000,
  });
  const challenge = signIpcChallenge(gatewayKeys.privateKey, {
    schema_version: "checkback.live-shadow-boundary.challenge.v1",
    challenge_id: fixtureId("challenge", operationLabel),
    challenge_request_id: challengeRequest.payload.challenge_request_id,
    challenge_request_sha256: sha256Canonical(challengeRequest),
    gateway_boot_id: fixtureId("boot", "gateway-boot-a"),
    gateway_sequence: 7,
    challenge_nonce: fixtureId("nonce", `gateway-${operationLabel}`),
    use_policy: "single_use",
    max_dispatch_commands: 1,
    context,
    issued_at_ms: now + 200,
    expires_at_ms: now + 10_000,
  });
  const command = signIpcDispatchCommand(collectorKeys.privateKey, {
    schema_version: "checkback.live-shadow-boundary.dispatch-command.v1",
    dispatch_command_id: fixtureId("command", operationLabel),
    challenge_request_sha256: sha256Canonical(challengeRequest),
    challenge_id: challenge.payload.challenge_id,
    challenge_sha256: sha256Canonical(challenge),
    gateway_boot_id: challenge.payload.gateway_boot_id,
    gateway_sequence: challenge.payload.gateway_sequence,
    context,
    authority_ticket: authorityTicket,
    remote_anchor_request: anchorRequest,
    remote_anchor_receipt: anchorReceiptEnvelope,
    dispatch_intent: intent,
    created_at_ms: now + 300,
    expires_at_ms: now + 9_000,
  });
  const result = signIpcGatewayResult(gatewayKeys.privateKey, {
    schema_version: "checkback.live-shadow-boundary.gateway-result.v1",
    gateway_result_id: fixtureId("result", operationLabel),
    challenge_request_sha256: sha256Canonical(challengeRequest),
    challenge_sha256: sha256Canonical(challenge),
    dispatch_command_id: command.payload.dispatch_command_id,
    dispatch_command_sha256: sha256Canonical(command),
    gateway_boot_id: challenge.payload.gateway_boot_id,
    gateway_sequence: challenge.payload.gateway_sequence,
    context,
    outcome: "provider_response",
    network_attempts: 1,
    retry_count: 0,
    redirect_count: 0,
    request_body: requestBody,
    response_body: responseBody,
    provider_status_code: 200,
    started_at_ms: now + 400,
    completed_at_ms: now + 500,
  });
  return {
    fixture,
    collectorKeys,
    gatewayKeys,
    authorityKeys,
    intent,
    policy,
    context,
    authorityTicket,
    anchorRequest,
    anchorReceiptEnvelope,
    challengeRequest,
    challenge,
    command,
    result,
    anchorReceiptBytes,
    requestBytes,
    responseBytes,
    anchorReceipt,
    requestBody,
    responseBody,
    now,
  };
}

function trustOptions(bundle) {
  return {
    collector_public_key: bundle.collectorKeys.publicKey,
    gateway_public_key: bundle.gatewayKeys.publicKey,
    authority_public_key: bundle.authorityKeys.publicKey,
    anchor_public_key: bundle.fixture.anchorKeys.publicKey,
    expected_anchor_service_profile: "offline_simulator",
  };
}

test("Phase19B IPC v1 verifies the complete four-signature chain", () => {
  const bundle = createBundle();
  assert.deepEqual(
    verifyIpcChallengeRequest(
      bundle.collectorKeys.publicKey,
      bundle.challengeRequest,
      bundle.now + 150,
    ),
    bundle.challengeRequest,
  );
  assert.deepEqual(
    verifyIpcChallenge(bundle.gatewayKeys.publicKey, bundle.challenge, {
      ...trustOptions(bundle),
      challenge_request: bundle.challengeRequest,
      now_ms: bundle.now + 250,
    }),
    bundle.challenge,
  );
  assert.deepEqual(
    verifyIpcDispatchCommand(bundle.collectorKeys.publicKey, bundle.command, {
      ...trustOptions(bundle),
      challenge_request: bundle.challengeRequest,
      challenge: bundle.challenge,
      now_ms: bundle.now + 350,
    }),
    bundle.command,
  );
  assert.deepEqual(
    verifyIpcGatewayResult(bundle.gatewayKeys.publicKey, bundle.result, {
      ...trustOptions(bundle),
      challenge_request: bundle.challengeRequest,
      challenge: bundle.challenge,
      dispatch_command: bundle.command,
    }),
    bundle.result,
  );
  assert.equal(bundle.result.payload.network_attempts, 1);
  assert.equal(bundle.result.payload.retry_count, 0);
  assert.equal(bundle.result.payload.redirect_count, 0);
});

test("all four objects reject unknown fields and policy widening", () => {
  const bundle = createBundle();
  assert.throws(() =>
    signIpcChallengeRequest(bundle.collectorKeys.privateKey, {
      ...bundle.challengeRequest.payload,
      extra: true,
    }),
  );
  assert.throws(() =>
    signIpcChallenge(bundle.gatewayKeys.privateKey, {
      ...bundle.challenge.payload,
      context: {
        ...bundle.context,
        policy: { ...bundle.policy, max_retries: 1 },
      },
    }),
  );
  assert.throws(() =>
    signIpcDispatchCommand(bundle.collectorKeys.privateKey, {
      ...bundle.command.payload,
      extra: "not allowed",
    }),
  );
  assert.throws(() =>
    signIpcGatewayResult(bundle.gatewayKeys.privateKey, {
      ...bundle.result.payload,
      context: {
        ...bundle.context,
        policy: { ...bundle.policy, redirect_policy: "follow" },
      },
    }),
  );
});

test("signer key IDs and all four signature domains are role-separated", () => {
  const bundle = createBundle();
  const other = generateKeyPairSync("ed25519");
  assert.throws(
    () =>
      signIpcChallengeRequest(other.privateKey, bundle.challengeRequest.payload),
    /ipc_collector_signer_key_mismatch/,
  );
  assert.throws(
    () =>
      verifyIpcChallengeRequest(
        other.publicKey,
        bundle.challengeRequest,
        bundle.now + 150,
      ),
    /ipc_challenge_request_signer_key_mismatch/,
  );
  const wrongDomain = {
    ...bundle.challengeRequest,
    signature_base64: signCanonicalEd25519(
      bundle.collectorKeys.privateKey,
      IPC_SIGNATURE_DOMAINS.challenge,
      bundle.challengeRequest.payload,
    ),
  };
  assert.throws(
    () =>
      verifyIpcChallengeRequest(
        bundle.collectorKeys.publicKey,
        wrongDomain,
        bundle.now + 150,
      ),
    /ipc_challenge_request_signature_invalid/,
  );
  assert.notEqual(
    IPC_SIGNATURE_DOMAINS.challenge_request,
    IPC_SIGNATURE_DOMAINS.dispatch_command,
  );
  assert.notEqual(
    IPC_SIGNATURE_DOMAINS.challenge,
    IPC_SIGNATURE_DOMAINS.gateway_result,
  );
});

test("challenge request, challenge, and command expire at the exact boundary", () => {
  const bundle = createBundle();
  assert.throws(
    () =>
      verifyIpcChallengeRequest(
        bundle.collectorKeys.publicKey,
        bundle.challengeRequest,
        bundle.challengeRequest.payload.expires_at_ms,
      ),
    /expired_or_not_yet_valid/,
  );
  assert.throws(
    () =>
      verifyIpcChallenge(bundle.gatewayKeys.publicKey, bundle.challenge, {
        ...trustOptions(bundle),
        challenge_request: bundle.challengeRequest,
        now_ms: bundle.challenge.payload.expires_at_ms,
      }),
    /expired_or_not_yet_valid/,
  );
  assert.throws(
    () =>
      verifyIpcDispatchCommand(bundle.collectorKeys.publicKey, bundle.command, {
        ...trustOptions(bundle),
        challenge_request: bundle.challengeRequest,
        challenge: bundle.challenge,
        now_ms: bundle.command.payload.expires_at_ms,
      }),
    /expired_or_not_yet_valid/,
  );
});

test("challenge boot, sequence, request digest, and operation cannot cross-bind", () => {
  const bundle = createBundle();
  const otherOperation = createBundle({
    fixture: bundle.fixture,
    collectorKeys: bundle.collectorKeys,
    gatewayKeys: bundle.gatewayKeys,
    authorityKeys: bundle.authorityKeys,
    operationLabel: "operation-b",
  });
  assert.throws(
    () =>
      verifyIpcChallenge(bundle.gatewayKeys.publicKey, otherOperation.challenge, {
        ...trustOptions(bundle),
        challenge_request: bundle.challengeRequest,
        now_ms: bundle.now + 250,
      }),
    /ipc_challenge_request_binding_mismatch/,
  );
  assert.throws(
    () =>
      verifyIpcDispatchCommand(bundle.collectorKeys.publicKey, bundle.command, {
        ...trustOptions(bundle),
        challenge_request: bundle.challengeRequest,
        challenge: otherOperation.challenge,
        now_ms: bundle.now + 350,
      }),
    /ipc_(challenge_request_binding|dispatch_chain_binding)_mismatch/,
  );
  assert.throws(
    () =>
      verifyIpcGatewayResult(bundle.gatewayKeys.publicKey, bundle.result, {
        ...trustOptions(bundle),
        challenge_request: bundle.challengeRequest,
        challenge: bundle.challenge,
        dispatch_command: otherOperation.command,
      }),
    /ipc_(dispatch_chain_binding|gateway_result_chain_binding)_mismatch/,
  );
  assert.throws(() =>
    signIpcChallenge(bundle.gatewayKeys.privateKey, {
      ...bundle.challenge.payload,
      gateway_sequence: 0,
    }),
  );
  assert.throws(() =>
    signIpcChallenge(bundle.gatewayKeys.privateKey, {
      ...bundle.challenge.payload,
      max_dispatch_commands: 2,
    }),
  );
});

test("dispatch context binds exact intent fields, canonical hash, and byte length", () => {
  const bundle = createBundle();
  assert.equal(
    bundle.context.dispatch_intent_sha256,
    fixtureHash(canonicalJson(bundle.intent)),
  );
  assert.equal(
    bundle.context.dispatch_intent_byte_length,
    Buffer.byteLength(canonicalJson(bundle.intent), "utf8"),
  );
  assert.throws(() =>
    signIpcDispatchCommand(bundle.collectorKeys.privateKey, {
      ...bundle.command.payload,
      dispatch_intent: {
        ...bundle.intent,
        operation_id: fixtureId("op", "substituted"),
      },
    }),
  );
  assert.throws(() =>
    signIpcDispatchCommand(bundle.collectorKeys.privateKey, {
      ...bundle.command.payload,
      created_at_ms: bundle.intent.expires_at_ms,
      expires_at_ms: bundle.intent.expires_at_ms + 1,
    }),
  );
  assert.throws(() =>
    IpcDispatchContextSchema.parse({
      ...bundle.context,
      policy_sha256: fixtureHash("wrong-policy"),
    }),
  );
  assert.throws(() =>
    IpcDispatchContextSchema.parse({
      ...bundle.context,
      request_body: {
        ...bundle.requestBody,
        byte_length: bundle.policy.max_request_body_bytes + 1,
      },
    }),
  );
});

test("canonical attachment frames preserve exact bytes independent of input order", () => {
  const bundle = createBundle();
  const reverse = encodeCanonicalAttachmentFrame([
    { descriptor: bundle.requestBody, bytes: bundle.requestBytes },
    { descriptor: bundle.anchorReceipt, bytes: bundle.anchorReceiptBytes },
  ]);
  const forward = encodeCanonicalAttachmentFrame([
    { descriptor: bundle.anchorReceipt, bytes: bundle.anchorReceiptBytes },
    { descriptor: bundle.requestBody, bytes: bundle.requestBytes },
  ]);
  assert.deepEqual(reverse, forward);
  const parsed = parseCanonicalAttachmentFrame(forward, [
    bundle.requestBody,
    bundle.anchorReceipt,
  ]);
  assert.deepEqual(
    parsed.map((item) => item.descriptor.name),
    ["anchor_receipt", "request_body"],
  );
  assert.deepEqual(Buffer.from(parsed[0].bytes), bundle.anchorReceiptBytes);
  assert.deepEqual(Buffer.from(parsed[1].bytes), bundle.requestBytes);
});

test("attachment parser rejects tamper, wrong length/hash, trailing bytes, and caps", () => {
  const bundle = createBundle();
  const frame = encodeCanonicalAttachmentFrame([
    { descriptor: bundle.requestBody, bytes: bundle.requestBytes },
  ]);
  const tampered = new Uint8Array(frame);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(
    () => parseCanonicalAttachmentFrame(tampered, [bundle.requestBody]),
    /ipc_attachment_bytes_mismatch/,
  );
  const trailing = Buffer.concat([Buffer.from(frame), Buffer.from([0])]);
  assert.throws(
    () => parseCanonicalAttachmentFrame(trailing, [bundle.requestBody]),
    /ipc_attachment_frame_trailing_bytes/,
  );
  assert.throws(
    () =>
      parseCanonicalAttachmentFrame(frame, [
        { ...bundle.requestBody, sha256: fixtureHash("wrong-body") },
      ]),
    /ipc_attachment_bytes_mismatch/,
  );
  assert.throws(() =>
    IpcAttachmentDescriptorSchema.parse({
      ...bundle.requestBody,
      byte_length: IPC_MAX_REQUEST_BODY_BYTES + 1,
    }),
  );
  const oversizedClaim = new Uint8Array(frame);
  const bodyLengthOffset = 12 + 1 + "request_body".length;
  new DataView(
    oversizedClaim.buffer,
    oversizedClaim.byteOffset,
    oversizedClaim.byteLength,
  ).setUint32(bodyLengthOffset, 0xffffffff, false);
  assert.throws(
    () => parseCanonicalAttachmentFrame(oversizedClaim, [bundle.requestBody]),
    /ipc_attachment_frame_item_too_large/,
  );
});

test("gateway results bind exact request and response with one attempt and zero retry/redirect", () => {
  const bundle = createBundle();
  for (const mutation of [
    { network_attempts: 2 },
    { retry_count: 1 },
    { redirect_count: 1 },
    {
      request_body: {
        ...bundle.requestBody,
        sha256: fixtureHash("different-request"),
      },
    },
    {
      completed_at_ms:
        bundle.result.payload.started_at_ms +
        bundle.policy.total_timeout_ms +
        1,
    },
  ]) {
    assert.throws(() =>
      IpcGatewayResultPayloadSchema.parse({
        ...bundle.result.payload,
        ...mutation,
      }),
    );
  }
  assert.throws(() =>
    signIpcGatewayResult(bundle.gatewayKeys.privateKey, {
      ...bundle.result.payload,
      outcome: "transport_failure",
      provider_status_code: null,
    }),
  );
  const emptyResponse = createIpcAttachmentDescriptor(
    "response_body",
    new Uint8Array(0),
  );
  const rejected = signIpcGatewayResult(bundle.gatewayKeys.privateKey, {
    ...bundle.result.payload,
    gateway_result_id: fixtureId("result", "pre-send"),
    outcome: "pre_send_rejected",
    network_attempts: 0,
    provider_status_code: null,
    response_body: emptyResponse,
  });
  assert.equal(rejected.payload.network_attempts, 0);
  assert.equal(rejected.payload.response_body.byte_length, 0);
});

test("signed payload and attachment mutation are independently detected", () => {
  const bundle = createBundle();
  assert.throws(() =>
    verifyIpcGatewayResult(
      bundle.gatewayKeys.publicKey,
      {
        ...bundle.result,
        payload: {
          ...bundle.result.payload,
          completed_at_ms: bundle.result.payload.completed_at_ms + 1,
        },
      },
      {
        ...trustOptions(bundle),
        challenge_request: bundle.challengeRequest,
        challenge: bundle.challenge,
        dispatch_command: bundle.command,
      },
    ),
  );
  assert.throws(() =>
    encodeCanonicalAttachmentFrame([
      {
        descriptor: bundle.responseBody,
        bytes: Buffer.from("not-the-signed-response", "utf8"),
      },
    ]),
  );
});

function malleateBase64PadBits(value) {
  assert.match(value, /^[A-Za-z0-9+/]{86}==$/);
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const index = value.length - 3;
  const canonical = alphabet.indexOf(value[index]);
  assert.notEqual(canonical, -1);
  const replacement = alphabet[(canonical & 0b110000) | 1];
  return `${value.slice(0, index)}${replacement}==`;
}

test("signature Base64 pad bits must use one canonical text encoding", () => {
  const bundle = createBundle();
  const malleatedSignature = malleateBase64PadBits(
    bundle.challengeRequest.signature_base64,
  );
  assert.deepEqual(
    Buffer.from(malleatedSignature, "base64"),
    Buffer.from(bundle.challengeRequest.signature_base64, "base64"),
  );
  assert.throws(() =>
    verifyIpcChallengeRequest(
      bundle.collectorKeys.publicKey,
      {
        ...bundle.challengeRequest,
        signature_base64: malleatedSignature,
      },
      bundle.now + 150,
    ),
  );
  assert.throws(() =>
    signIpcDispatchCommand(bundle.collectorKeys.privateKey, {
      ...bundle.command.payload,
      remote_anchor_receipt: {
        ...bundle.anchorReceiptEnvelope,
        signature_base64: malleateBase64PadBits(
          bundle.anchorReceiptEnvelope.signature_base64,
        ),
      },
    }),
  );
});

test("dispatch verification recursively rejects a forged gateway challenge", () => {
  const bundle = createBundle();
  const forgedChallenge = {
    ...bundle.challenge,
    signature_base64: Buffer.alloc(64, 7).toString("base64"),
  };
  const collectorSignedCommand = signIpcDispatchCommand(
    bundle.collectorKeys.privateKey,
    {
      ...bundle.command.payload,
      challenge_sha256: sha256Canonical(forgedChallenge),
    },
  );
  assert.throws(
    () =>
      verifyIpcDispatchCommand(
        bundle.collectorKeys.publicKey,
        collectorSignedCommand,
        {
          ...trustOptions(bundle),
          challenge_request: bundle.challengeRequest,
          challenge: forgedChallenge,
          now_ms: bundle.now + 350,
        },
      ),
    /ipc_challenge_signature_invalid/,
  );
});

test("pinned authority, anchor, and service profile are mandatory", () => {
  const bundle = createBundle();
  const otherAuthority = generateKeyPairSync("ed25519");
  const otherAnchor = generateKeyPairSync("ed25519");
  assert.throws(() =>
    verifyIpcDispatchCommand(bundle.collectorKeys.publicKey, bundle.command, {
      ...trustOptions(bundle),
      authority_public_key: otherAuthority.publicKey,
      challenge_request: bundle.challengeRequest,
      challenge: bundle.challenge,
      now_ms: bundle.now + 350,
    }),
  );
  assert.throws(() =>
    verifyIpcDispatchCommand(bundle.collectorKeys.publicKey, bundle.command, {
      ...trustOptions(bundle),
      anchor_public_key: otherAnchor.publicKey,
      challenge_request: bundle.challengeRequest,
      challenge: bundle.challenge,
      now_ms: bundle.now + 350,
    }),
  );
  assert.throws(
    () =>
      verifyIpcDispatchCommand(bundle.collectorKeys.publicKey, bundle.command, {
        ...trustOptions(bundle),
        expected_anchor_service_profile: "production_external",
        challenge_request: bundle.challengeRequest,
        challenge: bundle.challenge,
        now_ms: bundle.now + 350,
      }),
    /ipc_remote_anchor_service_profile_mismatch/,
  );
});

test("authority ticket prevents request-body and runtime-policy substitution", () => {
  const bundle = createBundle();
  const substitutedBytes = Buffer.from(
    canonicalJson({ model: "unauthorized-model", messages: [] }),
    "utf8",
  );
  const substitutedDescriptor = createIpcAttachmentDescriptor(
    "request_body",
    substitutedBytes,
  );
  const substitutedContext = IpcDispatchContextSchema.parse({
    ...bundle.context,
    request_body: substitutedDescriptor,
  });
  assert.throws(() =>
    signIpcDispatchCommand(bundle.collectorKeys.privateKey, {
      ...bundle.command.payload,
      context: substitutedContext,
    }),
  );
  const driftedPolicy = {
    ...bundle.policy,
    model_id: bundle.fixture.runtime.models.plus,
  };
  assert.throws(() =>
    signIpcAuthorityDispatchTicket(bundle.authorityKeys.privateKey, {
      ...bundle.authorityTicket.payload,
      policy: driftedPolicy,
      policy_sha256: sha256Canonical(driftedPolicy),
    }),
  );
  assert.throws(() =>
    IpcDispatchContextSchema.parse({
      ...bundle.context,
      gateway_key_id: bundle.context.collector_key_id,
    }),
  );
});

test("attachment parsing requires a verified complete-chain capability", () => {
  const bundle = createBundle();
  const frame = encodeCanonicalAttachmentFrame([
    { descriptor: bundle.anchorReceipt, bytes: bundle.anchorReceiptBytes },
    { descriptor: bundle.requestBody, bytes: bundle.requestBytes },
  ]);
  assert.throws(
    () => parseVerifiedIpcDispatchAttachmentFrame(bundle.command, frame, bundle.now + 350),
    /ipc_verified_dispatch_capability_required/,
  );
  const verified = verifyIpcDispatchCommand(
    bundle.collectorKeys.publicKey,
    bundle.command,
    {
      ...trustOptions(bundle),
      challenge_request: bundle.challengeRequest,
      challenge: bundle.challenge,
      now_ms: bundle.now + 350,
    },
  );
  const parsed = parseVerifiedIpcDispatchAttachmentFrame(verified, frame, bundle.now + 350);
  assert.deepEqual(Buffer.from(parsed.request_body_bytes), bundle.requestBytes);
  assert.deepEqual(
    Buffer.from(parsed.anchor_receipt_bytes),
    bundle.anchorReceiptBytes,
  );
  verified.payload.context.operation_id = fixtureId("op", "mutated-after-verify");
  assert.throws(
    () => parseVerifiedIpcDispatchAttachmentFrame(verified, frame, bundle.now + 350),
    /ipc_verified_dispatch_capability_required/,
  );
});

function verifiedCommandAndFrame(bundle) {
  const verified = verifyIpcDispatchCommand(
    bundle.collectorKeys.publicKey,
    bundle.command,
    {
      ...trustOptions(bundle),
      challenge_request: bundle.challengeRequest,
      challenge: bundle.challenge,
      now_ms: bundle.now + 350,
    },
  );
  const frame = encodeCanonicalAttachmentFrame([
    { descriptor: bundle.anchorReceipt, bytes: bundle.anchorReceiptBytes },
    { descriptor: bundle.requestBody, bytes: bundle.requestBytes },
  ]);
  return { verified, frame };
}

function compiledIdentity(bundle, overrides = {}) {
  return {
    schema_version:
      "checkback.live-shadow-boundary.gateway-compiled-identity.v1",
    gateway_build_sha256: bundle.fixture.runtime.gateway_build_sha256,
    runtime_policy_sha256: bundle.fixture.runtime.runtime_policy_sha256,
    request_template_sha256: bundle.fixture.runtime.request_template_sha256,
    response_schema_sha256: bundle.fixture.runtime.response_schema_sha256,
    preprocessing_config_sha256:
      bundle.fixture.runtime.preprocessing_config_sha256,
    ...overrides,
  };
}

test("gateway rebuilds only a verified canonical provider request", () => {
  const bundle = createBundle();
  const { verified, frame } = verifiedCommandAndFrame(bundle);
  const rebuilt = rebuildVerifiedGatewayRequest({
    verified_dispatch_command: verified,
    attachment_frame: frame,
    trusted_now_ms: bundle.now + 350,
    compiled_identity: compiledIdentity(bundle),
  });
  try {
    assert.equal(rebuilt.transport, "https");
    assert.equal(rebuilt.host, bundle.policy.host);
    assert.equal(rebuilt.path, bundle.policy.path);
    assert.equal(rebuilt.redirect_policy, "deny");
    assert.equal(rebuilt.proxy_policy, "deny");
    assert.equal(rebuilt.max_network_attempts, 1);
    assert.equal(rebuilt.max_retries, 0);
    assert.deepEqual(rebuilt.body_bytes, bundle.requestBytes);
    assert.equal(rebuilt.body_sha256, sha256Bytes(bundle.requestBytes));
  } finally {
    disposeRebuiltGatewayRequest(rebuilt);
  }
  assert.ok(rebuilt.body_bytes.every((value) => value === 0));
  assert.throws(
    () =>
      rebuildVerifiedGatewayRequest({
        verified_dispatch_command: structuredClone(bundle.command),
        attachment_frame: frame,
        trusted_now_ms: bundle.now + 350,
        compiled_identity: compiledIdentity(bundle),
      }),
    /ipc_verified_dispatch_capability_required/,
  );
});

test("gateway refuses non-canonical JSON even when Authority signed its bytes", () => {
  const seed = createBundle();
  const bundle = createBundle({
    fixture: seed.fixture,
    collectorKeys: seed.collectorKeys,
    gatewayKeys: seed.gatewayKeys,
    authorityKeys: seed.authorityKeys,
    operationLabel: "noncanonical-wire-json",
    requestBytes: Buffer.concat([seed.requestBytes, Buffer.from(" ", "utf8")]),
  });
  const { verified, frame } = verifiedCommandAndFrame(bundle);
  assert.throws(
    () =>
      rebuildVerifiedGatewayRequest({
        verified_dispatch_command: verified,
        attachment_frame: frame,
        trusted_now_ms: bundle.now + 350,
        compiled_identity: compiledIdentity(bundle),
      }),
    /gateway_request_body_not_canonical/,
  );
});

test("gateway refuses remote image URLs, noncanonical base64, and runtime drift", () => {
  const seed = createBundle();
  const base = JSON.parse(seed.requestBytes.toString("utf8"));
  const cases = [
    {
      label: "remote-image",
      mutate(body) {
        body.messages[1].content[1].image_url.url = "https://example.invalid/a.jpg";
      },
      pattern: /inline canonical JPEG\/PNG\/WebP data URLs/,
    },
    {
      label: "base64-pad-bits",
      mutate(body) {
        body.messages[1].content[1].image_url.url = "data:image/jpeg;base64,UjF=";
      },
      pattern: /non-canonical or out of bounds/,
    },
    {
      label: "token-drift",
      mutate(body) {
        body.max_tokens = 2199;
      },
      pattern: /gateway_request_runtime_binding_mismatch/,
    },
  ];
  for (const item of cases) {
    const body = structuredClone(base);
    item.mutate(body);
    const bundle = createBundle({
      fixture: seed.fixture,
      collectorKeys: seed.collectorKeys,
      gatewayKeys: seed.gatewayKeys,
      authorityKeys: seed.authorityKeys,
      operationLabel: item.label,
      requestBytes: Buffer.from(canonicalJson(body), "utf8"),
    });
    const { verified, frame } = verifiedCommandAndFrame(bundle);
    assert.throws(
      () =>
        rebuildVerifiedGatewayRequest({
          verified_dispatch_command: verified,
          attachment_frame: frame,
          trusted_now_ms: bundle.now + 350,
          compiled_identity: compiledIdentity(bundle),
        }),
      item.pattern,
    );
  }
});

test("gateway compiled build identity is pinned before body access", () => {
  const bundle = createBundle();
  const { verified, frame } = verifiedCommandAndFrame(bundle);
  assert.throws(
    () =>
      rebuildVerifiedGatewayRequest({
        verified_dispatch_command: verified,
        attachment_frame: frame,
        trusted_now_ms: bundle.now + 350,
        compiled_identity: compiledIdentity(bundle, {
          gateway_build_sha256: fixtureHash("other-gateway-build"),
        }),
      }),
    /gateway_compiled_identity_mismatch/,
  );
  assert.equal(
    bundle.fixture.runtime.request_template_sha256,
    GATEWAY_PROVIDER_REQUEST_TEMPLATE_SHA256,
  );
  assert.throws(
    () =>
      rebuildVerifiedGatewayRequest({
        verified_dispatch_command: verified,
        attachment_frame: frame,
        trusted_now_ms: bundle.now + 350,
        compiled_identity: compiledIdentity(bundle, {
          request_template_sha256: fixtureHash("untrusted-template"),
        }),
      }),
    /gateway_compiled_identity_mismatch/,
  );
});

test("dispatch command cannot outlive its Authority ticket", () => {
  const bundle = createBundle();
  const shortTicket = signIpcAuthorityDispatchTicket(
    bundle.authorityKeys.privateKey,
    {
      ...bundle.authorityTicket.payload,
      expires_at_ms: bundle.now + 250,
    },
  );
  const shortContext = createIpcDispatchContext({
    signed_authority_ticket: shortTicket,
    authority_public_key: bundle.authorityKeys.publicKey,
  });
  assert.throws(
    () =>
      signIpcDispatchCommand(bundle.collectorKeys.privateKey, {
        ...bundle.command.payload,
        context: shortContext,
        authority_ticket: shortTicket,
      }),
    /dispatch command exceeds the authority ticket window/,
  );
});
test("verified dispatch capability is rechecked at body-access time", () => {
  const bundle = createBundle();
  const { verified, frame } = verifiedCommandAndFrame(bundle);
  const expiredAt = Math.min(
    verified.payload.expires_at_ms,
    verified.payload.authority_ticket.payload.expires_at_ms,
  );
  assert.throws(
    () => parseVerifiedIpcDispatchAttachmentFrame(verified, frame, expiredAt),
    /ipc_verified_dispatch_expired_or_not_yet_valid/,
  );
  assert.throws(
    () =>
      rebuildVerifiedGatewayRequest({
        verified_dispatch_command: verified,
        attachment_frame: frame,
        trusted_now_ms: expiredAt,
        compiled_identity: compiledIdentity(bundle),
      }),
    /ipc_verified_dispatch_expired_or_not_yet_valid/,
  );
});
test("signed committed receipt object key must equal the dispatch intent hash", () => {
  const bundle = createBundle();
  const wrongReceipt = signRemoteAnchorReceipt(
    bundle.fixture.anchorKeys.privateKey,
    {
      ...bundle.anchorReceiptEnvelope.payload,
      object_key_sha256: fixtureHash("wrong-dispatch-object-key"),
    },
  );
  const wrongReceiptBytes = Buffer.from(canonicalJson(wrongReceipt), "utf8");
  const wrongReceiptDescriptor = createIpcAttachmentDescriptor(
    "anchor_receipt",
    wrongReceiptBytes,
  );
  const wrongTicket = signIpcAuthorityDispatchTicket(
    bundle.authorityKeys.privateKey,
    {
      ...bundle.authorityTicket.payload,
      remote_anchor_receipt_sha256: sha256Canonical(wrongReceipt),
      anchor_receipt: wrongReceiptDescriptor,
    },
  );
  const wrongContext = createIpcDispatchContext({
    signed_authority_ticket: wrongTicket,
    authority_public_key: bundle.authorityKeys.publicKey,
  });
  assert.throws(
    () =>
      signIpcDispatchCommand(bundle.collectorKeys.privateKey, {
        ...bundle.command.payload,
        context: wrongContext,
        authority_ticket: wrongTicket,
        remote_anchor_receipt: wrongReceipt,
      }),
    /committed remote consume receipt binding mismatch/,
  );
});