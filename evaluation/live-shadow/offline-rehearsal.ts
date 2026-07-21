import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LiveAuthorityRegistry } from "./authority-registry.ts";
import {
  signLiveConsent,
} from "./contracts.ts";
import {
  computeMediaPairCommitment,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
} from "./crypto.ts";
import { LocalAnchorStub } from "./local-anchor-stub.ts";
import { OfflineLiveShadowGateway } from "./offline-gateway.ts";

function opaqueId(prefix: string): string {
  return `${prefix}_${randomBytes(32).toString("hex")}`;
}

export async function runOfflineLiveShadowSafetyRehearsal() {
  const directory = mkdtempSync(join(tmpdir(), "checkback-live-safety-"));
  const anchorPath = join(directory, "offline-anchor.sqlite");
  const authorityPath = join(directory, "offline-authority.sqlite");
  const consentKeys = generateKeyPairSync("ed25519");
  const anchorKeys = generateKeyPairSync("ed25519");
  const authoritySecret = randomBytes(32);
  const registryId = opaqueId("registry");
  const realmId = opaqueId("realm");
  const authorizationId = opaqueId("auth");
  const executionId = opaqueId("exec");
  const mediaScopeId = opaqueId("scope");
  const createdAt = 10_000;
  let now = createdAt;
  const clock = () => now++;
  const runtime = {
    schema_version: "checkback.live-shadow.runtime.v1",
    run_mode: "live_shadow",
    provider_id: "aliyun_bailian_openai_compatible",
    endpoint: {
      transport: "https",
      host: "offline-fixture.cn-beijing.maas.aliyuncs.com",
      port: 443,
      path: "/compatible-mode/v1/chat/completions",
      redirect_policy: "deny",
      proxy_policy: "deny",
    },
    models: {
      primary: "offline-primary-fixture",
      flash: "offline-flash-fixture",
      plus: "offline-plus-fixture",
    },
    timeouts_ms: { primary: 1_000, flash: 1_000, plus: 1_000 },
    max_retries: 0,
    client_package: "checkback-offline-fake-gateway",
    client_version: "0.0.0-offline",
    primary_prompt_sha256: sha256Bytes("offline-primary-prompt"),
    verifier_prompt_sha256: sha256Bytes("offline-verifier-prompt"),
    request_template_sha256: sha256Bytes("offline-request-template"),
    response_schema_sha256: sha256Bytes("offline-response-schema"),
    preprocessing_config_sha256: sha256Bytes("offline-preprocessing"),
    collector_build_sha256: sha256Bytes("offline-collector-build"),
    gateway_build_sha256: sha256Bytes("offline-gateway-build"),
    runtime_policy_sha256: sha256Bytes("offline-runtime-policy"),
    authority_registry_id: registryId,
    anchor_realm_id: realmId,
    anchor_key_id: publicKeyId(anchorKeys.publicKey),
  };
  const beforeBytes = Buffer.from("offline-authorized-before", "utf8");
  const afterBytes = Buffer.from("offline-authorized-after", "utf8");
  const pairCommitment = computeMediaPairCommitment(authoritySecret, {
    before_bytes: beforeBytes,
    after_bytes: afterBytes,
    preprocessing_config_sha256: runtime.preprocessing_config_sha256,
  });
  const consent = {
    schema_version: "checkback.live-shadow.consent.v1",
    run_mode: "live_shadow",
    authorization_id: authorizationId,
    purpose: "checkback-isolated-live-shadow-evaluation",
    consent_ui_version: "offline-fixture-v1",
    consent_text_sha256: sha256Bytes("offline-consent-text"),
    consent_evidence_sha256: sha256Bytes("offline-consent-evidence"),
    provider_id: runtime.provider_id,
    provider_terms_document_sha256: sha256Bytes("offline-provider-document"),
    provider_terms_content_sha256: sha256Bytes("offline-provider-content"),
    anchor_realm_id: realmId,
    runtime_manifest_sha256: sha256Canonical(runtime),
    created_at_ms: createdAt,
    not_before_ms: createdAt,
    expires_at_ms: createdAt + 60_000,
    local_media_delete_by_ms: createdAt + 70_000,
    sanitized_record_delete_by_ms: createdAt + 80_000,
    max_executions: 1,
    calls_per_execution: 3,
    max_provider_calls: 3,
    max_retries: 0,
    call_slots: ["primary", "flash", "plus"],
    media_scopes: [
      {
        media_scope_id: mediaScopeId,
        pair_commitment_hmac_sha256: pairCommitment,
        preprocessing_config_sha256: runtime.preprocessing_config_sha256,
      },
    ],
    authorized_executions: [
      {
        execution_id: executionId,
        media_scope_id: mediaScopeId,
        pair_commitment_hmac_sha256: pairCommitment,
        call_slots: ["primary", "flash", "plus"],
      },
    ],
  };
  const signedConsent = signLiveConsent(consentKeys.privateKey, consent);
  const plan = {
    schema_version: "checkback.live-shadow.execution.v1",
    run_mode: "live_shadow",
    authorization_id: authorizationId,
    authorization_fingerprint_sha256: sha256Canonical(signedConsent),
    signed_consent_sha256: sha256Canonical(signedConsent),
    runtime_manifest_sha256: sha256Canonical(runtime),
    authority_registry_id: registryId,
    anchor_realm_id: realmId,
    execution_id: executionId,
    media_scope_id: mediaScopeId,
    pair_commitment_hmac_sha256: pairCommitment,
    created_at_ms: createdAt,
    expires_at_ms: consent.expires_at_ms,
    call_slots: ["primary", "flash", "plus"],
  };
  let anchor: LocalAnchorStub | undefined;
  let authority: LiveAuthorityRegistry | undefined;
  try {
    LocalAnchorStub.initialize({
      database_path: anchorPath,
      realm_id: realmId,
      private_key: anchorKeys.privateKey,
      public_key: anchorKeys.publicKey,
      now: clock,
    });
    anchor = LocalAnchorStub.openExisting({
      database_path: anchorPath,
      realm_id: realmId,
      private_key: anchorKeys.privateKey,
      public_key: anchorKeys.publicKey,
      now: clock,
    });
    LiveAuthorityRegistry.initialize({
      database_path: authorityPath,
      registry_id: registryId,
      authority_secret: authoritySecret,
      consent_public_key: consentKeys.publicKey,
      anchor_public_key: anchorKeys.publicKey,
      anchor,
      now: clock,
    });
    authority = LiveAuthorityRegistry.openExisting({
      database_path: authorityPath,
      expected_registry_id: registryId,
      authority_secret: authoritySecret,
      consent_public_key: consentKeys.publicKey,
      anchor_public_key: anchorKeys.publicKey,
      anchor,
      session_id: opaqueId("session"),
      now: clock,
    });
    authority.importAuthorization({
      signed_consent: signedConsent,
      runtime_manifest: runtime,
    });
    const gateway = new OfflineLiveShadowGateway({ authority });
    const outcomes = [];
    for (const slot of ["primary", "flash", "plus"] as const) {
      outcomes.push(
        await gateway.dispatch({
          execution_plan: plan,
          runtime_manifest: runtime,
          slot,
          operation_id: opaqueId("op"),
          media_pair: {
            before_bytes: beforeBytes,
            after_bytes: afterBytes,
          },
        }),
      );
    }
    const snapshot = gateway.snapshot();
    return Object.freeze({
      schema_version: "checkback.live-shadow.offline-safety-summary.v1",
      mode: "offline_stub" as const,
      provider: "fake_gateway" as const,
      network_calls: 0 as const,
      executions: 1,
      authorized_call_cap: 3,
      fake_send_attempts: snapshot.send_attempts,
      completed_results: outcomes.length,
      outcomes: Object.freeze(outcomes.map((item) => item.outcome)),
      real_model_ready: false as const,
    });
  } finally {
    try {
      authority?.close();
    } finally {
      try {
        anchor?.close();
      } finally {
        beforeBytes.fill(0);
        afterBytes.fill(0);
        authoritySecret.fill(0);
        rmSync(directory, { recursive: true, force: true });
      }
    }
  }
}
