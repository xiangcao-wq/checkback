import { createHash, generateKeyPairSync } from "node:crypto";
import {
  computeMediaPairCommitment,
  publicKeyId,
  sha256Canonical,
} from "../../evaluation/live-shadow/crypto.ts";
import {
  signLiveConsent,
} from "../../evaluation/live-shadow/contracts.ts";

export function fixtureHash(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function fixtureId(prefix, value) {
  return `${prefix}_${fixtureHash(value)}`;
}

export function createLiveContractFixture(options = {}) {
  const count = options.count ?? 2;
  const createdAt = options.created_at_ms ?? 10_000;
  const consentKeys = generateKeyPairSync("ed25519");
  const anchorKeys = generateKeyPairSync("ed25519");
  const authoritySecret = Buffer.alloc(32, 41);
  const registryId = fixtureId("registry", "registry-a");
  const realmId = fixtureId("realm", "anchor-realm-a");
  const runtime = {
    schema_version: "checkback.live-shadow.runtime.v1",
    run_mode: "live_shadow",
    provider_id: "aliyun_bailian_openai_compatible",
    endpoint: {
      transport: "https",
      host: "fixture.cn-beijing.maas.aliyuncs.com",
      port: 443,
      path: "/compatible-mode/v1/chat/completions",
      redirect_policy: "deny",
      proxy_policy: "deny",
    },
    models: {
      primary: "qwen-vl-primary-fixture",
      flash: "qwen-vl-flash-fixture",
      plus: "qwen-vl-plus-fixture",
    },
    timeouts_ms: { primary: 30_000, flash: 20_000, plus: 30_000 },
    max_retries: 0,
    client_package: "checkback-live-gateway",
    client_version: "0.0.0-offline",
    primary_prompt_sha256: fixtureHash("primary-prompt-fixture"),
    verifier_prompt_sha256: fixtureHash("verifier-prompt-fixture"),
    request_template_sha256:
      options.request_template_sha256 ?? fixtureHash("request-template-fixture"),
    response_schema_sha256: fixtureHash("response-schema-fixture"),
    preprocessing_config_sha256: fixtureHash("preprocessing-fixture"),
    collector_build_sha256: fixtureHash("collector-build-fixture"),
    gateway_build_sha256: fixtureHash("gateway-build-fixture"),
    runtime_policy_sha256: fixtureHash("runtime-policy-fixture"),
    authority_registry_id: registryId,
    anchor_realm_id: realmId,
    anchor_key_id: publicKeyId(anchorKeys.publicKey),
  };
  const mediaPairs = Array.from({ length: count }, (_, index) => ({
    before_bytes: Buffer.from(`AUTHORIZED_BEFORE_${index}`, "utf8"),
    after_bytes: Buffer.from(`AUTHORIZED_AFTER_${index}`, "utf8"),
  }));
  const mediaScopes = mediaPairs.map((pair, index) => ({
    media_scope_id: fixtureId("scope", `scope-${index}`),
    pair_commitment_hmac_sha256: computeMediaPairCommitment(
      authoritySecret,
      {
        ...pair,
        preprocessing_config_sha256: runtime.preprocessing_config_sha256,
      },
    ),
    preprocessing_config_sha256: runtime.preprocessing_config_sha256,
  }));
  const authorizedExecutions = mediaScopes.map((scope, index) => ({
    execution_id: fixtureId("exec", `execution-${index}`),
    media_scope_id: scope.media_scope_id,
    pair_commitment_hmac_sha256: scope.pair_commitment_hmac_sha256,
    call_slots: ["primary", "flash", "plus"],
  }));
  const consent = {
    schema_version: "checkback.live-shadow.consent.v1",
    run_mode: "live_shadow",
    authorization_id: fixtureId("auth", "authorization-a"),
    purpose: "checkback-isolated-live-shadow-evaluation",
    consent_ui_version: "consent-ui-v1",
    consent_text_sha256: fixtureHash("consent-text-fixture"),
    consent_evidence_sha256: fixtureHash("consent-evidence-fixture"),
    provider_id: runtime.provider_id,
    provider_terms_document_sha256: fixtureHash("provider-terms-document"),
    provider_terms_content_sha256: fixtureHash("provider-terms-content"),
    anchor_realm_id: realmId,
    runtime_manifest_sha256: sha256Canonical(runtime),
    created_at_ms: createdAt,
    not_before_ms: createdAt,
    expires_at_ms: createdAt + 60_000,
    local_media_delete_by_ms: createdAt + 70_000,
    sanitized_record_delete_by_ms: createdAt + 80_000,
    max_executions: count,
    calls_per_execution: 3,
    max_provider_calls: count * 3,
    max_retries: 0,
    call_slots: ["primary", "flash", "plus"],
    media_scopes: mediaScopes,
    authorized_executions: authorizedExecutions,
  };
  const signedConsent = signLiveConsent(consentKeys.privateKey, consent);
  const execution = authorizedExecutions[0];
  const plan = {
    schema_version: "checkback.live-shadow.execution.v1",
    run_mode: "live_shadow",
    authorization_id: consent.authorization_id,
    authorization_fingerprint_sha256: sha256Canonical(signedConsent),
    signed_consent_sha256: sha256Canonical(signedConsent),
    runtime_manifest_sha256: sha256Canonical(runtime),
    authority_registry_id: registryId,
    anchor_realm_id: realmId,
    execution_id: execution.execution_id,
    media_scope_id: execution.media_scope_id,
    pair_commitment_hmac_sha256: execution.pair_commitment_hmac_sha256,
    created_at_ms: createdAt,
    expires_at_ms: consent.expires_at_ms,
    call_slots: ["primary", "flash", "plus"],
  };
  return {
    anchorKeys,
    consentKeys,
    registryId,
    realmId,
    runtime,
    consent,
    signedConsent,
    plan,
    mediaPairs,
    authoritySecret,
  };
}
