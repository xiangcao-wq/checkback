import type { KeyObject } from "node:crypto";
import { z } from "zod";
import {
  publicKeyId,
  sha256Canonical,
  signCanonicalEd25519,
  verifyCanonicalEd25519,
} from "./crypto.ts";

const Hex64Schema = z.string().regex(/^[a-f0-9]{64}$/);
const Base64SignatureSchema = z
  .string()
  .regex(/^[A-Za-z0-9+/]{86}==$/);
const SafeIdentifierSchema = z
  .string()
  .min(1)
  .max(100)
  .regex(/^[A-Za-z0-9._-]+$/);
const HighEntropyIdentifierSchema = (prefix: string) =>
  z.string().regex(new RegExp(`^${prefix}_[a-f0-9]{64}$`));
const TimestampSchema = z.number().int().nonnegative();
const HostnameSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/)
  .refine((value) => value.endsWith(".maas.aliyuncs.com"), {
    message: "endpoint host must use the pinned Bailian service suffix",
  });

export const LIVE_CALL_SLOTS = Object.freeze([
  "primary",
  "flash",
  "plus",
] as const);

export const LiveCallSlotSchema = z.enum(LIVE_CALL_SLOTS);
export type LiveCallSlot = z.infer<typeof LiveCallSlotSchema>;

const ExactCallSlotsSchema = z
  .tuple([
    z.literal("primary"),
    z.literal("flash"),
    z.literal("plus"),
  ])
  .readonly();

const LiveMediaScopeSchema = z
  .object({
    media_scope_id: HighEntropyIdentifierSchema("scope"),
    pair_commitment_hmac_sha256: Hex64Schema,
    preprocessing_config_sha256: Hex64Schema,
  })
  .strict();

const LiveAuthorizedExecutionSchema = z
  .object({
    execution_id: HighEntropyIdentifierSchema("exec"),
    media_scope_id: HighEntropyIdentifierSchema("scope"),
    pair_commitment_hmac_sha256: Hex64Schema,
    call_slots: ExactCallSlotsSchema,
  })
  .strict();

export const LiveRuntimeManifestSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.runtime.v1"),
    run_mode: z.literal("live_shadow"),
    provider_id: z.literal("aliyun_bailian_openai_compatible"),
    endpoint: z
      .object({
        transport: z.literal("https"),
        host: HostnameSchema,
        port: z.literal(443),
        path: z.literal("/compatible-mode/v1/chat/completions"),
        redirect_policy: z.literal("deny"),
        proxy_policy: z.literal("deny"),
      })
      .strict(),
    models: z
      .object({
        primary: SafeIdentifierSchema,
        flash: SafeIdentifierSchema,
        plus: SafeIdentifierSchema,
      })
      .strict(),
    timeouts_ms: z
      .object({
        primary: z.number().int().min(1).max(300_000),
        flash: z.number().int().min(1).max(300_000),
        plus: z.number().int().min(1).max(300_000),
      })
      .strict(),
    max_retries: z.literal(0),
    client_package: SafeIdentifierSchema,
    client_version: SafeIdentifierSchema,
    primary_prompt_sha256: Hex64Schema,
    verifier_prompt_sha256: Hex64Schema,
    request_template_sha256: Hex64Schema,
    response_schema_sha256: Hex64Schema,
    preprocessing_config_sha256: Hex64Schema,
    collector_build_sha256: Hex64Schema,
    gateway_build_sha256: Hex64Schema,
    runtime_policy_sha256: Hex64Schema,
    authority_registry_id: HighEntropyIdentifierSchema("registry"),
    anchor_realm_id: HighEntropyIdentifierSchema("realm"),
    anchor_key_id: Hex64Schema,
  })
  .strict();

export type LiveRuntimeManifest = z.infer<typeof LiveRuntimeManifestSchema>;

export const LiveConsentGrantSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.consent.v1"),
    run_mode: z.literal("live_shadow"),
    authorization_id: HighEntropyIdentifierSchema("auth"),
    purpose: z.literal("checkback-isolated-live-shadow-evaluation"),
    consent_ui_version: SafeIdentifierSchema,
    consent_text_sha256: Hex64Schema,
    consent_evidence_sha256: Hex64Schema,
    provider_id: z.literal("aliyun_bailian_openai_compatible"),
    provider_terms_document_sha256: Hex64Schema,
    provider_terms_content_sha256: Hex64Schema,
    anchor_realm_id: HighEntropyIdentifierSchema("realm"),
    runtime_manifest_sha256: Hex64Schema,
    created_at_ms: TimestampSchema,
    not_before_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
    local_media_delete_by_ms: TimestampSchema,
    sanitized_record_delete_by_ms: TimestampSchema,
    max_executions: z.number().int().min(1).max(100),
    calls_per_execution: z.literal(3),
    max_provider_calls: z.number().int().min(3).max(300),
    max_retries: z.literal(0),
    call_slots: ExactCallSlotsSchema,
    media_scopes: z.array(LiveMediaScopeSchema).min(1).max(100),
    authorized_executions: z
      .array(LiveAuthorizedExecutionSchema)
      .min(1)
      .max(100),
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.not_before_ms < value.created_at_ms ||
      value.not_before_ms >= value.expires_at_ms
    ) {
      context.addIssue({
        code: "custom",
        path: ["not_before_ms"],
        message: "authorization validity window is invalid",
      });
    }
    if (
      value.local_media_delete_by_ms < value.expires_at_ms ||
      value.sanitized_record_delete_by_ms < value.local_media_delete_by_ms ||
      value.sanitized_record_delete_by_ms >
        value.created_at_ms + 30 * 24 * 60 * 60 * 1000
    ) {
      context.addIssue({
        code: "custom",
        path: ["sanitized_record_delete_by_ms"],
        message: "retention window is invalid",
      });
    }
    if (value.max_provider_calls !== value.max_executions * 3) {
      context.addIssue({
        code: "custom",
        path: ["max_provider_calls"],
        message: "provider call cap must equal 3N",
      });
    }
    if (
      value.media_scopes.length !== value.max_executions ||
      value.authorized_executions.length !== value.max_executions
    ) {
      context.addIssue({
        code: "custom",
        path: ["authorized_executions"],
        message: "authorization must pre-allocate exactly N scopes and executions",
      });
    }
    const scopeIds = value.media_scopes.map((item) => item.media_scope_id);
    const executionIds = value.authorized_executions.map(
      (item) => item.execution_id,
    );
    const executionScopeIds = value.authorized_executions.map(
      (item) => item.media_scope_id,
    );
    if (
      new Set(scopeIds).size !== scopeIds.length ||
      new Set(executionIds).size !== executionIds.length ||
      new Set(executionScopeIds).size !== executionScopeIds.length ||
      scopeIds.some((scopeId) => !executionScopeIds.includes(scopeId))
    ) {
      context.addIssue({
        code: "custom",
        path: ["authorized_executions"],
        message: "scope and execution IDs must be unique",
      });
    }
    const scopes = new Map(
      value.media_scopes.map((item) => [item.media_scope_id, item]),
    );
    for (const execution of value.authorized_executions) {
      const scope = scopes.get(execution.media_scope_id);
      if (
        !scope ||
        scope.pair_commitment_hmac_sha256 !==
          execution.pair_commitment_hmac_sha256
      ) {
        context.addIssue({
          code: "custom",
          path: ["authorized_executions"],
          message: "each execution must match one authorized media scope",
        });
        break;
      }
    }
  });

export type LiveConsentGrant = z.infer<typeof LiveConsentGrantSchema>;

export const LiveSignedConsentSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.signed-consent.v1"),
    payload: LiveConsentGrantSchema,
    signer_key_id: Hex64Schema,
    signature_base64: Base64SignatureSchema,
  })
  .strict();

export type LiveSignedConsent = z.infer<typeof LiveSignedConsentSchema>;

export const LiveExecutionPlanSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.execution.v1"),
    run_mode: z.literal("live_shadow"),
    authorization_id: HighEntropyIdentifierSchema("auth"),
    authorization_fingerprint_sha256: Hex64Schema,
    signed_consent_sha256: Hex64Schema,
    runtime_manifest_sha256: Hex64Schema,
    authority_registry_id: HighEntropyIdentifierSchema("registry"),
    anchor_realm_id: HighEntropyIdentifierSchema("realm"),
    execution_id: HighEntropyIdentifierSchema("exec"),
    media_scope_id: HighEntropyIdentifierSchema("scope"),
    pair_commitment_hmac_sha256: Hex64Schema,
    created_at_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
    call_slots: ExactCallSlotsSchema,
  })
  .strict();

export type LiveExecutionPlan = z.infer<typeof LiveExecutionPlanSchema>;

export const LiveDispatchIntentSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.dispatch-intent.v1"),
    authority_registry_id: HighEntropyIdentifierSchema("registry"),
    anchor_realm_id: HighEntropyIdentifierSchema("realm"),
    authorization_id: HighEntropyIdentifierSchema("auth"),
    authorization_fingerprint_sha256: Hex64Schema,
    execution_id: HighEntropyIdentifierSchema("exec"),
    media_scope_id: HighEntropyIdentifierSchema("scope"),
    pair_commitment_hmac_sha256: Hex64Schema,
    slot: LiveCallSlotSchema,
    ordinal: z.number().int().min(1).max(3),
    operation_id: HighEntropyIdentifierSchema("op"),
    request_commitment_hmac_sha256: Hex64Schema,
    runtime_manifest_sha256: Hex64Schema,
    created_at_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (LIVE_CALL_SLOTS[value.ordinal - 1] !== value.slot) {
      context.addIssue({
        code: "custom",
        path: ["ordinal"],
        message: "slot ordinal mismatch",
      });
    }
    if (value.expires_at_ms <= value.created_at_ms) {
      context.addIssue({
        code: "custom",
        path: ["expires_at_ms"],
        message: "dispatch intent must expire after creation",
      });
    }
  });

export type LiveDispatchIntent = z.infer<typeof LiveDispatchIntentSchema>;

export const LocalAnchorReceiptPayloadSchema = z
  .object({
    schema_version: z.literal("checkback.live-shadow.anchor-receipt.v1"),
    anchor_mode: z.literal("offline_local_stub"),
    anchor_realm_id: HighEntropyIdentifierSchema("realm"),
    anchor_key_id: Hex64Schema,
    authority_registry_id: HighEntropyIdentifierSchema("registry"),
    global_sequence: z.number().int().positive(),
    registry_sequence: z.number().int().positive(),
    previous_registry_head_sha256: Hex64Schema,
    registry_head_sha256: Hex64Schema,
    event_type: z.enum([
      "register_registry",
      "acquire_session",
      "claim_authorization",
      "consume_slot",
      "release_session",
    ]),
    object_key_sha256: Hex64Schema,
    session_id: HighEntropyIdentifierSchema("session").nullable(),
    fencing_token: z.number().int().nonnegative(),
    recorded_at_ms: TimestampSchema,
  })
  .strict();

export type LocalAnchorReceiptPayload = z.infer<
  typeof LocalAnchorReceiptPayloadSchema
>;

export const LocalAnchorReceiptSchema = z
  .object({
    payload: LocalAnchorReceiptPayloadSchema,
    signature_base64: Base64SignatureSchema,
  })
  .strict();

export type LocalAnchorReceipt = z.infer<typeof LocalAnchorReceiptSchema>;

export const LIVE_SIGNATURE_DOMAINS = Object.freeze({
  consent: "checkback.live-shadow.consent-signature.v1",
  anchor_receipt: "checkback.live-shadow.anchor-receipt-signature.v1",
});

export function signLiveConsent(
  privateKey: KeyObject,
  input: unknown,
): LiveSignedConsent {
  const payload = LiveConsentGrantSchema.parse(input);
  const envelope = {
    schema_version: "checkback.live-shadow.signed-consent.v1" as const,
    payload,
    signer_key_id: publicKeyId(privateKey),
    signature_base64: signCanonicalEd25519(
      privateKey,
      LIVE_SIGNATURE_DOMAINS.consent,
      payload,
    ),
  };
  return LiveSignedConsentSchema.parse(envelope);
}

export function verifyLiveConsent(
  publicKey: KeyObject,
  input: unknown,
): LiveSignedConsent {
  const envelope = LiveSignedConsentSchema.parse(input);
  if (envelope.signer_key_id !== publicKeyId(publicKey)) {
    throw new Error("consent_signer_key_mismatch");
  }
  if (
    !verifyCanonicalEd25519(
      publicKey,
      LIVE_SIGNATURE_DOMAINS.consent,
      envelope.payload,
      envelope.signature_base64,
    )
  ) {
    throw new Error("consent_signature_invalid");
  }
  return envelope;
}

export function signLocalAnchorReceipt(
  privateKey: KeyObject,
  input: unknown,
): LocalAnchorReceipt {
  const payload = LocalAnchorReceiptPayloadSchema.parse(input);
  if (payload.anchor_key_id !== publicKeyId(privateKey)) {
    throw new Error("anchor_signer_key_mismatch");
  }
  return LocalAnchorReceiptSchema.parse({
    payload,
    signature_base64: signCanonicalEd25519(
      privateKey,
      LIVE_SIGNATURE_DOMAINS.anchor_receipt,
      payload,
    ),
  });
}

export function verifyLocalAnchorReceipt(
  publicKey: KeyObject,
  input: unknown,
): LocalAnchorReceipt {
  const receipt = LocalAnchorReceiptSchema.parse(input);
  if (receipt.payload.anchor_key_id !== publicKeyId(publicKey)) {
    throw new Error("anchor_receipt_key_mismatch");
  }
  if (
    !verifyCanonicalEd25519(
      publicKey,
      LIVE_SIGNATURE_DOMAINS.anchor_receipt,
      receipt.payload,
      receipt.signature_base64,
    )
  ) {
    throw new Error("anchor_receipt_signature_invalid");
  }
  return receipt;
}

export function authorizeLiveExecution(input: {
  signed_consent: unknown;
  runtime_manifest: unknown;
  execution_plan: unknown;
  consent_public_key: KeyObject;
  now_ms: number;
}) {
  const signedConsent = verifyLiveConsent(
    input.consent_public_key,
    input.signed_consent,
  );
  const consent = signedConsent.payload;
  const runtime = LiveRuntimeManifestSchema.parse(input.runtime_manifest);
  const plan = LiveExecutionPlanSchema.parse(input.execution_plan);
  const now = TimestampSchema.parse(input.now_ms);
  const signedConsentSha256 = sha256Canonical(signedConsent);
  const runtimeSha256 = sha256Canonical(runtime);

  if (now < consent.not_before_ms || now >= consent.expires_at_ms) {
    throw new Error("authorization_outside_validity_window");
  }
  if (
    runtimeSha256 !== consent.runtime_manifest_sha256 ||
    plan.runtime_manifest_sha256 !== runtimeSha256
  ) {
    throw new Error("runtime_manifest_hash_mismatch");
  }
  if (
    runtime.provider_id !== consent.provider_id ||
    runtime.anchor_realm_id !== consent.anchor_realm_id ||
    runtime.authority_registry_id !== plan.authority_registry_id ||
    runtime.anchor_realm_id !== plan.anchor_realm_id
  ) {
    throw new Error("runtime_authority_binding_mismatch");
  }
  if (
    plan.authorization_id !== consent.authorization_id ||
    plan.signed_consent_sha256 !== signedConsentSha256 ||
    plan.authorization_fingerprint_sha256 !== signedConsentSha256 ||
    plan.expires_at_ms !== consent.expires_at_ms
  ) {
    throw new Error("execution_consent_binding_mismatch");
  }
  const execution = consent.authorized_executions.find(
    (item) => item.execution_id === plan.execution_id,
  );
  if (
    !execution ||
    execution.media_scope_id !== plan.media_scope_id ||
    execution.pair_commitment_hmac_sha256 !==
      plan.pair_commitment_hmac_sha256
  ) {
    throw new Error("execution_scope_not_authorized");
  }
  return { signed_consent: signedConsent, consent, runtime, plan };
}
