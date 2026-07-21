import type { KeyObject } from "node:crypto";
import { z } from "zod";
import {
  canonicalJson,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
  signCanonicalEd25519,
  verifyCanonicalEd25519,
} from "../live-shadow/crypto.ts";
import {
  LIVE_CALL_SLOTS,
  LiveCallSlotSchema,
  LiveDispatchIntentSchema,
  LiveRuntimeManifestSchema,
} from "../live-shadow/contracts.ts";
import {
  SignedRemoteAnchorReceiptSchema,
  SignedRemoteAnchorRequestSchema,
  remoteAnchorRequestTimeStatus,
  remoteAnchorSignedRequestSha256,
  verifyRemoteAnchorReceipt,
  verifyRemoteAnchorRequest,
} from "./remote-anchor-contracts.ts";
import { MAX_CANONICAL_PROVIDER_REQUEST_BODY_BYTES } from "./boundary-limits.ts";

const KiB = 1024;
const MiB = 1024 * KiB;

export const IPC_MAX_ANCHOR_RECEIPT_BYTES = 256 * KiB;
export const IPC_MAX_REQUEST_BODY_BYTES =
  MAX_CANONICAL_PROVIDER_REQUEST_BODY_BYTES;
export const IPC_MAX_RESPONSE_BODY_BYTES = 4 * MiB;
export const IPC_MAX_ATTACHMENT_FRAME_BYTES = 37 * MiB;
export const IPC_MAX_REQUEST_TTL_MS = 2 * 60 * 1000;
export const IPC_MAX_CHALLENGE_TTL_MS = 30 * 1000;
export const IPC_MAX_COMMAND_TTL_MS = 30 * 1000;

const FRAME_MAGIC = Buffer.from("CBIPCV1\0", "ascii");
const FRAME_HEADER_BYTES = FRAME_MAGIC.byteLength + 4;
const EMPTY_SHA256 = sha256Bytes(new Uint8Array(0));
const VERIFIED_DISPATCH_COMMANDS = new WeakMap<
  object,
  { canonical_sha256: string; not_before_ms: number; expires_at_ms: number }
>();

const Hex64Schema = z.string().regex(/^[a-f0-9]{64}$/);
const Base64SignatureSchema = z
  .string()
  .regex(/^[A-Za-z0-9+/]{86}==$/)
  .refine(
    (value) =>
      Buffer.from(value, "base64").byteLength === 64 &&
      Buffer.from(value, "base64").toString("base64") === value,
    { message: "Ed25519 signature base64 must be canonical" },
  );
const TimestampSchema = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER);
const PositiveSafeIntegerSchema = z
  .number()
  .int()
  .positive()
  .max(Number.MAX_SAFE_INTEGER);
const HighEntropyIdentifierSchema = (prefix: string) =>
  z.string().regex(new RegExp(`^${prefix}_[a-f0-9]{64}$`));
const SafeTokenSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._-]+$/);
const BailianHostnameSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/,
  )
  .refine((value) => value.endsWith(".maas.aliyuncs.com"), {
    message: "gateway endpoint must use the pinned Bailian suffix",
  });

export const IpcAttachmentNameSchema = z.enum([
  "anchor_receipt",
  "request_body",
  "response_body",
]);
export type IpcAttachmentName = z.infer<typeof IpcAttachmentNameSchema>;

export const IpcAttachmentDescriptorSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow-boundary.attachment.v1",
    ),
    name: IpcAttachmentNameSchema,
    media_type: z.literal("application/json"),
    byte_length: z.number().int().nonnegative(),
    sha256: Hex64Schema,
  })
  .strict()
  .superRefine((value, context) => {
    const limit = attachmentLimit(value.name);
    const minimum = value.name === "response_body" ? 0 : 1;
    if (value.byte_length < minimum || value.byte_length > limit) {
      context.addIssue({
        code: "custom",
        path: ["byte_length"],
        message: "attachment length is outside its fixed boundary",
      });
    }
    if (value.byte_length === 0 && value.sha256 !== EMPTY_SHA256) {
      context.addIssue({
        code: "custom",
        path: ["sha256"],
        message: "empty attachment digest mismatch",
      });
    }
  });

export type IpcAttachmentDescriptor = z.infer<
  typeof IpcAttachmentDescriptorSchema
>;

export const IpcGatewayPolicySchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow-boundary.gateway-policy.v1",
    ),
    provider_id: z.literal("aliyun_bailian_openai_compatible"),
    transport: z.literal("https"),
    host: BailianHostnameSchema,
    port: z.literal(443),
    path: z.literal("/compatible-mode/v1/chat/completions"),
    method: z.literal("POST"),
    request_content_type: z.literal("application/json"),
    redirect_policy: z.literal("deny"),
    proxy_policy: z.literal("deny"),
    max_network_attempts: z.literal(1),
    max_retries: z.literal(0),
    model_id: SafeTokenSchema,
    connect_timeout_ms: z.number().int().min(1).max(30_000),
    total_timeout_ms: z.number().int().min(1).max(300_000),
    max_request_body_bytes: z
      .number()
      .int()
      .min(1)
      .max(IPC_MAX_REQUEST_BODY_BYTES),
    max_response_body_bytes: z
      .number()
      .int()
      .min(1)
      .max(IPC_MAX_RESPONSE_BODY_BYTES),
    resolved_destination_policy_sha256: Hex64Schema,
    tls_policy_sha256: Hex64Schema,
    gateway_build_sha256: Hex64Schema,
    runtime_policy_sha256: Hex64Schema,
  })
  .strict()
  .superRefine((value, context) => {
    if (value.total_timeout_ms < value.connect_timeout_ms) {
      context.addIssue({
        code: "custom",
        path: ["total_timeout_ms"],
        message: "total timeout cannot be shorter than connect timeout",
      });
    }
  });

export type IpcGatewayPolicy = z.infer<typeof IpcGatewayPolicySchema>;
export const IpcAuthorityDispatchTicketPayloadSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow-boundary.authority-dispatch-ticket.v1",
    ),
    expected_anchor_service_profile: z.enum([
      "offline_simulator",
      "production_external",
    ]),
    collector_key_id: Hex64Schema,
    gateway_key_id: Hex64Schema,
    authority_key_id: Hex64Schema,
    anchor_key_id: Hex64Schema,
    dispatch_intent: LiveDispatchIntentSchema,
    runtime_manifest: LiveRuntimeManifestSchema,
    runtime_manifest_sha256: Hex64Schema,
    policy: IpcGatewayPolicySchema,
    policy_sha256: Hex64Schema,
    remote_anchor_request_sha256: Hex64Schema,
    remote_anchor_receipt_sha256: Hex64Schema,
    anchor_receipt: IpcAttachmentDescriptorSchema,
    request_body: IpcAttachmentDescriptorSchema,
    issued_at_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    validateWindow(
      value.issued_at_ms,
      value.expires_at_ms,
      IPC_MAX_REQUEST_TTL_MS,
      context,
      ["expires_at_ms"],
    );
    validateAuthorityTicket(value, context);
  });

export type IpcAuthorityDispatchTicketPayload = z.infer<
  typeof IpcAuthorityDispatchTicketPayloadSchema
>;

export const SignedIpcAuthorityDispatchTicketSchema = signedEnvelopeSchema(
  "checkback.live-shadow-boundary.signed-authority-dispatch-ticket.v1",
  IpcAuthorityDispatchTicketPayloadSchema,
);
export type SignedIpcAuthorityDispatchTicket = z.infer<
  typeof SignedIpcAuthorityDispatchTicketSchema
>;

export const IpcDispatchContextSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow-boundary.dispatch-context.v1",
    ),
    collector_key_id: Hex64Schema,
    gateway_key_id: Hex64Schema,
    authority_key_id: Hex64Schema,
    anchor_key_id: Hex64Schema,
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
    runtime_manifest_sha256: Hex64Schema,
    request_commitment_hmac_sha256: Hex64Schema,
    policy: IpcGatewayPolicySchema,
    policy_sha256: Hex64Schema,
    authority_ticket_sha256: Hex64Schema,
    dispatch_intent_sha256: Hex64Schema,
    dispatch_intent_byte_length: z.number().int().min(1).max(256 * KiB),
    anchor_receipt: IpcAttachmentDescriptorSchema,
    request_body: IpcAttachmentDescriptorSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (
      new Set([
        value.collector_key_id,
        value.gateway_key_id,
        value.authority_key_id,
        value.anchor_key_id,
      ]).size !== 4
    ) {
      context.addIssue({
        code: "custom",
        path: ["collector_key_id"],
        message: "collector, gateway, authority, and anchor keys must differ",
      });
    }
    if (LIVE_CALL_SLOTS[value.ordinal - 1] !== value.slot) {
      context.addIssue({
        code: "custom",
        path: ["ordinal"],
        message: "slot ordinal mismatch",
      });
    }
    if (value.policy_sha256 !== sha256Canonical(value.policy)) {
      context.addIssue({
        code: "custom",
        path: ["policy_sha256"],
        message: "gateway policy digest mismatch",
      });
    }
    if (value.anchor_receipt.name !== "anchor_receipt") {
      context.addIssue({
        code: "custom",
        path: ["anchor_receipt", "name"],
        message: "anchor receipt attachment name mismatch",
      });
    }
    if (value.request_body.name !== "request_body") {
      context.addIssue({
        code: "custom",
        path: ["request_body", "name"],
        message: "request body attachment name mismatch",
      });
    }
    if (
      value.request_body.byte_length > value.policy.max_request_body_bytes
    ) {
      context.addIssue({
        code: "custom",
        path: ["request_body", "byte_length"],
        message: "request body exceeds the signed gateway policy",
      });
    }
  });

export type IpcDispatchContext = z.infer<typeof IpcDispatchContextSchema>;

export const IpcChallengeRequestPayloadSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow-boundary.challenge-request.v1",
    ),
    challenge_request_id: HighEntropyIdentifierSchema("challenge_request"),
    collector_nonce: HighEntropyIdentifierSchema("nonce"),
    context: IpcDispatchContextSchema,
    created_at_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    validateWindow(
      value.created_at_ms,
      value.expires_at_ms,
      IPC_MAX_REQUEST_TTL_MS,
      context,
      ["expires_at_ms"],
    );
  });

export type IpcChallengeRequestPayload = z.infer<
  typeof IpcChallengeRequestPayloadSchema
>;

export const SignedIpcChallengeRequestSchema = signedEnvelopeSchema(
  "checkback.live-shadow-boundary.signed-challenge-request.v1",
  IpcChallengeRequestPayloadSchema,
);
export type SignedIpcChallengeRequest = z.infer<
  typeof SignedIpcChallengeRequestSchema
>;

export const IpcChallengePayloadSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow-boundary.challenge.v1",
    ),
    challenge_id: HighEntropyIdentifierSchema("challenge"),
    challenge_request_id: HighEntropyIdentifierSchema("challenge_request"),
    challenge_request_sha256: Hex64Schema,
    gateway_boot_id: HighEntropyIdentifierSchema("boot"),
    gateway_sequence: PositiveSafeIntegerSchema,
    challenge_nonce: HighEntropyIdentifierSchema("nonce"),
    use_policy: z.literal("single_use"),
    max_dispatch_commands: z.literal(1),
    context: IpcDispatchContextSchema,
    issued_at_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    validateWindow(
      value.issued_at_ms,
      value.expires_at_ms,
      IPC_MAX_CHALLENGE_TTL_MS,
      context,
      ["expires_at_ms"],
    );
  });

export type IpcChallengePayload = z.infer<typeof IpcChallengePayloadSchema>;

export const SignedIpcChallengeSchema = signedEnvelopeSchema(
  "checkback.live-shadow-boundary.signed-challenge.v1",
  IpcChallengePayloadSchema,
);
export type SignedIpcChallenge = z.infer<typeof SignedIpcChallengeSchema>;

export const IpcDispatchCommandPayloadSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow-boundary.dispatch-command.v1",
    ),
    dispatch_command_id: HighEntropyIdentifierSchema("command"),
    challenge_request_sha256: Hex64Schema,
    challenge_id: HighEntropyIdentifierSchema("challenge"),
    challenge_sha256: Hex64Schema,
    gateway_boot_id: HighEntropyIdentifierSchema("boot"),
    gateway_sequence: PositiveSafeIntegerSchema,
    context: IpcDispatchContextSchema,
    authority_ticket: SignedIpcAuthorityDispatchTicketSchema,
    remote_anchor_request: SignedRemoteAnchorRequestSchema,
    remote_anchor_receipt: SignedRemoteAnchorReceiptSchema,
    dispatch_intent: LiveDispatchIntentSchema,
    created_at_ms: TimestampSchema,
    expires_at_ms: TimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    validateWindow(
      value.created_at_ms,
      value.expires_at_ms,
      IPC_MAX_COMMAND_TTL_MS,
      context,
      ["expires_at_ms"],
    );
    validateIntentBinding(value.context, value.dispatch_intent, context);
    validateCommandProofBinding(value, context);
    if (
      value.created_at_ms < value.dispatch_intent.created_at_ms ||
      value.created_at_ms >= value.dispatch_intent.expires_at_ms ||
      value.expires_at_ms > value.dispatch_intent.expires_at_ms
    ) {
      context.addIssue({
        code: "custom",
        path: ["expires_at_ms"],
        message: "dispatch command exceeds the authority intent window",
      });
    }
    if (
      value.created_at_ms < value.authority_ticket.payload.issued_at_ms ||
      value.created_at_ms >= value.authority_ticket.payload.expires_at_ms ||
      value.expires_at_ms > value.authority_ticket.payload.expires_at_ms
    ) {
      context.addIssue({
        code: "custom",
        path: ["authority_ticket", "payload", "expires_at_ms"],
        message: "dispatch command exceeds the authority ticket window",
      });
    }
  });

export type IpcDispatchCommandPayload = z.infer<
  typeof IpcDispatchCommandPayloadSchema
>;

export const SignedIpcDispatchCommandSchema = signedEnvelopeSchema(
  "checkback.live-shadow-boundary.signed-dispatch-command.v1",
  IpcDispatchCommandPayloadSchema,
);
export type SignedIpcDispatchCommand = z.infer<
  typeof SignedIpcDispatchCommandSchema
>;

export const IpcGatewayResultPayloadSchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow-boundary.gateway-result.v1",
    ),
    gateway_result_id: HighEntropyIdentifierSchema("result"),
    challenge_request_sha256: Hex64Schema,
    challenge_sha256: Hex64Schema,
    dispatch_command_id: HighEntropyIdentifierSchema("command"),
    dispatch_command_sha256: Hex64Schema,
    gateway_boot_id: HighEntropyIdentifierSchema("boot"),
    gateway_sequence: PositiveSafeIntegerSchema,
    context: IpcDispatchContextSchema,
    outcome: z.enum([
      "provider_response",
      "transport_failure",
      "pre_send_rejected",
    ]),
    network_attempts: z.union([z.literal(0), z.literal(1)]),
    retry_count: z.literal(0),
    redirect_count: z.literal(0),
    request_body: IpcAttachmentDescriptorSchema,
    response_body: IpcAttachmentDescriptorSchema,
    provider_status_code: z.number().int().min(100).max(599).nullable(),
    started_at_ms: TimestampSchema,
    completed_at_ms: TimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (!sameCanonical(value.request_body, value.context.request_body)) {
      context.addIssue({
        code: "custom",
        path: ["request_body"],
        message: "gateway result request binding mismatch",
      });
    }
    if (value.response_body.name !== "response_body") {
      context.addIssue({
        code: "custom",
        path: ["response_body", "name"],
        message: "response body attachment name mismatch",
      });
    }
    if (
      value.response_body.byte_length > value.context.policy.max_response_body_bytes
    ) {
      context.addIssue({
        code: "custom",
        path: ["response_body", "byte_length"],
        message: "response body exceeds the signed gateway policy",
      });
    }
    if (value.completed_at_ms < value.started_at_ms) {
      context.addIssue({
        code: "custom",
        path: ["completed_at_ms"],
        message: "gateway result time order is invalid",
      });
    }
    if (
      value.completed_at_ms - value.started_at_ms >
      value.context.policy.total_timeout_ms
    ) {
      context.addIssue({
        code: "custom",
        path: ["completed_at_ms"],
        message: "gateway result exceeds the signed total timeout",
      });
    }
    if (value.outcome === "pre_send_rejected") {
      if (
        value.network_attempts !== 0 ||
        value.provider_status_code !== null ||
        value.response_body.byte_length !== 0 ||
        value.response_body.sha256 !== EMPTY_SHA256
      ) {
        context.addIssue({
          code: "custom",
          path: ["outcome"],
          message: "pre-send rejection must have no network or response bytes",
        });
      }
    } else if (value.network_attempts !== 1) {
      context.addIssue({
        code: "custom",
        path: ["network_attempts"],
        message: "post-send result requires exactly one network attempt",
      });
    }
    if (
      value.outcome === "provider_response" &&
      value.provider_status_code === null
    ) {
      context.addIssue({
        code: "custom",
        path: ["provider_status_code"],
        message: "provider response requires an HTTP status",
      });
    }
    if (
      value.outcome === "transport_failure" &&
      (value.provider_status_code !== null ||
        value.response_body.byte_length !== 0 ||
        value.response_body.sha256 !== EMPTY_SHA256)
    ) {
      context.addIssue({
        code: "custom",
        path: ["outcome"],
        message: "transport failure cannot claim provider response bytes",
      });
    }
  });

export type IpcGatewayResultPayload = z.infer<
  typeof IpcGatewayResultPayloadSchema
>;

export const SignedIpcGatewayResultSchema = signedEnvelopeSchema(
  "checkback.live-shadow-boundary.signed-gateway-result.v1",
  IpcGatewayResultPayloadSchema,
);
export type SignedIpcGatewayResult = z.infer<
  typeof SignedIpcGatewayResultSchema
>;

export const IPC_SIGNATURE_DOMAINS = Object.freeze({
  authority_ticket:
    "checkback.live-shadow-boundary.authority-dispatch-ticket-signature.v1",
  challenge_request:
    "checkback.live-shadow-boundary.challenge-request-signature.v1",
  challenge: "checkback.live-shadow-boundary.challenge-signature.v1",
  dispatch_command:
    "checkback.live-shadow-boundary.dispatch-command-signature.v1",
  gateway_result:
    "checkback.live-shadow-boundary.gateway-result-signature.v1",
});

export function createIpcAttachmentDescriptor(
  name: IpcAttachmentName,
  bytes: Uint8Array,
): IpcAttachmentDescriptor {
  assertBytes(bytes);
  const snapshot = new Uint8Array(bytes);
  return IpcAttachmentDescriptorSchema.parse({
    schema_version: "checkback.live-shadow-boundary.attachment.v1",
    name,
    media_type: "application/json",
    byte_length: snapshot.byteLength,
    sha256: sha256Bytes(snapshot),
  });
}

export function signIpcAuthorityDispatchTicket(
  privateKey: KeyObject,
  input: unknown,
): SignedIpcAuthorityDispatchTicket {
  const payload = IpcAuthorityDispatchTicketPayloadSchema.parse(input);
  requireRoleKey(privateKey, payload.authority_key_id, "authority");
  return SignedIpcAuthorityDispatchTicketSchema.parse({
    schema_version:
      "checkback.live-shadow-boundary.signed-authority-dispatch-ticket.v1",
    payload,
    signer_key_id: publicKeyId(privateKey),
    signature_algorithm: "Ed25519",
    signature_base64: signCanonicalEd25519(
      privateKey,
      IPC_SIGNATURE_DOMAINS.authority_ticket,
      payload,
    ),
  });
}

export function verifyIpcAuthorityDispatchTicket(
  publicKey: KeyObject,
  input: unknown,
): SignedIpcAuthorityDispatchTicket {
  const envelope = SignedIpcAuthorityDispatchTicketSchema.parse(input);
  verifyEnvelope(
    publicKey,
    envelope,
    IPC_SIGNATURE_DOMAINS.authority_ticket,
    envelope.payload.authority_key_id,
    "authority_ticket",
  );
  return envelope;
}

export function createIpcDispatchContext(input: {
  signed_authority_ticket: unknown;
  authority_public_key: KeyObject;
}): IpcDispatchContext {
  const ticket = verifyIpcAuthorityDispatchTicket(
    input.authority_public_key,
    input.signed_authority_ticket,
  );
  const payload = ticket.payload;
  const intent = payload.dispatch_intent;
  const intentBytes = Buffer.from(canonicalJson(intent), "utf8");
  return IpcDispatchContextSchema.parse({
    schema_version: "checkback.live-shadow-boundary.dispatch-context.v1",
    collector_key_id: payload.collector_key_id,
    gateway_key_id: payload.gateway_key_id,
    authority_key_id: payload.authority_key_id,
    anchor_key_id: payload.anchor_key_id,
    authority_registry_id: intent.authority_registry_id,
    anchor_realm_id: intent.anchor_realm_id,
    authorization_id: intent.authorization_id,
    authorization_fingerprint_sha256:
      intent.authorization_fingerprint_sha256,
    execution_id: intent.execution_id,
    media_scope_id: intent.media_scope_id,
    pair_commitment_hmac_sha256: intent.pair_commitment_hmac_sha256,
    slot: intent.slot,
    ordinal: intent.ordinal,
    operation_id: intent.operation_id,
    runtime_manifest_sha256: payload.runtime_manifest_sha256,
    request_commitment_hmac_sha256:
      intent.request_commitment_hmac_sha256,
    policy: payload.policy,
    policy_sha256: payload.policy_sha256,
    authority_ticket_sha256: sha256Canonical(ticket),
    dispatch_intent_sha256: sha256Bytes(intentBytes),
    dispatch_intent_byte_length: intentBytes.byteLength,
    anchor_receipt: payload.anchor_receipt,
    request_body: payload.request_body,
  });
}

export function signIpcChallengeRequest(
  privateKey: KeyObject,
  input: unknown,
): SignedIpcChallengeRequest {
  const payload = IpcChallengeRequestPayloadSchema.parse(input);
  requireRoleKey(privateKey, payload.context.collector_key_id, "collector");
  return SignedIpcChallengeRequestSchema.parse({
    schema_version:
      "checkback.live-shadow-boundary.signed-challenge-request.v1",
    payload,
    signer_key_id: publicKeyId(privateKey),
    signature_algorithm: "Ed25519",
    signature_base64: signCanonicalEd25519(
      privateKey,
      IPC_SIGNATURE_DOMAINS.challenge_request,
      payload,
    ),
  });
}

export function verifyIpcChallengeRequest(
  publicKey: KeyObject,
  input: unknown,
  nowMs: number,
): SignedIpcChallengeRequest {
  const envelope = SignedIpcChallengeRequestSchema.parse(input);
  verifyEnvelope(
    publicKey,
    envelope,
    IPC_SIGNATURE_DOMAINS.challenge_request,
    envelope.payload.context.collector_key_id,
    "challenge_request",
  );
  assertActiveWindow(
    parseNow(nowMs),
    envelope.payload.created_at_ms,
    envelope.payload.expires_at_ms,
    "challenge_request",
  );
  return envelope;
}

export function signIpcChallenge(
  privateKey: KeyObject,
  input: unknown,
): SignedIpcChallenge {
  const payload = IpcChallengePayloadSchema.parse(input);
  requireRoleKey(privateKey, payload.context.gateway_key_id, "gateway");
  return SignedIpcChallengeSchema.parse({
    schema_version: "checkback.live-shadow-boundary.signed-challenge.v1",
    payload,
    signer_key_id: publicKeyId(privateKey),
    signature_algorithm: "Ed25519",
    signature_base64: signCanonicalEd25519(
      privateKey,
      IPC_SIGNATURE_DOMAINS.challenge,
      payload,
    ),
  });
}

export function verifyIpcChallenge(
  publicKey: KeyObject,
  input: unknown,
  options: {
    challenge_request: SignedIpcChallengeRequest;
    collector_public_key: KeyObject;
    now_ms: number;
  },
): SignedIpcChallenge {
  const envelope = SignedIpcChallengeSchema.parse(input);
  const request = verifyIpcChallengeRequest(
    options.collector_public_key,
    options.challenge_request,
    options.now_ms,
  );
  verifyEnvelope(
    publicKey,
    envelope,
    IPC_SIGNATURE_DOMAINS.challenge,
    envelope.payload.context.gateway_key_id,
    "challenge",
  );
  assertActiveWindow(
    parseNow(options.now_ms),
    envelope.payload.issued_at_ms,
    envelope.payload.expires_at_ms,
    "challenge",
  );
  if (
    envelope.payload.challenge_request_id !==
      request.payload.challenge_request_id ||
    envelope.payload.challenge_request_sha256 !== sha256Canonical(request) ||
    !sameCanonical(envelope.payload.context, request.payload.context)
  ) {
    throw new Error("ipc_challenge_request_binding_mismatch");
  }
  if (
    envelope.payload.issued_at_ms < request.payload.created_at_ms ||
    envelope.payload.issued_at_ms >= request.payload.expires_at_ms ||
    envelope.payload.expires_at_ms > request.payload.expires_at_ms
  ) {
    throw new Error("ipc_challenge_request_window_mismatch");
  }
  return envelope;
}

export function signIpcDispatchCommand(
  privateKey: KeyObject,
  input: unknown,
): SignedIpcDispatchCommand {
  const payload = IpcDispatchCommandPayloadSchema.parse(input);
  requireRoleKey(privateKey, payload.context.collector_key_id, "collector");
  return SignedIpcDispatchCommandSchema.parse({
    schema_version:
      "checkback.live-shadow-boundary.signed-dispatch-command.v1",
    payload,
    signer_key_id: publicKeyId(privateKey),
    signature_algorithm: "Ed25519",
    signature_base64: signCanonicalEd25519(
      privateKey,
      IPC_SIGNATURE_DOMAINS.dispatch_command,
      payload,
    ),
  });
}

export function verifyIpcDispatchCommand(
  publicKey: KeyObject,
  input: unknown,
  options: {
    challenge_request: SignedIpcChallengeRequest;
    challenge: SignedIpcChallenge;
    gateway_public_key: KeyObject;
    authority_public_key: KeyObject;
    anchor_public_key: KeyObject;
    expected_anchor_service_profile:
      | "offline_simulator"
      | "production_external";
    now_ms: number;
  },
): SignedIpcDispatchCommand {
  const envelope = SignedIpcDispatchCommandSchema.parse(input);
  const request = verifyIpcChallengeRequest(
    publicKey,
    options.challenge_request,
    options.now_ms,
  );
  const challenge = verifyIpcChallenge(
    options.gateway_public_key,
    options.challenge,
    {
      challenge_request: request,
      collector_public_key: publicKey,
      now_ms: options.now_ms,
    },
  );
  const ticket = verifyIpcAuthorityDispatchTicket(
    options.authority_public_key,
    envelope.payload.authority_ticket,
  );
  const anchorRequest = verifyRemoteAnchorRequest(
    options.authority_public_key,
    envelope.payload.remote_anchor_request,
  );
  const anchorReceipt = verifyRemoteAnchorReceipt(
    options.anchor_public_key,
    envelope.payload.remote_anchor_receipt,
  );
  if (
    ticket.payload.expected_anchor_service_profile !==
      options.expected_anchor_service_profile ||
    anchorRequest.payload.expected_service_profile !==
      options.expected_anchor_service_profile ||
    anchorReceipt.payload.service_profile !==
      options.expected_anchor_service_profile
  ) {
    throw new Error("ipc_remote_anchor_service_profile_mismatch");
  }
  verifyEnvelope(
    publicKey,
    envelope,
    IPC_SIGNATURE_DOMAINS.dispatch_command,
    envelope.payload.context.collector_key_id,
    "dispatch_command",
  );
  assertActiveWindow(
    parseNow(options.now_ms),
    envelope.payload.created_at_ms,
    envelope.payload.expires_at_ms,
    "dispatch_command",
  );
  if (
    envelope.payload.challenge_request_sha256 !== sha256Canonical(request) ||
    envelope.payload.challenge_id !== challenge.payload.challenge_id ||
    envelope.payload.challenge_sha256 !== sha256Canonical(challenge) ||
    envelope.payload.gateway_boot_id !== challenge.payload.gateway_boot_id ||
    envelope.payload.gateway_sequence !== challenge.payload.gateway_sequence ||
    !sameCanonical(envelope.payload.context, request.payload.context) ||
    !sameCanonical(envelope.payload.context, challenge.payload.context)
  ) {
    throw new Error("ipc_dispatch_chain_binding_mismatch");
  }
  if (
    envelope.payload.created_at_ms < challenge.payload.issued_at_ms ||
    envelope.payload.created_at_ms >= challenge.payload.expires_at_ms ||
    envelope.payload.expires_at_ms > challenge.payload.expires_at_ms
  ) {
    throw new Error("ipc_dispatch_challenge_window_mismatch");
  }
  VERIFIED_DISPATCH_COMMANDS.set(envelope, {
    canonical_sha256: sha256Canonical(envelope),
    not_before_ms: envelope.payload.created_at_ms,
    expires_at_ms: Math.min(
      envelope.payload.expires_at_ms,
      envelope.payload.authority_ticket.payload.expires_at_ms,
      envelope.payload.dispatch_intent.expires_at_ms,
      challenge.payload.expires_at_ms,
      request.payload.expires_at_ms,
    ),
  });
  return envelope;
}

export function signIpcGatewayResult(
  privateKey: KeyObject,
  input: unknown,
): SignedIpcGatewayResult {
  const payload = IpcGatewayResultPayloadSchema.parse(input);
  requireRoleKey(privateKey, payload.context.gateway_key_id, "gateway");
  return SignedIpcGatewayResultSchema.parse({
    schema_version:
      "checkback.live-shadow-boundary.signed-gateway-result.v1",
    payload,
    signer_key_id: publicKeyId(privateKey),
    signature_algorithm: "Ed25519",
    signature_base64: signCanonicalEd25519(
      privateKey,
      IPC_SIGNATURE_DOMAINS.gateway_result,
      payload,
    ),
  });
}

export function verifyIpcGatewayResult(
  publicKey: KeyObject,
  input: unknown,
  options: {
    challenge_request: SignedIpcChallengeRequest;
    challenge: SignedIpcChallenge;
    dispatch_command: SignedIpcDispatchCommand;
    collector_public_key: KeyObject;
    authority_public_key: KeyObject;
    anchor_public_key: KeyObject;
    expected_anchor_service_profile:
      | "offline_simulator"
      | "production_external";
  },
): SignedIpcGatewayResult {
  const envelope = SignedIpcGatewayResultSchema.parse(input);
  const commandInput = SignedIpcDispatchCommandSchema.parse(
    options.dispatch_command,
  );
  const commandVerificationTime = commandInput.payload.created_at_ms;
  const request = verifyIpcChallengeRequest(
    options.collector_public_key,
    options.challenge_request,
    commandVerificationTime,
  );
  const challenge = verifyIpcChallenge(publicKey, options.challenge, {
    challenge_request: request,
    collector_public_key: options.collector_public_key,
    now_ms: commandVerificationTime,
  });
  const command = verifyIpcDispatchCommand(
    options.collector_public_key,
    options.dispatch_command,
    {
      challenge_request: request,
      challenge,
      gateway_public_key: publicKey,
      authority_public_key: options.authority_public_key,
      anchor_public_key: options.anchor_public_key,
      expected_anchor_service_profile:
        options.expected_anchor_service_profile,
      now_ms: commandVerificationTime,
    },
  );
  verifyEnvelope(
    publicKey,
    envelope,
    IPC_SIGNATURE_DOMAINS.gateway_result,
    envelope.payload.context.gateway_key_id,
    "gateway_result",
  );
  if (
    envelope.payload.challenge_request_sha256 !== sha256Canonical(request) ||
    envelope.payload.challenge_sha256 !== sha256Canonical(challenge) ||
    envelope.payload.dispatch_command_id !==
      command.payload.dispatch_command_id ||
    envelope.payload.dispatch_command_sha256 !== sha256Canonical(command) ||
    envelope.payload.gateway_boot_id !== challenge.payload.gateway_boot_id ||
    envelope.payload.gateway_sequence !== challenge.payload.gateway_sequence ||
    !sameCanonical(envelope.payload.context, request.payload.context) ||
    !sameCanonical(envelope.payload.context, challenge.payload.context) ||
    !sameCanonical(envelope.payload.context, command.payload.context)
  ) {
    throw new Error("ipc_gateway_result_chain_binding_mismatch");
  }
  if (
    envelope.payload.started_at_ms < command.payload.created_at_ms ||
    envelope.payload.started_at_ms >= command.payload.expires_at_ms
  ) {
    throw new Error("ipc_gateway_result_start_window_mismatch");
  }
  return envelope;
}

export function parseVerifiedIpcDispatchAttachmentFrame(
  command: SignedIpcDispatchCommand,
  frame: Uint8Array,
  trustedNowMs: number,
): {
  anchor_receipt_bytes: Uint8Array;
  request_body_bytes: Uint8Array;
} {
  const verifiedState = VERIFIED_DISPATCH_COMMANDS.get(command);
  if (
    verifiedState === undefined ||
    verifiedState.canonical_sha256 !== sha256Canonical(command)
  ) {
    throw new Error("ipc_verified_dispatch_capability_required");
  }
  const now = parseNow(trustedNowMs);
  if (
    now < verifiedState.not_before_ms ||
    now >= verifiedState.expires_at_ms
  ) {
    throw new Error("ipc_verified_dispatch_expired_or_not_yet_valid");
  }
  const parsed = parseCanonicalAttachmentFrame(frame, [
    command.payload.context.anchor_receipt,
    command.payload.context.request_body,
  ]);
  const anchorReceiptBytes = parsed.find(
    (item) => item.descriptor.name === "anchor_receipt",
  )?.bytes;
  const requestBodyBytes = parsed.find(
    (item) => item.descriptor.name === "request_body",
  )?.bytes;
  if (!anchorReceiptBytes || !requestBodyBytes) {
    throw new Error("ipc_verified_dispatch_attachments_incomplete");
  }
  const canonicalReceiptBytes = Buffer.from(
    canonicalJson(command.payload.remote_anchor_receipt),
    "utf8",
  );
  if (!Buffer.from(anchorReceiptBytes).equals(canonicalReceiptBytes)) {
    throw new Error("ipc_verified_anchor_receipt_bytes_mismatch");
  }
  return {
    anchor_receipt_bytes: new Uint8Array(anchorReceiptBytes),
    request_body_bytes: new Uint8Array(requestBodyBytes),
  };
}

export function encodeCanonicalAttachmentFrame(
  attachments: ReadonlyArray<{
    descriptor: IpcAttachmentDescriptor;
    bytes: Uint8Array;
  }>,
): Uint8Array {
  if (attachments.length < 1 || attachments.length > 3) {
    throw new Error("ipc_attachment_count_invalid");
  }
  const normalized = attachments
    .map((item) => {
      const descriptor = IpcAttachmentDescriptorSchema.parse(item.descriptor);
      assertBytes(item.bytes);
      const bytes = Buffer.from(item.bytes);
      validateAttachmentBytes(descriptor, bytes);
      return { descriptor, bytes };
    })
    .sort((left, right) =>
      compareAttachmentNames(left.descriptor.name, right.descriptor.name),
    );
  assertUniqueAttachmentNames(normalized.map((item) => item.descriptor.name));

  const recordLengths = normalized.map((item) => {
    const nameLength = Buffer.byteLength(item.descriptor.name, "utf8");
    return 1 + nameLength + 4 + item.bytes.byteLength;
  });
  const totalLength =
    FRAME_HEADER_BYTES +
    recordLengths.reduce((sum, recordLength) => sum + recordLength, 0);
  if (totalLength > IPC_MAX_ATTACHMENT_FRAME_BYTES) {
    throw new Error("ipc_attachment_frame_too_large");
  }
  const output = Buffer.allocUnsafe(totalLength);
  FRAME_MAGIC.copy(output, 0);
  output.writeUInt16BE(normalized.length, FRAME_MAGIC.byteLength);
  output.writeUInt16BE(0, FRAME_MAGIC.byteLength + 2);
  let offset = FRAME_HEADER_BYTES;
  for (const item of normalized) {
    const nameBytes = Buffer.from(item.descriptor.name, "utf8");
    output.writeUInt8(nameBytes.byteLength, offset);
    offset += 1;
    nameBytes.copy(output, offset);
    offset += nameBytes.byteLength;
    output.writeUInt32BE(item.bytes.byteLength, offset);
    offset += 4;
    item.bytes.copy(output, offset);
    offset += item.bytes.byteLength;
  }
  if (offset !== output.byteLength) {
    throw new Error("ipc_attachment_frame_internal_length_mismatch");
  }
  return new Uint8Array(output);
}

export function parseCanonicalAttachmentFrame(
  frame: Uint8Array,
  expectedDescriptors: readonly IpcAttachmentDescriptor[],
): ReadonlyArray<{
  descriptor: IpcAttachmentDescriptor;
  bytes: Uint8Array;
}> {
  assertBytes(frame);
  if (
    frame.byteLength < FRAME_HEADER_BYTES ||
    frame.byteLength > IPC_MAX_ATTACHMENT_FRAME_BYTES
  ) {
    throw new Error("ipc_attachment_frame_length_invalid");
  }
  const input = Buffer.from(frame);
  if (!input.subarray(0, FRAME_MAGIC.byteLength).equals(FRAME_MAGIC)) {
    throw new Error("ipc_attachment_frame_magic_invalid");
  }
  const count = input.readUInt16BE(FRAME_MAGIC.byteLength);
  const reserved = input.readUInt16BE(FRAME_MAGIC.byteLength + 2);
  if (count < 1 || count > 3 || reserved !== 0) {
    throw new Error("ipc_attachment_frame_header_invalid");
  }
  const expected = expectedDescriptors
    .map((item) => IpcAttachmentDescriptorSchema.parse(item))
    .sort((left, right) => compareAttachmentNames(left.name, right.name));
  assertUniqueAttachmentNames(expected.map((item) => item.name));
  if (count !== expected.length) {
    throw new Error("ipc_attachment_frame_count_mismatch");
  }

  const output: Array<{
    descriptor: IpcAttachmentDescriptor;
    bytes: Uint8Array;
  }> = [];
  let offset = FRAME_HEADER_BYTES;
  let previousName = "";
  for (let index = 0; index < count; index += 1) {
    requireRemaining(input, offset, 1);
    const nameLength = input.readUInt8(offset);
    offset += 1;
    if (nameLength < 1 || nameLength > 32) {
      throw new Error("ipc_attachment_frame_name_length_invalid");
    }
    requireRemaining(input, offset, nameLength + 4);
    const nameBytes = input.subarray(offset, offset + nameLength);
    offset += nameLength;
    let decodedName: string;
    try {
      decodedName = new TextDecoder("utf-8", { fatal: true }).decode(nameBytes);
    } catch {
      throw new Error("ipc_attachment_frame_name_utf8_invalid");
    }
    const name = IpcAttachmentNameSchema.parse(decodedName);
    if (
      previousName !== "" &&
      compareAttachmentNames(previousName, name) >= 0
    ) {
      throw new Error("ipc_attachment_frame_order_invalid");
    }
    previousName = name;
    const byteLength = input.readUInt32BE(offset);
    offset += 4;
    if (byteLength > attachmentLimit(name)) {
      throw new Error("ipc_attachment_frame_item_too_large");
    }
    requireRemaining(input, offset, byteLength);
    const bytes = new Uint8Array(input.subarray(offset, offset + byteLength));
    offset += byteLength;
    const descriptor = expected[index];
    if (!descriptor || descriptor.name !== name) {
      throw new Error("ipc_attachment_frame_name_mismatch");
    }
    validateAttachmentBytes(descriptor, bytes);
    output.push({ descriptor, bytes });
  }
  if (offset !== input.byteLength) {
    throw new Error("ipc_attachment_frame_trailing_bytes");
  }
  return output;
}

function signedEnvelopeSchema<Payload extends z.ZodType>(
  schemaVersion: string,
  payload: Payload,
) {
  return z
    .object({
      schema_version: z.literal(schemaVersion),
      payload,
      signer_key_id: Hex64Schema,
      signature_algorithm: z.literal("Ed25519"),
      signature_base64: Base64SignatureSchema,
    })
    .strict();
}

function validateAuthorityTicket(
  value: IpcAuthorityDispatchTicketPayload,
  context: z.RefinementCtx,
) {
  const intent = value.dispatch_intent;
  const runtime = value.runtime_manifest;
  const policy = value.policy;
  const roleKeyIds = [
    value.collector_key_id,
    value.gateway_key_id,
    value.authority_key_id,
    value.anchor_key_id,
  ];
  if (new Set(roleKeyIds).size !== roleKeyIds.length) {
    context.addIssue({
      code: "custom",
      path: ["collector_key_id"],
      message: "authority ticket role keys must be distinct",
    });
  }
  if (
    value.runtime_manifest_sha256 !== sha256Canonical(runtime) ||
    intent.runtime_manifest_sha256 !== value.runtime_manifest_sha256
  ) {
    context.addIssue({
      code: "custom",
      path: ["runtime_manifest_sha256"],
      message: "authority ticket runtime digest mismatch",
    });
  }
  if (
    value.policy_sha256 !== sha256Canonical(policy) ||
    policy.runtime_policy_sha256 !== runtime.runtime_policy_sha256
  ) {
    context.addIssue({
      code: "custom",
      path: ["policy_sha256"],
      message: "authority ticket policy digest mismatch",
    });
  }
  if (
    runtime.authority_registry_id !== intent.authority_registry_id ||
    runtime.anchor_realm_id !== intent.anchor_realm_id ||
    runtime.anchor_key_id !== value.anchor_key_id ||
    runtime.provider_id !== policy.provider_id ||
    runtime.endpoint.transport !== policy.transport ||
    runtime.endpoint.host !== policy.host ||
    runtime.endpoint.port !== policy.port ||
    runtime.endpoint.path !== policy.path ||
    runtime.endpoint.redirect_policy !== policy.redirect_policy ||
    runtime.endpoint.proxy_policy !== policy.proxy_policy ||
    runtime.models[intent.slot] !== policy.model_id ||
    runtime.timeouts_ms[intent.slot] !== policy.total_timeout_ms ||
    runtime.gateway_build_sha256 !== policy.gateway_build_sha256
  ) {
    context.addIssue({
      code: "custom",
      path: ["policy"],
      message: "authority ticket runtime and gateway policy diverge",
    });
  }
  if (
    value.issued_at_ms < intent.created_at_ms ||
    value.issued_at_ms >= intent.expires_at_ms ||
    value.expires_at_ms > intent.expires_at_ms
  ) {
    context.addIssue({
      code: "custom",
      path: ["expires_at_ms"],
      message: "authority ticket exceeds dispatch intent window",
    });
  }
  if (
    value.anchor_receipt.name !== "anchor_receipt" ||
    value.request_body.name !== "request_body" ||
    value.request_body.byte_length > policy.max_request_body_bytes ||
    value.remote_anchor_receipt_sha256 !== value.anchor_receipt.sha256
  ) {
    context.addIssue({
      code: "custom",
      path: ["request_body"],
      message: "authority ticket attachment binding is invalid",
    });
  }
}

function validateCommandProofBinding(
  value: IpcDispatchCommandPayload,
  context: z.RefinementCtx,
) {
  const ticket = value.authority_ticket;
  const ticketPayload = ticket.payload;
  const request = value.remote_anchor_request;
  const receipt = value.remote_anchor_receipt;
  const requestPayload = request.payload;
  const receiptPayload = receipt.payload;
  const receiptBytes = Buffer.from(canonicalJson(receipt), "utf8");
  if (
    !isCanonicalBase64(request.signature_base64) ||
    !isCanonicalBase64(receipt.signature_base64)
  ) {
    context.addIssue({
      code: "custom",
      path: ["remote_anchor_receipt", "signature_base64"],
      message: "remote proof signature base64 must be canonical",
    });
  }
  if (
    value.context.authority_ticket_sha256 !== sha256Canonical(ticket) ||
    ticketPayload.collector_key_id !== value.context.collector_key_id ||
    ticketPayload.gateway_key_id !== value.context.gateway_key_id ||
    ticketPayload.authority_key_id !== value.context.authority_key_id ||
    ticketPayload.anchor_key_id !== value.context.anchor_key_id ||
    ticketPayload.runtime_manifest_sha256 !==
      value.context.runtime_manifest_sha256 ||
    ticketPayload.policy_sha256 !== value.context.policy_sha256 ||
    !sameCanonical(ticketPayload.policy, value.context.policy) ||
    !sameCanonical(ticketPayload.dispatch_intent, value.dispatch_intent) ||
    !sameCanonical(ticketPayload.anchor_receipt, value.context.anchor_receipt) ||
    !sameCanonical(ticketPayload.request_body, value.context.request_body)
  ) {
    context.addIssue({
      code: "custom",
      path: ["authority_ticket"],
      message: "authority ticket does not match the IPC dispatch context",
    });
  }
  if (
    ticketPayload.remote_anchor_request_sha256 !== sha256Canonical(request) ||
    ticketPayload.remote_anchor_receipt_sha256 !== sha256Canonical(receipt) ||
    ticketPayload.anchor_receipt.sha256 !== sha256Bytes(receiptBytes) ||
    ticketPayload.anchor_receipt.byte_length !== receiptBytes.byteLength
  ) {
    context.addIssue({
      code: "custom",
      path: ["remote_anchor_receipt"],
      message: "remote proof bytes or digests do not match the authority ticket",
    });
  }
  if (
    requestPayload.operation !== "consume_slot" ||
    requestPayload.body.operation !== "consume_slot" ||
    !sameCanonical(requestPayload.body.intent, value.dispatch_intent) ||
    requestPayload.anchor_realm_id !== value.context.anchor_realm_id ||
    requestPayload.authority_registry_id !==
      value.context.authority_registry_id ||
    requestPayload.authority_key_id !== value.context.authority_key_id ||
    requestPayload.expected_service_profile !==
      ticketPayload.expected_anchor_service_profile
  ) {
    context.addIssue({
      code: "custom",
      path: ["remote_anchor_request"],
      message: "remote anchor consume request binding mismatch",
    });
  }
  if (
    receiptPayload.decision !== "committed" ||
    receiptPayload.operation !== "consume_slot" ||
    receiptPayload.service_profile !==
      ticketPayload.expected_anchor_service_profile ||
    receiptPayload.anchor_realm_id !== value.context.anchor_realm_id ||
    receiptPayload.authority_registry_id !==
      value.context.authority_registry_id ||
    receiptPayload.authority_key_id !== value.context.authority_key_id ||
    receiptPayload.anchor_key_id !== value.context.anchor_key_id ||
    receiptPayload.request_id !== requestPayload.request_id ||
    receiptPayload.idempotency_key !== requestPayload.idempotency_key ||
    receiptPayload.request_nonce_sha256 !==
      sha256Bytes(requestPayload.request_nonce_hex) ||
    receiptPayload.signed_request_sha256 !==
      remoteAnchorSignedRequestSha256(request) ||
    receiptPayload.object_key_sha256 !==
      value.context.dispatch_intent_sha256
  ) {
    context.addIssue({
      code: "custom",
      path: ["remote_anchor_receipt"],
      message: "committed remote consume receipt binding mismatch",
    });
  }
  const anchorTime = BigInt(receiptPayload.anchor_time.unix_ms);
  if (
    remoteAnchorRequestTimeStatus(
      requestPayload,
      receiptPayload.anchor_time,
    ) !== "active" ||
    BigInt(ticketPayload.issued_at_ms) < anchorTime
  ) {
    context.addIssue({
      code: "custom",
      path: ["remote_anchor_receipt", "payload", "anchor_time"],
      message: "remote anchor trusted-time binding mismatch",
    });
  }
}

function isCanonicalBase64(value: string): boolean {
  return (
    /^[A-Za-z0-9+/]{86}==$/.test(value) &&
    Buffer.from(value, "base64").byteLength === 64 &&
    Buffer.from(value, "base64").toString("base64") === value
  );
}

function validateWindow(
  issuedAtMs: number,
  expiresAtMs: number,
  maxTtlMs: number,
  context: z.RefinementCtx,
  path: PropertyKey[],
) {
  if (
    expiresAtMs <= issuedAtMs ||
    expiresAtMs - issuedAtMs > maxTtlMs
  ) {
    context.addIssue({
      code: "custom",
      path,
      message: "signed IPC validity window is invalid",
    });
  }
}

function validateIntentBinding(
  contextValue: IpcDispatchContext,
  intent: z.infer<typeof LiveDispatchIntentSchema>,
  context: z.RefinementCtx,
) {
  const intentBytes = Buffer.from(canonicalJson(intent), "utf8");
  const fieldsMatch =
    contextValue.authority_registry_id === intent.authority_registry_id &&
    contextValue.anchor_realm_id === intent.anchor_realm_id &&
    contextValue.authorization_id === intent.authorization_id &&
    contextValue.authorization_fingerprint_sha256 ===
      intent.authorization_fingerprint_sha256 &&
    contextValue.execution_id === intent.execution_id &&
    contextValue.media_scope_id === intent.media_scope_id &&
    contextValue.pair_commitment_hmac_sha256 ===
      intent.pair_commitment_hmac_sha256 &&
    contextValue.slot === intent.slot &&
    contextValue.ordinal === intent.ordinal &&
    contextValue.operation_id === intent.operation_id &&
    contextValue.runtime_manifest_sha256 ===
      intent.runtime_manifest_sha256 &&
    contextValue.request_commitment_hmac_sha256 ===
      intent.request_commitment_hmac_sha256;
  if (
    !fieldsMatch ||
    contextValue.dispatch_intent_sha256 !== sha256Bytes(intentBytes) ||
    contextValue.dispatch_intent_byte_length !== intentBytes.byteLength
  ) {
    context.addIssue({
      code: "custom",
      path: ["dispatch_intent"],
      message: "dispatch intent does not match the signed IPC context",
    });
  }
}

function attachmentLimit(name: IpcAttachmentName): number {
  if (name === "anchor_receipt") return IPC_MAX_ANCHOR_RECEIPT_BYTES;
  if (name === "request_body") return IPC_MAX_REQUEST_BODY_BYTES;
  return IPC_MAX_RESPONSE_BODY_BYTES;
}

function compareAttachmentNames(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function assertBytes(value: Uint8Array) {
  if (!(value instanceof Uint8Array)) {
    throw new Error("ipc_attachment_bytes_required");
  }
}

function validateAttachmentBytes(
  descriptor: IpcAttachmentDescriptor,
  bytes: Uint8Array,
) {
  if (
    bytes.byteLength !== descriptor.byte_length ||
    sha256Bytes(bytes) !== descriptor.sha256
  ) {
    throw new Error("ipc_attachment_bytes_mismatch");
  }
}

function assertUniqueAttachmentNames(names: readonly string[]) {
  if (new Set(names).size !== names.length) {
    throw new Error("ipc_attachment_name_duplicate");
  }
}

function requireRemaining(input: Buffer, offset: number, needed: number) {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(needed) ||
    offset < 0 ||
    needed < 0 ||
    offset + needed > input.byteLength
  ) {
    throw new Error("ipc_attachment_frame_truncated");
  }
}

function requireRoleKey(
  key: KeyObject,
  expectedKeyId: string,
  role: "collector" | "gateway" | "authority",
) {
  if (publicKeyId(key) !== expectedKeyId) {
    throw new Error(`ipc_${role}_signer_key_mismatch`);
  }
}

function verifyEnvelope(
  publicKey: KeyObject,
  envelope: {
    signer_key_id: string;
    payload: unknown;
    signature_base64: string;
  },
  domain: string,
  expectedRoleKeyId: string,
  objectName: string,
) {
  const actualKeyId = publicKeyId(publicKey);
  if (
    envelope.signer_key_id !== actualKeyId ||
    expectedRoleKeyId !== actualKeyId
  ) {
    throw new Error(`ipc_${objectName}_signer_key_mismatch`);
  }
  if (
    !verifyCanonicalEd25519(
      publicKey,
      domain,
      envelope.payload,
      envelope.signature_base64,
    )
  ) {
    throw new Error(`ipc_${objectName}_signature_invalid`);
  }
}

function parseNow(value: number): number {
  return TimestampSchema.parse(value);
}

function assertActiveWindow(
  nowMs: number,
  issuedAtMs: number,
  expiresAtMs: number,
  objectName: string,
) {
  if (nowMs < issuedAtMs || nowMs >= expiresAtMs) {
    throw new Error(`ipc_${objectName}_expired_or_not_yet_valid`);
  }
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}
