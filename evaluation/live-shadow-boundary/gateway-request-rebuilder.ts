import { z } from "zod";
import { canonicalJson, sha256Bytes, sha256Canonical } from "../live-shadow/crypto.ts";
import {
  IPC_MAX_REQUEST_BODY_BYTES,
  parseVerifiedIpcDispatchAttachmentFrame,
} from "./ipc-contracts.ts";
import type { SignedIpcDispatchCommand } from "./ipc-contracts.ts";
import { MAX_PREPROCESSED_MEDIA_PART_BYTES } from "./boundary-limits.ts";

const MAX_IMAGE_BYTES = MAX_PREPROCESSED_MEDIA_PART_BYTES;
const MAX_SYSTEM_PROMPT_BYTES = 256 * 1024;
const MAX_TEXT_PART_BYTES = 1024 * 1024;
const Hex64Schema = z.string().regex(/^[a-f0-9]{64}$/);

export const GATEWAY_PROVIDER_REQUEST_TEMPLATE_SHA256 = sha256Canonical({
  schema_version:
    "checkback.live-shadow-boundary.qwen-provider-request-template.v1",
  top_level_fields: [
    "enable_thinking",
    "max_tokens",
    "messages",
    "model",
    "response_format",
    "stream",
    "vl_high_resolution_images",
  ],
  fixed_parameters: {
    response_format: { type: "json_object" },
    enable_thinking: false,
    vl_high_resolution_images: true,
    stream: false,
  },
  max_tokens_by_slot: { primary: 4000, flash: 2200, plus: 2200 },
  messages: [
    { role: "system", content: "prompt-bound-by-runtime-sha256" },
    {
      role: "user",
      content: "two-labeled-inline-jpeg-png-or-webp-images-with-text",
    },
  ],
});

const CanonicalImageDataUrlSchema = z
  .string()
  .max(Math.ceil(MAX_IMAGE_BYTES / 3) * 4 + 64)
  .superRefine((value, context) => {
    const match = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(
      value,
    );
    if (!match) {
      context.addIssue({
        code: "custom",
        message: "provider images must be inline canonical JPEG/PNG/WebP data URLs",
      });
      return;
    }
    const encoded = match[2];
    const decoded = Buffer.from(encoded, "base64");
    try {
      if (
        decoded.byteLength === 0 ||
        decoded.byteLength > MAX_IMAGE_BYTES ||
        decoded.toString("base64") !== encoded
      ) {
        context.addIssue({
          code: "custom",
          message: "provider image base64 is non-canonical or out of bounds",
        });
      }
    } finally {
      decoded.fill(0);
    }
  });

const TextPartSchema = z
  .object({
    type: z.literal("text"),
    text: z.string().min(1).max(MAX_TEXT_PART_BYTES),
  })
  .strict();

const ImagePartSchema = z
  .object({
    type: z.literal("image_url"),
    image_url: z
      .object({ url: CanonicalImageDataUrlSchema })
      .strict(),
  })
  .strict();

const QwenWireBodySchema = z
  .object({
    model: z.string().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/),
    max_tokens: z.number().int().min(1).max(8_192),
    response_format: z.object({ type: z.literal("json_object") }).strict(),
    enable_thinking: z.literal(false),
    vl_high_resolution_images: z.literal(true),
    stream: z.literal(false),
    messages: z.tuple([
      z
        .object({
          role: z.literal("system"),
          content: z.string().min(1).max(MAX_SYSTEM_PROMPT_BYTES),
        })
        .strict(),
      z
        .object({
          role: z.literal("user"),
          content: z
            .array(z.discriminatedUnion("type", [TextPartSchema, ImagePartSchema]))
            .min(4)
            .max(8),
        })
        .strict(),
    ]),
  })
  .strict()
  .superRefine((value, context) => {
    const parts = value.messages[1].content;
    const imageIndexes = parts
      .map((part, index) => (part.type === "image_url" ? index : -1))
      .filter((index) => index >= 0);
    const textCount = parts.length - imageIndexes.length;
    if (
      imageIndexes.length !== 2 ||
      textCount < 2 ||
      parts[0]?.type !== "text" ||
      imageIndexes.some(
        (index) => index === 0 || parts[index - 1]?.type !== "text",
      )
    ) {
      context.addIssue({
        code: "custom",
        path: ["messages", 1, "content"],
        message: "provider request must contain two labeled inline images",
      });
    }
  });

export const GatewayCompiledIdentitySchema = z
  .object({
    schema_version: z.literal(
      "checkback.live-shadow-boundary.gateway-compiled-identity.v1",
    ),
    gateway_build_sha256: Hex64Schema,
    runtime_policy_sha256: Hex64Schema,
    request_template_sha256: Hex64Schema,
    response_schema_sha256: Hex64Schema,
    preprocessing_config_sha256: Hex64Schema,
  })
  .strict();

export type GatewayCompiledIdentity = z.infer<
  typeof GatewayCompiledIdentitySchema
>;

export interface RebuiltGatewayRequest {
  readonly transport: "https";
  readonly host: string;
  readonly port: 443;
  readonly path: "/compatible-mode/v1/chat/completions";
  readonly method: "POST";
  readonly content_type: "application/json";
  readonly redirect_policy: "deny";
  readonly proxy_policy: "deny";
  readonly max_network_attempts: 1;
  readonly max_retries: 0;
  readonly connect_timeout_ms: number;
  readonly total_timeout_ms: number;
  /** Caller-owned sensitive bytes. Zeroize immediately after the one send. */
  readonly body_bytes: Buffer;
  readonly body_sha256: string;
}

const EXPECTED_MAX_TOKENS = Object.freeze({
  primary: 4_000,
  flash: 2_200,
  plus: 2_200,
});

/**
 * Rebuilds the only provider wire request the gateway may send. The command
 * must be the exact object previously returned by verifyIpcDispatchCommand;
 * cloned or merely schema-valid commands cannot unlock attachment bytes.
 *
 * This function performs no network operation and never accepts credentials.
 */
export function rebuildVerifiedGatewayRequest(input: {
  verified_dispatch_command: SignedIpcDispatchCommand;
  attachment_frame: Uint8Array;
  compiled_identity: unknown;
  trusted_now_ms: number;
}): RebuiltGatewayRequest {
  const identity = GatewayCompiledIdentitySchema.parse(input.compiled_identity);
  const command = input.verified_dispatch_command;
  const context = command.payload.context;
  const ticket = command.payload.authority_ticket.payload;
  const runtime = ticket.runtime_manifest;
  const policy = context.policy;

  if (
    identity.gateway_build_sha256 !== runtime.gateway_build_sha256 ||
    identity.gateway_build_sha256 !== policy.gateway_build_sha256 ||
    identity.runtime_policy_sha256 !== runtime.runtime_policy_sha256 ||
    identity.runtime_policy_sha256 !== policy.runtime_policy_sha256 ||
    identity.request_template_sha256 !==
      GATEWAY_PROVIDER_REQUEST_TEMPLATE_SHA256 ||
    runtime.request_template_sha256 !==
      GATEWAY_PROVIDER_REQUEST_TEMPLATE_SHA256 ||
    identity.response_schema_sha256 !== runtime.response_schema_sha256 ||
    identity.preprocessing_config_sha256 !==
      runtime.preprocessing_config_sha256
  ) {
    throw new Error("gateway_compiled_identity_mismatch");
  }

  const attachments = parseVerifiedIpcDispatchAttachmentFrame(
    command,
    input.attachment_frame,
    input.trusted_now_ms,
  );
  if (attachments.request_body_bytes.byteLength > IPC_MAX_REQUEST_BODY_BYTES) {
    throw new Error("gateway_request_body_too_large");
  }

  const requestBytes = Buffer.from(attachments.request_body_bytes);
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(requestBytes);
    const parsed = QwenWireBodySchema.parse(JSON.parse(text));
    const canonicalBytes = Buffer.from(canonicalJson(parsed), "utf8");
    try {
      if (!canonicalBytes.equals(requestBytes)) {
        throw new Error("gateway_request_body_not_canonical");
      }
      if (
        parsed.model !== policy.model_id ||
        parsed.model !== runtime.models[context.slot] ||
        parsed.max_tokens !== EXPECTED_MAX_TOKENS[context.slot]
      ) {
        throw new Error("gateway_request_runtime_binding_mismatch");
      }
      const expectedPromptHash =
        context.slot === "primary"
          ? runtime.primary_prompt_sha256
          : runtime.verifier_prompt_sha256;
      if (sha256Bytes(parsed.messages[0].content) !== expectedPromptHash) {
        throw new Error("gateway_request_prompt_binding_mismatch");
      }

      const output = Buffer.from(canonicalBytes);
      return Object.freeze({
        transport: "https" as const,
        host: policy.host,
        port: 443 as const,
        path: "/compatible-mode/v1/chat/completions" as const,
        method: "POST" as const,
        content_type: "application/json" as const,
        redirect_policy: "deny" as const,
        proxy_policy: "deny" as const,
        max_network_attempts: 1 as const,
        max_retries: 0 as const,
        connect_timeout_ms: policy.connect_timeout_ms,
        total_timeout_ms: policy.total_timeout_ms,
        body_bytes: output,
        body_sha256: sha256Bytes(output),
      });
    } finally {
      canonicalBytes.fill(0);
    }
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof TypeError) {
      throw new Error("gateway_request_body_invalid_json");
    }
    throw error;
  } finally {
    requestBytes.fill(0);
  }
}

export function disposeRebuiltGatewayRequest(
  request: RebuiltGatewayRequest,
): void {
  request.body_bytes.fill(0);
}
