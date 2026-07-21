import {
  createHash,
  createHmac,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import type { KeyObject } from "node:crypto";

const DOMAIN_PATTERN = /^[A-Za-z0-9._-]{1,96}$/;

function normalizeCanonical(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical_number_invalid");
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (item === undefined) throw new Error("canonical_value_undefined");
      return normalizeCanonical(item);
    });
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("canonical_object_prototype_invalid");
    }
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item === undefined) throw new Error("canonical_value_undefined");
      output[key] = normalizeCanonical(item);
    }
    return output;
  }
  throw new Error("canonical_value_type_invalid");
}

function domainBytes(domain: string, payload: Uint8Array): Buffer {
  if (!DOMAIN_PATTERN.test(domain)) throw new Error("crypto_domain_invalid");
  return Buffer.concat([
    Buffer.from(domain, "utf8"),
    Buffer.from([0]),
    Buffer.from(payload),
  ]);
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalizeCanonical(value));
}

export function sha256Bytes(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function sha256Canonical(value: unknown): string {
  return sha256Bytes(canonicalJson(value));
}

export function hmacSha256Bytes(
  secret: Uint8Array,
  domain: string,
  value: Uint8Array,
): string {
  if (secret.byteLength < 32) throw new Error("hmac_secret_too_short");
  return createHmac("sha256", secret)
    .update(domainBytes(domain, value))
    .digest("hex");
}

export function hmacSha256Canonical(
  secret: Uint8Array,
  domain: string,
  value: unknown,
): string {
  return hmacSha256Bytes(
    secret,
    domain,
    Buffer.from(canonicalJson(value), "utf8"),
  );
}

export function computeMediaPairCommitment(
  secret: Uint8Array,
  input: {
    before_bytes: Uint8Array;
    after_bytes: Uint8Array;
    preprocessing_config_sha256: string;
  },
): string {
  if (
    !(input.before_bytes instanceof Uint8Array) ||
    !(input.after_bytes instanceof Uint8Array) ||
    input.before_bytes.byteLength < 1 ||
    input.after_bytes.byteLength < 1 ||
    input.before_bytes.byteLength > 32 * 1024 * 1024 ||
    input.after_bytes.byteLength > 32 * 1024 * 1024 ||
    !/^[a-f0-9]{64}$/.test(input.preprocessing_config_sha256)
  ) {
    throw new Error("media_pair_input_invalid");
  }
  return hmacSha256Canonical(
    secret,
    "checkback.live-shadow.media-pair.v1",
    {
      before_sha256: sha256Bytes(input.before_bytes),
      after_sha256: sha256Bytes(input.after_bytes),
      preprocessing_config_sha256: input.preprocessing_config_sha256,
    },
  );
}
export function secretKeyId(secret: Uint8Array): string {
  if (secret.byteLength < 32) throw new Error("authority_secret_too_short");
  return sha256Bytes(
    Buffer.concat([
      Buffer.from("checkback.live-shadow.authority-key.v1", "utf8"),
      Buffer.from([0]),
      Buffer.from(secret),
    ]),
  );
}

export function publicKeyId(key: KeyObject): string {
  const publicKey = key.type === "public" ? key : createPublicKey(key);
  const der = publicKey.export({ type: "spki", format: "der" });
  return sha256Bytes(der);
}

export function signCanonicalEd25519(
  privateKey: KeyObject,
  domain: string,
  value: unknown,
): string {
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("ed25519_private_key_required");
  }
  const payload = domainBytes(
    domain,
    Buffer.from(canonicalJson(value), "utf8"),
  );
  return cryptoSign(null, payload, privateKey).toString("base64");
}

export function verifyCanonicalEd25519(
  publicKey: KeyObject,
  domain: string,
  value: unknown,
  signatureBase64: string,
): boolean {
  const key = publicKey.type === "public" ? publicKey : createPublicKey(publicKey);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("ed25519_public_key_required");
  }
  let signature: Buffer;
  try {
    signature = Buffer.from(signatureBase64, "base64");
  } catch {
    return false;
  }
  if (signature.byteLength !== 64) return false;
  const payload = domainBytes(
    domain,
    Buffer.from(canonicalJson(value), "utf8"),
  );
  return cryptoVerify(null, payload, key, signature);
}
