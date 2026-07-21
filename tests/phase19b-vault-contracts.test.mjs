import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import test from "node:test";
import { FakeKeyCustody } from "../evaluation/live-shadow-boundary/fake-key-custody.ts";
import {
  VAULT_DELETION_RECEIPT_SIGNATURE_DOMAIN,
  VaultDeletionReceiptPayloadSchema,
  VaultDeletionReceiptSchema,
  VaultObjectBindingSchema,
  VaultSealRequestSchema,
  VaultSealedObjectSchema,
  canonicalVaultAad,
  vaultAadSha256,
  verifyVaultDeletionReceipt,
} from "../evaluation/live-shadow-boundary/vault-contracts.ts";
import {
  publicKeyId,
  signCanonicalEd25519,
} from "../evaluation/live-shadow/crypto.ts";

function hash(label) {
  return createHash("sha256").update(label).digest("hex");
}

function id(prefix, label) {
  return `${prefix}_${hash(label)}`;
}

function makeBinding(overrides = {}) {
  return {
    schema_version: "checkback.live-shadow.vault-object-binding.v1",
    authorization_fingerprint_sha256: hash("authorization"),
    execution_id: id("exec", "execution-1"),
    media_scope_id: id("scope", "scope-1"),
    pair_commitment_hmac_sha256: hash("pair-1"),
    preprocessing_config_sha256: hash("preprocess-1"),
    part: "reference",
    plaintext_length: 32,
    delete_by_ms: 2_000,
    ...overrides,
  };
}

function syntheticBytes(label = "canary") {
  return Buffer.from(label.padEnd(32, "!"), "utf8");
}

function tamperBase64(value) {
  const bytes = Buffer.from(value, "base64");
  try {
    bytes[0] ^= 0x80;
    return bytes.toString("base64");
  } finally {
    bytes.fill(0);
  }
}

test("vault seals and unwraps synthetic bytes with unique nonce and pair part", () => {
  const custody = new FakeKeyCustody();
  const referenceBytes = syntheticBytes("reference-canary");
  const comparisonBytes = syntheticBytes("comparison-canary");
  try {
    const reference = custody.sealObject({
      binding: makeBinding({ plaintext_length: referenceBytes.byteLength }),
      plaintext: referenceBytes,
      now_ms: 1_000,
    });
    const comparison = custody.sealObject({
      binding: makeBinding({
        part: "comparison",
        plaintext_length: comparisonBytes.byteLength,
      }),
      plaintext: comparisonBytes,
      now_ms: 1_001,
    });

    assert.deepEqual(VaultSealedObjectSchema.parse(reference), reference);
    assert.notEqual(reference.nonce_base64, comparison.nonce_base64);
    assert.equal(reference.aad_sha256, vaultAadSha256(reference.binding));
    assert.throws(
      () =>
        custody.sealObject({
          binding: reference.binding,
          plaintext: referenceBytes,
          now_ms: 1_002,
        }),
      /vault_part_already_sealed/,
    );

    const unwrapped = custody.unwrapObject({
      sealed_object: reference,
      expected_binding: reference.binding,
      now_ms: 1_999,
    });
    try {
      assert.deepEqual(unwrapped, referenceBytes);
    } finally {
      unwrapped.fill(0);
    }
  } finally {
    referenceBytes.fill(0);
    comparisonBytes.fill(0);
    custody.close();
  }
});

test("canonical AAD changes for every required authorization and media binding", () => {
  const binding = makeBinding();
  const baseline = vaultAadSha256(binding);
  const variants = [
    { authorization_fingerprint_sha256: hash("authorization-2") },
    { execution_id: id("exec", "execution-2") },
    { media_scope_id: id("scope", "scope-2") },
    { pair_commitment_hmac_sha256: hash("pair-2") },
    { preprocessing_config_sha256: hash("preprocess-2") },
    { part: "comparison" },
    { plaintext_length: binding.plaintext_length + 1 },
    { delete_by_ms: binding.delete_by_ms + 1 },
  ];
  for (const variant of variants) {
    assert.notEqual(vaultAadSha256({ ...binding, ...variant }), baseline);
  }
  const first = canonicalVaultAad(binding);
  const second = canonicalVaultAad({ ...binding });
  try {
    assert.deepEqual(first, second);
  } finally {
    first.fill(0);
    second.fill(0);
  }
});

test("AES-GCM rejects ciphertext tampering", () => {
  const custody = new FakeKeyCustody();
  const plaintext = syntheticBytes("tamper-canary");
  try {
    const sealed = custody.sealObject({
      binding: makeBinding({ plaintext_length: plaintext.byteLength }),
      plaintext,
      now_ms: 1_000,
    });
    const tampered = {
      ...sealed,
      ciphertext_base64: tamperBase64(sealed.ciphertext_base64),
    };
    assert.throws(
      () =>
        custody.unwrapObject({
          sealed_object: tampered,
          expected_binding: sealed.binding,
          now_ms: 1_001,
        }),
      /vault_authentication_failed/,
    );
  } finally {
    plaintext.fill(0);
    custody.close();
  }
});

test("unwrap rejects a valid but wrong expected binding", () => {
  const custody = new FakeKeyCustody();
  const plaintext = syntheticBytes("binding-canary");
  try {
    const sealed = custody.sealObject({
      binding: makeBinding({ plaintext_length: plaintext.byteLength }),
      plaintext,
      now_ms: 1_000,
    });
    assert.throws(
      () =>
        custody.unwrapObject({
          sealed_object: sealed,
          expected_binding: {
            ...sealed.binding,
            authorization_fingerprint_sha256: hash("wrong-authorization"),
          },
          now_ms: 1_001,
        }),
      /vault_binding_mismatch/,
    );
  } finally {
    plaintext.fill(0);
    custody.close();
  }
});

test("deadline is exclusive for seal and unwrap", () => {
  const custody = new FakeKeyCustody();
  const plaintext = syntheticBytes("deadline-canary");
  const binding = makeBinding({ plaintext_length: plaintext.byteLength });
  try {
    const sealed = custody.sealObject({
      binding,
      plaintext,
      now_ms: 1_000,
    });
    const beforeDeadline = custody.unwrapObject({
      sealed_object: sealed,
      expected_binding: binding,
      now_ms: binding.delete_by_ms - 1,
    });
    beforeDeadline.fill(0);
    assert.throws(
      () =>
        custody.unwrapObject({
          sealed_object: sealed,
          expected_binding: binding,
          now_ms: binding.delete_by_ms,
        }),
      /vault_deadline_reached/,
    );
    assert.throws(
      () =>
        new FakeKeyCustody().sealObject({
          binding,
          plaintext,
          now_ms: binding.delete_by_ms,
        }),
      /vault_deadline_reached/,
    );
  } finally {
    plaintext.fill(0);
    custody.close();
  }
});

test("key destruction is inspectable, signed, scoped, and blocks unwrap", () => {
  const signingKeys = generateKeyPairSync("ed25519");
  const custody = new FakeKeyCustody({
    receipt_signing_private_key: signingKeys.privateKey,
  });
  const canary = "PHASE19B-PLAINTEXT-CANARY-DO-NOT-RECEIPT";
  const plaintext = syntheticBytes(canary);
  try {
    const sealed = custody.sealObject({
      binding: makeBinding({ plaintext_length: plaintext.byteLength }),
      plaintext,
      now_ms: 1_000,
    });
    assert.equal(
      custody.inspectObjectKey({
        object_id: sealed.object_id,
        object_key_id: sealed.object_key_id,
      }).state,
      "active",
    );
    const receipt = custody.destroyObjectKey({
      sealed_object: sealed,
      reason: "test_cleanup",
      destroyed_at_ms: 1_100,
    });
    assert.deepEqual(
      verifyVaultDeletionReceipt(signingKeys.publicKey, receipt),
      receipt,
    );
    assert.equal(receipt.payload.claim_scope, "object_key_only");
    assert.equal(receipt.payload.object_key_state, "destroyed");
    assert.equal(JSON.stringify(receipt).includes(canary), false);
    assert.equal(
      custody.inspectObjectKey({
        object_id: sealed.object_id,
        object_key_id: sealed.object_key_id,
      }).state,
      "destroyed",
    );
    assert.throws(
      () =>
        custody.unwrapObject({
          sealed_object: sealed,
          expected_binding: sealed.binding,
          now_ms: 1_101,
        }),
      /vault_key_destroyed/,
    );
  } finally {
    plaintext.fill(0);
    custody.close();
  }
});

test("deletion receipt rejects the wrong signer, wrong domain, and payload tampering", () => {
  const signingKeys = generateKeyPairSync("ed25519");
  const custody = new FakeKeyCustody({
    receipt_signing_private_key: signingKeys.privateKey,
  });
  const plaintext = syntheticBytes("receipt-canary");
  try {
    const sealed = custody.sealObject({
      binding: makeBinding({ plaintext_length: plaintext.byteLength }),
      plaintext,
      now_ms: 1_000,
    });
    const receipt = custody.destroyObjectKey({
      sealed_object: sealed,
      reason: "test_cleanup",
      destroyed_at_ms: 1_100,
    });
    const wrongKeys = generateKeyPairSync("ed25519");
    assert.throws(
      () => verifyVaultDeletionReceipt(wrongKeys.publicKey, receipt),
      /vault_receipt_signer_key_mismatch/,
    );

    const wrongDomainReceipt = VaultDeletionReceiptSchema.parse({
      ...receipt,
      signature_base64: signCanonicalEd25519(
        signingKeys.privateKey,
        `${VAULT_DELETION_RECEIPT_SIGNATURE_DOMAIN}.wrong`,
        receipt.payload,
      ),
    });
    assert.throws(
      () => verifyVaultDeletionReceipt(signingKeys.publicKey, wrongDomainReceipt),
      /vault_receipt_signature_invalid/,
    );

    assert.throws(
      () =>
        verifyVaultDeletionReceipt(signingKeys.publicKey, {
          ...receipt,
          payload: { ...receipt.payload, destroyed_at_ms: 1_101 },
        }),
      /vault_receipt_signature_invalid/,
    );
  } finally {
    plaintext.fill(0);
    custody.close();
  }
});

test("receipt schema cannot sign an ambiguous deletion-complete claim", () => {
  const signingKeys = generateKeyPairSync("ed25519");
  const custody = new FakeKeyCustody({
    receipt_signing_private_key: signingKeys.privateKey,
  });
  const plaintext = syntheticBytes("scope-canary");
  try {
    const sealed = custody.sealObject({
      binding: makeBinding({ plaintext_length: plaintext.byteLength }),
      plaintext,
      now_ms: 1_000,
    });
    const receipt = custody.destroyObjectKey({
      sealed_object: sealed,
      reason: "test_cleanup",
      destroyed_at_ms: 1_100,
    });
    assert.throws(() =>
      VaultDeletionReceiptPayloadSchema.parse({
        ...receipt.payload,
        complete: true,
      }),
    );
    assert.equal("complete" in receipt.payload, false);
    assert.equal(receipt.payload.claim_scope, "object_key_only");
  } finally {
    plaintext.fill(0);
    custody.close();
  }
});

test("all public input and envelope schemas reject unknown fields", () => {
  const binding = makeBinding();
  assert.deepEqual(VaultObjectBindingSchema.parse(binding), binding);
  assert.throws(() =>
    VaultObjectBindingSchema.parse({ ...binding, provider_hint: "qwen" }),
  );
  assert.throws(() =>
    VaultSealRequestSchema.parse({
      binding,
      plaintext: syntheticBytes(),
      now_ms: 1_000,
      retry: true,
    }),
  );

  const custody = new FakeKeyCustody();
  const plaintext = syntheticBytes("strict-canary");
  try {
    const sealed = custody.sealObject({
      binding: makeBinding({ plaintext_length: plaintext.byteLength }),
      plaintext,
      now_ms: 1_000,
    });
    assert.throws(() =>
      VaultSealedObjectSchema.parse({ ...sealed, key_material: "forbidden" }),
    );
    const receipt = custody.destroyObjectKey({
      sealed_object: sealed,
      reason: "test_cleanup",
      destroyed_at_ms: 1_100,
    });
    assert.throws(() =>
      VaultDeletionReceiptSchema.parse({ ...receipt, verified: true }),
    );
  } finally {
    plaintext.fill(0);
    custody.close();
  }
});

test("retention-deadline destruction is rejected early and accepted at boundary", () => {
  const signingKeys = generateKeyPairSync("ed25519");
  const custody = new FakeKeyCustody({
    receipt_signing_private_key: signingKeys.privateKey,
  });
  const plaintext = syntheticBytes("retention-canary");
  try {
    const sealed = custody.sealObject({
      binding: makeBinding({ plaintext_length: plaintext.byteLength }),
      plaintext,
      now_ms: 1_000,
    });
    assert.throws(
      () =>
        custody.destroyObjectKey({
          sealed_object: sealed,
          reason: "retention_deadline",
          destroyed_at_ms: sealed.binding.delete_by_ms - 1,
        }),
      /vault_retention_deadline_not_reached/,
    );
    const receipt = custody.destroyObjectKey({
      sealed_object: sealed,
      reason: "retention_deadline",
      destroyed_at_ms: sealed.binding.delete_by_ms,
    });
    assert.equal(receipt.payload.destroyed_at_ms, sealed.binding.delete_by_ms);
    assert.equal(
      receipt.payload.custody_receipt_key_id,
      publicKeyId(signingKeys.publicKey),
    );
    verifyVaultDeletionReceipt(signingKeys.publicKey, receipt);
  } finally {
    plaintext.fill(0);
    custody.close();
  }
});
