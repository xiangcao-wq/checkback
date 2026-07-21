import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  closeSync,
  mkdtempSync,
  openSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { sha256Canonical, secretKeyId } from "../evaluation/live-shadow/crypto.ts";
import {
  computeLiveSlotKey,
  LocalAnchorStub,
} from "../evaluation/live-shadow/local-anchor-stub.ts";
import {
  createLiveContractFixture,
  fixtureHash,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

function tempWorkspace() {
  const directory = mkdtempSync(join(tmpdir(), "checkback-live-anchor-"));
  return {
    directory,
    databasePath: join(directory, "anchor.sqlite"),
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function initializeFixtureAnchor(workspace, fixture, now = 10_000) {
  LocalAnchorStub.initialize({
    database_path: workspace.databasePath,
    realm_id: fixture.realmId,
    private_key: fixture.anchorKeys.privateKey,
    public_key: fixture.anchorKeys.publicKey,
    now: () => now,
  });
  return LocalAnchorStub.openExisting({
    database_path: workspace.databasePath,
    realm_id: fixture.realmId,
    private_key: fixture.anchorKeys.privateKey,
    public_key: fixture.anchorKeys.publicKey,
    now: () => now,
  });
}

function registerAndAcquire(anchor, fixture, registryId, seed) {
  anchor.registerRegistry({
    authority_registry_id: registryId,
    authority_key_id: secretKeyId(fixture.authoritySecret),
    recorded_at_ms: 10_000,
  });
  const sessionId = fixtureId("session", seed);
  anchor.acquireSession({
    authority_registry_id: registryId,
    expected_checkpoint: anchor.inspectRegistry(registryId),
    session_id: sessionId,
    recorded_at_ms: 10_001,
  });
  return sessionId;
}

function claimInput(anchor, fixture, registryId, sessionId) {
  const checkpoint = anchor.inspectRegistry(registryId);
  return {
    authority_registry_id: registryId,
    expected_checkpoint: checkpoint,
    session_id: sessionId,
    fencing_token: checkpoint.fencing_token,
    authorization_id: fixture.consent.authorization_id,
    authorization_fingerprint_sha256: sha256Canonical(fixture.signedConsent),
    signed_consent_sha256: sha256Canonical(fixture.signedConsent),
    runtime_manifest_sha256: sha256Canonical(fixture.runtime),
    expires_at_ms: fixture.consent.expires_at_ms,
    executions: fixture.consent.authorized_executions.map((execution) => ({
      execution_id: execution.execution_id,
      media_scope_id: execution.media_scope_id,
      pair_commitment_hmac_sha256:
        execution.pair_commitment_hmac_sha256,
    })),
    recorded_at_ms: 10_002,
  };
}

test("local anchor initialization and open-existing are distinct and fail closed", () => {
  const workspace = tempWorkspace();
  const fixture = createLiveContractFixture();
  try {
    assert.throws(
      () =>
        LocalAnchorStub.openExisting({
          database_path: workspace.databasePath,
          realm_id: fixture.realmId,
          private_key: fixture.anchorKeys.privateKey,
          public_key: fixture.anchorKeys.publicKey,
        }),
      /anchor_database_missing/,
    );
    LocalAnchorStub.initialize({
      database_path: workspace.databasePath,
      realm_id: fixture.realmId,
      private_key: fixture.anchorKeys.privateKey,
      public_key: fixture.anchorKeys.publicKey,
    });
    assert.throws(
      () =>
        LocalAnchorStub.initialize({
          database_path: workspace.databasePath,
          realm_id: fixture.realmId,
          private_key: fixture.anchorKeys.privateKey,
          public_key: fixture.anchorKeys.publicKey,
        }),
      /anchor_database_already_exists/,
    );
    const anchor = LocalAnchorStub.openExisting({
      database_path: workspace.databasePath,
      realm_id: fixture.realmId,
      private_key: fixture.anchorKeys.privateKey,
      public_key: fixture.anchorKeys.publicKey,
    });
    anchor.close();
  } finally {
    workspace.cleanup();
  }
});

test("local anchor rejects empty state, wrong realm, and wrong signing key", () => {
  const empty = tempWorkspace();
  const fixture = createLiveContractFixture();
  try {
    closeSync(openSync(empty.databasePath, "wx"));
    assert.throws(
      () =>
        LocalAnchorStub.openExisting({
          database_path: empty.databasePath,
          realm_id: fixture.realmId,
          private_key: fixture.anchorKeys.privateKey,
          public_key: fixture.anchorKeys.publicKey,
        }),
      /anchor_database_empty/,
    );
  } finally {
    empty.cleanup();
  }

  const workspace = tempWorkspace();
  const anchor = initializeFixtureAnchor(workspace, fixture);
  anchor.close();
  try {
    assert.throws(() =>
      LocalAnchorStub.openExisting({
        database_path: workspace.databasePath,
        realm_id: fixtureId("realm", "wrong-realm"),
        private_key: fixture.anchorKeys.privateKey,
        public_key: fixture.anchorKeys.publicKey,
      }),
    );
    const other = generateKeyPairSync("ed25519");
    assert.throws(() =>
      LocalAnchorStub.openExisting({
        database_path: workspace.databasePath,
        realm_id: fixture.realmId,
        private_key: other.privateKey,
        public_key: other.publicKey,
      }),
    );
  } finally {
    workspace.cleanup();
  }
});

test("local anchor rejects a non-SQLite header", () => {
  const workspace = tempWorkspace();
  const fixture = createLiveContractFixture({ count: 1 });
  try {
    writeFileSync(workspace.databasePath, Buffer.from("not-sqlite", "utf8"));
    assert.throws(
      () =>
        LocalAnchorStub.openExisting({
          database_path: workspace.databasePath,
          realm_id: fixture.realmId,
          private_key: fixture.anchorKeys.privateKey,
          public_key: fixture.anchorKeys.publicKey,
        }),
      /anchor_database_header_invalid/,
    );
  } finally {
    workspace.cleanup();
  }
});
test("anchor checkpoint CAS and session fencing are monotonic", () => {
  const workspace = tempWorkspace();
  const fixture = createLiveContractFixture();
  const anchor = initializeFixtureAnchor(workspace, fixture);
  try {
    const registration = anchor.registerRegistry({
      authority_registry_id: fixture.registryId,
      authority_key_id: secretKeyId(fixture.authoritySecret),
      recorded_at_ms: 10_000,
    });
    assert.equal(registration.payload.registry_sequence, 1);
    const initial = anchor.inspectRegistry(fixture.registryId);
    const sessionId = fixtureId("session", "session-a");
    const acquired = anchor.acquireSession({
      authority_registry_id: fixture.registryId,
      expected_checkpoint: initial,
      session_id: sessionId,
      recorded_at_ms: 10_001,
    });
    assert.equal(acquired.payload.registry_sequence, 2);
    assert.equal(acquired.payload.fencing_token, 1);
    assert.throws(
      () =>
        anchor.acquireSession({
          authority_registry_id: fixture.registryId,
          expected_checkpoint: initial,
          session_id: fixtureId("session", "clone"),
          recorded_at_ms: 10_002,
        }),
      /anchor_checkpoint_mismatch/,
    );
  } finally {
    anchor.close();
    workspace.cleanup();
  }
});

test("one anchor globally rejects the same authorization across registries", () => {
  const workspace = tempWorkspace();
  const fixture = createLiveContractFixture();
  const anchor = initializeFixtureAnchor(workspace, fixture);
  const secondRegistry = fixtureId("registry", "registry-b");
  try {
    const sessionA = registerAndAcquire(
      anchor,
      fixture,
      fixture.registryId,
      "session-a",
    );
    const sessionB = registerAndAcquire(
      anchor,
      fixture,
      secondRegistry,
      "session-b",
    );
    anchor.claimAuthorization(
      claimInput(anchor, fixture, fixture.registryId, sessionA),
    );
    assert.throws(
      () =>
        anchor.claimAuthorization(
          claimInput(anchor, fixture, secondRegistry, sessionB),
        ),
      /anchor_authorization_already_claimed/,
    );
  } finally {
    anchor.close();
    workspace.cleanup();
  }
});

test("slot burn is non-idempotent even for the same operation", () => {
  const workspace = tempWorkspace();
  const fixture = createLiveContractFixture();
  const anchor = initializeFixtureAnchor(workspace, fixture);
  try {
    const sessionId = registerAndAcquire(
      anchor,
      fixture,
      fixture.registryId,
      "session-a",
    );
    anchor.claimAuthorization(
      claimInput(anchor, fixture, fixture.registryId, sessionId),
    );
    const checkpoint = anchor.inspectRegistry(fixture.registryId);
    const intent = {
      schema_version: "checkback.live-shadow.dispatch-intent.v1",
      authority_registry_id: fixture.registryId,
      anchor_realm_id: fixture.realmId,
      authorization_id: fixture.consent.authorization_id,
      authorization_fingerprint_sha256: sha256Canonical(
        fixture.signedConsent,
      ),
      execution_id: fixture.plan.execution_id,
      media_scope_id: fixture.plan.media_scope_id,
      pair_commitment_hmac_sha256:
        fixture.plan.pair_commitment_hmac_sha256,
      slot: "primary",
      ordinal: 1,
      operation_id: fixtureId("op", "operation-a"),
      request_commitment_hmac_sha256: fixtureHash("request-a"),
      runtime_manifest_sha256: sha256Canonical(fixture.runtime),
      created_at_ms: 10_000,
      expires_at_ms: fixture.consent.expires_at_ms,
    };
    const consumed = anchor.consumeSlot({
      authority_registry_id: fixture.registryId,
      expected_checkpoint: checkpoint,
      session_id: sessionId,
      fencing_token: checkpoint.fencing_token,
      intent,
      recorded_at_ms: 10_003,
    });
    assert.equal(consumed.payload.event_type, "consume_slot");
    assert.equal(
      computeLiveSlotKey(intent),
      computeLiveSlotKey({
        authorization_id: intent.authorization_id,
        execution_id: intent.execution_id,
        slot: intent.slot,
      }),
    );
    const next = anchor.inspectRegistry(fixture.registryId);
    assert.throws(
      () =>
        anchor.consumeSlot({
          authority_registry_id: fixture.registryId,
          expected_checkpoint: next,
          session_id: sessionId,
          fencing_token: next.fencing_token,
          intent,
          recorded_at_ms: 10_004,
        }),
      /anchor_slot_already_consumed/,
    );
  } finally {
    anchor.close();
    workspace.cleanup();
  }
});

test("anchor rejects physical schema drift on reopen", () => {
  const workspace = tempWorkspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const anchor = initializeFixtureAnchor(workspace, fixture);
  anchor.close();
  try {
    const db = new DatabaseSync(workspace.databasePath);
    db.exec("DROP TRIGGER anchor_events_no_delete");
    db.close();
    assert.throws(
      () =>
        LocalAnchorStub.openExisting({
          database_path: workspace.databasePath,
          realm_id: fixture.realmId,
          private_key: fixture.anchorKeys.privateKey,
          public_key: fixture.anchorKeys.publicKey,
        }),
      /anchor_schema_mismatch/,
    );
  } finally {
    workspace.cleanup();
  }
});

test("opened anchor rejects projection rows inserted by a second writer", () => {
  const workspace = tempWorkspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const anchor = initializeFixtureAnchor(workspace, fixture);
  try {
    const sessionId = registerAndAcquire(
      anchor,
      fixture,
      fixture.registryId,
      "projection-session",
    );
    anchor.claimAuthorization(
      claimInput(anchor, fixture, fixture.registryId, sessionId),
    );
    const checkpoint = anchor.inspectRegistry(fixture.registryId);
    const intent = {
      schema_version: "checkback.live-shadow.dispatch-intent.v1",
      authority_registry_id: fixture.registryId,
      anchor_realm_id: fixture.realmId,
      authorization_id: fixture.consent.authorization_id,
      authorization_fingerprint_sha256: sha256Canonical(
        fixture.signedConsent,
      ),
      execution_id: fixture.plan.execution_id,
      media_scope_id: fixture.plan.media_scope_id,
      pair_commitment_hmac_sha256:
        fixture.plan.pair_commitment_hmac_sha256,
      slot: "primary",
      ordinal: 1,
      operation_id: fixtureId("op", "projection-consume"),
      request_commitment_hmac_sha256: fixtureHash("projection-request"),
      runtime_manifest_sha256: sha256Canonical(fixture.runtime),
      created_at_ms: 10_003,
      expires_at_ms: fixture.consent.expires_at_ms,
    };
    const forgedExecutionId = fixtureId("exec", "forged-execution");
    const forgedScopeId = fixtureId("scope", "forged-scope");
    const db = new DatabaseSync(workspace.databasePath);
    db.exec("PRAGMA foreign_keys=ON");
    db.prepare(
      "INSERT INTO execution_ids VALUES(?,?,?,?,?,?)",
    ).run(
      forgedExecutionId,
      fixture.consent.authorization_id,
      fixture.registryId,
      2,
      forgedScopeId,
      fixtureHash("forged-pair"),
    );
    const insertSlot = db.prepare(
      "INSERT INTO call_slots(slot_key_sha256,authorization_id,execution_id,slot,ordinal,state) " +
        "VALUES(?,?,?,?,?,'allocated')",
    );
    ["primary", "flash", "plus"].forEach((slot, index) => {
      insertSlot.run(
        computeLiveSlotKey({
          authorization_id: fixture.consent.authorization_id,
          execution_id: forgedExecutionId,
          slot,
        }),
        fixture.consent.authorization_id,
        forgedExecutionId,
        slot,
        index + 1,
      );
    });
    db.close();
    assert.throws(
      () =>
        anchor.consumeSlot({
          authority_registry_id: fixture.registryId,
          expected_checkpoint: checkpoint,
          session_id: sessionId,
          fencing_token: checkpoint.fencing_token,
          intent,
          recorded_at_ms: 10_003,
        }),
      /anchor_authorization_projection_invalid/,
    );
  } finally {
    anchor.close();
    workspace.cleanup();
  }
});
test("opened anchor rejects runtime physical schema drift", () => {
  const workspace = tempWorkspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const anchor = initializeFixtureAnchor(workspace, fixture);
  try {
    const db = new DatabaseSync(workspace.databasePath);
    db.exec("DROP TRIGGER anchor_events_no_delete");
    const changedSchema = db.prepare(
      "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' " +
        "ORDER BY type,name",
    ).all();
    db.prepare(
      "UPDATE anchor_meta SET value=? WHERE key='physical_schema_sha256'",
    ).run(sha256Canonical(changedSchema));
    db.close();
    assert.throws(
      () => anchor.inspectRegistry(fixture.registryId),
      /anchor_schema_mismatch/,
    );
  } finally {
    anchor.close();
    workspace.cleanup();
  }
});
test("anchor canonical intent detects redundant slot-field tampering", () => {
  const workspace = tempWorkspace();
  const fixture = createLiveContractFixture({ count: 1 });
  let anchor = initializeFixtureAnchor(workspace, fixture);
  try {
    const sessionId = registerAndAcquire(
      anchor,
      fixture,
      fixture.registryId,
      "canonical-intent-session",
    );
    anchor.claimAuthorization(
      claimInput(anchor, fixture, fixture.registryId, sessionId),
    );
    const checkpoint = anchor.inspectRegistry(fixture.registryId);
    const intent = {
      schema_version: "checkback.live-shadow.dispatch-intent.v1",
      authority_registry_id: fixture.registryId,
      anchor_realm_id: fixture.realmId,
      authorization_id: fixture.consent.authorization_id,
      authorization_fingerprint_sha256: sha256Canonical(
        fixture.signedConsent,
      ),
      execution_id: fixture.plan.execution_id,
      media_scope_id: fixture.plan.media_scope_id,
      pair_commitment_hmac_sha256:
        fixture.plan.pair_commitment_hmac_sha256,
      slot: "primary",
      ordinal: 1,
      operation_id: fixtureId("op", "canonical-intent-original"),
      request_commitment_hmac_sha256: fixtureHash("canonical-request"),
      runtime_manifest_sha256: sha256Canonical(fixture.runtime),
      created_at_ms: 10_000,
      expires_at_ms: fixture.consent.expires_at_ms,
    };
    anchor.consumeSlot({
      authority_registry_id: fixture.registryId,
      expected_checkpoint: checkpoint,
      session_id: sessionId,
      fencing_token: checkpoint.fencing_token,
      intent,
      recorded_at_ms: 10_003,
    });
    anchor.close();
    anchor = null;
    const db = new DatabaseSync(workspace.databasePath);
    const trigger = db.prepare(
      "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='call_slots_monotonic'",
    ).get();
    db.exec("DROP TRIGGER call_slots_monotonic");
    db.prepare(
      "UPDATE call_slots SET operation_id=? WHERE execution_id=? AND slot='primary'",
    ).run(
      fixtureId("op", "canonical-intent-tampered"),
      fixture.plan.execution_id,
    );
    db.exec(trigger.sql);
    db.close();
    assert.throws(
      () =>
        LocalAnchorStub.openExisting({
          database_path: workspace.databasePath,
          realm_id: fixture.realmId,
          private_key: fixture.anchorKeys.privateKey,
          public_key: fixture.anchorKeys.publicKey,
          now: () => 10_000,
        }),
      /anchor_dispatch_intent_projection_invalid/,
    );
  } finally {
    anchor?.close();
    workspace.cleanup();
  }
});