import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { AnchorError } from "../evaluation/live-shadow/anchor-port.ts";
import { LiveAuthorityRegistry } from "../evaluation/live-shadow/authority-registry.ts";
import { LocalAnchorStub } from "../evaluation/live-shadow/local-anchor-stub.ts";
import {
  createOfflineCanonicalRequest,
  disposeOfflineCanonicalRequest,
} from "../evaluation/live-shadow/offline-request.ts";
import {
  createLiveContractFixture,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

function workspace() {
  const directory = mkdtempSync(join(tmpdir(), "checkback-live-authority-"));
  return {
    directory,
    anchorPath: join(directory, "anchor.sqlite"),
    authorityPath: join(directory, "authority.sqlite"),
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function initializeSystem(space, fixture, clock) {
  LocalAnchorStub.initialize({
    database_path: space.anchorPath,
    realm_id: fixture.realmId,
    private_key: fixture.anchorKeys.privateKey,
    public_key: fixture.anchorKeys.publicKey,
    now: clock,
  });
  const anchor = LocalAnchorStub.openExisting({
    database_path: space.anchorPath,
    realm_id: fixture.realmId,
    private_key: fixture.anchorKeys.privateKey,
    public_key: fixture.anchorKeys.publicKey,
    now: clock,
  });
  LiveAuthorityRegistry.initialize({
    database_path: space.authorityPath,
    registry_id: fixture.registryId,
    authority_secret: fixture.authoritySecret,
    consent_public_key: fixture.consentKeys.publicKey,
    anchor_public_key: fixture.anchorKeys.publicKey,
    anchor,
    now: clock,
  });
  return anchor;
}

function openAuthority(space, fixture, anchor, clock, seed = "session-a") {
  return LiveAuthorityRegistry.openExisting({
    database_path: space.authorityPath,
    expected_registry_id: fixture.registryId,
    authority_secret: fixture.authoritySecret,
    consent_public_key: fixture.consentKeys.publicKey,
    anchor_public_key: fixture.anchorKeys.publicKey,
    anchor,
    session_id: fixtureId("session", seed),
    now: clock,
  });
}

test("authority rejects a non-SQLite header", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  try {
    writeFileSync(space.authorityPath, Buffer.from("not-sqlite", "utf8"));
    assert.throws(
      () => openAuthority(space, fixture, {}, () => 10_000),
      /authority_database_header_invalid/,
    );
  } finally {
    space.cleanup();
  }
});
test("authority initialize/open are explicit and clean reopen advances fencing", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  let now = 10_000;
  const clock = () => now;
  let anchor;
  try {
    assert.throws(
      () => openAuthority(space, fixture, {}, clock),
      /authority_database_missing/,
    );
    anchor = initializeSystem(space, fixture, clock);
    assert.throws(
      () =>
        LiveAuthorityRegistry.initialize({
          database_path: space.authorityPath,
          registry_id: fixture.registryId,
          authority_secret: fixture.authoritySecret,
          consent_public_key: fixture.consentKeys.publicKey,
          anchor_public_key: fixture.anchorKeys.publicKey,
          anchor,
          now: clock,
        }),
      /authority_database_already_exists/,
    );
    const first = openAuthority(space, fixture, anchor, clock, "session-a");
    assert.equal(first.status().authority_state, "active");
    assert.equal(first.status().checkpoint.fencing_token, 1);
    now += 1;
    first.close();
    const second = openAuthority(space, fixture, anchor, clock, "session-b");
    assert.equal(second.status().checkpoint.fencing_token, 2);
    second.close();
  } finally {
    anchor?.close();
    space.cleanup();
  }
});

test("authority open rejects wrong registry and wrong authority secret without leaking handles", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const clock = () => 10_000;
  let anchor;
  try {
    anchor = initializeSystem(space, fixture, clock);
    assert.throws(() =>
      LiveAuthorityRegistry.openExisting({
        database_path: space.authorityPath,
        expected_registry_id: fixtureId("registry", "wrong-registry"),
        authority_secret: fixture.authoritySecret,
        consent_public_key: fixture.consentKeys.publicKey,
        anchor_public_key: fixture.anchorKeys.publicKey,
        anchor,
        session_id: fixtureId("session", "wrong-registry"),
        now: clock,
      }),
    );
    assert.throws(() =>
      LiveAuthorityRegistry.openExisting({
        database_path: space.authorityPath,
        expected_registry_id: fixture.registryId,
        authority_secret: Buffer.alloc(32, 99),
        consent_public_key: fixture.consentKeys.publicKey,
        anchor_public_key: fixture.anchorKeys.publicKey,
        anchor,
        session_id: fixtureId("session", "wrong-key"),
        now: clock,
      }),
    );
  } finally {
    anchor?.close();
    space.cleanup();
  }
});

test("anchor session fencing rejects a cloned authority database", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const clonePath = join(space.directory, "authority-clone.sqlite");
  const clock = () => 10_000;
  let anchor;
  let authority;
  try {
    anchor = initializeSystem(space, fixture, clock);
    copyFileSync(space.authorityPath, clonePath);
    authority = openAuthority(space, fixture, anchor, clock, "winner");
    assert.throws(
      () =>
        LiveAuthorityRegistry.openExisting({
          database_path: clonePath,
          expected_registry_id: fixture.registryId,
          authority_secret: fixture.authoritySecret,
          consent_public_key: fixture.consentKeys.publicKey,
          anchor_public_key: fixture.anchorKeys.publicKey,
          anchor,
          session_id: fixtureId("session", "clone"),
          now: clock,
        }),
      /authority_clone_or_rollback_detected/,
    );
  } finally {
    authority?.close();
    anchor?.close();
    space.cleanup();
  }
});

test("an old authority snapshot is rejected after the anchor advances", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const oldSnapshot = join(space.directory, "old-authority.sqlite");
  let now = 10_000;
  const clock = () => now;
  let anchor;
  try {
    anchor = initializeSystem(space, fixture, clock);
    copyFileSync(space.authorityPath, oldSnapshot);
    const authority = openAuthority(space, fixture, anchor, clock, "advance");
    authority.importAuthorization({
      signed_consent: fixture.signedConsent,
      runtime_manifest: fixture.runtime,
      now_ms: now,
    });
    now += 1;
    authority.close();
    assert.throws(
      () =>
        LiveAuthorityRegistry.openExisting({
          database_path: oldSnapshot,
          expected_registry_id: fixture.registryId,
          authority_secret: fixture.authoritySecret,
          consent_public_key: fixture.consentKeys.publicKey,
          anchor_public_key: fixture.anchorKeys.publicKey,
          anchor,
          session_id: fixtureId("session", "rollback"),
          now: clock,
        }),
      /authority_clone_or_rollback_detected/,
    );
  } finally {
    anchor?.close();
    space.cleanup();
  }
});

test("authority schema fingerprint rejects physical schema drift", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const clock = () => 10_000;
  let anchor;
  try {
    anchor = initializeSystem(space, fixture, clock);
    const db = new DatabaseSync(space.authorityPath);
    db.exec("DROP TRIGGER authority_events_no_delete");
    db.close();
    assert.throws(
      () => openAuthority(space, fixture, anchor, clock, "schema-drift"),
      /authority_schema_mismatch/,
    );
  } finally {
    anchor?.close();
    space.cleanup();
  }
});

test("authorization import, slot burn, and result are one-shot", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  let now = 10_000;
  const clock = () => now;
  let anchor;
  let authority;
  try {
    anchor = initializeSystem(space, fixture, clock);
    authority = openAuthority(space, fixture, anchor, clock);
    const imported = authority.importAuthorization({
      signed_consent: fixture.signedConsent,
      runtime_manifest: fixture.runtime,
      now_ms: now,
    });
    assert.equal(imported.max_provider_calls, 3);
    now += 1;
    const requestEnvelope = createOfflineCanonicalRequest({
      execution_plan: fixture.plan,
      runtime_manifest: fixture.runtime,
      slot: "primary",
      before_bytes: fixture.mediaPairs[0].before_bytes,
      after_bytes: fixture.mediaPairs[0].after_bytes,
    });
    const intent = authority.prepareDispatch({
      request_envelope: requestEnvelope,
      operation_id: fixtureId("op", "one-shot"),
    });
    now += 1;
    const capability = authority.burnDispatch(intent);
    disposeOfflineCanonicalRequest(requestEnvelope);
    assert.equal(
      authority.slotState(fixture.plan.execution_id, "primary"),
      "dispatching",
    );
    assert.throws(() => authority.burnDispatch(intent, now));
    assert.throws(() =>
      authority.completeDispatch({
        capability: {},
        outcome: "success",
        result_bytes: Buffer.alloc(0),
        now_ms: now,
      }),
    );
    now += 1;
    const result = Buffer.from("SYNTHETIC_PRIVATE_RESULT_CANARY", "utf8");
    authority.completeDispatch({
      capability,
      outcome: "success",
      result_bytes: result,
      now_ms: now,
    });
    assert.equal(
      authority.slotState(fixture.plan.execution_id, "primary"),
      "result",
    );
    assert.throws(() =>
      authority.completeDispatch({
        capability,
        outcome: "success",
        result_bytes: result,
        now_ms: now,
      }),
    );
    result.fill(0);
    now += 1;
    authority.close();
    authority = null;
    anchor.close();
    anchor = null;
    for (const path of [space.authorityPath, space.anchorPath]) {
      const bytes = readFileSync(path);
      assert.equal(bytes.includes("AUTHORIZED_BEFORE_0"), false);
      assert.equal(bytes.includes("AUTHORIZED_AFTER_0"), false);
      assert.equal(bytes.includes("SYNTHETIC_PRIVATE_RESULT_CANARY"), false);
    }
  } finally {
    authority?.close();
    anchor?.close();
    space.cleanup();
  }
});

test("an ambiguous anchor consume quarantines before any send capability exists", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  let now = 10_000;
  const clock = () => now;
  let anchor;
  let authority;
  try {
    anchor = initializeSystem(space, fixture, clock);
    authority = openAuthority(space, fixture, anchor, clock);
    authority.importAuthorization({
      signed_consent: fixture.signedConsent,
      runtime_manifest: fixture.runtime,
      now_ms: now,
    });
    now += 1;
    const requestEnvelope = createOfflineCanonicalRequest({
      execution_plan: fixture.plan,
      runtime_manifest: fixture.runtime,
      slot: "primary",
      before_bytes: fixture.mediaPairs[0].before_bytes,
      after_bytes: fixture.mediaPairs[0].after_bytes,
    });
    const intent = authority.prepareDispatch({
      request_envelope: requestEnvelope,
      operation_id: fixtureId("op", "anchor-outage"),
    });
    disposeOfflineCanonicalRequest(requestEnvelope);
    const originalConsume = anchor.consumeSlot.bind(anchor);
    anchor.consumeSlot = () => {
      throw new AnchorError("anchor_outcome_unknown", true);
    };
    now += 1;
    assert.throws(
      () => authority.burnDispatch(intent, now),
      /authority_anchor_slot_consume_failed/,
    );
    assert.equal(authority.status().authority_state, "quarantined");
    assert.equal(
      authority.slotState(fixture.plan.execution_id, "primary"),
      "anchor_ambiguous",
    );
    anchor.consumeSlot = originalConsume;
  } finally {
    authority?.close();
    anchor?.close();
    space.cleanup();
  }
});

test("authority projection HMAC rejects offline row tampering on reopen", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  let now = 10_000;
  const clock = () => now;
  let anchor;
  let authority;
  try {
    anchor = initializeSystem(space, fixture, clock);
    authority = openAuthority(space, fixture, anchor, clock);
    authority.importAuthorization({
      signed_consent: fixture.signedConsent,
      runtime_manifest: fixture.runtime,
    });
    now += 1;
    authority.close();
    authority = null;
    const db = new DatabaseSync(space.authorityPath);
    db.prepare(
      "UPDATE call_slots SET state='result' WHERE execution_id=? AND slot='primary'",
    ).run(fixture.plan.execution_id);
    db.close();
    assert.throws(
      () => openAuthority(space, fixture, anchor, clock, "tampered-reopen"),
      /authority_projection_hmac_invalid/,
    );
  } finally {
    try {
      authority?.close();
    } catch {}
    anchor?.close();
    space.cleanup();
  }
});

test("opened authority rejects projection changes from a second writer", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const clock = () => 10_000;
  let anchor;
  let authority;
  try {
    anchor = initializeSystem(space, fixture, clock);
    authority = openAuthority(space, fixture, anchor, clock);
    authority.importAuthorization({
      signed_consent: fixture.signedConsent,
      runtime_manifest: fixture.runtime,
    });
    const db = new DatabaseSync(space.authorityPath);
    db.prepare(
      "UPDATE authorizations SET expires_at_ms=expires_at_ms+1 WHERE authorization_id=?",
    ).run(fixture.consent.authorization_id);
    db.close();
    assert.throws(() => authority.status(), /authority_projection_hmac_invalid/);
  } finally {
    try {
      authority?.close();
    } catch {}
    anchor?.close();
    space.cleanup();
  }
});

test("burn uses the private authority clock at the exact expiry boundary", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  let now = 10_000;
  const clock = () => now;
  let anchor;
  let authority;
  let envelope;
  try {
    anchor = initializeSystem(space, fixture, clock);
    authority = openAuthority(space, fixture, anchor, clock);
    authority.importAuthorization({
      signed_consent: fixture.signedConsent,
      runtime_manifest: fixture.runtime,
    });
    now = fixture.consent.expires_at_ms - 1;
    envelope = createOfflineCanonicalRequest({
      execution_plan: fixture.plan,
      runtime_manifest: fixture.runtime,
      slot: "primary",
      before_bytes: fixture.mediaPairs[0].before_bytes,
      after_bytes: fixture.mediaPairs[0].after_bytes,
    });
    const intent = authority.prepareDispatch({
      request_envelope: envelope,
      operation_id: fixtureId("op", "expiry-boundary"),
    });
    disposeOfflineCanonicalRequest(envelope);
    envelope = null;
    now = fixture.consent.expires_at_ms;
    assert.throws(
      () => authority.burnDispatch(intent, fixture.consent.expires_at_ms - 1),
      /authority_dispatch_intent_expired/,
    );
    assert.equal(
      authority.slotState(fixture.plan.execution_id, "primary"),
      "prepared",
    );
  } finally {
    if (envelope) disposeOfflineCanonicalRequest(envelope);
    try {
      authority?.close();
    } catch {}
    anchor?.close();
    space.cleanup();
  }
});

test("authority rejects a forged canonical request envelope", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const clock = () => 10_000;
  let anchor;
  let authority;
  try {
    anchor = initializeSystem(space, fixture, clock);
    authority = openAuthority(space, fixture, anchor, clock);
    authority.importAuthorization({
      signed_consent: fixture.signedConsent,
      runtime_manifest: fixture.runtime,
    });
    assert.throws(
      () =>
        authority.prepareDispatch({
          request_envelope: Object.freeze({}),
          operation_id: fixtureId("op", "forged-envelope"),
        }),
      /authority_request_envelope_invalid/,
    );
  } finally {
    authority?.close();
    anchor?.close();
    space.cleanup();
  }
});
test("opened authority rejects runtime physical schema drift", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const clock = () => 10_000;
  let anchor;
  let authority;
  try {
    anchor = initializeSystem(space, fixture, clock);
    authority = openAuthority(space, fixture, anchor, clock);
    const db = new DatabaseSync(space.authorityPath);
    db.exec("DROP TRIGGER authority_events_no_delete");
    db.close();
    assert.throws(() => authority.status(), /authority_schema_mismatch/);
  } finally {
    try {
      authority?.close();
    } catch {}
    anchor?.close();
    space.cleanup();
  }
});
test("result persistence failure immediately quarantines the authority", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  let now = 10_000;
  const clock = () => now;
  let anchor;
  let authority;
  let envelope;
  const originalPrepare = DatabaseSync.prototype.prepare;
  try {
    anchor = initializeSystem(space, fixture, clock);
    authority = openAuthority(space, fixture, anchor, clock);
    authority.importAuthorization({
      signed_consent: fixture.signedConsent,
      runtime_manifest: fixture.runtime,
    });
    now += 1;
    envelope = createOfflineCanonicalRequest({
      execution_plan: fixture.plan,
      runtime_manifest: fixture.runtime,
      slot: "primary",
      before_bytes: fixture.mediaPairs[0].before_bytes,
      after_bytes: fixture.mediaPairs[0].after_bytes,
    });
    const intent = authority.prepareDispatch({
      request_envelope: envelope,
      operation_id: fixtureId("op", "result-persist-failure"),
    });
    const capability = authority.burnDispatch(intent);
    disposeOfflineCanonicalRequest(envelope);
    envelope = null;
    DatabaseSync.prototype.prepare = function prepare(sql) {
      if (String(sql).startsWith("UPDATE call_slots SET state='result'")) {
        throw new Error("synthetic_result_persist_failure");
      }
      return originalPrepare.call(this, sql);
    };
    assert.throws(
      () =>
        authority.completeDispatch({
          capability,
          outcome: "success",
          result_bytes: Buffer.from("SYNTHETIC_RESULT", "utf8"),
        }),
      /authority_result_persist_failed/,
    );
    DatabaseSync.prototype.prepare = originalPrepare;
    assert.equal(authority.status().authority_state, "quarantined");
    assert.throws(
      () =>
        authority.completeDispatch({
          capability,
          outcome: "success",
          result_bytes: Buffer.alloc(0),
        }),
      /authority_not_active/,
    );
  } finally {
    DatabaseSync.prototype.prepare = originalPrepare;
    if (envelope) disposeOfflineCanonicalRequest(envelope);
    try {
      authority?.close();
    } catch {}
    anchor?.close();
    space.cleanup();
  }
});

test("anchor claim followed by local activation failure quarantines", () => {
  const space = workspace();
  const fixture = createLiveContractFixture({ count: 1 });
  const clock = () => 10_000;
  let anchor;
  let authority;
  const originalPrepare = DatabaseSync.prototype.prepare;
  try {
    anchor = initializeSystem(space, fixture, clock);
    authority = openAuthority(space, fixture, anchor, clock);
    DatabaseSync.prototype.prepare = function prepare(sql) {
      if (String(sql).startsWith("UPDATE authorizations SET state='active'")) {
        throw new Error("synthetic_activation_persist_failure");
      }
      return originalPrepare.call(this, sql);
    };
    assert.throws(
      () =>
        authority.importAuthorization({
          signed_consent: fixture.signedConsent,
          runtime_manifest: fixture.runtime,
        }),
      /authority_local_authorization_activation_failed/,
    );
    DatabaseSync.prototype.prepare = originalPrepare;
    assert.equal(authority.status().authority_state, "quarantined");
  } finally {
    DatabaseSync.prototype.prepare = originalPrepare;
    try {
      authority?.close();
    } catch {}
    anchor?.close();
    space.cleanup();
  }
});