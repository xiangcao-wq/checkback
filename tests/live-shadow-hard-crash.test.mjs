import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { LiveAuthorityRegistry } from "../evaluation/live-shadow/authority-registry.ts";
import { LocalAnchorStub } from "../evaluation/live-shadow/local-anchor-stub.ts";
import {
  createLiveContractFixture,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

const SCENARIOS = Object.freeze([
  Object.freeze({
    name: "anchor commit before authority dispatching persistence",
    scenario: "anchor_committed_before_authority",
    exitCode: 71,
    sendAttempts: 0,
    authoritySlotState: "prepared",
  }),
  Object.freeze({
    name: "authority dispatching persistence before fake send",
    scenario: "dispatching_before_send",
    exitCode: 72,
    sendAttempts: 0,
    authoritySlotState: "dispatching",
  }),
  Object.freeze({
    name: "one fake send before result persistence",
    scenario: "sent_before_result",
    exitCode: 73,
    sendAttempts: 1,
    authoritySlotState: "dispatching",
  }),
]);

function exportPrivateKey(key) {
  return key.export({ type: "pkcs8", format: "pem" }).toString();
}

function exportPublicKey(key) {
  return key.export({ type: "spki", format: "pem" }).toString();
}

function prepareCase(scenario) {
  const directory = mkdtempSync(join(tmpdir(), "checkback-live-hard-crash-"));
  const anchorPath = join(directory, "anchor.sqlite");
  const authorityPath = join(directory, "authority.sqlite");
  const markerPath = join(directory, "hard-crash-marker.json");
  const configPath = join(directory, "worker-config.json");
  const fixture = createLiveContractFixture({ count: 1 });
  const setupClock = () => 10_001;
  let anchor;
  let authority;
  try {
    LocalAnchorStub.initialize({
      database_path: anchorPath,
      realm_id: fixture.realmId,
      private_key: fixture.anchorKeys.privateKey,
      public_key: fixture.anchorKeys.publicKey,
      now: setupClock,
    });
    anchor = LocalAnchorStub.openExisting({
      database_path: anchorPath,
      realm_id: fixture.realmId,
      private_key: fixture.anchorKeys.privateKey,
      public_key: fixture.anchorKeys.publicKey,
      now: setupClock,
    });
    LiveAuthorityRegistry.initialize({
      database_path: authorityPath,
      registry_id: fixture.registryId,
      authority_secret: fixture.authoritySecret,
      consent_public_key: fixture.consentKeys.publicKey,
      anchor_public_key: fixture.anchorKeys.publicKey,
      anchor,
      now: setupClock,
    });
    authority = LiveAuthorityRegistry.openExisting({
      database_path: authorityPath,
      expected_registry_id: fixture.registryId,
      authority_secret: fixture.authoritySecret,
      consent_public_key: fixture.consentKeys.publicKey,
      anchor_public_key: fixture.anchorKeys.publicKey,
      anchor,
      session_id: fixtureId("session", `hard-crash-setup-${scenario}`),
      now: setupClock,
    });
    authority.importAuthorization({
      signed_consent: fixture.signedConsent,
      runtime_manifest: fixture.runtime,
    });
    authority.close();
    authority = null;
    anchor.close();
    anchor = null;
  } catch (error) {
    authority?.close();
    anchor?.close();
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }

  const config = {
    scenario,
    anchor_path: anchorPath,
    authority_path: authorityPath,
    marker_path: markerPath,
    realm_id: fixture.realmId,
    registry_id: fixture.registryId,
    authority_secret_hex: fixture.authoritySecret.toString("hex"),
    anchor_private_key_pem: exportPrivateKey(fixture.anchorKeys.privateKey),
    anchor_public_key_pem: exportPublicKey(fixture.anchorKeys.publicKey),
    consent_public_key_pem: exportPublicKey(fixture.consentKeys.publicKey),
    session_id: fixtureId("session", `hard-crash-worker-${scenario}`),
    operation_id: fixtureId("op", `hard-crash-${scenario}`),
    now_ms: 20_000,
    execution_plan: fixture.plan,
    runtime_manifest: fixture.runtime,
    before_bytes_base64: fixture.mediaPairs[0].before_bytes.toString("base64"),
    after_bytes_base64: fixture.mediaPairs[0].after_bytes.toString("base64"),
  };
  writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
  return {
    directory,
    anchorPath,
    authorityPath,
    markerPath,
    configPath,
    config,
    fixture,
  };
}

function readAuthorityState(space) {
  const db = new DatabaseSync(space.authorityPath, { readOnly: true });
  try {
    const slot = db.prepare(
      "SELECT state,operation_id FROM call_slots WHERE execution_id=? AND slot='primary'",
    ).get(space.fixture.plan.execution_id);
    const metaRows = db.prepare(
      "SELECT key,value FROM authority_meta WHERE key IN ('authority_state','registry_sequence')",
    ).all();
    return {
      slot,
      meta: Object.fromEntries(metaRows.map((row) => [row.key, row.value])),
    };
  } finally {
    db.close();
  }
}

function readAnchorSlot(space) {
  const db = new DatabaseSync(space.anchorPath, { readOnly: true });
  try {
    return db.prepare(
      "SELECT state,operation_id,consumed_registry_sequence FROM call_slots " +
        "WHERE execution_id=? AND slot='primary'",
    ).get(space.fixture.plan.execution_id);
  } finally {
    db.close();
  }
}

function assertRestartFailsClosed(space) {
  const anchorPrivateKey = createPrivateKey(space.config.anchor_private_key_pem);
  const anchorPublicKey = createPublicKey(space.config.anchor_public_key_pem);
  const consentPublicKey = createPublicKey(space.config.consent_public_key_pem);
  const anchor = LocalAnchorStub.openExisting({
    database_path: space.anchorPath,
    realm_id: space.config.realm_id,
    private_key: anchorPrivateKey,
    public_key: anchorPublicKey,
    now: () => 30_000,
  });
  try {
    let recoveredAuthority;
    assert.throws(
      () => {
        recoveredAuthority = LiveAuthorityRegistry.openExisting({
          database_path: space.authorityPath,
          expected_registry_id: space.config.registry_id,
          authority_secret: Buffer.from(
            space.config.authority_secret_hex,
            "hex",
          ),
          consent_public_key: consentPublicKey,
          anchor_public_key: anchorPublicKey,
          anchor,
          session_id: fixtureId(
            "session",
            `hard-crash-recovery-${space.config.scenario}`,
          ),
          now: () => 30_000,
        });
      },
      /authority_not_cleanly_closed/,
    );
    assert.equal(recoveredAuthority, undefined);
  } finally {
    anchor.close();
  }
}

for (const scenario of SCENARIOS) {
  test(`hard process crash: ${scenario.name} is fail-closed`, () => {
    const space = prepareCase(scenario.scenario);
    try {
      const child = spawnSync(
        process.execPath,
        [
          "--experimental-strip-types",
          "tests/helpers/live-shadow-hard-crash-process.mjs",
          space.configPath,
        ],
        {
          cwd: process.cwd(),
          encoding: "utf8",
          windowsHide: true,
          timeout: 20_000,
        },
      );
      assert.equal(child.error, undefined);
      assert.equal(
        child.status,
        scenario.exitCode,
        `unexpected child output: ${child.stderr}`,
      );
      assert.equal(child.signal, null);

      const markerText = readFileSync(space.markerPath, "utf8");
      const marker = JSON.parse(markerText);
      assert.equal(marker.phase, scenario.scenario);
      assert.equal(marker.network_calls, 0);
      assert.equal(marker.send_attempts, scenario.sendAttempts);

      const authority = readAuthorityState(space);
      assert.equal(authority.meta.authority_state, "active");
      assert.equal(authority.slot.state, scenario.authoritySlotState);
      assert.equal(authority.slot.operation_id, space.config.operation_id);

      const anchorSlot = readAnchorSlot(space);
      assert.equal(anchorSlot.state, "consumed");
      assert.equal(anchorSlot.operation_id, space.config.operation_id);
      assert.ok(anchorSlot.consumed_registry_sequence > 0);

      assertRestartFailsClosed(space);
      assert.equal(readFileSync(space.markerPath, "utf8"), markerText);
    } finally {
      rmSync(space.directory, { recursive: true, force: true });
    }
  });
}
