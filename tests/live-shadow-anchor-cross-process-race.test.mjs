import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { secretKeyId, sha256Canonical } from "../evaluation/live-shadow/crypto.ts";
import { LocalAnchorStub } from "../evaluation/live-shadow/local-anchor-stub.ts";
import {
  createLiveContractFixture,
  fixtureHash,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

const WORKER_PATH = "tests/helpers/live-shadow-anchor-claim-racer.mjs";

function runRacer(configPath) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", WORKER_PATH, configPath],
      { cwd: process.cwd(), windowsHide: true },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code !== 0) {
        reject(new Error(`anchor_claim_racer_exit_${code}:${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(new Error(`anchor_claim_racer_invalid_output:${stdout}:${stderr}`));
      }
    });
  });
}

async function waitUntilReady(paths) {
  const deadline = Date.now() + 10_000;
  while (!paths.every((path) => existsSync(path))) {
    if (Date.now() >= deadline) {
      throw new Error("anchor_claim_racers_not_ready");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function claimFromFixture(fixture, overrides = {}) {
  return {
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
    ...overrides,
  };
}

async function runClaimRace({ claimA, claimB, expectedLoserCode }) {
  const directory = mkdtempSync(join(tmpdir(), "checkback-anchor-claim-race-"));
  const anchorPath = join(directory, "anchor.sqlite");
  const barrierPath = join(directory, "go.barrier");
  const readyA = join(directory, "racer-a.ready");
  const readyB = join(directory, "racer-b.ready");
  const fixture = createLiveContractFixture({ count: 1 });
  const registryA = fixtureId("registry", "claim-race-registry-a");
  const registryB = fixtureId("registry", "claim-race-registry-b");
  const sessionA = fixtureId("session", "claim-race-session-a");
  const sessionB = fixtureId("session", "claim-race-session-b");
  let anchor;
  try {
    LocalAnchorStub.initialize({
      database_path: anchorPath,
      realm_id: fixture.realmId,
      private_key: fixture.anchorKeys.privateKey,
      public_key: fixture.anchorKeys.publicKey,
      now: () => 10_000,
    });
    anchor = LocalAnchorStub.openExisting({
      database_path: anchorPath,
      realm_id: fixture.realmId,
      private_key: fixture.anchorKeys.privateKey,
      public_key: fixture.anchorKeys.publicKey,
      now: () => 10_000,
    });
    const authorityKeyId = secretKeyId(fixture.authoritySecret);
    for (const [registryId, sessionId] of [
      [registryA, sessionA],
      [registryB, sessionB],
    ]) {
      anchor.registerRegistry({
        authority_registry_id: registryId,
        authority_key_id: authorityKeyId,
        recorded_at_ms: 10_000,
      });
      const checkpoint = anchor.inspectRegistry(registryId);
      anchor.acquireSession({
        authority_registry_id: registryId,
        expected_checkpoint: checkpoint,
        session_id: sessionId,
        recorded_at_ms: 10_000,
      });
    }
    const checkpointA = anchor.inspectRegistry(registryA);
    const checkpointB = anchor.inspectRegistry(registryB);
    assert.equal(checkpointA.active_session_id, sessionA);
    assert.equal(checkpointB.active_session_id, sessionB);
    anchor.close();
    anchor = null;

    const common = {
      anchor_path: anchorPath,
      barrier_path: barrierPath,
      realm_id: fixture.realmId,
      anchor_private_key_pem: fixture.anchorKeys.privateKey
        .export({ type: "pkcs8", format: "pem" })
        .toString(),
      anchor_public_key_pem: fixture.anchorKeys.publicKey
        .export({ type: "spki", format: "pem" })
        .toString(),
      now_ms: 10_001,
    };
    const configAPath = join(directory, "racer-a.json");
    const configBPath = join(directory, "racer-b.json");
    writeFileSync(
      configAPath,
      JSON.stringify({
        ...common,
        ready_path: readyA,
        registry_id: registryA,
        session_id: sessionA,
        fencing_token: checkpointA.fencing_token,
        claim: claimA(fixture),
      }),
      { mode: 0o600 },
    );
    writeFileSync(
      configBPath,
      JSON.stringify({
        ...common,
        ready_path: readyB,
        registry_id: registryB,
        session_id: sessionB,
        fencing_token: checkpointB.fencing_token,
        claim: claimB(fixture),
      }),
      { mode: 0o600 },
    );

    const racers = [runRacer(configAPath), runRacer(configBPath)];
    await waitUntilReady([readyA, readyB]);
    writeFileSync(barrierPath, "go", { mode: 0o600 });
    const results = await Promise.all(racers);
    assert.equal(results.filter((result) => result.ok).length, 1, JSON.stringify(results));
    assert.equal(results.filter((result) => !result.ok).length, 1, JSON.stringify(results));
    assert.equal(results.find((result) => !result.ok).code, expectedLoserCode);

    anchor = LocalAnchorStub.openExisting({
      database_path: anchorPath,
      realm_id: fixture.realmId,
      private_key: fixture.anchorKeys.privateKey,
      public_key: fixture.anchorKeys.publicKey,
      now: () => 10_001,
    });
    anchor.close();
    anchor = null;
    const db = new DatabaseSync(anchorPath, { readOnly: true });
    try {
      assert.equal(
        db.prepare("SELECT COUNT(*) AS count FROM authorizations").get().count,
        1,
      );
      assert.equal(
        db.prepare("SELECT COUNT(*) AS count FROM execution_ids").get().count,
        1,
      );
      assert.equal(
        db.prepare("SELECT COUNT(*) AS count FROM call_slots").get().count,
        3,
      );
      assert.equal(
        db.prepare("SELECT COUNT(*) AS count FROM anchor_events WHERE event_type='claim_authorization'").get().count,
        1,
      );
    } finally {
      db.close();
    }
  } finally {
    anchor?.close();
    rmSync(directory, { recursive: true, force: true });
  }
}

test("two active registries racing the same authorization and fingerprint commit exactly one claim", async () => {
  await runClaimRace({
    claimA: (fixture) => claimFromFixture(fixture),
    claimB: (fixture) => claimFromFixture(fixture),
    expectedLoserCode: "anchor_authorization_already_claimed",
  });
});

test("two active registries racing different authorization IDs with one fingerprint commit exactly one claim", async () => {
  await runClaimRace({
    claimA: (fixture) => claimFromFixture(fixture),
    claimB: (fixture) =>
      claimFromFixture(fixture, {
        authorization_id: fixtureId("auth", "claim-race-authorization-b"),
        executions: [
          {
            ...claimFromFixture(fixture).executions[0],
            execution_id: fixtureId("exec", "claim-race-execution-b"),
            media_scope_id: fixtureId("scope", "claim-race-scope-b"),
          },
        ],
      }),
    expectedLoserCode: "anchor_authorization_already_claimed",
  });
});

test("two active registries racing one execution ID under distinct authorizations commit exactly one claim", async () => {
  await runClaimRace({
    claimA: (fixture) => claimFromFixture(fixture),
    claimB: (fixture) =>
      claimFromFixture(fixture, {
        authorization_id: fixtureId("auth", "claim-race-authorization-b"),
        authorization_fingerprint_sha256: fixtureHash("claim-race-fingerprint-b"),
        signed_consent_sha256: fixtureHash("claim-race-consent-b"),
      }),
    expectedLoserCode: "anchor_execution_already_claimed",
  });
});
