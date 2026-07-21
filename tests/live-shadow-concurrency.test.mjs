import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  copyFileSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { LiveAuthorityRegistry } from "../evaluation/live-shadow/authority-registry.ts";
import { LocalAnchorStub } from "../evaluation/live-shadow/local-anchor-stub.ts";
import {
  createLiveContractFixture,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

function runRacer(configPath) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        "--experimental-strip-types",
        "tests/helpers/live-shadow-authority-racer.mjs",
        configPath,
      ],
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
        reject(new Error(`racer_exit_${code}:${stderr}`));
        return;
      }
      resolve(JSON.parse(stdout));
    });
  });
}

test("two cloned authority processes cannot both acquire the anchor session", async () => {
  const directory = mkdtempSync(join(tmpdir(), "checkback-live-race-"));
  const anchorPath = join(directory, "anchor.sqlite");
  const authorityA = join(directory, "authority-a.sqlite");
  const authorityB = join(directory, "authority-b.sqlite");
  const barrierPath = join(directory, "go.barrier");
  const fixture = createLiveContractFixture({ count: 1 });
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
    LiveAuthorityRegistry.initialize({
      database_path: authorityA,
      registry_id: fixture.registryId,
      authority_secret: fixture.authoritySecret,
      consent_public_key: fixture.consentKeys.publicKey,
      anchor_public_key: fixture.anchorKeys.publicKey,
      anchor,
      now: () => 10_000,
    });
    anchor.close();
    anchor = null;
    copyFileSync(authorityA, authorityB);
    const common = {
      anchor_path: anchorPath,
      barrier_path: barrierPath,
      realm_id: fixture.realmId,
      registry_id: fixture.registryId,
      authority_secret_hex: fixture.authoritySecret.toString("hex"),
      anchor_private_key_pem: fixture.anchorKeys.privateKey
        .export({ type: "pkcs8", format: "pem" })
        .toString(),
      anchor_public_key_pem: fixture.anchorKeys.publicKey
        .export({ type: "spki", format: "pem" })
        .toString(),
      consent_public_key_pem: fixture.consentKeys.publicKey
        .export({ type: "spki", format: "pem" })
        .toString(),
      now_ms: 10_001,
    };
    const configA = join(directory, "racer-a.json");
    const configB = join(directory, "racer-b.json");
    writeFileSync(
      configA,
      JSON.stringify({
        ...common,
        authority_path: authorityA,
        session_id: fixtureId("session", "racer-a"),
      }),
      { mode: 0o600 },
    );
    writeFileSync(
      configB,
      JSON.stringify({
        ...common,
        authority_path: authorityB,
        session_id: fixtureId("session", "racer-b"),
      }),
      { mode: 0o600 },
    );
    const racers = [runRacer(configA), runRacer(configB)];
    writeFileSync(barrierPath, "go", { mode: 0o600 });
    const results = await Promise.all(racers);
    assert.equal(results.filter((result) => result.ok).length, 1);
    assert.equal(results.filter((result) => !result.ok).length, 1);
    assert.match(
      results.find((result) => !result.ok).code,
      /authority_(clone_or_rollback_detected|anchor_session_failed)/,
    );
  } finally {
    anchor?.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
