import { createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { LocalAnchorStub } from "../../evaluation/live-shadow/local-anchor-stub.ts";
import { LiveAuthorityRegistry } from "../../evaluation/live-shadow/authority-registry.ts";

const configPath = process.argv[2];
if (!configPath || process.argv.length !== 3) {
  throw new Error("offline_racer_requires_one_config_path");
}

const config = JSON.parse(readFileSync(configPath, "utf8"));
while (!existsSync(config.barrier_path)) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2);
}

const anchorPrivateKey = createPrivateKey(config.anchor_private_key_pem);
const anchorPublicKey = createPublicKey(config.anchor_public_key_pem);
const consentPublicKey = createPublicKey(config.consent_public_key_pem);
let anchor;
let authority;
try {
  anchor = LocalAnchorStub.openExisting({
    database_path: config.anchor_path,
    realm_id: config.realm_id,
    private_key: anchorPrivateKey,
    public_key: anchorPublicKey,
    now: () => config.now_ms,
  });
  authority = LiveAuthorityRegistry.openExisting({
    database_path: config.authority_path,
    expected_registry_id: config.registry_id,
    authority_secret: Buffer.from(config.authority_secret_hex, "hex"),
    consent_public_key: consentPublicKey,
    anchor_public_key: anchorPublicKey,
    anchor,
    session_id: config.session_id,
    now: () => config.now_ms,
  });
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
  process.stdout.write(JSON.stringify({ ok: true }));
} catch (error) {
  process.stdout.write(
    JSON.stringify({
      ok: false,
      code: error && typeof error === "object" && "code" in error
        ? error.code
        : "unknown_error",
    }),
  );
} finally {
  authority?.close();
  anchor?.close();
}
