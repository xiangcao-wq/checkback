import { createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { LocalAnchorStub } from "../../evaluation/live-shadow/local-anchor-stub.ts";

const configPath = process.argv[2];
if (!configPath || process.argv.length !== 3) {
  throw new Error("offline_anchor_claim_racer_requires_one_config_path");
}

const config = JSON.parse(readFileSync(configPath, "utf8"));
const anchorPrivateKey = createPrivateKey(config.anchor_private_key_pem);
const anchorPublicKey = createPublicKey(config.anchor_public_key_pem);
let anchor;

try {
  anchor = LocalAnchorStub.openExisting({
    database_path: config.anchor_path,
    realm_id: config.realm_id,
    private_key: anchorPrivateKey,
    public_key: anchorPublicKey,
    now: () => config.now_ms,
  });
  const checkpoint = anchor.inspectRegistry(config.registry_id);
  if (
    !checkpoint ||
    checkpoint.active_session_id !== config.session_id ||
    checkpoint.fencing_token !== config.fencing_token
  ) {
    throw new Error("offline_anchor_claim_racer_session_not_active");
  }

  writeFileSync(config.ready_path, "ready", {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  const deadline = Date.now() + 10_000;
  while (!existsSync(config.barrier_path)) {
    if (Date.now() >= deadline) {
      throw new Error("offline_anchor_claim_racer_barrier_timeout");
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2);
  }

  const receipt = anchor.claimAuthorization({
    ...config.claim,
    authority_registry_id: config.registry_id,
    expected_checkpoint: checkpoint,
    session_id: config.session_id,
    fencing_token: config.fencing_token,
    recorded_at_ms: config.now_ms,
  });
  process.stdout.write(
    JSON.stringify({
      ok: true,
      registry_id: config.registry_id,
      authorization_id: config.claim.authorization_id,
      registry_sequence: receipt.payload.registry_sequence,
      global_sequence: receipt.payload.global_sequence,
    }),
  );
} catch (error) {
  process.stdout.write(
    JSON.stringify({
      ok: false,
      registry_id: config.registry_id,
      authorization_id: config.claim.authorization_id,
      code:
        error && typeof error === "object" && "code" in error
          ? error.code
          : error instanceof Error
            ? error.message
            : "unknown_error",
    }),
  );
} finally {
  anchor?.close();
}
