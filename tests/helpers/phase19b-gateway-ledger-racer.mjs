import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { PersistentGatewayLedger } from "../../evaluation/live-shadow-boundary/gateway-ledger.ts";

const waitBuffer = new Int32Array(new SharedArrayBuffer(4));

function waitForFile(path, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(path)) {
    if (Date.now() >= deadline) throw new Error("race_barrier_timeout");
    Atomics.wait(waitBuffer, 0, 0, 10);
  }
}

function codeOf(error) {
  if (error && typeof error === "object" && typeof error.code === "string") {
    return error.code;
  }
  return "gateway_racer_failed";
}

let ledger;
let secret;
try {
  const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
  secret = Buffer.from(config.ledger_secret_hex, "hex");
  ledger = PersistentGatewayLedger.openExisting({
    database_path: config.database_path,
    ledger_secret: secret,
    profile: config.profile,
    boot_session_id: config.boot_session_id,
    mode: "join_active",
    expected_fencing_token: config.fencing_token,
    now: () => config.now_ms,
  });
  writeFileSync(config.ready_path, "ready", { mode: 0o600 });
  waitForFile(config.barrier_path);
  ledger.claimBeforeSend(config.claim);
  process.stdout.write(JSON.stringify({ ok: true, code: "claimed" }));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, code: codeOf(error) }));
} finally {
  ledger?.close();
  secret?.fill(0);
}
