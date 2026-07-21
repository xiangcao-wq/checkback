import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { LiveAuthorityRegistry } from "../../evaluation/live-shadow/authority-registry.ts";
import { LocalAnchorStub } from "../../evaluation/live-shadow/local-anchor-stub.ts";
import { OfflineLiveShadowGateway } from "../../evaluation/live-shadow/offline-gateway.ts";

const configPath = process.argv[2];
if (!configPath || process.argv.length !== 3) {
  throw new Error("offline_hard_crash_worker_requires_one_config_path");
}

const config = JSON.parse(readFileSync(configPath, "utf8"));
const EXIT_CODES = Object.freeze({
  anchor_committed_before_authority: 71,
  dispatching_before_send: 72,
  sent_before_result: 73,
});

function errorCode(error) {
  if (error && typeof error === "object" && "code" in error) {
    return String(error.code);
  }
  return error instanceof Error ? error.message : "unknown_error";
}

function writeMarker(value) {
  writeFileSync(config.marker_path, JSON.stringify(value), {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

function hardExit(phase, gateway, extra = {}) {
  writeMarker({
    schema_version: "checkback.live-shadow.hard-crash-marker.v1",
    phase,
    network_calls: 0,
    send_attempts: gateway.snapshot().send_attempts,
    ...extra,
  });
  process.exit(EXIT_CODES[phase]);
}

const anchorPrivateKey = createPrivateKey(config.anchor_private_key_pem);
const anchorPublicKey = createPublicKey(config.anchor_public_key_pem);
const consentPublicKey = createPublicKey(config.consent_public_key_pem);
const clock = () => config.now_ms;

const anchor = LocalAnchorStub.openExisting({
  database_path: config.anchor_path,
  realm_id: config.realm_id,
  private_key: anchorPrivateKey,
  public_key: anchorPublicKey,
  now: clock,
});
const authority = LiveAuthorityRegistry.openExisting({
  database_path: config.authority_path,
  expected_registry_id: config.registry_id,
  authority_secret: Buffer.from(config.authority_secret_hex, "hex"),
  consent_public_key: consentPublicKey,
  anchor_public_key: anchorPublicKey,
  anchor,
  session_id: config.session_id,
  now: clock,
});
const gateway = new OfflineLiveShadowGateway({ authority });

if (config.scenario === "anchor_committed_before_authority") {
  const originalConsume = anchor.consumeSlot.bind(anchor);
  anchor.consumeSlot = (input) => {
    const receipt = originalConsume(input);
    hardExit(config.scenario, gateway, {
      anchor_registry_sequence: receipt.payload.registry_sequence,
    });
  };
}

const faultPoint =
  config.scenario === "dispatching_before_send"
    ? "after_anchor_burn_before_send"
    : config.scenario === "sent_before_result"
      ? "after_send_before_result"
      : "none";

try {
  await gateway.dispatch({
    execution_plan: config.execution_plan,
    runtime_manifest: config.runtime_manifest,
    slot: "primary",
    operation_id: config.operation_id,
    media_pair: {
      before_bytes: Buffer.from(config.before_bytes_base64, "base64"),
      after_bytes: Buffer.from(config.after_bytes_base64, "base64"),
    },
    fault_point: faultPoint,
  });
  writeMarker({
    schema_version: "checkback.live-shadow.hard-crash-marker.v1",
    phase: "unexpected_dispatch_completion",
    network_calls: 0,
    send_attempts: gateway.snapshot().send_attempts,
  });
  process.exit(91);
} catch (error) {
  const expected =
    config.scenario === "dispatching_before_send"
      ? "offline_crash_simulation:after_anchor_burn_before_send"
      : config.scenario === "sent_before_result"
        ? "offline_crash_simulation:after_send_before_result"
        : null;
  if (expected && errorCode(error) === expected) {
    hardExit(config.scenario, gateway, {
      authority_slot_state: authority.slotState(
        config.execution_plan.execution_id,
        "primary",
      ),
    });
  }
  writeMarker({
    schema_version: "checkback.live-shadow.hard-crash-marker.v1",
    phase: "unexpected_error",
    network_calls: 0,
    send_attempts: gateway.snapshot().send_attempts,
    error_code: errorCode(error),
  });
  process.exit(92);
}
