import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { AnchorError } from "../evaluation/live-shadow/anchor-port.ts";
import { LiveAuthorityRegistry } from "../evaluation/live-shadow/authority-registry.ts";
import { LocalAnchorStub } from "../evaluation/live-shadow/local-anchor-stub.ts";
import { OfflineLiveShadowGateway } from "../evaluation/live-shadow/offline-gateway.ts";
import {
  createLiveContractFixture,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

function createSystem(fakeOutcome = "success") {
  const directory = mkdtempSync(join(tmpdir(), "checkback-live-gateway-"));
  const anchorPath = join(directory, "anchor.sqlite");
  const authorityPath = join(directory, "authority.sqlite");
  const fixture = createLiveContractFixture({ count: 1 });
  let now = 10_000;
  const clock = () => now++;
  LocalAnchorStub.initialize({
    database_path: anchorPath,
    realm_id: fixture.realmId,
    private_key: fixture.anchorKeys.privateKey,
    public_key: fixture.anchorKeys.publicKey,
    now: clock,
  });
  const anchor = LocalAnchorStub.openExisting({
    database_path: anchorPath,
    realm_id: fixture.realmId,
    private_key: fixture.anchorKeys.privateKey,
    public_key: fixture.anchorKeys.publicKey,
    now: clock,
  });
  LiveAuthorityRegistry.initialize({
    database_path: authorityPath,
    registry_id: fixture.registryId,
    authority_secret: fixture.authoritySecret,
    consent_public_key: fixture.consentKeys.publicKey,
    anchor_public_key: fixture.anchorKeys.publicKey,
    anchor,
    now: clock,
  });
  const authority = LiveAuthorityRegistry.openExisting({
    database_path: authorityPath,
    expected_registry_id: fixture.registryId,
    authority_secret: fixture.authoritySecret,
    consent_public_key: fixture.consentKeys.publicKey,
    anchor_public_key: fixture.anchorKeys.publicKey,
    anchor,
    session_id: fixtureId("session", "gateway-session"),
    now: clock,
  });
  authority.importAuthorization({
    signed_consent: fixture.signedConsent,
    runtime_manifest: fixture.runtime,
    now_ms: clock(),
  });
  const gateway = new OfflineLiveShadowGateway({
    authority,
    fake_outcome: fakeOutcome,
    now: clock,
  });
  return {
    directory,
    anchorPath,
    authorityPath,
    fixture,
    anchor,
    authority,
    gateway,
    cleanup() {
      authority.close();
      anchor.close();
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function dispatchInput(system, slot, seed, faultPoint = "none") {
  return {
    execution_plan: system.fixture.plan,
    runtime_manifest: system.fixture.runtime,
    slot,
    operation_id: fixtureId("op", seed),
    media_pair: {
      before_bytes: system.fixture.mediaPairs[0].before_bytes,
      after_bytes: system.fixture.mediaPairs[0].after_bytes,
    },
    fault_point: faultPoint,
  };
}

test("offline gateway sends exactly once only after the anchor burn", async () => {
  const system = createSystem();
  try {
    const input = dispatchInput(system, "primary", "success");
    const result = await system.gateway.dispatch(input);
    assert.deepEqual(
      {
        mode: result.mode,
        provider: result.provider,
        network_calls: result.network_calls,
        outcome: result.outcome,
      },
      {
        mode: "offline_stub",
        provider: "fake_gateway",
        network_calls: 0,
        outcome: "success",
      },
    );
    assert.equal(system.gateway.snapshot().send_attempts, 1);
    await assert.rejects(() => system.gateway.dispatch(input));
    assert.equal(system.gateway.snapshot().send_attempts, 1);
  } finally {
    system.cleanup();
  }
});

test("gateway rejects flash and plus before their preceding slot results", async () => {
  const system = createSystem();
  try {
    await assert.rejects(
      () =>
        system.gateway.dispatch(
          dispatchInput(system, "flash", "out-of-order-flash"),
        ),
      /authority_slot_order_invalid/,
    );
    await assert.rejects(
      () =>
        system.gateway.dispatch(
          dispatchInput(system, "plus", "out-of-order-plus"),
        ),
      /authority_slot_order_invalid/,
    );
    assert.equal(system.gateway.snapshot().send_attempts, 0);
    assert.equal(
      system.authority.slotState(system.fixture.plan.execution_id, "flash"),
      "allocated",
    );
    assert.equal(
      system.authority.slotState(system.fixture.plan.execution_id, "plus"),
      "allocated",
    );
  } finally {
    system.cleanup();
  }
});
test("fake transport failures record one request_error without retry", async () => {
  const system = createSystem("request_error");
  try {
    const result = await system.gateway.dispatch(
      dispatchInput(system, "primary", "request-error"),
    );
    assert.equal(result.outcome, "request_error");
    assert.equal(system.gateway.snapshot().send_attempts, 1);
    assert.equal(
      system.authority.slotState(system.fixture.plan.execution_id, "primary"),
      "result",
    );
  } finally {
    system.cleanup();
  }
});

test("timeout and invalid_output are terminal one-shot outcomes without retry", async () => {
  for (const outcome of ["timeout", "invalid_output"]) {
    const system = createSystem(outcome);
    try {
      const result = await system.gateway.dispatch(
        dispatchInput(system, "primary", `terminal-${outcome}`),
      );
      assert.equal(result.outcome, outcome);
      assert.equal(system.gateway.snapshot().send_attempts, 1);
      assert.equal(
        system.authority.slotState(system.fixture.plan.execution_id, "primary"),
        "result",
      );
    } finally {
      system.cleanup();
    }
  }
});
test("crash after anchor burn but before send performs zero sends", async () => {
  const system = createSystem();
  try {
    await assert.rejects(
      () =>
        system.gateway.dispatch(
          dispatchInput(
            system,
            "primary",
            "before-send-crash",
            "after_anchor_burn_before_send",
          ),
        ),
      /offline_crash_simulation:after_anchor_burn_before_send/,
    );
    assert.equal(system.gateway.snapshot().send_attempts, 0);
    assert.equal(
      system.authority.slotState(system.fixture.plan.execution_id, "primary"),
      "dispatching",
    );
    system.authority.close();
    const db = new DatabaseSync(system.authorityPath, { readOnly: true });
    const row = db.prepare(
      "SELECT state FROM call_slots WHERE execution_id=? AND slot='primary'",
    ).get(system.fixture.plan.execution_id);
    db.close();
    assert.equal(row.state, "unknown_after_crash");
  } finally {
    system.cleanup();
  }
});

test("crash after send but before result remains exactly one send", async () => {
  const system = createSystem();
  try {
    await assert.rejects(
      () =>
        system.gateway.dispatch(
          dispatchInput(
            system,
            "primary",
            "after-send-crash",
            "after_send_before_result",
          ),
        ),
      /offline_crash_simulation:after_send_before_result/,
    );
    assert.equal(system.gateway.snapshot().send_attempts, 1);
    assert.equal(
      system.authority.slotState(system.fixture.plan.execution_id, "primary"),
      "dispatching",
    );
    system.authority.close();
  } finally {
    system.cleanup();
  }
});

test("anchor uncertainty prevents fake send and quarantines the registry", async () => {
  const system = createSystem();
  const originalConsume = system.anchor.consumeSlot.bind(system.anchor);
  try {
    system.anchor.consumeSlot = () => {
      throw new AnchorError("anchor_outcome_unknown", true);
    };
    await assert.rejects(
      () =>
        system.gateway.dispatch(
          dispatchInput(system, "primary", "anchor-uncertain"),
        ),
      /authority_anchor_slot_consume_failed/,
    );
    assert.equal(system.gateway.snapshot().send_attempts, 0);
    assert.equal(system.authority.status().authority_state, "quarantined");
  } finally {
    system.anchor.consumeSlot = originalConsume;
    system.cleanup();
  }
});
test("anchor commit followed by lost receipt still performs zero sends", async () => {
  const system = createSystem();
  const originalConsume = system.anchor.consumeSlot.bind(system.anchor);
  try {
    system.anchor.consumeSlot = (input) => {
      originalConsume(input);
      throw new AnchorError("anchor_receipt_lost_after_commit", true);
    };
    await assert.rejects(
      () =>
        system.gateway.dispatch(
          dispatchInput(system, "primary", "commit-then-disconnect"),
        ),
      /authority_anchor_slot_consume_failed/,
    );
    assert.equal(system.gateway.snapshot().send_attempts, 0);
    assert.equal(system.authority.status().authority_state, "quarantined");
    const localSequence = system.authority.status().checkpoint.registry_sequence;
    const anchorSequence = system.anchor.inspectRegistry(
      system.fixture.registryId,
    ).registry_sequence;
    assert.equal(anchorSequence, localSequence + 1);
  } finally {
    system.anchor.consumeSlot = originalConsume;
    system.cleanup();
  }
});