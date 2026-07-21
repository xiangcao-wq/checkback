import assert from "node:assert/strict";
import { readFile, readdir, rm, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Worker } from "node:worker_threads";
import test from "node:test";
import {
  ReceiptSigner,
  sha256Canonical,
  signCollectorManifest,
} from "../evaluation/collector/contracts.ts";
import { DeterministicFakeProvider } from "../evaluation/collector/fake-provider.ts";
import {
  LedgerError,
  ShadowCollectorLedger,
} from "../evaluation/collector/ledger.ts";
import { createOfflineRehearsalBundle } from "../evaluation/collector/rehearsal-fixture.ts";
import { runOfflineShadowExecution } from "../evaluation/collector/runner.ts";
import { runRehearsal } from "../scripts/rehearse-shadow-collector.mjs";

function successBatch(ids, verdict = "confirmed_missing") {
  return {
    verifications: ids.map((id) => ({
      id,
      verdict,
      certainty: "high",
      current_location: null,
    })),
  };
}

function truthFor(ids) {
  return {
    truth_source: "staged_protocol",
    truth_locked_before_output: true,
    labeler_count: 2,
    adjudication: "agreed",
    items: ids.map((id) => ({
      id,
      state: "missing",
      observability: "supported",
      expected_zone: null,
    })),
  };
}

function providerScript(input = {}) {
  const ids = input.ids ?? ["item-0001", "item-0002"];
  return {
    private_request_canary: input.requestCanary,
    primary: input.primary ?? {
      outcome: "success",
      latency_ms: 11,
      candidate_ids: ids,
      private_response_canary: input.primaryCanary,
    },
    flash: input.flash ?? {
      outcome: "success",
      latency_ms: 12,
      batch: successBatch(ids),
      private_response_canary: input.flashCanary,
    },
    plus: input.plus ?? {
      outcome: "success",
      latency_ms: 13,
      batch: successBatch(ids),
      private_response_canary: input.plusCanary,
    },
  };
}

async function withLedger(numericId, run, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "checkback-shadow-"));
  const databasePath = join(directory, "ledger.sqlite");
  const clock = { value: options.createdAt ?? 1_000 };
  const bundle = createOfflineRehearsalBundle({
    numeric_id: numericId,
    execution_count: options.executionCount ?? 1,
    created_at_ms: clock.value,
    lifetime_ms: options.lifetime ?? 10_000,
  });
  const ledger = new ShadowCollectorLedger({
    database_path: databasePath,
    signer: bundle.signer,
    now: () => clock.value,
  });
  try {
    ledger.createRound({
      signed_manifest: bundle.signed_manifest,
      consent_grant: bundle.consent_grant,
    });
    ledger.armRound(bundle.manifest.round_id);
    return await run({
      directory,
      databasePath,
      clock,
      bundle,
      ledger,
    });
  } finally {
    ledger.close();
    bundle.signer.dispose();
    await rm(directory, { recursive: true, force: true });
  }
}

test("offline collector records exactly 1/1/1 and exports a smoke suite", async () => {
  await withLedger(11, async ({ bundle, ledger, clock }) => {
    const ids = ["item-0001", "item-0002"];
    const script = providerScript({ ids });
    const result = await runOfflineShadowExecution({
      ledger,
      execution_plan: bundle.execution_plans[0],
      provider_script: script,
      signer: bundle.signer,
      now: () => clock.value,
      ground_truth: ({ candidate_ids }) => truthFor(candidate_ids),
    });
    assert.equal(result.status, "complete");
    assert.deepEqual(result.provider_calls, ["primary", "flash", "plus"]);
    const execution = ledger.getExecution(result.execution_id);
    assert.equal(execution.state, "complete");
    assert.deepEqual(
      execution.calls.map((item) => item.state),
      ["result", "result", "result"],
    );
    assert.equal(ledger.verifyAuditChain(), true);
    ledger.completeRound(bundle.manifest.round_id);
    const suite = ledger.exportSuite(bundle.manifest.round_id);
    assert.equal(suite.cases.length, 1);
    assert.equal(suite.cases[0].split, "smoke");
    assert.deepEqual(suite.cases[0].execution, {
      execution_id: bundle.execution_plans[0].execution_id,
      config_sha256: bundle.manifest.runtime.config_sha256,
      primary_calls: 1,
      flash_calls: 1,
      plus_calls: 1,
      retry_calls: 0,
      total_calls: 3,
    });
  });
});

test("Flash timeout still consumes Plus exactly once and remains evaluable", async () => {
  await withLedger(12, async ({ bundle, ledger, clock }) => {
    const ids = ["item-0001"];
    const script = providerScript({
      ids,
      flash: { outcome: "timeout", latency_ms: 20 },
    });
    const result = await runOfflineShadowExecution({
      ledger,
      execution_plan: bundle.execution_plans[0],
      provider_script: script,
      signer: bundle.signer,
      now: () => clock.value,
      ground_truth: ({ candidate_ids }) => truthFor(candidate_ids),
    });
    assert.equal(result.status, "complete");
    assert.deepEqual(result.provider_calls, ["primary", "flash", "plus"]);
    assert.equal(result.evaluation_case.flash.outcome, "timeout");
    assert.equal(result.evaluation_case.plus.outcome, "success");
  });
});

test("primary failure never calls either verifier and cannot export", async () => {
  await withLedger(13, async ({ bundle, ledger, clock }) => {
    const script = providerScript({
      primary: { outcome: "request_error", latency_ms: 9 },
    });
    const result = await runOfflineShadowExecution({
      ledger,
      execution_plan: bundle.execution_plans[0],
      provider_script: script,
      signer: bundle.signer,
      now: () => clock.value,
      ground_truth: () => {
        throw new Error("ground truth must not be requested");
      },
    });
    assert.equal(result.status, "incomplete");
    assert.deepEqual(result.provider_calls, ["primary"]);
    const status = ledger.getRoundStatus(bundle.manifest.round_id);
    assert.equal(status.reserved_provider_calls, 1);
    assert.throws(
      () => ledger.completeRound(bundle.manifest.round_id),
      (error) =>
        error instanceof LedgerError && error.code === "round_not_complete",
    );
  });
});

test("call ordering and duplicate slot reservations fail closed", async () => {
  await withLedger(14, async ({ bundle, ledger }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    assert.throws(
      () => ledger.reserveCall(plan.execution_id, "flash"),
      /flash_prerequisites_not_met/,
    );
    ledger.reserveCall(plan.execution_id, "primary");
    assert.throws(
      () => ledger.reserveCall(plan.execution_id, "primary"),
      /call_slot_not_planned|call_slot_already_consumed/,
    );
    assert.equal(
      ledger.getRoundStatus(bundle.manifest.round_id).reserved_provider_calls,
      1,
    );
  });
});

test("authorization expires at the exact boundary and stops new dispatch", async () => {
  await withLedger(
    15,
    async ({ bundle, ledger, clock }) => {
      const plan = bundle.execution_plans[0];
      ledger.claimExecution({
        round_id: plan.round_id,
        execution_plan: plan,
      });
      clock.value = bundle.manifest.expires_at_ms;
      assert.throws(
        () => ledger.reserveCall(plan.execution_id, "primary"),
        /authorization_expired/,
      );
      assert.equal(
        ledger.getRoundStatus(bundle.manifest.round_id).status,
        "expired",
      );
    },
    { lifetime: 1_000 },
  );
});

test("clock rollback marks the round review_required", async () => {
  await withLedger(16, async ({ bundle, ledger, clock }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    clock.value -= 1;
    assert.throws(
      () => ledger.reserveCall(plan.execution_id, "primary"),
      /clock_rollback/,
    );
    assert.equal(
      ledger.getRoundStatus(bundle.manifest.round_id).status,
      "review_required",
    );
  });
});

test("crash recovery consumes an open slot and is idempotent", async () => {
  await withLedger(17, async ({ bundle, ledger }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    ledger.reserveCall(plan.execution_id, "primary");
    const first = ledger.recoverInterrupted(bundle.manifest.round_id);
    const second = ledger.recoverInterrupted(bundle.manifest.round_id);
    assert.equal(first.recovered_calls, 1);
    assert.equal(second.recovered_calls, 0);
    const execution = ledger.getExecution(plan.execution_id);
    assert.equal(execution.state, "incomplete");
    assert.equal(execution.calls[0].outcome, "cancelled_before_dispatch");
    assert.equal(
      ledger.getRoundStatus(bundle.manifest.round_id).reserved_provider_calls,
      1,
    );
  });
});

test("revocation is append-only and blocks all remaining calls", async () => {
  await withLedger(18, async ({ bundle, ledger }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    ledger.revokeAuthorization(bundle.manifest.authorization_id);
    ledger.revokeAuthorization(bundle.manifest.authorization_id);
    assert.equal(
      ledger.getRoundStatus(bundle.manifest.round_id).status,
      "stopped",
    );
    assert.throws(
      () => ledger.reserveCall(plan.execution_id, "primary"),
      /authorization_revoked|round_not_active|round_terminal_event_present/,
    );
  });
});

test("private fake-provider canaries never reach SQLite, WAL, or fixture", async () => {
  await withLedger(19, async ({
    bundle,
    ledger,
    clock,
    directory,
  }) => {
    const ids = ["item-0001"];
    const canaries = [
      "PRIVATE_SOURCE_PATH_C_DRIVE",
      "RAW_PRIMARY_OBJECT_LABEL",
      "RAW_FLASH_EVIDENCE",
      "RAW_PLUS_ERROR_DETAIL",
    ];
    const script = providerScript({
      ids,
      requestCanary: canaries[0],
      primaryCanary: canaries[1],
      flashCanary: canaries[2],
      plusCanary: canaries[3],
    });
    const result = await runOfflineShadowExecution({
      ledger,
      execution_plan: bundle.execution_plans[0],
      provider_script: script,
      signer: bundle.signer,
      now: () => clock.value,
      ground_truth: ({ candidate_ids }) => truthFor(candidate_ids),
    });
    assert.equal(result.status, "complete");
    ledger.completeRound(bundle.manifest.round_id);
    const fixture = JSON.stringify(ledger.exportSuite(bundle.manifest.round_id));
    const names = await readdir(directory);
    let persisted = fixture;
    for (const name of names) {
      persisted += (await readFile(join(directory, name))).toString("latin1");
    }
    for (const canary of canaries) {
      assert.equal(persisted.includes(canary), false);
    }
  });
});
test("execution IDs remain globally unique across rounds and suites", async () => {
  await withLedger(20, async ({ bundle, ledger, clock }) => {
    const second = createOfflineRehearsalBundle({
      numeric_id: 21,
      execution_count: 1,
      created_at_ms: clock.value,
      lifetime_ms: 10_000,
      signer: bundle.signer,
    });
    const reused = bundle.consent_grant.authorized_executions;
    const grant = {
      ...second.consent_grant,
      authorized_executions: reused,
    };
    const manifest = {
      ...second.manifest,
      consent_grant_sha256: sha256Canonical(grant),
      authorized_executions: reused,
    };
    const signed = signCollectorManifest(bundle.signer, manifest);
    assert.throws(
      () =>
        ledger.createRound({
          signed_manifest: signed,
          consent_grant: grant,
        }),
      /execution_id_already_registered/,
    );
  });
});

test("rehearsal CLI path is fake-only, zero-network, and smoke-only", async () => {
  const summary = await runRehearsal({ now: 5_000, numericId: 22 });
  assert.deepEqual(summary, {
    run_mode: "rehearsal",
    provider: "fake_local",
    network_calls: 0,
    executions: 1,
    provider_call_slots: 3,
    audit_chain_valid: true,
    export_split: "smoke",
  });
  const source = await readFile(
    new URL("../scripts/rehearse-shadow-collector.mjs", import.meta.url),
    "utf8",
  );
  for (const forbidden of [
    "openai",
    "dashscope",
    "process.env",
    "fetch(",
    "photo_path",
    "image_path",
  ]) {
    assert.equal(source.toLowerCase().includes(forbidden), false);
  }
  const collectorDirectory = new URL(
    "../evaluation/collector/",
    import.meta.url,
  );
  const collectorFiles = (await readdir(collectorDirectory))
    .filter((name) => name.endsWith(".ts"));
  const transitiveSource = [
    source,
    ...await Promise.all(
      collectorFiles.map((name) =>
        readFile(new URL(name, collectorDirectory), "utf8"),
      ),
    ),
  ].join("\n").toLowerCase();
  for (const forbidden of [
    "process.env",
    "fetch(",
    "http://",
    "https://",
    "xmlhttprequest",
    "websocket",
    "dashscope_api_key",
    "openai_api_key",
    "photo_path",
    "image_path",
  ]) {
    assert.equal(transitiveSource.includes(forbidden), false);
  }
});

async function runLedgerRace(workerInputs) {
  const barrier = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
  const view = new Int32Array(barrier);
  const workerUrl = new URL("./helpers/ledger-racer.mjs", import.meta.url);
  const workers = workerInputs.map(
    (input) =>
      new Worker(workerUrl, {
        workerData: { ...input, barrier },
      }),
  );
  const results = workers.map(
    (worker) =>
      new Promise((resolve, reject) => {
        worker.once("message", resolve);
        worker.once("error", reject);
      }),
  );
  const deadline = Date.now() + 10_000;
  while (Atomics.load(view, 0) < workers.length) {
    if (Date.now() >= deadline) {
      await Promise.all(workers.map((worker) => worker.terminate()));
      throw new Error("ledger race workers did not reach the barrier");
    }
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  Atomics.store(view, 1, 1);
  Atomics.notify(view, 1, workers.length);
  return Promise.all(results);
}

test("two real Workers racing one SQLite slot yield exactly one reservation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "checkback-race-"));
  const databasePath = join(directory, "ledger.sqlite");
  const key = Buffer.alloc(32, 23);
  const keyHex = key.toString("hex");
  const signer = new ReceiptSigner(key);
  key.fill(0);
  const now = 10_000;
  const bundle = createOfflineRehearsalBundle({
    numeric_id: 23,
    execution_count: 1,
    created_at_ms: now,
    lifetime_ms: 10_000,
    signer,
  });
  const ledger = new ShadowCollectorLedger({
    database_path: databasePath,
    signer,
    now: () => now,
  });
  try {
    ledger.createRound({
      signed_manifest: bundle.signed_manifest,
      consent_grant: bundle.consent_grant,
    });
    ledger.armRound(bundle.manifest.round_id);
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    const base = {
      databasePath,
      keyHex,
      now,
      executionId: plan.execution_id,
      slot: "primary",
      action: "reserve",
    };
    const results = await runLedgerRace([base, base]);
    assert.equal(results.filter((item) => item.ok).length, 1);
    assert.equal(
      results.filter((item) => ["call_slot_not_planned", "call_slot_already_consumed"].includes(item.code)).length,
      1,
    );
    assert.equal(
      ledger.getRoundStatus(bundle.manifest.round_id).reserved_provider_calls,
      1,
    );
    assert.equal(ledger.verifyAuditChain(), true);
  } finally {
    ledger.close();
    signer.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});

test("one authorization cannot mint a second round budget", async () => {
  await withLedger(24, async ({ bundle, ledger, clock }) => {
    const second = createOfflineRehearsalBundle({
      numeric_id: 25,
      execution_count: 1,
      created_at_ms: clock.value,
      lifetime_ms: 10_000,
      signer: bundle.signer,
    });
    const grant = {
      ...second.consent_grant,
      authorization_id: bundle.manifest.authorization_id,
    };
    const manifest = {
      ...second.manifest,
      authorization_id: bundle.manifest.authorization_id,
      consent_grant_sha256: sha256Canonical(grant),
    };
    assert.throws(
      () =>
        ledger.createRound({
          signed_manifest: signCollectorManifest(bundle.signer, manifest),
          consent_grant: grant,
        }),
      /authorization_already_consumed/,
    );
  });
});

test("finishCall verifies exact in-memory provider bytes, not hex shape", async () => {
  await withLedger(26, async ({ bundle, ledger }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    const reservation = ledger.reserveCall(plan.execution_id, "primary");
    const dispatch = ledger.markDispatched(reservation);
    const provider = new DeterministicFakeProvider(
      providerScript({ ids: ["item-0001"] }),
    );
    const envelope = await provider.invokePrimary({
      execution_id: plan.execution_id,
    });
    try {
      const requestReceipt = bundle.signer.signBytes(
        "collector.provider-request.primary.v1",
        envelope.request_bytes,
      );
      assert.throws(
        () =>
          ledger.finishCall({
            dispatch_token: dispatch,
            outcome: "success",
            latency_ms: envelope.normalized.latency_ms,
            request_receipt: requestReceipt,
            response_receipt: "0".repeat(64),
            request_bytes: envelope.request_bytes,
            response_bytes: envelope.response_bytes,
            normalized: {
              candidate_ids: envelope.normalized.candidate_ids,
            },
          }),
        /provider_byte_receipt_invalid/,
      );
      assert.equal(
        ledger.getExecution(plan.execution_id).calls[0].state,
        "dispatched",
      );
    } finally {
      envelope.request_bytes.fill(0);
      envelope.response_bytes.fill(0);
      ledger.markExecutionIncomplete(
        plan.execution_id,
        "receipt_test_cleanup",
      );
    }
  });
});

test("audit tampering blocks the next reservation", async () => {
  await withLedger(27, async ({ bundle, ledger, databasePath }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    const database = new DatabaseSync(databasePath);
    try {
      database.exec("DROP TRIGGER audit_no_update");
      database.prepare(
        "UPDATE audit_events SET event_hash=? WHERE seq=1",
      ).run("0".repeat(64));
    } finally {
      database.close();
    }
    assert.equal(ledger.verifyAuditChain(), false);
    assert.throws(
      () => ledger.reserveCall(plan.execution_id, "primary"),
      /audit_chain_invalid/,
    );
  });
});

test("resetting a consumed call row cannot reopen its slot", async () => {
  await withLedger(28, async ({ bundle, ledger, databasePath }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    ledger.reserveCall(plan.execution_id, "primary");
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare(
        "UPDATE calls SET state='planned',reserved_at_ms=NULL," +
          "reservation_receipt=NULL WHERE execution_id=? AND slot='primary'",
      ).run(plan.execution_id);
    } finally {
      database.close();
    }
    assert.equal(ledger.verifyAuditChain(), true);
    assert.throws(
      () => ledger.reserveCall(plan.execution_id, "primary"),
      /call_slot_already_consumed/,
    );
  });
});

test("persistent SQLite storage is mandatory", () => {
  const key = Buffer.alloc(32, 29);
  const signer = new ReceiptSigner(key);
  key.fill(0);
  try {
    assert.throws(
      () =>
        new ShadowCollectorLedger({
          database_path: ":memory:",
          signer,
        }),
      /persistent_database_path_required/,
    );
  } finally {
    signer.dispose();
  }
});

test("DISPATCHED crash recovery records unknown and never retries", async () => {
  await withLedger(30, async ({ bundle, ledger }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    const reservation = ledger.reserveCall(plan.execution_id, "primary");
    ledger.markDispatched(reservation);
    const result = ledger.recoverInterrupted(bundle.manifest.round_id);
    assert.equal(result.recovered_calls, 1);
    const call = ledger.getExecution(plan.execution_id).calls[0];
    assert.equal(call.outcome, "unknown_after_crash");
    assert.equal(
      ledger.getRoundStatus(bundle.manifest.round_id).reserved_provider_calls,
      1,
    );
  });
});

test("stop and dispatch share one linearization boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "checkback-stop-race-"));
  const databasePath = join(directory, "ledger.sqlite");
  const key = Buffer.alloc(32, 31);
  const keyHex = key.toString("hex");
  const signer = new ReceiptSigner(key);
  key.fill(0);
  const now = 20_000;
  const bundle = createOfflineRehearsalBundle({
    numeric_id: 31,
    execution_count: 1,
    created_at_ms: now,
    lifetime_ms: 10_000,
    signer,
  });
  const ledger = new ShadowCollectorLedger({
    database_path: databasePath,
    signer,
    now: () => now,
  });
  try {
    ledger.createRound({
      signed_manifest: bundle.signed_manifest,
      consent_grant: bundle.consent_grant,
    });
    ledger.armRound(bundle.manifest.round_id);
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    ledger.reserveCall(plan.execution_id, "primary");
    const common = {
      databasePath,
      keyHex,
      now,
      executionId: plan.execution_id,
      slot: "primary",
    };
    const results = await runLedgerRace([
      { ...common, action: "dispatch" },
      { ...common, action: "stop" },
    ]);
    assert.equal(
      results.filter((item) => item.code === "round_stopped").length,
      1,
    );
    assert.equal(
      ledger.getRoundStatus(bundle.manifest.round_id).status,
      "stopped",
    );
    const database = new DatabaseSync(databasePath, { readOnly: true });
    try {
      const events = database.prepare(
        "SELECT seq,event_type FROM audit_events " +
          "WHERE round_id=? AND event_type IN ('call_dispatched','round_stopped') " +
          "ORDER BY seq",
      ).all(bundle.manifest.round_id);
      const stopped = events.find((item) => item.event_type === "round_stopped");
      const dispatched = events.find(
        (item) => item.event_type === "call_dispatched",
      );
      assert.ok(stopped);
      if (dispatched) assert.ok(dispatched.seq < stopped.seq);
    } finally {
      database.close();
    }
  } finally {
    ledger.close();
    signer.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});

test("cleanup runs in finally when ground truth fails", async () => {
  await withLedger(32, async ({ bundle, ledger, clock }) => {
    let cleanupCalls = 0;
    await assert.rejects(
      runOfflineShadowExecution({
        ledger,
        execution_plan: bundle.execution_plans[0],
        provider_script: providerScript({ ids: ["item-0001"] }),
        signer: bundle.signer,
        now: () => clock.value,
        ground_truth: () => {
          throw new Error("private labeler error");
        },
        verify_cleanup: () => {
          cleanupCalls += 1;
          return true;
        },
      }),
      /ground_truth_invalid/,
    );
    assert.equal(cleanupCalls, 1);
    assert.deepEqual(
      ledger.getExecution(bundle.execution_plans[0].execution_id).calls
        .map((call) => call.state),
      ["result", "cancelled", "cancelled"],
    );
  });
});

test("unverified cleanup blocks finalization after all three calls", async () => {
  await withLedger(33, async ({ bundle, ledger, clock }) => {
    await assert.rejects(
      runOfflineShadowExecution({
        ledger,
        execution_plan: bundle.execution_plans[0],
        provider_script: providerScript({ ids: ["item-0001"] }),
        signer: bundle.signer,
        now: () => clock.value,
        ground_truth: ({ candidate_ids }) => truthFor(candidate_ids),
        verify_cleanup: () => false,
      }),
      /cleanup_not_verified/,
    );
    const execution = ledger.getExecution(
      bundle.execution_plans[0].execution_id,
    );
    assert.equal(execution.state, "incomplete");
    assert.equal(execution.has_case, false);
    assert.deepEqual(
      execution.calls.map((call) => call.state),
      ["result", "result", "result"],
    );
  });
});

test("Plus request_error is exported only after its one consumed slot", async () => {
  await withLedger(34, async ({ bundle, ledger, clock }) => {
    const script = providerScript({
      ids: ["item-0001"],
      plus: { outcome: "request_error", latency_ms: 30 },
    });
    const result = await runOfflineShadowExecution({
      ledger,
      execution_plan: bundle.execution_plans[0],
      provider_script: script,
      signer: bundle.signer,
      now: () => clock.value,
      ground_truth: ({ candidate_ids }) => truthFor(candidate_ids),
    });
    assert.equal(result.status, "complete");
    assert.equal(result.evaluation_case.plus.outcome, "request_error");
    assert.deepEqual(result.provider_calls, ["primary", "flash", "plus"]);
  });
});

test("authenticated fake response semantics cannot diverge from the ledger result", async () => {
  await withLedger(35, async ({ bundle, ledger }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    const dispatch = ledger.markDispatched(
      ledger.reserveCall(plan.execution_id, "primary"),
    );
    const provider = new DeterministicFakeProvider(
      providerScript({ ids: ["item-0001"] }),
    );
    const envelope = await provider.invokePrimary({
      execution_id: plan.execution_id,
    });
    try {
      const requestReceipt = bundle.signer.signBytes(
        "collector.provider-request.primary.v1",
        envelope.request_bytes,
      );
      const responseReceipt = bundle.signer.signBytes(
        "collector.provider-response.primary.v1",
        envelope.response_bytes,
      );
      assert.throws(
        () =>
          ledger.finishCall({
            dispatch_token: dispatch,
            outcome: "success",
            latency_ms: envelope.normalized.latency_ms + 1,
            request_receipt: requestReceipt,
            response_receipt: responseReceipt,
            request_bytes: envelope.request_bytes,
            response_bytes: envelope.response_bytes,
            normalized: {
              candidate_ids: envelope.normalized.candidate_ids,
            },
          }),
        /provider_response_payload_mismatch/,
      );
      assert.throws(
        () =>
          ledger.finishCall({
            dispatch_token: dispatch,
            outcome: "success",
            latency_ms: envelope.normalized.latency_ms,
            request_receipt: requestReceipt,
            response_receipt: responseReceipt,
            request_bytes: envelope.request_bytes,
            response_bytes: envelope.response_bytes,
            normalized: { candidate_ids: ["item-0002"] },
          }),
        /provider_response_payload_mismatch/,
      );
      assert.throws(
        () =>
          ledger.finishCall({
            dispatch_token: dispatch,
            outcome: "timeout",
            latency_ms: envelope.normalized.latency_ms,
            request_receipt: requestReceipt,
            response_receipt: responseReceipt,
            request_bytes: envelope.request_bytes,
            response_bytes: envelope.response_bytes,
          }),
        /provider_response_payload_mismatch/,
      );
      assert.equal(
        ledger.getExecution(plan.execution_id).calls[0].state,
        "dispatched",
      );
    } finally {
      envelope.request_bytes.fill(0);
      envelope.response_bytes.fill(0);
      ledger.markExecutionIncomplete(
        plan.execution_id,
        "semantic_receipt_test_cleanup",
      );
    }
  });
});

test("a dispatched audit event prevents state-row dispatch replay", async () => {
  await withLedger(36, async ({ bundle, ledger, databasePath }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    const reservation = ledger.reserveCall(plan.execution_id, "primary");
    ledger.markDispatched(reservation);
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare(
        "UPDATE calls SET state='reserved',dispatched_at_ms=NULL," +
          "dispatch_receipt=NULL WHERE execution_id=? AND slot='primary'",
      ).run(plan.execution_id);
    } finally {
      database.close();
    }
    assert.equal(ledger.verifyAuditChain(), true);
    assert.throws(
      () => ledger.markDispatched(reservation),
      /call_dispatch_already_recorded/,
    );
    ledger.markExecutionIncomplete(plan.execution_id, "dispatch_replay_cleanup");
  });
});

test("the signed audit head detects deletion of the chain tail", async () => {
  await withLedger(37, async ({ bundle, ledger, databasePath }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    const database = new DatabaseSync(databasePath);
    try {
      database.exec("DROP TRIGGER audit_no_delete");
      database.exec(
        "DELETE FROM audit_events WHERE seq=(SELECT MAX(seq) FROM audit_events)",
      );
    } finally {
      database.close();
    }
    assert.equal(ledger.verifyAuditChain(), false);
    assert.throws(
      () => ledger.reserveCall(plan.execution_id, "primary"),
      /audit_chain_invalid/,
    );
  });
});

test("authorization consumption survives deletion of mutable round rows", async () => {
  await withLedger(38, async ({ bundle, ledger, databasePath }) => {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare(
        "DELETE FROM execution_grants WHERE round_id=?",
      ).run(bundle.manifest.round_id);
      database.prepare(
        "DELETE FROM rounds WHERE round_id=?",
      ).run(bundle.manifest.round_id);
    } finally {
      database.close();
    }
    assert.equal(ledger.verifyAuditChain(), true);
    assert.throws(
      () =>
        ledger.createRound({
          signed_manifest: bundle.signed_manifest,
          consent_grant: bundle.consent_grant,
        }),
      /authorization_already_consumed/,
    );
  });
});

test("a signed revocation event makes revocation-row deletion fail closed", async () => {
  await withLedger(39, async ({ bundle, ledger, databasePath }) => {
    ledger.revokeAuthorization(bundle.manifest.authorization_id);
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare(
        "DELETE FROM revocations WHERE authorization_id=?",
      ).run(bundle.manifest.authorization_id);
    } finally {
      database.close();
    }
    assert.equal(ledger.verifyAuditChain(), true);
    assert.throws(
      () => ledger.revokeAuthorization(bundle.manifest.authorization_id),
      /revocation_state_invalid/,
    );
  });
});

test("rehearsal runner constructs its fake provider internally", async () => {
  await withLedger(40, async ({ bundle, ledger, clock }) => {
    let injectedProviderReads = 0;
    const injectedProvider = new Proxy({}, {
      get() {
        injectedProviderReads += 1;
        return async () => ({ injected: true });
      },
    });
    await assert.rejects(
      runOfflineShadowExecution({
        ledger,
        execution_plan: bundle.execution_plans[0],
        provider_script: providerScript(),
        provider: injectedProvider,
        signer: bundle.signer,
        now: () => clock.value,
        ground_truth: ({ candidate_ids }) => truthFor(candidate_ids),
      }),
      /rehearsal_provider_injection_forbidden/,
    );
    assert.equal(injectedProviderReads, 0);
    assert.equal(Object.isFrozen(DeterministicFakeProvider.prototype), true);
    assert.equal(
      Object.isFrozen(DeterministicFakeProvider.prototype.invokePrimary),
      true,
    );
    assert.throws(
      () =>
        Object.defineProperty(
          DeterministicFakeProvider.prototype.invokePrimary,
          "bind",
          { value: () => async () => ({ injected: true }) },
        ),
      TypeError,
    );
    const direct = new DeterministicFakeProvider(providerScript());
    const callsSnapshot = direct.calls;
    assert.equal(Object.isFrozen(callsSnapshot), true);
    assert.throws(() => callsSnapshot.push("primary"), TypeError);

    const result = await runOfflineShadowExecution({
      ledger,
      execution_plan: bundle.execution_plans[0],
      provider_script: providerScript(),
      signer: bundle.signer,
      now: () => clock.value,
      ground_truth: ({ candidate_ids }) => truthFor(candidate_ids),
    });
    assert.deepEqual(result.provider_calls, ["primary", "flash", "plus"]);
  });
});
test("reopening the WAL ledger preserves crash semantics", async () => {
  await withLedger(41, async ({ bundle, ledger, databasePath, clock }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    ledger.reserveCall(plan.execution_id, "primary");
    ledger.close();
    const reopened = new ShadowCollectorLedger({
      database_path: databasePath,
      signer: bundle.signer,
      now: () => clock.value,
    });
    try {
      const recovered = reopened.recoverInterrupted(bundle.manifest.round_id);
      assert.equal(recovered.recovered_calls, 1);
      const primary = reopened.getExecution(plan.execution_id).calls[0];
      assert.equal(primary.outcome, "cancelled_before_dispatch");
      assert.equal(reopened.verifyAuditChain(), true);
    } finally {
      reopened.close();
    }
  });
});
test("revocation remains durable when round reconciliation data is damaged", async () => {
  await withLedger(42, async ({ bundle, ledger, databasePath }) => {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare(
        "UPDATE rounds SET manifest_sha256=? WHERE round_id=?",
      ).run("0".repeat(64), bundle.manifest.round_id);
    } finally {
      database.close();
    }
    ledger.revokeAuthorization(bundle.manifest.authorization_id);
    const inspection = new DatabaseSync(databasePath, { readOnly: true });
    try {
      const revocations = inspection.prepare(
        "SELECT COUNT(*) AS n FROM revocations WHERE authorization_id=?",
      ).get(bundle.manifest.authorization_id);
      const events = inspection.prepare(
        "SELECT COUNT(*) AS n FROM audit_events " +
          "WHERE event_type='authorization_revoked'",
      ).get();
      const round = inspection.prepare(
        "SELECT status FROM rounds WHERE round_id=?",
      ).get(bundle.manifest.round_id);
      assert.equal(revocations.n, 1);
      assert.equal(events.n, 1);
      assert.equal(round.status, "stopped");
      assert.equal(ledger.verifyAuditChain(), true);
    } finally {
      inspection.close();
    }
  });
});
test("execution registration history survives mutable grant-row deletion", async () => {
  await withLedger(43, async ({ bundle, ledger, databasePath, clock }) => {
    const second = createOfflineRehearsalBundle({
      numeric_id: 44,
      execution_count: 1,
      created_at_ms: clock.value,
      lifetime_ms: 10_000,
      signer: bundle.signer,
    });
    const grant = {
      ...second.consent_grant,
      authorized_executions: bundle.consent_grant.authorized_executions,
    };
    const manifest = {
      ...second.manifest,
      authorized_executions: bundle.manifest.authorized_executions,
      consent_grant_sha256: sha256Canonical(grant),
    };
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare(
        "DELETE FROM execution_grants WHERE round_id=?",
      ).run(bundle.manifest.round_id);
      database.prepare(
        "DELETE FROM rounds WHERE round_id=?",
      ).run(bundle.manifest.round_id);
    } finally {
      database.close();
    }
    assert.equal(ledger.verifyAuditChain(), true);
    assert.throws(
      () =>
        ledger.createRound({
          signed_manifest: signCollectorManifest(bundle.signer, manifest),
          consent_grant: grant,
        }),
      /execution_id_already_registered/,
    );
  });
});
test("a recorded call result cannot be replayed after state-row rollback", async () => {
  await withLedger(45, async ({ bundle, ledger, databasePath }) => {
    const plan = bundle.execution_plans[0];
    ledger.claimExecution({
      round_id: plan.round_id,
      execution_plan: plan,
    });
    const dispatch = ledger.markDispatched(
      ledger.reserveCall(plan.execution_id, "primary"),
    );
    const provider = new DeterministicFakeProvider(
      providerScript({ ids: ["item-0001"] }),
    );
    const envelope = await provider.invokePrimary({
      execution_id: plan.execution_id,
    });
    const requestReceipt = bundle.signer.signBytes(
      "collector.provider-request.primary.v1",
      envelope.request_bytes,
    );
    const responseReceipt = bundle.signer.signBytes(
      "collector.provider-response.primary.v1",
      envelope.response_bytes,
    );
    try {
      ledger.finishCall({
        dispatch_token: dispatch,
        outcome: "success",
        latency_ms: envelope.normalized.latency_ms,
        request_receipt: requestReceipt,
        response_receipt: responseReceipt,
        request_bytes: envelope.request_bytes,
        response_bytes: envelope.response_bytes,
        normalized: { candidate_ids: envelope.normalized.candidate_ids },
      });
      const database = new DatabaseSync(databasePath);
      try {
        database.prepare(
          "UPDATE calls SET state='dispatched',outcome=NULL,latency_ms=NULL," +
            "normalized_json=NULL,request_receipt=NULL,response_receipt=NULL," +
            "result_receipt=NULL,completed_at_ms=NULL " +
            "WHERE execution_id=? AND slot='primary'",
        ).run(plan.execution_id);
      } finally {
        database.close();
      }
      assert.equal(ledger.verifyAuditChain(), true);
      assert.throws(
        () =>
          ledger.finishCall({
            dispatch_token: dispatch,
            outcome: "success",
            latency_ms: envelope.normalized.latency_ms,
            request_receipt: requestReceipt,
            response_receipt: responseReceipt,
            request_bytes: envelope.request_bytes,
            response_bytes: envelope.response_bytes,
            normalized: { candidate_ids: envelope.normalized.candidate_ids },
          }),
        /call_result_already_recorded/,
      );
    } finally {
      envelope.request_bytes.fill(0);
      envelope.response_bytes.fill(0);
      ledger.markExecutionIncomplete(plan.execution_id, "result_replay_cleanup");
    }
  });
});