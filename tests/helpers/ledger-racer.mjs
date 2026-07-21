import { DatabaseSync } from "node:sqlite";
import {
  isMainThread,
  parentPort,
  workerData,
} from "node:worker_threads";
import { ReceiptSigner } from "../../evaluation/collector/contracts.ts";
import {
  LedgerError,
  ShadowCollectorLedger,
} from "../../evaluation/collector/ledger.ts";

export const LEDGER_RACE_BARRIER_ARRIVED_INDEX = 0;
export const LEDGER_RACE_BARRIER_RELEASE_INDEX = 1;
export const LEDGER_RACE_BARRIER_BYTES = Int32Array.BYTES_PER_ELEMENT * 2;

const ACTIONS = new Set(["reserve", "dispatch", "stop"]);
const SLOTS = new Set(["primary", "flash", "plus"]);
const EXECUTION_ID = /^execution-[0-9]{4,8}$/;
const HEX_32_BYTES = /^[a-f0-9]{64}$/;

class RacerError extends Error {
  constructor(code) {
    super(code);
    this.name = "RacerError";
    this.code = code;
  }
}

function parseInput(value) {
  if (!value || typeof value !== "object") {
    throw new RacerError("worker_input_invalid");
  }

  const keyHex = value.keyHex ?? value.receiptKeyHex;
  if (
    typeof value.databasePath !== "string" ||
    value.databasePath.length === 0 ||
    !HEX_32_BYTES.test(keyHex ?? "") ||
    !Number.isInteger(value.now) ||
    value.now < 0 ||
    !EXECUTION_ID.test(value.executionId ?? "") ||
    !ACTIONS.has(value.action) ||
    !(value.barrier instanceof SharedArrayBuffer) ||
    value.barrier.byteLength < LEDGER_RACE_BARRIER_BYTES ||
    (value.action !== "stop" && !SLOTS.has(value.slot))
  ) {
    throw new RacerError("worker_input_invalid");
  }

  return {
    databasePath: value.databasePath,
    keyHex,
    now: value.now,
    executionId: value.executionId,
    slot: value.slot,
    action: value.action,
    barrier: value.barrier,
  };
}

function waitForSimultaneousRelease(buffer) {
  const barrier = new Int32Array(buffer);
  Atomics.add(barrier, LEDGER_RACE_BARRIER_ARRIVED_INDEX, 1);
  Atomics.notify(barrier, LEDGER_RACE_BARRIER_ARRIVED_INDEX);

  while (Atomics.load(barrier, LEDGER_RACE_BARRIER_RELEASE_INDEX) === 0) {
    const result = Atomics.wait(
      barrier,
      LEDGER_RACE_BARRIER_RELEASE_INDEX,
      0,
      30_000,
    );
    if (result === "timed-out") throw new RacerError("barrier_timeout");
  }
}

function reservationToken(databasePath, executionId, slot) {
  const database = new DatabaseSync(databasePath, { readOnly: true });
  try {
    database.exec("PRAGMA busy_timeout=10000");
    const row = database
      .prepare(
        "SELECT round_id,execution_id,slot,reservation_receipt " +
          "FROM calls WHERE execution_id=? AND slot=?",
      )
      .get(executionId, slot);
    if (
      !row ||
      typeof row.round_id !== "string" ||
      typeof row.reservation_receipt !== "string"
    ) {
      throw new RacerError("dispatch_token_unavailable");
    }
    return {
      round_id: row.round_id,
      execution_id: row.execution_id,
      slot: row.slot,
      reservation_receipt: row.reservation_receipt,
    };
  } finally {
    database.close();
  }
}

function operation(ledger, input) {
  if (input.action === "reserve") {
    ledger.reserveCall(input.executionId, input.slot);
    return "call_reserved";
  }
  if (input.action === "dispatch") {
    ledger.markDispatched(
      reservationToken(input.databasePath, input.executionId, input.slot),
    );
    return "call_dispatched";
  }

  const execution = ledger.getExecution(input.executionId);
  ledger.stopRound(execution.round_id, "race_test_stop");
  return "round_stopped";
}

function errorCode(error) {
  if (error instanceof LedgerError || error instanceof RacerError) {
    return error.code;
  }
  if (
    error &&
    typeof error === "object" &&
    typeof error.code === "string" &&
    error.code === "SQLITE_BUSY"
  ) {
    return "sqlite_busy";
  }
  return "worker_operation_failed";
}

async function runWorker() {
  let ledger;
  let signer;
  let key;
  try {
    const input = parseInput(workerData);
    key = Buffer.from(input.keyHex, "hex");
    signer = new ReceiptSigner(key);
    key.fill(0);
    key = undefined;
    ledger = new ShadowCollectorLedger({
      database_path: input.databasePath,
      signer,
      now: () => input.now,
    });
    waitForSimultaneousRelease(input.barrier);
    const code = operation(ledger, input);
    parentPort?.postMessage({ ok: true, code });
  } catch (error) {
    parentPort?.postMessage({ ok: false, code: errorCode(error) });
  } finally {
    ledger?.close();
    signer?.dispose();
    key?.fill(0);
  }
}

if (!isMainThread) {
  await runWorker();
}
