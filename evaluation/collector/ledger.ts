import { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import {
  COLLECTOR_RECEIPT_DOMAINS,
  CollectorCallSlotSchema,
  CollectorCandidateManifestSchema,
  CollectorConsentGrantSchema,
  CollectorExecutionPlanSchema,
  CollectorGroundTruthEnvelopeSchema,
  CollectorSignedManifestSchema,
  ReceiptSigner,
  authorizeCollectorExecution,
  canonicalJson,
  createCollectorCandidateManifest,
  sha256Canonical,
  validateCollectorVerificationCoverage,
  verifyCollectorManifest,
} from "./contracts.ts";
import { parseFakeProviderWireEnvelope } from "./fake-provider.ts";
import type {
  CollectorCallSlot,
  CollectorProviderOutcome,
} from "./contracts.ts";
import {
  ShadowEvaluationCaseSchema,
  ShadowEvaluationSuiteSchema,
} from "../shadow-evaluator.ts";
import type {
  ShadowAttempt,
  ShadowEvaluationCase,
  ShadowEvaluationSuite,
} from "../shadow-evaluator.ts";

const HEX64 = /^[a-f0-9]{64}$/;
const REASON = /^[a-z][a-z0-9_]{0,63}$/;
const TERMINAL_PROVIDER_OUTCOMES = [
  "success",
  "timeout",
  "request_error",
  "invalid_output",
] as const;

type RoundStatus =
  | "draft"
  | "armed"
  | "running"
  | "completed"
  | "stopped"
  | "expired"
  | "review_required";

type RoundRow = {
  round_id: string;
  authorization_id: string;
  status: RoundStatus;
  signed_manifest_json: string;
  consent_grant_json: string;
  manifest_sha256: string;
  receipt_key_id: string;
  created_at_ms: number;
  expires_at_ms: number;
  max_executions: number;
  max_provider_calls: number;
  last_observed_ms: number;
};

type ExecutionRow = {
  execution_id: string;
  round_id: string;
  state: "running" | "complete" | "incomplete";
  plan_json: string;
  plan_receipt: string;
  candidate_json: string | null;
  candidate_receipt: string | null;
  truth_json: string | null;
  truth_receipt: string | null;
  case_json: string | null;
  case_receipt: string | null;
};

type CallRow = {
  execution_id: string;
  round_id: string;
  slot: CollectorCallSlot;
  ordinal: number;
  state: "planned" | "reserved" | "dispatched" | "result" | "cancelled";
  outcome: CollectorProviderOutcome | null;
  latency_ms: number | null;
  normalized_json: string | null;
  request_receipt: string | null;
  response_receipt: string | null;
  reservation_receipt: string | null;
  dispatch_receipt: string | null;
  result_receipt: string | null;
  reserved_at_ms: number | null;
  dispatched_at_ms: number | null;
  completed_at_ms: number | null;
};

type AuditRow = {
  seq: number;
  prev_hash: string;
  event_type: string;
  round_id: string | null;
  execution_id: string | null;
  slot: string | null;
  at_ms: number;
  payload_json: string;
  event_hash: string;
};

export class LedgerError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "LedgerError";
    this.code = code;
  }
}

export type ReservationToken = {
  round_id: string;
  execution_id: string;
  slot: CollectorCallSlot;
  reservation_receipt: string;
};

export type DispatchToken = ReservationToken & {
  dispatch_receipt: string;
};

export type FinishCallInput = {
  dispatch_token: DispatchToken;
  outcome: (typeof TERMINAL_PROVIDER_OUTCOMES)[number];
  latency_ms: number;
  request_receipt: string;
  response_receipt: string;
  request_bytes: Uint8Array;
  response_bytes: Uint8Array;
  normalized?: unknown;
};

const SQL = [
  "CREATE TABLE IF NOT EXISTS ledger_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS rounds(" +
    "round_id TEXT PRIMARY KEY,authorization_id TEXT NOT NULL," +
    "status TEXT NOT NULL CHECK(status IN ('draft','armed','running','completed','stopped','expired','review_required'))," +
    "signed_manifest_json TEXT NOT NULL,consent_grant_json TEXT NOT NULL," +
    "manifest_sha256 TEXT NOT NULL,manifest_receipt TEXT NOT NULL,receipt_key_id TEXT NOT NULL," +
    "created_at_ms INTEGER NOT NULL,expires_at_ms INTEGER NOT NULL,retention_until_ms INTEGER NOT NULL," +
    "max_executions INTEGER NOT NULL,max_provider_calls INTEGER NOT NULL,last_observed_ms INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS revocations(" +
    "authorization_id TEXT PRIMARY KEY,revoked_at_ms INTEGER NOT NULL,receipt TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS execution_grants(" +
    "execution_id TEXT PRIMARY KEY,round_id TEXT NOT NULL REFERENCES rounds(round_id)," +
    "position INTEGER NOT NULL,pair_commitment TEXT NOT NULL," +
    "state TEXT NOT NULL CHECK(state IN ('available','claimed')),UNIQUE(round_id,position))",
  "CREATE TABLE IF NOT EXISTS executions(" +
    "execution_id TEXT PRIMARY KEY REFERENCES execution_grants(execution_id)," +
    "round_id TEXT NOT NULL REFERENCES rounds(round_id)," +
    "state TEXT NOT NULL CHECK(state IN ('running','complete','incomplete'))," +
    "plan_json TEXT NOT NULL,plan_receipt TEXT NOT NULL," +
    "candidate_json TEXT,candidate_receipt TEXT,truth_json TEXT,truth_receipt TEXT," +
    "case_json TEXT,case_receipt TEXT,reason_code TEXT," +
    "started_at_ms INTEGER NOT NULL,completed_at_ms INTEGER)",
  "CREATE TABLE IF NOT EXISTS calls(" +
    "execution_id TEXT NOT NULL REFERENCES executions(execution_id)," +
    "round_id TEXT NOT NULL REFERENCES rounds(round_id)," +
    "slot TEXT NOT NULL CHECK(slot IN ('primary','flash','plus'))," +
    "ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 3)," +
    "state TEXT NOT NULL CHECK(state IN ('planned','reserved','dispatched','result','cancelled'))," +
    "outcome TEXT CHECK(outcome IS NULL OR outcome IN ('success','timeout','request_error','invalid_output','unknown_after_crash','cancelled_before_dispatch'))," +
    "latency_ms INTEGER,normalized_json TEXT,request_receipt TEXT,response_receipt TEXT," +
    "reservation_receipt TEXT,dispatch_receipt TEXT,result_receipt TEXT,reserved_at_ms INTEGER," +
    "dispatched_at_ms INTEGER,completed_at_ms INTEGER," +
    "PRIMARY KEY(execution_id,slot),UNIQUE(execution_id,ordinal))",
  "CREATE TABLE IF NOT EXISTS audit_events(" +
    "seq INTEGER PRIMARY KEY,prev_hash TEXT NOT NULL,event_type TEXT NOT NULL," +
    "round_id TEXT,execution_id TEXT,slot TEXT,at_ms INTEGER NOT NULL," +
    "payload_json TEXT NOT NULL,event_hash TEXT NOT NULL)",
  "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events " +
    "BEGIN SELECT RAISE(ABORT,'audit append only'); END",
  "CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events " +
    "BEGIN SELECT RAISE(ABORT,'audit append only'); END",
  "CREATE UNIQUE INDEX IF NOT EXISTS rounds_authorization_unique ON rounds(authorization_id)",
  "CREATE INDEX IF NOT EXISTS calls_round_state ON calls(round_id,state)",
  "CREATE INDEX IF NOT EXISTS executions_round_state ON executions(round_id,state)",
].join(";\n") + ";";

export class ShadowCollectorLedger {
  #db: DatabaseSync;
  #signer: ReceiptSigner;
  #clock: () => number;
  #closed = false;

  constructor(input: {
    database_path: string;
    signer: ReceiptSigner;
    now?: () => number;
  }) {
    if (!input.database_path || input.database_path === ":memory:") {
      throw new LedgerError("persistent_database_path_required");
    }
    this.#signer = input.signer;
    this.#clock = input.now ?? Date.now;
    this.#db = new DatabaseSync(input.database_path);
    this.#db.exec("PRAGMA journal_mode=WAL");
    this.#db.exec("PRAGMA synchronous=FULL");
    this.#db.exec("PRAGMA foreign_keys=ON");
    this.#db.exec("PRAGMA busy_timeout=10000");
    this.#db.exec(SQL);
    const journal = this.#db.prepare("PRAGMA journal_mode").get() as {
      journal_mode: string;
    };
    const synchronous = this.#db.prepare("PRAGMA synchronous").get() as {
      synchronous: number;
    };
    const foreignKeys = this.#db.prepare("PRAGMA foreign_keys").get() as {
      foreign_keys: number;
    };
    const busyTimeout = this.#db.prepare("PRAGMA busy_timeout").get() as {
      timeout: number;
    };
    const integrity = this.#db.prepare("PRAGMA integrity_check").get() as {
      integrity_check: string;
    };
    const foreignKeyErrors = this.#db.prepare("PRAGMA foreign_key_check").all();
    if (
      journal.journal_mode.toLowerCase() !== "wal" ||
      synchronous.synchronous !== 2 ||
      foreignKeys.foreign_keys !== 1 ||
      busyTimeout.timeout !== 10_000 ||
      integrity.integrity_check !== "ok" ||
      foreignKeyErrors.length !== 0
    ) {
      this.#db.close();
      this.#closed = true;
      throw new LedgerError("ledger_integrity_or_pragma_check_failed");
    }
    this.#transaction(() => {
      const schema = this.#db
        .prepare("SELECT value FROM ledger_meta WHERE key='schema_version'")
        .get() as { value: string } | undefined;
      if (schema && schema.value !== "checkback.shadow-ledger.v1") {
        throw new LedgerError("ledger_schema_mismatch");
      }
      if (!schema) {
        this.#db.prepare(
          "INSERT INTO ledger_meta(key,value) VALUES('schema_version',?)",
        ).run("checkback.shadow-ledger.v1");
      }
      const key = this.#db
        .prepare("SELECT value FROM ledger_meta WHERE key='receipt_key_id'")
        .get() as { value: string } | undefined;
      if (key && key.value !== this.#signer.keyId) {
        throw new LedgerError("ledger_receipt_key_mismatch");
      }
      if (!key) {
        this.#db.prepare(
          "INSERT INTO ledger_meta(key,value) VALUES('receipt_key_id',?)",
        ).run(this.#signer.keyId);
      }
    });
    if (!this.#auditChainValid()) {
      this.#db.close();
      this.#closed = true;
      throw new LedgerError("audit_chain_invalid");
    }
  }

  #assertOpen() {
    if (this.#closed) throw new LedgerError("ledger_closed");
  }

  #now() {
    const now = this.#clock();
    if (!Number.isInteger(now) || now < 0) throw new LedgerError("clock_invalid");
    return now;
  }

  #transaction<T>(fn: () => T): T {
    this.#assertOpen();
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.#db.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }

  #round(roundId: string) {
    const row = this.#db.prepare("SELECT * FROM rounds WHERE round_id=?")
      .get(roundId) as RoundRow | undefined;
    if (!row) throw new LedgerError("round_not_found");
    return row;
  }

  #execution(executionId: string) {
    const row = this.#db.prepare(
      "SELECT execution_id,round_id,state,plan_json,plan_receipt,candidate_json,candidate_receipt," +
        "truth_json,truth_receipt,case_json,case_receipt " +
        "FROM executions WHERE execution_id=?",
    ).get(executionId) as ExecutionRow | undefined;
    if (!row) throw new LedgerError("execution_not_found");
    return row;
  }

  #call(executionId: string, slot: CollectorCallSlot) {
    const row = this.#db.prepare(
      "SELECT execution_id,round_id,slot,ordinal,state,outcome,latency_ms,normalized_json," +
        "request_receipt,response_receipt,reservation_receipt,dispatch_receipt,result_receipt," +
        "reserved_at_ms,dispatched_at_ms,completed_at_ms " +
        "FROM calls WHERE execution_id=? AND slot=?",
    ).get(executionId, slot) as CallRow | undefined;
    if (!row) throw new LedgerError("call_not_found");
    return row;
  }

  #appendEvent(input: {
    event_type: string;
    round_id?: string;
    execution_id?: string;
    slot?: CollectorCallSlot;
    at_ms: number;
    payload?: unknown;
  }) {
    if (!REASON.test(input.event_type)) {
      throw new LedgerError("audit_event_type_invalid");
    }
    const last = this.#db.prepare(
      "SELECT seq,event_hash FROM audit_events ORDER BY seq DESC LIMIT 1",
    ).get() as { seq: number; event_hash: string } | undefined;
    const seq = (last?.seq ?? 0) + 1;
    const prev = last?.event_hash ?? "0".repeat(64);
    const payload = JSON.parse(canonicalJson(input.payload ?? {}));
    const value = {
      seq,
      prev_hash: prev,
      event_type: input.event_type,
      round_id: input.round_id ?? null,
      execution_id: input.execution_id ?? null,
      slot: input.slot ?? null,
      at_ms: input.at_ms,
      payload,
    };
    const hash = this.#signer.signValue(
      COLLECTOR_RECEIPT_DOMAINS.audit_event,
      value,
    );
    this.#db.prepare(
      "INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?,?)",
    ).run(
      seq,
      prev,
      input.event_type,
      input.round_id ?? null,
      input.execution_id ?? null,
      input.slot ?? null,
      input.at_ms,
      canonicalJson(payload),
      hash,
    );
    const head = { seq, event_hash: hash };
    const receipt = this.#signer.signValue(
      COLLECTOR_RECEIPT_DOMAINS.audit_head,
      head,
    );
    this.#db.prepare(
      "INSERT INTO ledger_meta(key,value) VALUES('audit_head',?) " +
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    ).run(canonicalJson({ ...head, receipt_hmac_sha256: receipt }));
  }

  #auditChainValid() {
    try {
      const rows = this.#db.prepare(
        "SELECT * FROM audit_events ORDER BY seq",
      ).all() as AuditRow[];
      const headRow = this.#db.prepare(
        "SELECT value FROM ledger_meta WHERE key='audit_head'",
      ).get() as { value: string } | undefined;
      if (rows.length === 0) {
        const state = this.#db.prepare(
          "SELECT (SELECT COUNT(*) FROM rounds) + " +
            "(SELECT COUNT(*) FROM revocations) + " +
            "(SELECT COUNT(*) FROM execution_grants) + " +
            "(SELECT COUNT(*) FROM executions) + " +
            "(SELECT COUNT(*) FROM calls) AS n",
        ).get() as { n: number };
        return !headRow && state.n === 0;
      }
      if (!headRow) return false;
      const head = z.object({
        seq: z.number().int().positive(),
        event_hash: z.string().regex(HEX64),
        receipt_hmac_sha256: z.string().regex(HEX64),
      }).strict().parse(JSON.parse(headRow.value));
      let previous = "0".repeat(64);
      let seq = 1;
      for (const row of rows) {
        if (row.seq !== seq || row.prev_hash !== previous) return false;
        const value = {
          seq: row.seq,
          prev_hash: row.prev_hash,
          event_type: row.event_type,
          round_id: row.round_id,
          execution_id: row.execution_id,
          slot: row.slot,
          at_ms: row.at_ms,
          payload: JSON.parse(row.payload_json),
        };
        if (!this.#signer.verifyValue(
          COLLECTOR_RECEIPT_DOMAINS.audit_event,
          value,
          row.event_hash,
        )) return false;
        previous = row.event_hash;
        seq += 1;
      }
      const expectedHead = {
        seq: rows.at(-1)!.seq,
        event_hash: rows.at(-1)!.event_hash,
      };
      return (
        head.seq === expectedHead.seq &&
        head.event_hash === expectedHead.event_hash &&
        this.#signer.verifyValue(
          COLLECTOR_RECEIPT_DOMAINS.audit_head,
          expectedHead,
          head.receipt_hmac_sha256,
        )
      );
    } catch {
      return false;
    }
  }

  #requireAudit() {
    if (!this.#auditChainValid()) {
      throw new LedgerError("audit_chain_invalid");
    }
  }

  #requireRoundBinding(row: RoundRow) {
    const manifest = verifyCollectorManifest(
      this.#signer,
      JSON.parse(row.signed_manifest_json),
    ).payload;
    if (
      manifest.round_id !== row.round_id ||
      manifest.authorization_id !== row.authorization_id ||
      manifest.created_at_ms !== row.created_at_ms ||
      manifest.expires_at_ms !== row.expires_at_ms ||
      manifest.max_executions !== row.max_executions ||
      manifest.max_provider_calls !== row.max_provider_calls ||
      manifest.receipt_key_id !== row.receipt_key_id ||
      sha256Canonical(manifest) !== row.manifest_sha256
    ) {
      throw new LedgerError("round_manifest_binding_invalid");
    }
  }

  #hasAuditEvent(
    eventType: string,
    roundId: string,
    executionId?: string,
    slot?: CollectorCallSlot,
  ) {
    return Boolean(this.#db.prepare(
      "SELECT 1 FROM audit_events WHERE event_type=? AND round_id=? " +
        "AND (? IS NULL OR execution_id=?) AND (? IS NULL OR slot=?) LIMIT 1",
    ).get(
      eventType,
      roundId,
      executionId ?? null,
      executionId ?? null,
      slot ?? null,
      slot ?? null,
    ));
  }

  #authorizationAuditEvent(
    eventType: "authorization_consumed" | "authorization_revoked",
    authorizationId: string,
  ) {
    const rows = this.#db.prepare(
      "SELECT payload_json FROM audit_events WHERE event_type=? ORDER BY seq",
    ).all(eventType) as Array<{ payload_json: string }>;
    return rows
      .map((row) => JSON.parse(row.payload_json) as Record<string, unknown>)
      .find((payload) => payload.authorization_id === authorizationId);
  }

  #executionIdWasRegistered(executionId: string) {
    return Boolean(this.#db.prepare(
      "SELECT 1 FROM audit_events " +
        "WHERE event_type='execution_registered' AND execution_id=? LIMIT 1",
    ).get(executionId));
  }

  #requireReservationReceipt(round: RoundRow, call: CallRow) {
    const manifest = CollectorSignedManifestSchema.parse(
      JSON.parse(round.signed_manifest_json),
    ).payload;
    if (
      call.reserved_at_ms === null ||
      !call.reservation_receipt ||
      !this.#signer.verifyValue(
        "collector.call-reservation.v1",
        {
          round_id: round.round_id,
          execution_id: call.execution_id,
          slot: call.slot,
          ordinal: call.ordinal,
          reserved_at_ms: call.reserved_at_ms,
          runtime_snapshot_sha256: manifest.runtime_snapshot_sha256,
        },
        call.reservation_receipt,
      )
    ) throw new LedgerError("reservation_state_receipt_invalid");
  }

  #requireDispatchReceipt(call: CallRow) {
    if (
      call.dispatched_at_ms === null ||
      !call.dispatch_receipt ||
      !call.reservation_receipt ||
      !this.#signer.verifyValue(
        "collector.call-dispatch.v1",
        {
          round_id: call.round_id,
          execution_id: call.execution_id,
          slot: call.slot,
          reservation_receipt: call.reservation_receipt,
          dispatched_at_ms: call.dispatched_at_ms,
        },
        call.dispatch_receipt,
      )
    ) throw new LedgerError("dispatch_state_receipt_invalid");
  }

  #requireCallResultReceipt(call: CallRow) {
    if (
      call.completed_at_ms === null ||
      call.latency_ms === null ||
      !call.outcome ||
      !call.request_receipt ||
      !call.response_receipt ||
      !call.dispatch_receipt ||
      !call.result_receipt
    ) throw new LedgerError("call_result_state_incomplete");
    const normalizedSha256 = call.normalized_json
      ? sha256Canonical(JSON.parse(call.normalized_json))
      : null;
    if (!this.#signer.verifyValue(
      "collector.call-result.v1",
      {
        round_id: call.round_id,
        execution_id: call.execution_id,
        slot: call.slot,
        dispatch_receipt: call.dispatch_receipt,
        outcome: call.outcome,
        latency_ms: call.latency_ms,
        normalized_sha256: normalizedSha256,
        request_receipt: call.request_receipt,
        response_receipt: call.response_receipt,
        completed_at_ms: call.completed_at_ms,
      },
      call.result_receipt,
    )) throw new LedgerError("call_result_state_receipt_invalid");
  }

  #isRevoked(authorizationId: string) {
    const row = this.#db.prepare(
      "SELECT revoked_at_ms,receipt FROM revocations WHERE authorization_id=?",
    ).get(authorizationId) as
      | { revoked_at_ms: number; receipt: string }
      | undefined;
    const event = this.#authorizationAuditEvent(
      "authorization_revoked",
      authorizationId,
    );
    if (!row && !event) return false;
    if (!row || !event) throw new LedgerError("revocation_state_invalid");
    if (
      event.revoked_at_ms !== row.revoked_at_ms ||
      event.receipt !== row.receipt ||
      !this.#signer.verifyValue(
        "collector.authorization-revocation.v1",
        {
          authorization_id: authorizationId,
          revoked_at_ms: row.revoked_at_ms,
        },
        row.receipt,
      )
    ) throw new LedgerError("revocation_state_invalid");
    return true;
  }

  #terminate(
    row: RoundRow,
    status: "stopped" | "expired" | "review_required",
    now: number,
    reason: string,
  ) {
    this.#db.prepare(
      "UPDATE rounds SET status=?,last_observed_ms=? WHERE round_id=?",
    ).run(status, now, row.round_id);
    this.#db.prepare(
      "UPDATE calls SET state='cancelled',outcome='cancelled_before_dispatch',completed_at_ms=? " +
        "WHERE round_id=? AND state IN ('planned','reserved')",
    ).run(now, row.round_id);
    this.#db.prepare(
      "UPDATE executions SET state='incomplete',reason_code=?,completed_at_ms=? " +
        "WHERE round_id=? AND state='running'",
    ).run(reason, now, row.round_id);
    this.#appendEvent({
      event_type: "round_" + status,
      round_id: row.round_id,
      at_ms: now,
      payload: { reason_code: reason },
    });
  }

  #guard(row: RoundRow, now: number) {
    this.#requireAudit();
    this.#requireRoundBinding(row);
    const terminalEvent = this.#db.prepare(
      "SELECT 1 FROM audit_events WHERE round_id=? AND event_type IN " +
        "('round_completed','round_stopped','round_expired','round_review_required'," +
        "'round_recovered') LIMIT 1",
    ).get(row.round_id);
    if (terminalEvent) return "round_terminal_event_present";
    const terminal = ["completed", "stopped", "expired", "review_required"];
    if (this.#isRevoked(row.authorization_id)) {
      if (!terminal.includes(row.status)) {
        this.#terminate(row, "stopped", now, "authorization_revoked");
      }
      return "authorization_revoked";
    }
    if (now < row.last_observed_ms) {
      if (!terminal.includes(row.status)) {
        this.#terminate(row, "review_required", now, "clock_rollback");
      }
      return "clock_rollback";
    }
    if (now >= row.expires_at_ms) {
      if (!terminal.includes(row.status)) {
        this.#terminate(row, "expired", now, "authorization_expired");
      }
      return "authorization_expired";
    }
    if (!["armed", "running"].includes(row.status)) return "round_not_active";
    this.#db.prepare(
      "UPDATE rounds SET last_observed_ms=? WHERE round_id=?",
    ).run(now, row.round_id);
    return null;
  }
  createRound(input: {
    signed_manifest: unknown;
    consent_grant: unknown;
  }) {
    const signed = verifyCollectorManifest(this.#signer, input.signed_manifest);
    const manifest = signed.payload;
    const grant = CollectorConsentGrantSchema.parse(input.consent_grant);
    if (manifest.consent_grant_sha256 !== sha256Canonical(grant)) {
      throw new LedgerError("consent_grant_hash_mismatch");
    }
    const projectionA = {
      authorization_id: manifest.authorization_id,
      purpose: manifest.purpose,
      provider_id: manifest.runtime.provider_id,
      provider_terms_sha256: manifest.provider_terms_sha256,
      created_at_ms: manifest.created_at_ms,
      expires_at_ms: manifest.expires_at_ms,
      retention_until_ms: manifest.retention_until_ms,
      max_executions: manifest.max_executions,
      max_provider_calls: manifest.max_provider_calls,
      authorized_executions: manifest.authorized_executions,
    };
    const projectionB = {
      authorization_id: grant.authorization_id,
      purpose: grant.purpose,
      provider_id: grant.provider_id,
      provider_terms_sha256: grant.provider_terms_sha256,
      created_at_ms: grant.created_at_ms,
      expires_at_ms: grant.expires_at_ms,
      retention_until_ms: grant.retention_until_ms,
      max_executions: grant.max_executions,
      max_provider_calls: grant.max_provider_calls,
      authorized_executions: grant.authorized_executions,
    };
    if (canonicalJson(projectionA) !== canonicalJson(projectionB)) {
      throw new LedgerError("consent_grant_field_mismatch");
    }

    return this.#transaction(() => {
      const now = this.#now();
      this.#requireAudit();
      if (now < manifest.created_at_ms || now >= manifest.expires_at_ms) {
        throw new LedgerError("authorization_outside_time_window");
      }
      if (
        this.#authorizationAuditEvent(
          "authorization_consumed",
          manifest.authorization_id,
        ) ||
        this.#db.prepare(
          "SELECT 1 FROM rounds WHERE authorization_id=?",
        ).get(manifest.authorization_id)
      ) {
        throw new LedgerError("authorization_already_consumed");
      }
      if (
        this.#hasAuditEvent("round_created", manifest.round_id) ||
        this.#db.prepare("SELECT 1 FROM rounds WHERE round_id=?")
          .get(manifest.round_id)
      ) {
        throw new LedgerError("round_already_exists");
      }
      if (this.#isRevoked(manifest.authorization_id)) {
        throw new LedgerError("authorization_revoked");
      }
      for (const item of manifest.authorized_executions) {
        if (
          this.#executionIdWasRegistered(item.execution_id) ||
          this.#db.prepare(
            "SELECT 1 FROM execution_grants WHERE execution_id=?",
          ).get(item.execution_id)
        ) {
          throw new LedgerError("execution_id_already_registered");
        }
      }
      this.#db.prepare(
        "INSERT INTO rounds VALUES(?,?,'draft',?,?,?,?,?,?,?,?,?,?,?)",
      ).run(
        manifest.round_id,
        manifest.authorization_id,
        canonicalJson(signed),
        canonicalJson(grant),
        sha256Canonical(manifest),
        signed.signature_hmac_sha256,
        manifest.receipt_key_id,
        manifest.created_at_ms,
        manifest.expires_at_ms,
        manifest.retention_until_ms,
        manifest.max_executions,
        manifest.max_provider_calls,
        now,
      );
      const insert = this.#db.prepare(
        "INSERT INTO execution_grants VALUES(?,?,?,?,'available')",
      );
      manifest.authorized_executions.forEach((item, index) => {
        const position = index + 1;
        insert.run(
          item.execution_id,
          manifest.round_id,
          position,
          item.pair_commitment_hmac_sha256,
        );
        this.#appendEvent({
          event_type: "execution_registered",
          round_id: manifest.round_id,
          execution_id: item.execution_id,
          at_ms: now,
          payload: {
            position,
            pair_commitment_hmac_sha256:
              item.pair_commitment_hmac_sha256,
          },
        });
      });
      this.#appendEvent({
        event_type: "authorization_consumed",
        round_id: manifest.round_id,
        at_ms: now,
        payload: {
          authorization_id: manifest.authorization_id,
          manifest_sha256: sha256Canonical(manifest),
        },
      });
      this.#appendEvent({
        event_type: "round_created",
        round_id: manifest.round_id,
        at_ms: now,
        payload: {
          authorization_id: manifest.authorization_id,
          manifest_sha256: sha256Canonical(manifest),
          max_executions: manifest.max_executions,
          max_provider_calls: manifest.max_provider_calls,
        },
      });
      return {
        round_id: manifest.round_id,
        manifest_sha256: sha256Canonical(manifest),
      };
    });
  }

  armRound(roundId: string) {
    let blocked: string | null = null;
    this.#transaction(() => {
      const now = this.#now();
      this.#requireAudit();
      const row = this.#round(roundId);
      this.#requireRoundBinding(row);
      if (row.status !== "draft") {
        blocked = "round_not_draft";
        return;
      }
      if (this.#isRevoked(row.authorization_id)) {
        this.#terminate(row, "stopped", now, "authorization_revoked");
        blocked = "authorization_revoked";
        return;
      }
      if (now < row.last_observed_ms) {
        this.#terminate(row, "review_required", now, "clock_rollback");
        blocked = "clock_rollback";
        return;
      }
      if (now >= row.expires_at_ms) {
        this.#terminate(row, "expired", now, "authorization_expired");
        blocked = "authorization_expired";
        return;
      }
      this.#db.prepare(
        "UPDATE rounds SET status='armed',last_observed_ms=? WHERE round_id=?",
      ).run(now, roundId);
      this.#appendEvent({
        event_type: "round_armed",
        round_id: roundId,
        at_ms: now,
      });
    });
    if (blocked) throw new LedgerError(blocked);
  }

  claimExecution(input: {
    round_id: string;
    execution_plan: unknown;
  }) {
    const plan = CollectorExecutionPlanSchema.parse(input.execution_plan);
    if (plan.round_id !== input.round_id) {
      throw new LedgerError("execution_round_mismatch");
    }
    let blocked: string | null = null;
    const result = this.#transaction(() => {
      const now = this.#now();
      const round = this.#round(input.round_id);
      blocked = this.#guard(round, now);
      if (blocked) return null;
      const signed = CollectorSignedManifestSchema.parse(
        JSON.parse(round.signed_manifest_json),
      );
      const grant = CollectorConsentGrantSchema.parse(
        JSON.parse(round.consent_grant_json),
      );
      authorizeCollectorExecution({
        signed_manifest: signed,
        consent_grant: grant,
        execution_plan: plan,
        signer: this.#signer,
        now_ms: now,
      });
      const allocation = this.#db.prepare(
        "SELECT state FROM execution_grants WHERE execution_id=? AND round_id=?",
      ).get(plan.execution_id, round.round_id) as
        | { state: "available" | "claimed" }
        | undefined;
      if (this.#hasAuditEvent(
        "execution_claimed",
        round.round_id,
        plan.execution_id,
      )) throw new LedgerError("execution_already_claimed");
      if (!allocation) throw new LedgerError("execution_not_authorized");
      if (allocation.state !== "available") {
        throw new LedgerError("execution_already_claimed");
      }
      const count = this.#db.prepare(
        "SELECT COUNT(*) AS n FROM execution_grants WHERE round_id=? AND state='claimed'",
      ).get(round.round_id) as { n: number };
      if (count.n >= round.max_executions) {
        throw new LedgerError("round_execution_budget_exhausted");
      }
      const planReceipt = this.#signer.signValue(
        COLLECTOR_RECEIPT_DOMAINS.execution_plan,
        plan,
      );
      this.#db.prepare(
        "INSERT INTO executions(execution_id,round_id,state,plan_json,plan_receipt,started_at_ms) " +
          "VALUES(?,?,'running',?,?,?)",
      ).run(
        plan.execution_id,
        round.round_id,
        canonicalJson(plan),
        planReceipt,
        now,
      );
      this.#db.prepare(
        "UPDATE execution_grants SET state='claimed' WHERE execution_id=?",
      ).run(plan.execution_id);
      const insert = this.#db.prepare(
        "INSERT INTO calls(execution_id,round_id,slot,ordinal,state) VALUES(?,?,?,?,'planned')",
      );
      insert.run(plan.execution_id, round.round_id, "primary", 1);
      insert.run(plan.execution_id, round.round_id, "flash", 2);
      insert.run(plan.execution_id, round.round_id, "plus", 3);
      this.#db.prepare(
        "UPDATE rounds SET status='running' WHERE round_id=?",
      ).run(round.round_id);
      this.#appendEvent({
        event_type: "execution_claimed",
        round_id: round.round_id,
        execution_id: plan.execution_id,
        at_ms: now,
        payload: { plan_receipt: planReceipt },
      });
      return { execution_id: plan.execution_id, plan_receipt: planReceipt };
    });
    if (blocked) throw new LedgerError(blocked);
    if (!result) throw new LedgerError("execution_claim_failed");
    return result;
  }

  reserveCall(
    executionId: string,
    slotInput: unknown,
  ): ReservationToken {
    const slot = CollectorCallSlotSchema.parse(slotInput);
    let blocked: string | null = null;
    const result = this.#transaction(() => {
      const now = this.#now();
      const execution = this.#execution(executionId);
      const round = this.#round(execution.round_id);
      blocked = this.#guard(round, now);
      if (blocked) return null;
      if (
        this.#hasAuditEvent(
          "execution_incomplete",
          round.round_id,
          executionId,
        ) ||
        this.#hasAuditEvent(
          "execution_completed",
          round.round_id,
          executionId,
        )
      ) {
        throw new LedgerError("execution_terminal_event_present");
      }
      if (execution.state !== "running") {
        throw new LedgerError("execution_not_running");
      }
      const call = this.#call(executionId, slot);
      if (this.#hasAuditEvent(
        "call_reserved",
        round.round_id,
        executionId,
        slot,
      )) throw new LedgerError("call_slot_already_consumed");
      if (
        call.reserved_at_ms !== null ||
        call.reservation_receipt !== null ||
        call.dispatch_receipt !== null ||
        call.result_receipt !== null
      ) throw new LedgerError("planned_call_state_invalid");
      if (call.state !== "planned") {
        throw new LedgerError("call_slot_not_planned");
      }
      if (slot === "flash") {
        const primary = this.#call(executionId, "primary");
        if (
          primary.state !== "result" ||
          primary.outcome !== "success" ||
          !execution.candidate_json ||
          !execution.truth_json
        ) {
          throw new LedgerError("flash_prerequisites_not_met");
        }
      }
      if (slot === "plus") {
        const primary = this.#call(executionId, "primary");
        const flash = this.#call(executionId, "flash");
        if (
          primary.state !== "result" ||
          primary.outcome !== "success" ||
          flash.state !== "result" ||
          !TERMINAL_PROVIDER_OUTCOMES.includes(
            flash.outcome as (typeof TERMINAL_PROVIDER_OUTCOMES)[number],
          ) ||
          !execution.truth_json
        ) {
          throw new LedgerError("plus_prerequisites_not_met");
        }
      }
      const total = this.#db.prepare(
        "SELECT COUNT(*) AS n FROM calls WHERE round_id=? AND reserved_at_ms IS NOT NULL",
      ).get(round.round_id) as { n: number };
      if (total.n >= round.max_provider_calls) {
        throw new LedgerError("round_call_budget_exhausted");
      }
      const perExecution = this.#db.prepare(
        "SELECT COUNT(*) AS n FROM calls WHERE execution_id=? AND reserved_at_ms IS NOT NULL",
      ).get(executionId) as { n: number };
      if (perExecution.n >= 3) {
        throw new LedgerError("execution_call_budget_exhausted");
      }
      const manifest = CollectorSignedManifestSchema.parse(
        JSON.parse(round.signed_manifest_json),
      ).payload;
      const receipt = this.#signer.signValue(
        "collector.call-reservation.v1",
        {
          round_id: round.round_id,
          execution_id: executionId,
          slot,
          ordinal: call.ordinal,
          reserved_at_ms: now,
          runtime_snapshot_sha256: manifest.runtime_snapshot_sha256,
        },
      );
      this.#db.prepare(
        "UPDATE calls SET state='reserved',reserved_at_ms=?,reservation_receipt=? " +
          "WHERE execution_id=? AND slot=? AND state='planned'",
      ).run(now, receipt, executionId, slot);
      this.#appendEvent({
        event_type: "call_reserved",
        round_id: round.round_id,
        execution_id: executionId,
        slot,
        at_ms: now,
        payload: { ordinal: call.ordinal, reservation_receipt: receipt },
      });
      return {
        round_id: round.round_id,
        execution_id: executionId,
        slot,
        reservation_receipt: receipt,
      };
    });
    if (blocked) throw new LedgerError(blocked);
    if (!result) throw new LedgerError("call_reservation_failed");
    return result;
  }

  markDispatched(token: ReservationToken): DispatchToken {
    const slot = CollectorCallSlotSchema.parse(token.slot);
    if (!HEX64.test(token.reservation_receipt)) {
      throw new LedgerError("reservation_receipt_invalid");
    }
    let blocked: string | null = null;
    const result = this.#transaction(() => {
      const now = this.#now();
      const execution = this.#execution(token.execution_id);
      const round = this.#round(execution.round_id);
      blocked = this.#guard(round, now);
      if (blocked) return null;
      if (
        this.#hasAuditEvent(
          "execution_incomplete",
          round.round_id,
          token.execution_id,
        ) ||
        this.#hasAuditEvent(
          "execution_completed",
          round.round_id,
          token.execution_id,
        )
      ) throw new LedgerError("execution_terminal_event_present");
      const call = this.#call(token.execution_id, slot);
      if (
        token.round_id !== round.round_id ||
        execution.state !== "running" ||
        call.state !== "reserved" ||
        call.reservation_receipt !== token.reservation_receipt
      ) {
        throw new LedgerError("dispatch_token_invalid");
      }
      this.#requireReservationReceipt(round, call);
      if (!this.#hasAuditEvent(
        "call_reserved",
        round.round_id,
        token.execution_id,
        slot,
      )) throw new LedgerError("reservation_audit_event_missing");
      if (
        this.#hasAuditEvent(
          "call_dispatched",
          round.round_id,
          token.execution_id,
          slot,
        ) ||
        this.#hasAuditEvent(
          "call_result",
          round.round_id,
          token.execution_id,
          slot,
        )
      ) throw new LedgerError("call_dispatch_already_recorded");
      const receipt = this.#signer.signValue(
        "collector.call-dispatch.v1",
        {
          round_id: round.round_id,
          execution_id: token.execution_id,
          slot,
          reservation_receipt: token.reservation_receipt,
          dispatched_at_ms: now,
        },
      );
      this.#db.prepare(
        "UPDATE calls SET state='dispatched',dispatched_at_ms=?,dispatch_receipt=? " +
          "WHERE execution_id=? AND slot=? AND state='reserved'",
      ).run(now, receipt, token.execution_id, slot);
      this.#appendEvent({
        event_type: "call_dispatched",
        round_id: round.round_id,
        execution_id: token.execution_id,
        slot,
        at_ms: now,
        payload: { dispatch_receipt: receipt },
      });
      return { ...token, slot, dispatch_receipt: receipt };
    });
    if (blocked) throw new LedgerError(blocked);
    if (!result) throw new LedgerError("call_dispatch_failed");
    return result;
  }

  finishCall(input: FinishCallInput) {
    const token = input.dispatch_token;
    const slot = CollectorCallSlotSchema.parse(token.slot);
    const outcome = z.enum(TERMINAL_PROVIDER_OUTCOMES).parse(input.outcome);
    const latency = z.number().int().min(0).max(300_000).parse(input.latency_ms);
    if (
      !HEX64.test(token.dispatch_receipt) ||
      !HEX64.test(input.request_receipt) ||
      !HEX64.test(input.response_receipt)
    ) {
      throw new LedgerError("call_receipt_invalid");
    }
    return this.#transaction(() => {
      const now = this.#now();
      this.#requireAudit();
      const execution = this.#execution(token.execution_id);
      const round = this.#round(execution.round_id);
      this.#requireRoundBinding(round);
      if (
        this.#hasAuditEvent(
          "execution_incomplete",
          round.round_id,
          token.execution_id,
        ) ||
        this.#hasAuditEvent(
          "execution_completed",
          round.round_id,
          token.execution_id,
        )
      ) throw new LedgerError("execution_terminal_event_present");
      const call = this.#call(token.execution_id, slot);
      if (
        token.round_id !== execution.round_id ||
        call.state !== "dispatched" ||
        call.reservation_receipt !== token.reservation_receipt ||
        call.dispatch_receipt !== token.dispatch_receipt
      ) {
        throw new LedgerError("call_dispatch_token_mismatch");
      }
      this.#requireReservationReceipt(round, call);
      this.#requireDispatchReceipt(call);
      if (!this.#hasAuditEvent(
        "call_dispatched",
        round.round_id,
        token.execution_id,
        slot,
      )) throw new LedgerError("dispatch_audit_event_missing");
      if (this.#hasAuditEvent(
        "call_result",
        round.round_id,
        token.execution_id,
        slot,
      )) throw new LedgerError("call_result_already_recorded");
      if (
        !this.#signer.verifyBytes(
          "collector.provider-request." + slot + ".v1",
          input.request_bytes,
          input.request_receipt,
        ) ||
        !this.#signer.verifyBytes(
          "collector.provider-response." + slot + ".v1",
          input.response_bytes,
          input.response_receipt,
        )
      ) throw new LedgerError("provider_byte_receipt_invalid");
      let requestWire: ReturnType<typeof parseFakeProviderWireEnvelope>;
      let responseWire: ReturnType<typeof parseFakeProviderWireEnvelope>;
      try {
        requestWire = parseFakeProviderWireEnvelope(input.request_bytes);
        responseWire = parseFakeProviderWireEnvelope(input.response_bytes);
      } catch {
        throw new LedgerError("provider_wire_envelope_invalid");
      }
      if (
        requestWire.execution_id !== token.execution_id ||
        responseWire.execution_id !== token.execution_id ||
        requestWire.slot !== slot ||
        responseWire.slot !== slot
      ) throw new LedgerError("provider_wire_binding_invalid");

      let candidatesForWire = null;
      const expectedRequestPayload = slot === "primary"
        ? { purpose: "shadow-rehearsal-primary" }
        : (() => {
            if (!execution.candidate_json) {
              throw new LedgerError("candidate_manifest_missing");
            }
            candidatesForWire = CollectorCandidateManifestSchema.parse(
              JSON.parse(execution.candidate_json),
            );
            return {
              purpose: "shadow-rehearsal-verifier",
              candidate_ids: candidatesForWire.ordered_item_ids,
            };
          })();
      if (
        canonicalJson(requestWire.payload) !==
        canonicalJson(expectedRequestPayload)
      ) throw new LedgerError("provider_request_payload_mismatch");

      let normalizedJson: string | null = null;
      let candidateManifest = null;
      let expectedResponsePayload: unknown;
      if (outcome === "success" && slot === "primary") {
        const parsed = z.object({
          candidate_ids: z.array(
            z.string().regex(/^item-[0-9]{4,8}$/),
          ).min(1).max(20),
        }).strict().parse(input.normalized);
        candidateManifest = createCollectorCandidateManifest({
          execution_id: token.execution_id,
          ordered_item_ids: parsed.candidate_ids,
        });
        const receipt = this.#signer.signValue(
          COLLECTOR_RECEIPT_DOMAINS.candidate_manifest,
          candidateManifest,
        );
        normalizedJson = canonicalJson({
          candidate_ids: candidateManifest.ordered_item_ids,
        });
        expectedResponsePayload = {
          outcome,
          latency_ms: latency,
          candidate_ids: candidateManifest.ordered_item_ids,
        };
        this.#db.prepare(
          "UPDATE executions SET candidate_json=?,candidate_receipt=? WHERE execution_id=?",
        ).run(
          canonicalJson(candidateManifest),
          receipt,
          token.execution_id,
        );
      } else if (outcome === "success") {
        if (!candidatesForWire) {
          throw new LedgerError("candidate_manifest_missing");
        }
        const batch = validateCollectorVerificationCoverage(
          candidatesForWire,
          input.normalized,
        );
        normalizedJson = canonicalJson(batch);
        expectedResponsePayload = {
          outcome,
          latency_ms: latency,
          batch,
        };
      } else {
        if (input.normalized !== undefined) {
          throw new LedgerError("failed_call_must_not_store_output");
        }
        expectedResponsePayload = { outcome, latency_ms: latency };
      }
      if (
        canonicalJson(responseWire.payload) !==
        canonicalJson(expectedResponsePayload)
      ) throw new LedgerError("provider_response_payload_mismatch");
      const resultReceipt = this.#signer.signValue(
        "collector.call-result.v1",
        {
          round_id: execution.round_id,
          execution_id: token.execution_id,
          slot,
          dispatch_receipt: token.dispatch_receipt,
          outcome,
          latency_ms: latency,
          normalized_sha256: normalizedJson
            ? sha256Canonical(JSON.parse(normalizedJson))
            : null,
          request_receipt: input.request_receipt,
          response_receipt: input.response_receipt,
          completed_at_ms: now,
        },
      );
      this.#db.prepare(
        "UPDATE calls SET state='result',outcome=?,latency_ms=?,normalized_json=?," +
          "request_receipt=?,response_receipt=?,result_receipt=?,completed_at_ms=? " +
          "WHERE execution_id=? AND slot=? AND state='dispatched'",
      ).run(
        outcome,
        latency,
        normalizedJson,
        input.request_receipt,
        input.response_receipt,
        resultReceipt,
        now,
        token.execution_id,
        slot,
      );
      this.#appendEvent({
        event_type: "call_result",
        round_id: execution.round_id,
        execution_id: token.execution_id,
        slot,
        at_ms: now,
        payload: {
          outcome,
          latency_ms: latency,
          request_receipt: input.request_receipt,
          response_receipt: input.response_receipt,
          result_receipt: resultReceipt,
        },
      });
      return { candidate_manifest: candidateManifest };
    });
  }

  lockGroundTruth(input: {
    execution_id: string;
    envelope: unknown;
  }) {
    const envelope = CollectorGroundTruthEnvelopeSchema.parse(input.envelope);
    let blocked: string | null = null;
    const result = this.#transaction(() => {
      const now = this.#now();
      const execution = this.#execution(input.execution_id);
      const round = this.#round(execution.round_id);
      blocked = this.#guard(round, now);
      if (blocked) return null;
      if (
        this.#hasAuditEvent(
          "execution_incomplete",
          execution.round_id,
          execution.execution_id,
        ) ||
        this.#hasAuditEvent(
          "execution_completed",
          execution.round_id,
          execution.execution_id,
        )
      ) throw new LedgerError("execution_terminal_event_present");
      if (this.#hasAuditEvent(
        "ground_truth_locked",
        execution.round_id,
        execution.execution_id,
      )) throw new LedgerError("ground_truth_already_locked");
      if (
        execution.state !== "running" ||
        envelope.execution_id !== execution.execution_id ||
        execution.truth_json ||
        !execution.candidate_json
      ) {
        throw new LedgerError("ground_truth_lock_state_invalid");
      }
      const primary = this.#call(input.execution_id, "primary");
      const flash = this.#call(input.execution_id, "flash");
      this.#requireCallResultReceipt(primary);
      if (
        primary.state !== "result" ||
        primary.outcome !== "success" ||
        flash.state !== "planned"
      ) {
        throw new LedgerError("ground_truth_lock_order_invalid");
      }
      const plan = CollectorExecutionPlanSchema.parse(
        JSON.parse(execution.plan_json),
      );
      const candidates = CollectorCandidateManifestSchema.parse(
        JSON.parse(execution.candidate_json),
      );
      if (
        !this.#signer.verifyValue(
          COLLECTOR_RECEIPT_DOMAINS.execution_plan,
          plan,
          execution.plan_receipt,
        ) ||
        !execution.candidate_receipt ||
        !this.#signer.verifyValue(
          COLLECTOR_RECEIPT_DOMAINS.candidate_manifest,
          candidates,
          execution.candidate_receipt,
        )
      ) throw new LedgerError("execution_input_receipt_invalid");
      if (
        envelope.execution_plan_sha256 !== sha256Canonical(plan) ||
        envelope.candidate_manifest_sha256 !==
          candidates.candidate_manifest_sha256 ||
        envelope.locked_at_ms < (primary.completed_at_ms ?? 0) ||
        envelope.locked_at_ms > now
      ) {
        throw new LedgerError("ground_truth_binding_invalid");
      }
      const ids = envelope.ground_truth.items.map((item) => item.id);
      if (
        ids.length !== candidates.ordered_item_ids.length ||
        new Set(ids).size !== ids.length ||
        candidates.ordered_item_ids.some((id) => !ids.includes(id))
      ) {
        throw new LedgerError("ground_truth_candidate_coverage_invalid");
      }
      const receipt = this.#signer.signValue(
        COLLECTOR_RECEIPT_DOMAINS.ground_truth,
        envelope,
      );
      this.#db.prepare(
        "UPDATE executions SET truth_json=?,truth_receipt=? WHERE execution_id=?",
      ).run(canonicalJson(envelope), receipt, input.execution_id);
      this.#appendEvent({
        event_type: "ground_truth_locked",
        round_id: execution.round_id,
        execution_id: input.execution_id,
        at_ms: now,
        payload: {
          candidate_manifest_sha256: candidates.candidate_manifest_sha256,
          truth_receipt: receipt,
        },
      });
      return receipt;
    });
    if (blocked) throw new LedgerError(blocked);
    if (!result) throw new LedgerError("ground_truth_lock_failed");
    return result;
  }

  markExecutionIncomplete(executionId: string, reason: string) {
    if (!REASON.test(reason)) throw new LedgerError("reason_code_invalid");
    this.#transaction(() => {
      const now = this.#now();
      this.#requireAudit();
      const execution = this.#execution(executionId);
      this.#requireRoundBinding(this.#round(execution.round_id));
      const incompleteRecorded = this.#hasAuditEvent(
        "execution_incomplete",
        execution.round_id,
        executionId,
      );
      const completeRecorded = this.#hasAuditEvent(
        "execution_completed",
        execution.round_id,
        executionId,
      );
      if (completeRecorded) {
        throw new LedgerError("execution_terminal_event_present");
      }
      if (incompleteRecorded) {
        if (execution.state === "incomplete") return;
        throw new LedgerError("execution_terminal_event_present");
      }
      if (execution.state !== "running") {
        throw new LedgerError("execution_terminal_state_invalid");
      }
      this.#db.prepare(
        "UPDATE executions SET state='incomplete',reason_code=?,completed_at_ms=? " +
          "WHERE execution_id=?",
      ).run(reason, now, executionId);
      this.#db.prepare(
        "UPDATE calls SET state='cancelled',outcome='cancelled_before_dispatch',completed_at_ms=? " +
          "WHERE execution_id=? AND state IN ('planned','reserved')",
      ).run(now, executionId);
      this.#db.prepare(
        "UPDATE calls SET state='result',outcome='unknown_after_crash',completed_at_ms=? " +
          "WHERE execution_id=? AND state='dispatched'",
      ).run(now, executionId);
      this.#appendEvent({
        event_type: "execution_incomplete",
        round_id: execution.round_id,
        execution_id: executionId,
        at_ms: now,
        payload: { reason_code: reason },
      });
    });
  }

  finalizeExecution(executionId: string): ShadowEvaluationCase {
    return this.#transaction(() => {
      const now = this.#now();
      this.#requireAudit();
      const execution = this.#execution(executionId);
      this.#requireRoundBinding(this.#round(execution.round_id));
      const completionRecorded = this.#hasAuditEvent(
        "execution_completed",
        execution.round_id,
        executionId,
      );
      const incompleteRecorded = this.#hasAuditEvent(
        "execution_incomplete",
        execution.round_id,
        executionId,
      );
      if (execution.state === "complete" && execution.case_json) {
        if (!completionRecorded || incompleteRecorded) {
          throw new LedgerError("execution_terminal_event_invalid");
        }
        const value = ShadowEvaluationCaseSchema.parse(
          JSON.parse(execution.case_json),
        );
        if (
          !execution.case_receipt ||
          !this.#signer.verifyValue(
            "collector.evaluation-case.v1",
            value,
            execution.case_receipt,
          )
        ) {
          throw new LedgerError("evaluation_case_receipt_invalid");
        }
        return value;
      }
      if (completionRecorded || incompleteRecorded) {
        throw new LedgerError("execution_terminal_event_present");
      }
      if (
        execution.state !== "running" ||
        !execution.candidate_json ||
        !execution.truth_json
      ) {
        throw new LedgerError("execution_not_finalizable");
      }
      const plan = CollectorExecutionPlanSchema.parse(
        JSON.parse(execution.plan_json),
      );
      const candidates = CollectorCandidateManifestSchema.parse(
        JSON.parse(execution.candidate_json),
      );
      const truth = CollectorGroundTruthEnvelopeSchema.parse(
        JSON.parse(execution.truth_json),
      );
      if (
        !this.#signer.verifyValue(
          COLLECTOR_RECEIPT_DOMAINS.execution_plan,
          plan,
          execution.plan_receipt,
        ) ||
        !execution.candidate_receipt ||
        !this.#signer.verifyValue(
          COLLECTOR_RECEIPT_DOMAINS.candidate_manifest,
          candidates,
          execution.candidate_receipt,
        ) ||
        !execution.truth_receipt ||
        !this.#signer.verifyValue(
          COLLECTOR_RECEIPT_DOMAINS.ground_truth,
          truth,
          execution.truth_receipt,
        )
      ) throw new LedgerError("execution_input_receipt_invalid");
      const primary = this.#call(executionId, "primary");
      const flash = this.#call(executionId, "flash");
      const plus = this.#call(executionId, "plus");
      this.#requireCallResultReceipt(primary);
      this.#requireCallResultReceipt(flash);
      this.#requireCallResultReceipt(plus);
      if (
        primary.state !== "result" ||
        primary.outcome !== "success" ||
        flash.state !== "result" ||
        plus.state !== "result"
      ) {
        throw new LedgerError("execution_calls_incomplete");
      }
      if (
        !TERMINAL_PROVIDER_OUTCOMES.includes(
          flash.outcome as (typeof TERMINAL_PROVIDER_OUTCOMES)[number],
        ) ||
        !TERMINAL_PROVIDER_OUTCOMES.includes(
          plus.outcome as (typeof TERMINAL_PROVIDER_OUTCOMES)[number],
        )
      ) {
        throw new LedgerError("execution_contains_non_evaluable_outcome");
      }
      const attempt = (call: CallRow): ShadowAttempt => {
        if (call.outcome === "success") {
          if (!call.normalized_json) {
            throw new LedgerError("successful_verifier_output_missing");
          }
          return {
            outcome: "success",
            latency_ms: call.latency_ms ?? 0,
            batch: JSON.parse(call.normalized_json),
          };
        }
        if (
          call.outcome === "timeout" ||
          call.outcome === "request_error" ||
          call.outcome === "invalid_output"
        ) {
          return {
            outcome: call.outcome,
            latency_ms: call.latency_ms ?? 0,
          };
        }
        throw new LedgerError("verifier_outcome_not_evaluable");
      };
      const manifest = CollectorSignedManifestSchema.parse(
        JSON.parse(this.#round(execution.round_id).signed_manifest_json),
      ).payload;
      const value = ShadowEvaluationCaseSchema.parse({
        case_id: plan.case_id,
        scene_id: plan.scene_id,
        trial_id: plan.trial_id,
        split: plan.split,
        cohort: plan.cohort,
        sampling_plan_id: plan.sampling_plan_id,
        scenario: plan.scenario,
        day_bucket: plan.day_bucket,
        time_period: plan.time_period,
        candidates: candidates.ordered_item_ids,
        ground_truth: truth.ground_truth,
        execution: {
          execution_id: plan.execution_id,
          config_sha256: manifest.runtime.config_sha256,
          primary_calls: 1,
          flash_calls: 1,
          plus_calls: 1,
          retry_calls: 0,
          total_calls: 3,
        },
        primary_latency_ms: primary.latency_ms ?? 0,
        flash: attempt(flash),
        plus: attempt(plus),
      });
      const receipt = this.#signer.signValue(
        "collector.evaluation-case.v1",
        value,
      );
      this.#db.prepare(
        "UPDATE executions SET state='complete',case_json=?,case_receipt=?,completed_at_ms=? " +
          "WHERE execution_id=?",
      ).run(canonicalJson(value), receipt, now, executionId);
      this.#appendEvent({
        event_type: "execution_completed",
        round_id: execution.round_id,
        execution_id: executionId,
        at_ms: now,
        payload: {
          case_sha256: sha256Canonical(value),
          case_receipt: receipt,
        },
      });
      return value;
    });
  }

  completeRound(roundId: string) {
    let blocked: string | null = null;
    this.#transaction(() => {
      const now = this.#now();
      const round = this.#round(roundId);
      blocked = this.#guard(round, now);
      if (blocked) return;
      const counts = this.#db.prepare(
        "SELECT COUNT(*) AS total," +
          "SUM(CASE WHEN state='complete' THEN 1 ELSE 0 END) AS done " +
          "FROM executions WHERE round_id=?",
      ).get(roundId) as { total: number; done: number };
      const calls = this.#db.prepare(
        "SELECT COUNT(*) AS n FROM calls WHERE round_id=? AND reserved_at_ms IS NOT NULL",
      ).get(roundId) as { n: number };
      if (
        counts.total !== round.max_executions ||
        counts.done !== round.max_executions ||
        calls.n !== round.max_provider_calls
      ) {
        throw new LedgerError("round_not_complete");
      }
      this.#db.prepare(
        "UPDATE rounds SET status='completed',last_observed_ms=? WHERE round_id=?",
      ).run(now, roundId);
      this.#appendEvent({
        event_type: "round_completed",
        round_id: roundId,
        at_ms: now,
        payload: {
          executions: counts.done,
          provider_call_slots: calls.n,
        },
      });
    });
    if (blocked) throw new LedgerError(blocked);
  }

  exportSuite(roundId: string): ShadowEvaluationSuite {
    return this.#transaction(() => {
      this.#requireAudit();
      const round = this.#round(roundId);
      this.#requireRoundBinding(round);
    if (round.status !== "completed") {
      throw new LedgerError("round_not_exportable");
    }
    const manifest = verifyCollectorManifest(
      this.#signer,
      JSON.parse(round.signed_manifest_json),
    ).payload;
    const rows = this.#db.prepare(
      "SELECT case_json,case_receipt FROM executions WHERE round_id=? ORDER BY execution_id",
    ).all(roundId) as Array<{
      case_json: string | null;
      case_receipt: string | null;
    }>;
    const cases = rows.map((row) => {
      if (!row.case_json || !row.case_receipt) {
        throw new LedgerError("evaluation_case_missing");
      }
      const value = ShadowEvaluationCaseSchema.parse(JSON.parse(row.case_json));
      if (!this.#signer.verifyValue(
        "collector.evaluation-case.v1",
        value,
        row.case_receipt,
      )) {
        throw new LedgerError("evaluation_case_receipt_invalid");
      }
      return value;
    });
    return ShadowEvaluationSuiteSchema.parse({
      schema_version: "checkback.shadow-eval.v1",
      suite_id: manifest.suite_id,
      scope: "verifier_only",
      sampling_plan: manifest.sampling_plan,
      config: manifest.config,
      cases,
      });
    });
  }

  stopRound(roundId: string, reason = "operator_stop") {
    if (!REASON.test(reason)) throw new LedgerError("reason_code_invalid");
    this.#transaction(() => {
      const now = this.#now();
      this.#requireAudit();
      const row = this.#round(roundId);
      this.#requireRoundBinding(row);
      if (row.status === "stopped") return;
      if (["completed", "expired", "review_required"].includes(row.status)) {
        throw new LedgerError("round_terminal");
      }
      this.#terminate(row, "stopped", now, reason);
    });
  }

  revokeAuthorization(authorizationId: string) {
    if (!/^authorization-[0-9]{4,8}$/.test(authorizationId)) {
      throw new LedgerError("authorization_id_invalid");
    }
    this.#transaction(() => {
      const now = this.#now();
      this.#requireAudit();
      if (this.#isRevoked(authorizationId)) return;
      const receipt = this.#signer.signValue(
        "collector.authorization-revocation.v1",
        { authorization_id: authorizationId, revoked_at_ms: now },
      );
      this.#db.prepare(
        "INSERT INTO revocations VALUES(?,?,?)",
      ).run(authorizationId, now, receipt);
      this.#appendEvent({
        event_type: "authorization_revoked",
        at_ms: now,
        payload: {
          authorization_id: authorizationId,
          revoked_at_ms: now,
          receipt,
        },
      });
    });

    this.#transaction(() => {
      const now = this.#now();
      this.#requireAudit();
      if (!this.#isRevoked(authorizationId)) {
        throw new LedgerError("revocation_durability_check_failed");
      }
      const rows = this.#db.prepare(
        "SELECT * FROM rounds WHERE authorization_id=? " +
          "AND status IN ('draft','armed','running')",
      ).all(authorizationId) as RoundRow[];
      for (const row of rows) {
        this.#terminate(row, "stopped", now, "authorization_revoked");
      }
    });
  }

  recoverInterrupted(roundId: string) {
    return this.#transaction(() => {
      const now = this.#now();
      this.#requireAudit();
      const integrity = this.#db.prepare("PRAGMA integrity_check").get() as {
        integrity_check: string;
      };
      const foreignKeyErrors = this.#db.prepare("PRAGMA foreign_key_check").all();
      if (
        integrity.integrity_check !== "ok" ||
        foreignKeyErrors.length !== 0
      ) throw new LedgerError("ledger_integrity_check_failed");
      const round = this.#round(roundId);
      this.#requireRoundBinding(round);
      const open = this.#db.prepare(
        "SELECT COUNT(*) AS n FROM calls WHERE round_id=? " +
          "AND state IN ('reserved','dispatched')",
      ).get(roundId) as { n: number };
      const planned = this.#db.prepare(
        "SELECT COUNT(*) AS n FROM calls WHERE round_id=? AND state='planned'",
      ).get(roundId) as { n: number };
      const running = this.#db.prepare(
        "SELECT COUNT(*) AS n FROM executions WHERE round_id=? AND state='running'",
      ).get(roundId) as { n: number };
      if (open.n === 0 && running.n === 0) {
        return {
          recovered_calls: 0,
          cancelled_planned_calls: 0,
          incomplete_executions: 0,
        };
      }
      this.#db.prepare(
        "UPDATE calls SET state='cancelled',outcome='cancelled_before_dispatch',completed_at_ms=? " +
          "WHERE round_id=? AND state='reserved'",
      ).run(now, roundId);
      this.#db.prepare(
        "UPDATE calls SET state='result',outcome='unknown_after_crash',completed_at_ms=? " +
          "WHERE round_id=? AND state='dispatched'",
      ).run(now, roundId);
      this.#db.prepare(
        "UPDATE calls SET state='cancelled',outcome='cancelled_before_dispatch',completed_at_ms=? " +
          "WHERE round_id=? AND state='planned'",
      ).run(now, roundId);
      this.#db.prepare(
        "UPDATE executions SET state='incomplete',reason_code='crash_recovery',completed_at_ms=? " +
          "WHERE round_id=? AND state='running'",
      ).run(now, roundId);
      if (["draft", "armed", "running"].includes(round.status)) {
        this.#db.prepare(
          "UPDATE rounds SET status='review_required',last_observed_ms=? WHERE round_id=?",
        ).run(now, roundId);
      }
      this.#appendEvent({
        event_type: "round_recovered",
        round_id: roundId,
        at_ms: now,
        payload: {
          recovered_calls: open.n,
          cancelled_planned_calls: planned.n,
          incomplete_executions: running.n,
        },
      });
      return {
        recovered_calls: open.n,
        cancelled_planned_calls: planned.n,
        incomplete_executions: running.n,
      };
    });
  }

  getRoundStatus(roundId: string) {
    this.#assertOpen();
    this.#requireAudit();
    const round = this.#round(roundId);
    this.#requireRoundBinding(round);
    const executions = this.#db.prepare(
      "SELECT state,COUNT(*) AS count FROM executions WHERE round_id=? GROUP BY state",
    ).all(roundId);
    const calls = this.#db.prepare(
      "SELECT state,outcome,COUNT(*) AS count FROM calls WHERE round_id=? " +
        "GROUP BY state,outcome ORDER BY state,outcome",
    ).all(roundId);
    const reserved = this.#db.prepare(
      "SELECT COUNT(*) AS n FROM calls WHERE round_id=? AND reserved_at_ms IS NOT NULL",
    ).get(roundId) as { n: number };
    return {
      round_id: round.round_id,
      status: round.status,
      max_executions: round.max_executions,
      max_provider_calls: round.max_provider_calls,
      reserved_provider_calls: reserved.n,
      executions,
      calls,
    };
  }

  getExecution(executionId: string) {
    this.#assertOpen();
    this.#requireAudit();
    const execution = this.#execution(executionId);
    this.#requireRoundBinding(this.#round(execution.round_id));
    const calls = this.#db.prepare(
      "SELECT slot,ordinal,state,outcome,latency_ms,reserved_at_ms," +
        "dispatched_at_ms,completed_at_ms FROM calls " +
        "WHERE execution_id=? ORDER BY ordinal",
    ).all(executionId);
    return {
      execution_id: execution.execution_id,
      round_id: execution.round_id,
      state: execution.state,
      has_candidates: Boolean(execution.candidate_json),
      has_ground_truth: Boolean(execution.truth_json),
      has_case: Boolean(execution.case_json),
      calls,
    };
  }

  verifyAuditChain() {
    this.#assertOpen();
    return this.#auditChainValid();
  }

  close() {
    if (this.#closed) return;
    this.#db.close();
    this.#closed = true;
  }
}
