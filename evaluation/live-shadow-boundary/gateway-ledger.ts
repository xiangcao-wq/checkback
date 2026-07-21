import { timingSafeEqual } from "node:crypto";
import type { KeyObject } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import { DatabaseSync } from "node:sqlite";
import {
  canonicalJson,
  hmacSha256Canonical,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
} from "../live-shadow/crypto.ts";
import { verifyIpcChallengeRequest } from "./ipc-contracts.ts";
import type {
  SignedIpcChallengeRequest,
  SignedIpcDispatchCommand,
} from "./ipc-contracts.ts";
import {
  disposeRebuiltGatewayRequest,
  rebuildVerifiedGatewayRequest,
} from "./gateway-request-rebuilder.ts";
import type {
  GatewayCompiledIdentity,
  RebuiltGatewayRequest,
} from "./gateway-request-rebuilder.ts";

const SCHEMA_VERSION = "checkback.live-shadow.gateway-ledger.v2";
const APPLICATION_ID = 0x4342474c;
const USER_VERSION = 2;
const ZERO_HASH = "0".repeat(64);
const MAX_OPERATION_TTL_MS = 30_000;
const EXPIRED_REASON_SHA256 = sha256Bytes("checkback.gateway.expired.v1");
const BOOT_CLOSED_REASON_SHA256 = sha256Bytes(
  "checkback.gateway.boot-closed.v1",
);
const DEAD_BOOT_REASON_SHA256 = sha256Bytes(
  "checkback.gateway.dead-boot-recovered.v1",
);
const SQLITE_HEADER = Buffer.from("SQLite format 3\0", "binary");
const IDENTITY_DOMAIN = "checkback.live-shadow.gateway-ledger.identity.v1";
const PROJECTION_DOMAIN = "checkback.live-shadow.gateway-ledger.projection.v1";
const AUDIT_DOMAIN = "checkback.live-shadow.gateway-ledger.audit.v1";
const CHECKPOINT_DOMAIN = "checkback.live-shadow.gateway-ledger.checkpoint.v1";

const SCHEMA_STATEMENTS = [
  "CREATE TABLE gateway_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
  "CREATE TABLE gateway_challenge_reservations(" +
    "gateway_sequence INTEGER PRIMARY KEY,challenge_request_id TEXT NOT NULL UNIQUE," +
    "challenge_request_sha256 TEXT NOT NULL UNIQUE,context_sha256 TEXT NOT NULL," +
    "gateway_boot_id TEXT NOT NULL,gateway_fencing_token INTEGER NOT NULL," +
    "state TEXT NOT NULL CHECK(state IN ('reserved','consumed','cancelled','expired'))," +
    "reserved_at_ms INTEGER NOT NULL,expires_at_ms INTEGER NOT NULL," +
    "challenge_sha256 TEXT UNIQUE,consumed_operation_id TEXT UNIQUE," +
    "terminal_at_ms INTEGER,cancellation_reason_sha256 TEXT)",
  "CREATE TRIGGER gateway_challenge_reservations_no_delete BEFORE DELETE ON gateway_challenge_reservations " +
    "BEGIN SELECT RAISE(ABORT,'gateway challenge reservations append only'); END",
  "CREATE TRIGGER gateway_challenge_reservations_monotonic BEFORE UPDATE ON gateway_challenge_reservations " +
    "WHEN NOT (" +
      "NEW.gateway_sequence IS OLD.gateway_sequence " +
      "AND NEW.challenge_request_id IS OLD.challenge_request_id " +
      "AND NEW.challenge_request_sha256 IS OLD.challenge_request_sha256 " +
      "AND NEW.context_sha256 IS OLD.context_sha256 " +
      "AND NEW.gateway_boot_id IS OLD.gateway_boot_id " +
      "AND NEW.gateway_fencing_token IS OLD.gateway_fencing_token " +
      "AND NEW.reserved_at_ms IS OLD.reserved_at_ms " +
      "AND NEW.expires_at_ms IS OLD.expires_at_ms " +
      "AND ((OLD.state='reserved' AND NEW.state='consumed' " +
        "AND OLD.challenge_sha256 IS NULL AND NEW.challenge_sha256 IS NOT NULL " +
        "AND OLD.consumed_operation_id IS NULL AND NEW.consumed_operation_id IS NOT NULL " +
        "AND OLD.terminal_at_ms IS NULL AND NEW.terminal_at_ms IS NOT NULL " +
        "AND NEW.cancellation_reason_sha256 IS NULL) " +
      "OR (OLD.state='reserved' AND NEW.state IN ('cancelled','expired') " +
        "AND NEW.challenge_sha256 IS NULL AND NEW.consumed_operation_id IS NULL " +
        "AND OLD.terminal_at_ms IS NULL AND NEW.terminal_at_ms IS NOT NULL " +
        "AND NEW.cancellation_reason_sha256 IS NOT NULL))) " +
    "BEGIN SELECT RAISE(ABORT,'gateway challenge reservation transition invalid'); END",
  "CREATE TABLE gateway_operations(" +
    "operation_id TEXT PRIMARY KEY,gateway_sequence INTEGER NOT NULL UNIQUE " +
      "REFERENCES gateway_challenge_reservations(gateway_sequence)," +
    "challenge_request_sha256 TEXT NOT NULL,challenge_sha256 TEXT NOT NULL UNIQUE," +
    "dispatch_command_sha256 TEXT NOT NULL UNIQUE,provider_request_body_sha256 TEXT NOT NULL," +
    "policy_sha256 TEXT NOT NULL,runtime_manifest_sha256 TEXT NOT NULL," +
    "context_sha256 TEXT NOT NULL," +
    "state TEXT NOT NULL CHECK(state IN ('issued','claimed_before_send','terminal','cancelled_before_send','expired_before_send','unknown_after_crash'))," +
    "issued_boot_session_id TEXT NOT NULL,issued_fencing_token INTEGER NOT NULL," +
    "issued_at_ms INTEGER NOT NULL,expires_at_ms INTEGER NOT NULL," +
    "claimed_boot_session_id TEXT,claimed_fencing_token INTEGER,claimed_at_ms INTEGER," +
    "terminal_at_ms INTEGER,terminal_outcome TEXT," +
    "network_attempts INTEGER,retry_count INTEGER,redirect_count INTEGER," +
    "response_sha256 TEXT,cancellation_reason_sha256 TEXT)",
  "CREATE TRIGGER gateway_operations_no_delete BEFORE DELETE ON gateway_operations " +
    "BEGIN SELECT RAISE(ABORT,'gateway operations append only'); END",
  "CREATE TRIGGER gateway_operations_monotonic BEFORE UPDATE ON gateway_operations " +
    "WHEN NOT (" +
      "NEW.operation_id IS OLD.operation_id AND NEW.gateway_sequence IS OLD.gateway_sequence " +
      "AND NEW.challenge_request_sha256 IS OLD.challenge_request_sha256 " +
      "AND NEW.challenge_sha256 IS OLD.challenge_sha256 " +
      "AND NEW.dispatch_command_sha256 IS OLD.dispatch_command_sha256 " +
      "AND NEW.provider_request_body_sha256 IS OLD.provider_request_body_sha256 " +
      "AND NEW.policy_sha256 IS OLD.policy_sha256 " +
      "AND NEW.runtime_manifest_sha256 IS OLD.runtime_manifest_sha256 " +
      "AND NEW.context_sha256 IS OLD.context_sha256 " +
      "AND NEW.issued_boot_session_id IS OLD.issued_boot_session_id " +
      "AND NEW.issued_fencing_token IS OLD.issued_fencing_token " +
      "AND NEW.issued_at_ms IS OLD.issued_at_ms AND NEW.expires_at_ms IS OLD.expires_at_ms " +
      "AND ((OLD.state='issued' AND NEW.state='claimed_before_send' " +
        "AND OLD.claimed_boot_session_id IS NULL AND NEW.claimed_boot_session_id IS NOT NULL " +
        "AND OLD.claimed_fencing_token IS NULL AND NEW.claimed_fencing_token IS NOT NULL " +
        "AND OLD.claimed_at_ms IS NULL AND NEW.claimed_at_ms IS NOT NULL " +
        "AND NEW.terminal_at_ms IS NULL AND NEW.terminal_outcome IS NULL " +
        "AND NEW.network_attempts IS NULL AND NEW.retry_count IS NULL " +
        "AND NEW.redirect_count IS NULL AND NEW.response_sha256 IS NULL " +
        "AND NEW.cancellation_reason_sha256 IS NULL) " +
      "OR (OLD.state='issued' AND NEW.state IN ('cancelled_before_send','expired_before_send') " +
        "AND NEW.claimed_boot_session_id IS NULL AND NEW.claimed_fencing_token IS NULL " +
        "AND NEW.claimed_at_ms IS NULL AND NEW.terminal_at_ms IS NOT NULL " +
        "AND NEW.terminal_outcome IS NULL AND NEW.network_attempts=0 " +
        "AND NEW.retry_count=0 AND NEW.redirect_count=0 AND NEW.response_sha256 IS NULL " +
        "AND NEW.cancellation_reason_sha256 IS NOT NULL) " +
      "OR (OLD.state='claimed_before_send' AND NEW.state='terminal' " +
        "AND NEW.claimed_boot_session_id IS OLD.claimed_boot_session_id " +
        "AND NEW.claimed_fencing_token IS OLD.claimed_fencing_token " +
        "AND NEW.claimed_at_ms IS OLD.claimed_at_ms AND NEW.terminal_at_ms IS NOT NULL " +
        "AND NEW.terminal_outcome IS NOT NULL AND NEW.network_attempts IN (0,1) " +
        "AND NEW.retry_count=0 AND NEW.redirect_count=0 " +
        "AND NEW.cancellation_reason_sha256 IS NULL) " +
      "OR (OLD.state='claimed_before_send' AND NEW.state='unknown_after_crash' " +
        "AND NEW.claimed_boot_session_id IS OLD.claimed_boot_session_id " +
        "AND NEW.claimed_fencing_token IS OLD.claimed_fencing_token " +
        "AND NEW.claimed_at_ms IS OLD.claimed_at_ms AND NEW.terminal_at_ms IS NOT NULL " +
        "AND NEW.terminal_outcome='unknown_after_crash' AND NEW.network_attempts=1 " +
        "AND NEW.retry_count=0 AND NEW.redirect_count=0 AND NEW.response_sha256 IS NULL " +
        "AND NEW.cancellation_reason_sha256 IS NULL))) " +
    "BEGIN SELECT RAISE(ABORT,'gateway operation transition invalid'); END",
  "CREATE TABLE gateway_events(" +
    "sequence INTEGER PRIMARY KEY,previous_event_hmac_sha256 TEXT NOT NULL," +
    "event_type TEXT NOT NULL,boot_session_id TEXT,operation_id TEXT," +
    "recorded_at_ms INTEGER NOT NULL,payload_json TEXT NOT NULL," +
    "event_hmac_sha256 TEXT NOT NULL)",
  "CREATE TRIGGER gateway_events_no_update BEFORE UPDATE ON gateway_events " +
    "BEGIN SELECT RAISE(ABORT,'gateway events append only'); END",
  "CREATE TRIGGER gateway_events_no_delete BEFORE DELETE ON gateway_events " +
    "BEGIN SELECT RAISE(ABORT,'gateway events append only'); END",
] as const;

const SCHEMA_SHA256 = sha256Canonical(SCHEMA_STATEMENTS);
const IDENTITY_KEYS = [
  "schema_version",
  "schema_sha256",
  "physical_schema_sha256",
  "gateway_instance_id",
  "runtime_policy_sha256",
  "gateway_key_id",
  "gateway_build_sha256",
  "ledger_key_id",
] as const;
const META_KEYS = new Set([
  ...IDENTITY_KEYS,
  "identity_hmac_sha256",
  "audit_sequence",
  "audit_head_hmac_sha256",
  "active_boot_session_id",
  "fencing_token",
  "clean_shutdown",
  "clock_watermark_ms",
  "gateway_sequence",
  "projection_hmac_sha256",
]);
const TERMINAL_OUTCOMES = new Set([
  "success",
  "request_error",
  "timeout",
  "invalid_response",
  "transport_unknown",
]);

export interface GatewayLedgerProfile {
  gateway_instance_id: string;
  runtime_policy_sha256: string;
  gateway_key_id: string;
  gateway_build_sha256: string;
}

export interface GatewayLedgerCheckpoint {
  schema_version: typeof SCHEMA_VERSION;
  gateway_instance_id: string;
  runtime_policy_sha256: string;
  gateway_build_sha256: string;
  gateway_sequence: number;
  fencing_token: number;
  audit_sequence: number;
  audit_head_hmac_sha256: string;
  checkpoint_hmac_sha256: string;
}

export interface GatewaySendCapability {
  readonly __gateway_send_capability_brand: unique symbol;
}

export interface GatewayIssuedDispatch {
  readonly operation: GatewayOperationRecord;
  /** Caller-owned sensitive bytes. Zeroize after the one provider send. */
  readonly provider_request: RebuiltGatewayRequest;
}

export interface GatewayIpcTrustRoots {
  collector_public_key: KeyObject;
  gateway_public_key: KeyObject;
  authority_public_key: KeyObject;
  anchor_public_key: KeyObject;
  expected_anchor_service_profile:
    | "offline_simulator"
    | "production_external";
}

export interface GatewayIpcLedgerAdapter {
  reserveChallenge(input: {
    challenge_request: SignedIpcChallengeRequest;
    trusted_now_ms: number;
  }): GatewayChallengeReservation;
  issueVerifiedDispatch(input: {
    verified_dispatch_command: SignedIpcDispatchCommand;
    attachment_frame: Uint8Array;
    compiled_identity: GatewayCompiledIdentity;
    trusted_now_ms: number;
  }): GatewayIssuedDispatch;
}

export type GatewayOperationState =
  | "issued"
  | "claimed_before_send"
  | "terminal"
  | "cancelled_before_send"
  | "expired_before_send"
  | "unknown_after_crash";

export type GatewayChallengeReservationState =
  | "reserved"
  | "consumed"
  | "cancelled"
  | "expired";

export interface GatewayChallengeReservation {
  gateway_sequence: number;
  challenge_request_id: string;
  challenge_request_sha256: string;
  context_sha256: string;
  gateway_boot_id: string;
  gateway_fencing_token: number;
  state: GatewayChallengeReservationState;
  reserved_at_ms: number;
  expires_at_ms: number;
  challenge_sha256: string | null;
  consumed_operation_id: string | null;
  terminal_at_ms: number | null;
  cancellation_reason_sha256: string | null;
}

export interface GatewayOperationRecord {
  operation_id: string;
  gateway_sequence: number;
  challenge_request_sha256: string;
  challenge_sha256: string;
  dispatch_command_sha256: string;
  provider_request_body_sha256: string;
  policy_sha256: string;
  runtime_manifest_sha256: string;
  context_sha256: string;
  state: GatewayOperationState;
  issued_boot_session_id: string;
  issued_fencing_token: number;
  issued_at_ms: number;
  expires_at_ms: number;
  claimed_boot_session_id: string | null;
  claimed_fencing_token: number | null;
  claimed_at_ms: number | null;
  terminal_at_ms: number | null;
  terminal_outcome: string | null;
  network_attempts: number | null;
  retry_count: number | null;
  redirect_count: number | null;
  response_sha256: string | null;
  cancellation_reason_sha256: string | null;
}

type CapabilityData = {
  ledger_instance_id: string;
  operation_id: string;
  gateway_sequence: number;
  challenge_sha256: string;
  dispatch_command_sha256: string;
  provider_request_body_sha256: string;
  boot_session_id: string;
  fencing_token: number;
  used: boolean;
};

const CAPABILITIES = new WeakMap<object, CapabilityData>();

export class GatewayLedgerError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "GatewayLedgerError";
    this.code = code;
  }
}

function validateSecret(secret: Uint8Array) {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 32) {
    throw new GatewayLedgerError("gateway_ledger_secret_too_short");
  }
}

function validateHex(code: string, value: string) {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new GatewayLedgerError(code);
}

function validateProfile(profile: GatewayLedgerProfile) {
  if (!/^gateway_[a-f0-9]{64}$/.test(profile.gateway_instance_id)) {
    throw new GatewayLedgerError("gateway_instance_id_invalid");
  }
  validateHex("gateway_runtime_policy_sha256_invalid", profile.runtime_policy_sha256);
  validateHex("gateway_key_id_invalid", profile.gateway_key_id);
  validateHex("gateway_build_sha256_invalid", profile.gateway_build_sha256);
}

function validateBootSession(value: string) {
  if (!/^boot_[a-f0-9]{64}$/.test(value)) {
    throw new GatewayLedgerError("gateway_boot_session_id_invalid");
  }
}

function validateOperationId(value: string) {
  if (!/^op_[a-f0-9]{64}$/.test(value)) {
    throw new GatewayLedgerError("gateway_operation_id_invalid");
  }
}

function requirePersistentPath(path: string) {
  if (!path || path === ":memory:") {
    throw new GatewayLedgerError("gateway_persistent_database_path_required");
  }
}

function assertExistingSqliteFile(path: string) {
  requirePersistentPath(path);
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    throw new GatewayLedgerError("gateway_database_missing");
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0) {
    throw new GatewayLedgerError("gateway_database_path_invalid");
  }
  const descriptor = openSync(path, fsConstants.O_RDONLY);
  try {
    const header = Buffer.alloc(SQLITE_HEADER.length);
    const bytesRead = readSync(descriptor, header, 0, header.length, 0);
    if (bytesRead !== header.length || !header.equals(SQLITE_HEADER)) {
      throw new GatewayLedgerError("gateway_database_header_invalid");
    }
  } finally {
    closeSync(descriptor);
  }
}

function ledgerKeyId(secret: Uint8Array): string {
  const domain = Buffer.from(
    "checkback.live-shadow.gateway-ledger-key.v1\0",
    "utf8",
  );
  const material = Buffer.from(secret);
  const input = Buffer.concat([domain, material]);
  try {
    return sha256Bytes(input);
  } finally {
    domain.fill(0);
    material.fill(0);
    input.fill(0);
  }
}

function schemaFingerprint(db: DatabaseSync): string {
  return sha256Canonical(
    db.prepare(
      "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
    ).all(),
  );
}

function readMeta(db: DatabaseSync): Record<string, string> {
  const rows = db.prepare("SELECT key,value FROM gateway_meta").all() as {
    key: string;
    value: string;
  }[];
  return Object.fromEntries(rows.map((row) => [row.key, row.value]));
}

function parseInteger(meta: Record<string, string>, key: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(meta[key] ?? "")) {
    throw new GatewayLedgerError("gateway_meta_invalid");
  }
  const value = Number(meta[key]);
  if (!Number.isSafeInteger(value)) {
    throw new GatewayLedgerError("gateway_meta_invalid");
  }
  return value;
}

function setMeta(db: DatabaseSync, key: string, value: string | number) {
  const result = db.prepare("UPDATE gateway_meta SET value=? WHERE key=?").run(
    String(value),
    key,
  );
  if (result.changes !== 1) throw new GatewayLedgerError("gateway_meta_missing");
}

function secureHexEqual(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right)) {
    return false;
  }
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  try {
    return timingSafeEqual(leftBytes, rightBytes);
  } finally {
    leftBytes.fill(0);
    rightBytes.fill(0);
  }
}

function identityObject(meta: Record<string, string>) {
  return Object.fromEntries(IDENTITY_KEYS.map((key) => [key, meta[key]]));
}

function computeProjectionHmac(db: DatabaseSync, secret: Uint8Array): string {
  return hmacSha256Canonical(secret, PROJECTION_DOMAIN, {
    meta: db.prepare(
      "SELECT key,value FROM gateway_meta WHERE key<>'projection_hmac_sha256' ORDER BY key",
    ).all(),
    challenge_reservations: db.prepare(
      "SELECT * FROM gateway_challenge_reservations ORDER BY gateway_sequence",
    ).all(),
    operations: db.prepare(
      "SELECT * FROM gateway_operations ORDER BY operation_id",
    ).all(),
    events: db.prepare(
      "SELECT * FROM gateway_events ORDER BY sequence",
    ).all(),
  });
}

function appendEvent(
  db: DatabaseSync,
  secret: Uint8Array,
  input: {
    event_type: string;
    boot_session_id: string | null;
    operation_id: string | null;
    recorded_at_ms: number;
    payload: unknown;
  },
) {
  const meta = readMeta(db);
  const sequence = parseInteger(meta, "audit_sequence") + 1;
  const previous = meta.audit_head_hmac_sha256;
  validateHex("gateway_audit_head_invalid", previous);
  const payloadJson = canonicalJson(input.payload);
  const event = {
    sequence,
    previous_event_hmac_sha256: previous,
    event_type: input.event_type,
    boot_session_id: input.boot_session_id,
    operation_id: input.operation_id,
    recorded_at_ms: input.recorded_at_ms,
    payload_json: payloadJson,
  };
  const eventHmac = hmacSha256Canonical(secret, AUDIT_DOMAIN, event);
  db.prepare(
    "INSERT INTO gateway_events(" +
      "sequence,previous_event_hmac_sha256,event_type,boot_session_id,operation_id," +
      "recorded_at_ms,payload_json,event_hmac_sha256) VALUES(?,?,?,?,?,?,?,?)",
  ).run(
    sequence,
    previous,
    input.event_type,
    input.boot_session_id,
    input.operation_id,
    input.recorded_at_ms,
    payloadJson,
    eventHmac,
  );
  setMeta(db, "audit_sequence", sequence);
  setMeta(db, "audit_head_hmac_sha256", eventHmac);
}

function configure(db: DatabaseSync) {
  db.exec("PRAGMA journal_mode=WAL");
  db.exec("PRAGMA synchronous=FULL");
  db.exec("PRAGMA foreign_keys=ON");
  db.exec("PRAGMA busy_timeout=10000");
}

function operationRow(value: unknown): GatewayOperationRecord {
  return { ...(value as GatewayOperationRecord) };
}

function challengeReservationRow(value: unknown): GatewayChallengeReservation {
  return { ...(value as GatewayChallengeReservation) };
}

export class PersistentGatewayLedger {
  readonly gatewayInstanceId: string;
  readonly runtimePolicySha256: string;
  readonly gatewayKeyId: string;
  readonly gatewayBuildSha256: string;
  readonly bootSessionId: string;
  #db: DatabaseSync;
  #secret: Buffer;
  #clock: () => number;
  #fencingToken = 0;
  #expectedPhysicalSchemaSha256 = "";
  #closed = false;
  #ownsBootSession = false;

  private constructor(input: {
    database_path: string;
    ledger_secret: Uint8Array;
    profile: GatewayLedgerProfile;
    boot_session_id: string;
    now?: () => number;
    mode: "activate" | "join_active" | "recovery";
    expected_fencing_token?: number;
    minimum_checkpoint?: GatewayLedgerCheckpoint;
  }) {
    validateSecret(input.ledger_secret);
    validateProfile(input.profile);
    if (input.mode !== "recovery") validateBootSession(input.boot_session_id);
    this.gatewayInstanceId = input.profile.gateway_instance_id;
    this.runtimePolicySha256 = input.profile.runtime_policy_sha256;
    this.gatewayKeyId = input.profile.gateway_key_id;
    this.gatewayBuildSha256 = input.profile.gateway_build_sha256;
    this.bootSessionId = input.boot_session_id;
    this.#secret = Buffer.from(input.ledger_secret);
    this.#clock = input.now ?? Date.now;
    this.#db = new DatabaseSync(input.database_path, { readOnly: false });
    try {
      configure(this.#db);
      this.#read(() => {
        if (input.minimum_checkpoint) {
          this.#verifyMinimumCheckpoint(input.minimum_checkpoint);
        }
      });
      if (input.mode === "activate") {
        this.#activateBoot();
      } else if (input.mode === "join_active") {
        this.#joinActive(input.expected_fencing_token);
      }
    } catch (error) {
      this.#db.close();
      this.#closed = true;
      this.#secret.fill(0);
      throw error;
    }
  }

  static initialize(input: {
    database_path: string;
    ledger_secret: Uint8Array;
    profile: GatewayLedgerProfile;
    now?: () => number;
  }): void {
    requirePersistentPath(input.database_path);
    validateSecret(input.ledger_secret);
    validateProfile(input.profile);
    let descriptor: number;
    try {
      descriptor = openSync(
        input.database_path,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
        0o600,
      );
    } catch {
      throw new GatewayLedgerError("gateway_database_already_exists");
    }
    closeSync(descriptor);
    const secret = Buffer.from(input.ledger_secret);
    const db = new DatabaseSync(input.database_path, { readOnly: false });
    try {
      configure(db);
      db.exec("BEGIN IMMEDIATE");
      db.exec(`PRAGMA application_id=${APPLICATION_ID}`);
      db.exec(`PRAGMA user_version=${USER_VERSION}`);
      for (const statement of SCHEMA_STATEMENTS) db.exec(statement);
      const identity = {
        schema_version: SCHEMA_VERSION,
        schema_sha256: SCHEMA_SHA256,
        physical_schema_sha256: schemaFingerprint(db),
        gateway_instance_id: input.profile.gateway_instance_id,
        runtime_policy_sha256: input.profile.runtime_policy_sha256,
        gateway_key_id: input.profile.gateway_key_id,
        gateway_build_sha256: input.profile.gateway_build_sha256,
        ledger_key_id: ledgerKeyId(secret),
      };
      const identityHmac = hmacSha256Canonical(
        secret,
        IDENTITY_DOMAIN,
        identity,
      );
      const insert = db.prepare("INSERT INTO gateway_meta(key,value) VALUES(?,?)");
      for (const [key, value] of Object.entries(identity)) insert.run(key, value);
      insert.run("identity_hmac_sha256", identityHmac);
      insert.run("audit_sequence", "0");
      insert.run("audit_head_hmac_sha256", ZERO_HASH);
      insert.run("active_boot_session_id", "");
      insert.run("fencing_token", "0");
      insert.run("clean_shutdown", "1");
      insert.run("projection_hmac_sha256", ZERO_HASH);
      const now = input.now?.() ?? Date.now();
      if (!Number.isSafeInteger(now) || now < 0) {
        throw new GatewayLedgerError("gateway_clock_invalid");
      }
      insert.run("clock_watermark_ms", String(now));
      insert.run("gateway_sequence", "0");
      appendEvent(db, secret, {
        event_type: "ledger_initialized",
        boot_session_id: null,
        operation_id: null,
        recorded_at_ms: now,
        payload: identity,
      });
      setMeta(db, "projection_hmac_sha256", computeProjectionHmac(db, secret));
      db.exec("COMMIT");
      db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    } catch (error) {
      try {
        db.exec("ROLLBACK");
      } catch {}
      throw error;
    } finally {
      db.close();
      secret.fill(0);
    }
  }

  static openExisting(input: {
    database_path: string;
    ledger_secret: Uint8Array;
    profile: GatewayLedgerProfile;
    boot_session_id: string;
    now?: () => number;
    mode?: "activate" | "join_active";
    expected_fencing_token?: number;
    minimum_checkpoint?: GatewayLedgerCheckpoint;
  }): PersistentGatewayLedger {
    assertExistingSqliteFile(input.database_path);
    return new PersistentGatewayLedger({
      ...input,
      mode: input.mode ?? "activate",
    });
  }

  static recoverConfirmedDead(input: {
    database_path: string;
    ledger_secret: Uint8Array;
    profile: GatewayLedgerProfile;
    dead_boot_session_id: string;
    recovery_id: string;
    confirmation: "confirmed_dead";
    now?: () => number;
    minimum_checkpoint?: GatewayLedgerCheckpoint;
  }): GatewayLedgerCheckpoint {
    assertExistingSqliteFile(input.database_path);
    validateBootSession(input.dead_boot_session_id);
    if (!/^recovery_[a-f0-9]{64}$/.test(input.recovery_id)) {
      throw new GatewayLedgerError("gateway_recovery_id_invalid");
    }
    if (input.confirmation !== "confirmed_dead") {
      throw new GatewayLedgerError("gateway_dead_confirmation_required");
    }
    const ledger = new PersistentGatewayLedger({
      database_path: input.database_path,
      ledger_secret: input.ledger_secret,
      profile: input.profile,
      boot_session_id: "",
      now: input.now,
      mode: "recovery",
      minimum_checkpoint: input.minimum_checkpoint,
    });
    try {
      return ledger.#recoverDeadSession(
        input.dead_boot_session_id,
        input.recovery_id,
      );
    } finally {
      ledger.#forceClose();
    }
  }

  #now(): number {
    const value = this.#clock();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new GatewayLedgerError("gateway_clock_invalid");
    }
    return value;
  }

  #advanceClock(meta: Record<string, string>): number {
    const now = this.#now();
    const watermark = parseInteger(meta, "clock_watermark_ms");
    if (now < watermark) {
      throw new GatewayLedgerError("gateway_clock_rollback_detected");
    }
    setMeta(this.#db, "clock_watermark_ms", now);
    return now;
  }

  #assertOpen() {
    if (this.#closed) throw new GatewayLedgerError("gateway_ledger_closed");
  }

  #verifyPhysicalDatabase() {
    const app = this.#db.prepare("PRAGMA application_id").get() as {
      application_id: number;
    };
    const version = this.#db.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    const integrity = this.#db.prepare("PRAGMA integrity_check").get() as {
      integrity_check: string;
    };
    if (
      app.application_id !== APPLICATION_ID ||
      version.user_version !== USER_VERSION ||
      integrity.integrity_check !== "ok" ||
      this.#db.prepare("PRAGMA foreign_key_check").all().length !== 0
    ) {
      throw new GatewayLedgerError("gateway_integrity_check_failed");
    }
  }

  #verifyIdentity(): Record<string, string> {
    const meta = readMeta(this.#db);
    if (
      Object.keys(meta).length !== META_KEYS.size ||
      Object.keys(meta).some((key) => !META_KEYS.has(key))
    ) {
      throw new GatewayLedgerError("gateway_meta_shape_invalid");
    }
    const identity = identityObject(meta);
    const expectedHmac = hmacSha256Canonical(
      this.#secret,
      IDENTITY_DOMAIN,
      identity,
    );
    if (!secureHexEqual(meta.identity_hmac_sha256, expectedHmac)) {
      throw new GatewayLedgerError("gateway_identity_hmac_invalid");
    }
    if (
      meta.schema_version !== SCHEMA_VERSION ||
      meta.schema_sha256 !== SCHEMA_SHA256 ||
      meta.gateway_instance_id !== this.gatewayInstanceId ||
      meta.runtime_policy_sha256 !== this.runtimePolicySha256 ||
      meta.gateway_key_id !== this.gatewayKeyId ||
      meta.gateway_build_sha256 !== this.gatewayBuildSha256 ||
      meta.ledger_key_id !== ledgerKeyId(this.#secret)
    ) {
      throw new GatewayLedgerError("gateway_identity_mismatch");
    }
    if (!this.#expectedPhysicalSchemaSha256) {
      this.#expectedPhysicalSchemaSha256 = meta.physical_schema_sha256;
    }
    if (
      meta.physical_schema_sha256 !== this.#expectedPhysicalSchemaSha256 ||
      schemaFingerprint(this.#db) !== this.#expectedPhysicalSchemaSha256
    ) {
      throw new GatewayLedgerError("gateway_schema_mismatch");
    }
    return meta;
  }

  #verifyAudit(meta: Record<string, string>) {
    const rows = this.#db.prepare(
      "SELECT * FROM gateway_events ORDER BY sequence",
    ).all() as Array<{
      sequence: number;
      previous_event_hmac_sha256: string;
      event_type: string;
      boot_session_id: string | null;
      operation_id: string | null;
      recorded_at_ms: number;
      payload_json: string;
      event_hmac_sha256: string;
    }>;
    let sequence = 0;
    let previous = ZERO_HASH;
    for (const row of rows) {
      sequence += 1;
      if (
        row.sequence !== sequence ||
        row.previous_event_hmac_sha256 !== previous ||
        !Number.isSafeInteger(row.recorded_at_ms) ||
        row.recorded_at_ms < 0
      ) {
        throw new GatewayLedgerError("gateway_audit_chain_invalid");
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(row.payload_json);
      } catch {
        throw new GatewayLedgerError("gateway_audit_payload_invalid");
      }
      if (canonicalJson(parsed) !== row.payload_json) {
        throw new GatewayLedgerError("gateway_audit_payload_invalid");
      }
      const event = {
        sequence: row.sequence,
        previous_event_hmac_sha256: row.previous_event_hmac_sha256,
        event_type: row.event_type,
        boot_session_id: row.boot_session_id,
        operation_id: row.operation_id,
        recorded_at_ms: row.recorded_at_ms,
        payload_json: row.payload_json,
      };
      const expected = hmacSha256Canonical(this.#secret, AUDIT_DOMAIN, event);
      if (!secureHexEqual(row.event_hmac_sha256, expected)) {
        throw new GatewayLedgerError("gateway_audit_hmac_invalid");
      }
      previous = row.event_hmac_sha256;
    }
    if (
      parseInteger(meta, "audit_sequence") !== sequence ||
      meta.audit_head_hmac_sha256 !== previous
    ) {
      throw new GatewayLedgerError("gateway_audit_head_invalid");
    }
  }

  #verifyProjection(meta: Record<string, string>) {
    const expected = computeProjectionHmac(this.#db, this.#secret);
    if (!secureHexEqual(meta.projection_hmac_sha256, expected)) {
      throw new GatewayLedgerError("gateway_projection_hmac_invalid");
    }
  }

  #verifyAll(): Record<string, string> {
    this.#assertOpen();
    this.#verifyPhysicalDatabase();
    const meta = this.#verifyIdentity();
    this.#verifyAudit(meta);
    this.#verifyProjection(meta);
    return meta;
  }

  #read<T>(callback: (meta: Record<string, string>) => T): T {
    this.#assertOpen();
    this.#db.exec("BEGIN");
    try {
      const meta = this.#verifyAll();
      const result = callback(meta);
      this.#db.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }

  #verifyMinimumCheckpoint(checkpoint: GatewayLedgerCheckpoint) {
    if (
      checkpoint.schema_version !== SCHEMA_VERSION ||
      checkpoint.gateway_instance_id !== this.gatewayInstanceId ||
      checkpoint.runtime_policy_sha256 !== this.runtimePolicySha256 ||
      checkpoint.gateway_build_sha256 !== this.gatewayBuildSha256 ||
      !Number.isSafeInteger(checkpoint.gateway_sequence) ||
      checkpoint.gateway_sequence < 0 ||
      !Number.isSafeInteger(checkpoint.fencing_token) ||
      checkpoint.fencing_token < 0 ||
      !Number.isSafeInteger(checkpoint.audit_sequence) ||
      checkpoint.audit_sequence < 0
    ) {
      throw new GatewayLedgerError("gateway_checkpoint_invalid");
    }
    validateHex(
      "gateway_checkpoint_invalid",
      checkpoint.audit_head_hmac_sha256,
    );
    const { checkpoint_hmac_sha256: supplied, ...body } = checkpoint;
    const expected = hmacSha256Canonical(this.#secret, CHECKPOINT_DOMAIN, body);
    if (!secureHexEqual(supplied, expected)) {
      throw new GatewayLedgerError("gateway_checkpoint_hmac_invalid");
    }
    const meta = readMeta(this.#db);
    const gatewaySequence = parseInteger(meta, "gateway_sequence");
    const fence = parseInteger(meta, "fencing_token");
    const sequence = parseInteger(meta, "audit_sequence");
    const checkpointEvent =
      checkpoint.audit_sequence === 0
        ? null
        : (this.#db.prepare(
            "SELECT event_hmac_sha256 FROM gateway_events WHERE sequence=?",
          ).get(checkpoint.audit_sequence) as
            | { event_hmac_sha256: string }
            | undefined);
    if (
      gatewaySequence < checkpoint.gateway_sequence ||
      fence < checkpoint.fencing_token ||
      sequence < checkpoint.audit_sequence ||
      (checkpoint.audit_sequence === 0
        ? checkpoint.audit_head_hmac_sha256 !== ZERO_HASH
        : checkpointEvent?.event_hmac_sha256 !==
          checkpoint.audit_head_hmac_sha256)
    ) {
      throw new GatewayLedgerError("gateway_checkpoint_rollback_detected");
    }
  }

  #activateBoot() {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const meta = this.#verifyAll();
      if (meta.clean_shutdown !== "1" || meta.active_boot_session_id !== "") {
        throw new GatewayLedgerError(
          "gateway_unclean_shutdown_requires_confirmed_dead_recovery",
        );
      }
      const fencingToken = parseInteger(meta, "fencing_token") + 1;
      setMeta(this.#db, "active_boot_session_id", this.bootSessionId);
      setMeta(this.#db, "fencing_token", fencingToken);
      setMeta(this.#db, "clean_shutdown", "0");
      const now = this.#advanceClock(meta);
      appendEvent(this.#db, this.#secret, {
        event_type: "boot_session_activated",
        boot_session_id: this.bootSessionId,
        operation_id: null,
        recorded_at_ms: now,
        payload: { fencing_token: fencingToken },
      });
      setMeta(
        this.#db,
        "projection_hmac_sha256",
        computeProjectionHmac(this.#db, this.#secret),
      );
      this.#db.exec("COMMIT");
      this.#fencingToken = fencingToken;
      this.#ownsBootSession = true;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }

  #joinActive(expectedFencingToken: number | undefined) {
    if (
      !Number.isSafeInteger(expectedFencingToken) ||
      (expectedFencingToken ?? 0) < 1
    ) {
      throw new GatewayLedgerError("gateway_expected_fencing_token_invalid");
    }
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const meta = this.#verifyAll();
      const fencingToken = parseInteger(meta, "fencing_token");
      if (
        meta.clean_shutdown !== "0" ||
        meta.active_boot_session_id !== this.bootSessionId ||
        fencingToken !== expectedFencingToken
      ) {
        throw new GatewayLedgerError("gateway_stale_boot_session");
      }
      this.#db.exec("COMMIT");
      this.#fencingToken = fencingToken;
      this.#ownsBootSession = false;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }

  #assertActiveSession(meta: Record<string, string>) {
    if (
      meta.clean_shutdown !== "0" ||
      meta.active_boot_session_id !== this.bootSessionId ||
      parseInteger(meta, "fencing_token") !== this.#fencingToken
    ) {
      throw new GatewayLedgerError("gateway_stale_boot_session");
    }
  }

  #mutate<T>(
    event: {
      type: string | ((result: T) => string);
      operation_id: string | null;
      payload: (result: T) => unknown;
    },
    callback: (now: number) => T,
  ): T {
    this.#assertOpen();
    if (!this.#ownsBootSession) {
      throw new GatewayLedgerError("gateway_mutation_requires_owner");
    }
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const meta = this.#verifyAll();
      this.#assertActiveSession(meta);
      const now = this.#advanceClock(meta);
      const result = callback(now);
      appendEvent(this.#db, this.#secret, {
        event_type:
          typeof event.type === "function" ? event.type(result) : event.type,
        boot_session_id: this.bootSessionId,
        operation_id: event.operation_id,
        recorded_at_ms: now,
        payload: event.payload(result),
      });
      setMeta(
        this.#db,
        "projection_hmac_sha256",
        computeProjectionHmac(this.#db, this.#secret),
      );
      this.#db.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }

  createIpcAdapter(trustRoots: GatewayIpcTrustRoots): GatewayIpcLedgerAdapter {
    this.#assertOpen();
    const trust = Object.freeze({
      collector_key_id: publicKeyId(trustRoots.collector_public_key),
      gateway_key_id: publicKeyId(trustRoots.gateway_public_key),
      authority_key_id: publicKeyId(trustRoots.authority_public_key),
      anchor_key_id: publicKeyId(trustRoots.anchor_public_key),
      expected_anchor_service_profile:
        trustRoots.expected_anchor_service_profile,
    });
    if (
      (trust.expected_anchor_service_profile !== "offline_simulator" &&
        trust.expected_anchor_service_profile !== "production_external") ||
      trust.gateway_key_id !== this.gatewayKeyId ||
      new Set([
        trust.collector_key_id,
        trust.gateway_key_id,
        trust.authority_key_id,
        trust.anchor_key_id,
      ]).size !== 4
    ) {
      throw new GatewayLedgerError("gateway_ipc_trust_roots_invalid");
    }
    return Object.freeze({
      reserveChallenge: (input: {
        challenge_request: SignedIpcChallengeRequest;
        trusted_now_ms: number;
      }) =>
        this.#reserveIpcChallenge({
          ...input,
          collector_public_key: trustRoots.collector_public_key,
          trusted_collector_key_id: trust.collector_key_id,
        }),
      issueVerifiedDispatch: (input: {
        verified_dispatch_command: SignedIpcDispatchCommand;
        attachment_frame: Uint8Array;
        compiled_identity: GatewayCompiledIdentity;
        trusted_now_ms: number;
      }) => this.#issueVerifiedIpcDispatch({ ...input, trust }),
    });
  }
  #reserveIpcChallenge(input: {
    collector_public_key: KeyObject;
    trusted_collector_key_id: string;
    challenge_request: SignedIpcChallengeRequest;
    trusted_now_ms: number;
  }): GatewayChallengeReservation {
    const request = verifyIpcChallengeRequest(
      input.collector_public_key,
      input.challenge_request,
      input.trusted_now_ms,
    );
    const context = request.payload.context;
    if (
      context.collector_key_id !== input.trusted_collector_key_id ||
      context.gateway_key_id !== this.gatewayKeyId ||
      context.policy.gateway_build_sha256 !== this.gatewayBuildSha256 ||
      context.policy.runtime_policy_sha256 !== this.runtimePolicySha256
    ) {
      throw new GatewayLedgerError("gateway_ipc_profile_mismatch");
    }
    const challengeRequestSha256 = sha256Canonical(request);
    const contextSha256 = sha256Canonical(context);
    return this.#mutate(
      {
        type: "challenge_reserved",
        operation_id: null,
        payload: (reservation) => reservation,
      },
      (now) => {
        if (now !== input.trusted_now_ms) {
          throw new GatewayLedgerError("gateway_trusted_time_mismatch");
        }
        const previous = this.#db.prepare(
          "SELECT gateway_sequence FROM gateway_challenge_reservations " +
            "WHERE challenge_request_id=? OR challenge_request_sha256=?",
        ).get(
          request.payload.challenge_request_id,
          challengeRequestSha256,
        );
        if (previous) {
          throw new GatewayLedgerError("gateway_challenge_request_reused");
        }
        const meta = readMeta(this.#db);
        const gatewaySequence = parseInteger(meta, "gateway_sequence") + 1;
        if (!Number.isSafeInteger(gatewaySequence)) {
          throw new GatewayLedgerError("gateway_sequence_exhausted");
        }
        const expiresAtMs = Math.min(
          request.payload.expires_at_ms,
          now + MAX_OPERATION_TTL_MS,
        );
        setMeta(this.#db, "gateway_sequence", gatewaySequence);
        this.#db.prepare(
          "INSERT INTO gateway_challenge_reservations(" +
            "gateway_sequence,challenge_request_id,challenge_request_sha256," +
            "context_sha256,gateway_boot_id,gateway_fencing_token,state," +
            "reserved_at_ms,expires_at_ms) VALUES(?,?,?,?,?,?,'reserved',?,?)",
        ).run(
          gatewaySequence,
          request.payload.challenge_request_id,
          challengeRequestSha256,
          contextSha256,
          this.bootSessionId,
          this.#fencingToken,
          now,
          expiresAtMs,
        );
        return challengeReservationRow(
          this.#db.prepare(
            "SELECT * FROM gateway_challenge_reservations WHERE gateway_sequence=?",
          ).get(gatewaySequence),
        );
      },
    );
  }

  #issueVerifiedIpcDispatch(input: {
    verified_dispatch_command: SignedIpcDispatchCommand;
    attachment_frame: Uint8Array;
    compiled_identity: GatewayCompiledIdentity;
    trusted_now_ms: number;
    trust: {
      collector_key_id: string;
      gateway_key_id: string;
      authority_key_id: string;
      anchor_key_id: string;
      expected_anchor_service_profile:
        | "offline_simulator"
        | "production_external";
    };
  }): GatewayIssuedDispatch {
    const command = input.verified_dispatch_command;
    const context = command.payload.context;
    if (
      command.payload.gateway_boot_id !== this.bootSessionId ||
      context.collector_key_id !== input.trust.collector_key_id ||
      context.gateway_key_id !== input.trust.gateway_key_id ||
      context.authority_key_id !== input.trust.authority_key_id ||
      context.anchor_key_id !== input.trust.anchor_key_id ||
      context.gateway_key_id !== this.gatewayKeyId ||
      command.payload.authority_ticket.payload
        .expected_anchor_service_profile !==
        input.trust.expected_anchor_service_profile ||
      command.payload.remote_anchor_request.payload.expected_service_profile !==
        input.trust.expected_anchor_service_profile ||
      command.payload.remote_anchor_receipt.payload.service_profile !==
        input.trust.expected_anchor_service_profile ||
      context.policy.gateway_build_sha256 !== this.gatewayBuildSha256 ||
      context.policy.runtime_policy_sha256 !== this.runtimePolicySha256 ||
      command.payload.authority_ticket.payload.runtime_manifest
        .gateway_build_sha256 !== this.gatewayBuildSha256 ||
      command.payload.authority_ticket.payload.runtime_manifest
        .runtime_policy_sha256 !== this.runtimePolicySha256
    ) {
      throw new GatewayLedgerError("gateway_ipc_profile_mismatch");
    }
    const providerRequest = rebuildVerifiedGatewayRequest({
      verified_dispatch_command: command,
      attachment_frame: input.attachment_frame,
      compiled_identity: input.compiled_identity,
      trusted_now_ms: input.trusted_now_ms,
    });
    try {
      const issue = {
        operation_id: context.operation_id,
        gateway_sequence: command.payload.gateway_sequence,
        challenge_request_sha256: command.payload.challenge_request_sha256,
        challenge_sha256: command.payload.challenge_sha256,
        dispatch_command_sha256: sha256Canonical(command),
        provider_request_body_sha256: providerRequest.body_sha256,
        policy_sha256: context.policy_sha256,
        runtime_manifest_sha256: context.runtime_manifest_sha256,
        context_sha256: sha256Canonical(context),
        expires_at_ms: command.payload.expires_at_ms,
      };
      const result = this.#mutate<{
        reservation: GatewayChallengeReservation;
        operation: GatewayOperationRecord | null;
      }>(
        {
          type: (value) =>
            value.operation === null
              ? "challenge_reservation_expired"
              : "operation_issued",
          operation_id: issue.operation_id,
          payload: (value) => ({
            reservation: value.reservation,
            operation: value.operation,
          }),
        },
        (now) => {
          if (now !== input.trusted_now_ms) {
            throw new GatewayLedgerError("gateway_trusted_time_mismatch");
          }
          const reservation = this.#db.prepare(
            "SELECT * FROM gateway_challenge_reservations WHERE gateway_sequence=?",
          ).get(issue.gateway_sequence) as GatewayChallengeReservation | undefined;
          if (!reservation) {
            throw new GatewayLedgerError("gateway_reservation_missing");
          }
          if (
            reservation.challenge_request_sha256 !==
              issue.challenge_request_sha256 ||
            reservation.context_sha256 !== issue.context_sha256 ||
            reservation.gateway_boot_id !== this.bootSessionId ||
            reservation.gateway_fencing_token !== this.#fencingToken
          ) {
            throw new GatewayLedgerError("gateway_reservation_binding_mismatch");
          }
          if (reservation.state !== "reserved") {
            throw new GatewayLedgerError("gateway_reservation_not_consumable");
          }
          if (now >= reservation.expires_at_ms) {
            this.#db.prepare(
              "UPDATE gateway_challenge_reservations SET state='expired'," +
                "terminal_at_ms=?,cancellation_reason_sha256=? " +
                "WHERE gateway_sequence=? AND state='reserved'",
            ).run(now, EXPIRED_REASON_SHA256, issue.gateway_sequence);
            return {
              reservation: challengeReservationRow(
                this.#db.prepare(
                  "SELECT * FROM gateway_challenge_reservations WHERE gateway_sequence=?",
                ).get(issue.gateway_sequence),
              ),
              operation: null,
            };
          }
          if (
            issue.expires_at_ms <= now ||
            issue.expires_at_ms > reservation.expires_at_ms
          ) {
            throw new GatewayLedgerError("gateway_operation_window_mismatch");
          }
          if (issue.expires_at_ms - now > MAX_OPERATION_TTL_MS) {
            throw new GatewayLedgerError("gateway_expiry_window_too_long");
          }
          const conflicts = this.#db.prepare(
            "SELECT operation_id,challenge_sha256,dispatch_command_sha256 " +
              "FROM gateway_operations WHERE operation_id=? " +
              "OR challenge_sha256=? OR dispatch_command_sha256=?",
          ).all(
            issue.operation_id,
            issue.challenge_sha256,
            issue.dispatch_command_sha256,
          ) as Array<{
            operation_id: string;
            challenge_sha256: string;
            dispatch_command_sha256: string;
          }>;
          if (conflicts.some((row) => row.operation_id === issue.operation_id)) {
            throw new GatewayLedgerError("gateway_operation_id_reused");
          }
          if (
            conflicts.some(
              (row) => row.challenge_sha256 === issue.challenge_sha256,
            )
          ) {
            throw new GatewayLedgerError("gateway_challenge_reused");
          }
          if (
            conflicts.some(
              (row) =>
                row.dispatch_command_sha256 === issue.dispatch_command_sha256,
            )
          ) {
            throw new GatewayLedgerError("gateway_dispatch_command_reused");
          }
          this.#db.prepare(
            "UPDATE gateway_challenge_reservations SET state='consumed'," +
              "challenge_sha256=?,consumed_operation_id=?,terminal_at_ms=? " +
              "WHERE gateway_sequence=? AND state='reserved'",
          ).run(
            issue.challenge_sha256,
            issue.operation_id,
            now,
            issue.gateway_sequence,
          );
          this.#db.prepare(
            "INSERT INTO gateway_operations(" +
              "operation_id,gateway_sequence,challenge_request_sha256," +
              "challenge_sha256,dispatch_command_sha256," +
              "provider_request_body_sha256,policy_sha256," +
              "runtime_manifest_sha256,context_sha256,state," +
              "issued_boot_session_id,issued_fencing_token,issued_at_ms," +
              "expires_at_ms) VALUES(?,?,?,?,?,?,?,?,?,'issued',?,?,?,?)",
          ).run(
            issue.operation_id,
            issue.gateway_sequence,
            issue.challenge_request_sha256,
            issue.challenge_sha256,
            issue.dispatch_command_sha256,
            issue.provider_request_body_sha256,
            issue.policy_sha256,
            issue.runtime_manifest_sha256,
            issue.context_sha256,
            this.bootSessionId,
            this.#fencingToken,
            now,
            issue.expires_at_ms,
          );
          return {
            reservation: challengeReservationRow(
              this.#db.prepare(
                "SELECT * FROM gateway_challenge_reservations WHERE gateway_sequence=?",
              ).get(issue.gateway_sequence),
            ),
            operation: operationRow(
              this.#db.prepare(
                "SELECT * FROM gateway_operations WHERE operation_id=?",
              ).get(issue.operation_id),
            ),
          };
        },
      );
      if (result.operation === null) {
        throw new GatewayLedgerError("gateway_reservation_expired");
      }
      return Object.freeze({
        operation: result.operation,
        provider_request: providerRequest,
      });
    } catch (error) {
      disposeRebuiltGatewayRequest(providerRequest);
      throw error;
    }
  }
  claimBeforeSend(input: {
    operation_id: string;
    gateway_sequence: number;
    challenge_sha256: string;
    dispatch_command_sha256: string;
    provider_request_body_sha256: string;
  }): GatewaySendCapability {
    validateOperationId(input.operation_id);
    if (
      !Number.isSafeInteger(input.gateway_sequence) ||
      input.gateway_sequence < 1
    ) {
      throw new GatewayLedgerError("gateway_sequence_invalid");
    }
    validateHex("gateway_challenge_sha256_invalid", input.challenge_sha256);
    validateHex(
      "gateway_dispatch_command_sha256_invalid",
      input.dispatch_command_sha256,
    );
    validateHex(
      "gateway_provider_request_body_sha256_invalid",
      input.provider_request_body_sha256,
    );
    const record = this.#mutate<GatewayOperationRecord>(
      {
        type: (result) =>
          result.state === "expired_before_send"
            ? "operation_expired"
            : "operation_claimed_before_send",
        operation_id: input.operation_id,
        payload: (result) => ({
          operation_id: result.operation_id,
          gateway_sequence: result.gateway_sequence,
          challenge_sha256: result.challenge_sha256,
          dispatch_command_sha256: result.dispatch_command_sha256,
          provider_request_body_sha256:
            result.provider_request_body_sha256,
          state: result.state,
          fencing_token: result.claimed_fencing_token,
          cancellation_reason_sha256: result.cancellation_reason_sha256,
        }),
      },
      (now) => {
        const row = this.#db.prepare(
          "SELECT * FROM gateway_operations WHERE operation_id=?",
        ).get(input.operation_id) as GatewayOperationRecord | undefined;
        if (!row) throw new GatewayLedgerError("gateway_operation_missing");
        if (
          row.gateway_sequence !== input.gateway_sequence ||
          row.challenge_sha256 !== input.challenge_sha256 ||
          row.dispatch_command_sha256 !== input.dispatch_command_sha256 ||
          row.provider_request_body_sha256 !==
            input.provider_request_body_sha256
        ) {
          throw new GatewayLedgerError("gateway_claim_binding_mismatch");
        }
        if (row.state !== "issued") {
          throw new GatewayLedgerError("gateway_operation_not_claimable");
        }
        if (
          row.issued_boot_session_id !== this.bootSessionId ||
          row.issued_fencing_token !== this.#fencingToken
        ) {
          throw new GatewayLedgerError("gateway_issued_session_stale");
        }
        if (now >= row.expires_at_ms) {
          this.#db.prepare(
            "UPDATE gateway_operations SET state='expired_before_send',terminal_at_ms=?," +
              "network_attempts=0,retry_count=0,redirect_count=0," +
              "cancellation_reason_sha256=? WHERE operation_id=? AND state='issued'",
          ).run(now, EXPIRED_REASON_SHA256, input.operation_id);
          return operationRow(
            this.#db.prepare(
              "SELECT * FROM gateway_operations WHERE operation_id=?",
            ).get(input.operation_id),
          );
        }
        this.#db.prepare(
          "UPDATE gateway_operations SET state='claimed_before_send'," +
            "claimed_boot_session_id=?,claimed_fencing_token=?,claimed_at_ms=? " +
            "WHERE operation_id=? AND state='issued'",
        ).run(this.bootSessionId, this.#fencingToken, now, input.operation_id);
        return operationRow(
          this.#db.prepare(
            "SELECT * FROM gateway_operations WHERE operation_id=?",
          ).get(input.operation_id),
        );
      },
    );
    if (record.state === "expired_before_send") {
      throw new GatewayLedgerError("gateway_operation_expired");
    }
    const capability = Object.freeze(Object.create(null)) as object;
    CAPABILITIES.set(capability, {
      ledger_instance_id: this.gatewayInstanceId,
      operation_id: record.operation_id,
      gateway_sequence: record.gateway_sequence,
      challenge_sha256: record.challenge_sha256,
      dispatch_command_sha256: record.dispatch_command_sha256,
      provider_request_body_sha256: record.provider_request_body_sha256,
      boot_session_id: this.bootSessionId,
      fencing_token: this.#fencingToken,
      used: false,
    });
    return capability as GatewaySendCapability;
  }
  complete(
    capability: GatewaySendCapability,
    input: {
      outcome: string;
      network_attempts: 0 | 1;
      retry_count: 0;
      redirect_count: 0;
      response_sha256?: string | null;
    },
  ): GatewayOperationRecord {
    const data = CAPABILITIES.get(capability as object);
    if (!data || data.ledger_instance_id !== this.gatewayInstanceId) {
      throw new GatewayLedgerError("gateway_capability_invalid");
    }
    if (data.used) throw new GatewayLedgerError("gateway_capability_used");
    data.used = true;
    if (
      !TERMINAL_OUTCOMES.has(input.outcome) ||
      (input.network_attempts !== 0 && input.network_attempts !== 1) ||
      input.retry_count !== 0 ||
      input.redirect_count !== 0
    ) {
      throw new GatewayLedgerError("gateway_terminal_result_invalid");
    }
    const responseSha256 = input.response_sha256 ?? null;
    if (responseSha256 !== null) {
      validateHex("gateway_response_sha256_invalid", responseSha256);
    }
    if (
      (input.outcome === "success" &&
        (input.network_attempts !== 1 || responseSha256 === null)) ||
      (input.network_attempts === 0 && responseSha256 !== null)
    ) {
      throw new GatewayLedgerError("gateway_terminal_result_inconsistent");
    }
    return this.#mutate(
      {
        type: "operation_terminal",
        operation_id: data.operation_id,
        payload: (record) => ({
          operation_id: record.operation_id,
          outcome: record.terminal_outcome,
          network_attempts: record.network_attempts,
          retry_count: record.retry_count,
          redirect_count: record.redirect_count,
          response_sha256: record.response_sha256,
        }),
      },
      (now) => {
        const row = this.#db.prepare(
          "SELECT * FROM gateway_operations WHERE operation_id=?",
        ).get(data.operation_id) as GatewayOperationRecord | undefined;
        if (
          !row ||
          row.state !== "claimed_before_send" ||
          row.gateway_sequence !== data.gateway_sequence ||
          row.challenge_sha256 !== data.challenge_sha256 ||
          row.dispatch_command_sha256 !== data.dispatch_command_sha256 ||
          row.provider_request_body_sha256 !==
            data.provider_request_body_sha256 ||
          row.claimed_boot_session_id !== data.boot_session_id ||
          row.claimed_fencing_token !== data.fencing_token ||
          data.boot_session_id !== this.bootSessionId ||
          data.fencing_token !== this.#fencingToken
        ) {
          throw new GatewayLedgerError("gateway_capability_binding_invalid");
        }
        this.#db.prepare(
          "UPDATE gateway_operations SET state='terminal',terminal_at_ms=?," +
            "terminal_outcome=?,network_attempts=?,retry_count=0,redirect_count=0," +
            "response_sha256=? WHERE operation_id=? AND state='claimed_before_send'",
        ).run(
          now,
          input.outcome,
          input.network_attempts,
          responseSha256,
          data.operation_id,
        );
        return operationRow(
          this.#db.prepare(
            "SELECT * FROM gateway_operations WHERE operation_id=?",
          ).get(data.operation_id),
        );
      },
    );
  }

  cancelIssued(
    operationId: string,
    cancellationReasonSha256: string,
  ): GatewayOperationRecord {
    validateOperationId(operationId);
    validateHex(
      "gateway_cancellation_reason_sha256_invalid",
      cancellationReasonSha256,
    );
    return this.#finishIssued(
      operationId,
      "cancelled_before_send",
      cancellationReasonSha256,
    );
  }

  expireIssued(operationId: string): GatewayOperationRecord {
    validateOperationId(operationId);
    return this.#finishIssued(
      operationId,
      "expired_before_send",
      EXPIRED_REASON_SHA256,
      true,
    );
  }

  #finishIssued(
    operationId: string,
    state: "cancelled_before_send" | "expired_before_send",
    reasonSha256: string,
    requireExpired = false,
  ): GatewayOperationRecord {
    return this.#mutate(
      {
        type: state === "cancelled_before_send" ? "operation_cancelled" : "operation_expired",
        operation_id: operationId,
        payload: (record) => ({
          operation_id: record.operation_id,
          state: record.state,
          cancellation_reason_sha256: record.cancellation_reason_sha256,
        }),
      },
      (now) => {
        const row = this.#db.prepare(
          "SELECT * FROM gateway_operations WHERE operation_id=?",
        ).get(operationId) as GatewayOperationRecord | undefined;
        if (!row) throw new GatewayLedgerError("gateway_operation_missing");
        if (row.state !== "issued") {
          throw new GatewayLedgerError("gateway_operation_not_issued");
        }
        if (requireExpired && now < row.expires_at_ms) {
          throw new GatewayLedgerError("gateway_operation_not_expired");
        }
        this.#db.prepare(
          "UPDATE gateway_operations SET state=?,terminal_at_ms=?,network_attempts=0," +
            "retry_count=0,redirect_count=0,cancellation_reason_sha256=? " +
            "WHERE operation_id=? AND state='issued'",
        ).run(state, now, reasonSha256, operationId);
        return operationRow(
          this.#db.prepare(
            "SELECT * FROM gateway_operations WHERE operation_id=?",
          ).get(operationId),
        );
      },
    );
  }

  getChallengeReservation(
    gatewaySequence: number,
  ): GatewayChallengeReservation {
    if (!Number.isSafeInteger(gatewaySequence) || gatewaySequence < 1) {
      throw new GatewayLedgerError("gateway_sequence_invalid");
    }
    return this.#read((meta) => {
      this.#assertActiveSession(meta);
      const row = this.#db.prepare(
        "SELECT * FROM gateway_challenge_reservations WHERE gateway_sequence=?",
      ).get(gatewaySequence);
      if (!row) {
        throw new GatewayLedgerError("gateway_reservation_missing");
      }
      return challengeReservationRow(row);
    });
  }
  getOperation(operationId: string): GatewayOperationRecord {
    validateOperationId(operationId);
    return this.#read((meta) => {
      this.#assertActiveSession(meta);
      const row = this.#db.prepare(
        "SELECT * FROM gateway_operations WHERE operation_id=?",
      ).get(operationId);
      if (!row) throw new GatewayLedgerError("gateway_operation_missing");
      return operationRow(row);
    });
  }

  checkpoint(): GatewayLedgerCheckpoint {
    return this.#read((meta) => {
      this.#assertActiveSession(meta);
      return this.#checkpointFromMeta(meta);
    });
  }

  #checkpointFromMeta(meta: Record<string, string>): GatewayLedgerCheckpoint {
    const body: Omit<GatewayLedgerCheckpoint, "checkpoint_hmac_sha256"> = {
      schema_version: SCHEMA_VERSION,
      gateway_instance_id: this.gatewayInstanceId,
      runtime_policy_sha256: this.runtimePolicySha256,
      gateway_build_sha256: this.gatewayBuildSha256,
      gateway_sequence: parseInteger(meta, "gateway_sequence"),
      fencing_token: parseInteger(meta, "fencing_token"),
      audit_sequence: parseInteger(meta, "audit_sequence"),
      audit_head_hmac_sha256: meta.audit_head_hmac_sha256,
    };
    return {
      ...body,
      checkpoint_hmac_sha256: hmacSha256Canonical(
        this.#secret,
        CHECKPOINT_DOMAIN,
        body,
      ),
    };
  }

  #recoverDeadSession(
    deadBootSessionId: string,
    recoveryId: string,
  ): GatewayLedgerCheckpoint {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const meta = this.#verifyAll();
      if (
        meta.clean_shutdown !== "0" ||
        meta.active_boot_session_id !== deadBootSessionId
      ) {
        throw new GatewayLedgerError("gateway_dead_session_mismatch");
      }
      const now = this.#advanceClock(meta);
      const deadFencingToken = parseInteger(meta, "fencing_token");
      const reservedChallenges = this.#db.prepare(
        "SELECT gateway_sequence FROM gateway_challenge_reservations " +
          "WHERE state='reserved' AND gateway_boot_id=? " +
          "AND gateway_fencing_token=? ORDER BY gateway_sequence",
      ).all(deadBootSessionId, deadFencingToken) as Array<{
        gateway_sequence: number;
      }>;
      const issued = this.#db.prepare(
        "SELECT operation_id FROM gateway_operations WHERE state='issued' " +
          "AND issued_boot_session_id=? AND issued_fencing_token=? ORDER BY operation_id",
      ).all(deadBootSessionId, deadFencingToken) as Array<{
        operation_id: string;
      }>;
      const claimed = this.#db.prepare(
        "SELECT operation_id FROM gateway_operations WHERE state='claimed_before_send' " +
          "AND claimed_boot_session_id=? AND claimed_fencing_token=? ORDER BY operation_id",
      ).all(deadBootSessionId, deadFencingToken) as Array<{
        operation_id: string;
      }>;
      this.#db.prepare(
        "UPDATE gateway_challenge_reservations SET state='cancelled'," +
          "terminal_at_ms=?,cancellation_reason_sha256=? " +
          "WHERE state='reserved' AND gateway_boot_id=? " +
          "AND gateway_fencing_token=?",
      ).run(
        now,
        DEAD_BOOT_REASON_SHA256,
        deadBootSessionId,
        deadFencingToken,
      );
      this.#db.prepare(
        "UPDATE gateway_operations SET state='cancelled_before_send',terminal_at_ms=?," +
          "network_attempts=0,retry_count=0,redirect_count=0,cancellation_reason_sha256=? " +
          "WHERE state='issued' AND issued_boot_session_id=? AND issued_fencing_token=?",
      ).run(
        now,
        DEAD_BOOT_REASON_SHA256,
        deadBootSessionId,
        deadFencingToken,
      );
      this.#db.prepare(
        "UPDATE gateway_operations SET state='unknown_after_crash',terminal_at_ms=?," +
          "terminal_outcome='unknown_after_crash',network_attempts=1,retry_count=0," +
          "redirect_count=0 WHERE state='claimed_before_send' " +
          "AND claimed_boot_session_id=? AND claimed_fencing_token=?",
      ).run(now, deadBootSessionId, deadFencingToken);
      const fencingToken = deadFencingToken + 1;
      setMeta(this.#db, "active_boot_session_id", "");
      setMeta(this.#db, "clean_shutdown", "1");
      setMeta(this.#db, "fencing_token", fencingToken);
      appendEvent(this.#db, this.#secret, {
        event_type: "dead_boot_session_recovered",
        boot_session_id: deadBootSessionId,
        operation_id: null,
        recorded_at_ms: now,
        payload: {
          recovery_id: recoveryId,
          fenced_at_token: fencingToken,
          cancelled_gateway_sequences: reservedChallenges.map(
            (row) => row.gateway_sequence,
          ),
          cancelled_operation_ids: issued.map((row) => row.operation_id),
          unknown_operation_ids: claimed.map((row) => row.operation_id),
        },
      });
      setMeta(
        this.#db,
        "projection_hmac_sha256",
        computeProjectionHmac(this.#db, this.#secret),
      );
      const checkpoint = this.#checkpointFromMeta(this.#verifyAll());
      this.#db.exec("COMMIT");
      return checkpoint;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }

  close(): GatewayLedgerCheckpoint | null {
    if (this.#closed) return null;
    let failure: unknown;
    let checkpoint: GatewayLedgerCheckpoint | null = null;
    try {
      if (this.#ownsBootSession) {
        this.#db.exec("BEGIN IMMEDIATE");
        try {
          const meta = this.#verifyAll();
          this.#assertActiveSession(meta);
          const reservedChallenges = this.#db.prepare(
            "SELECT gateway_sequence FROM gateway_challenge_reservations " +
              "WHERE state='reserved' AND gateway_boot_id=? " +
              "AND gateway_fencing_token=? ORDER BY gateway_sequence",
          ).all(this.bootSessionId, this.#fencingToken) as Array<{
            gateway_sequence: number;
          }>;
          const issued = this.#db.prepare(
            "SELECT operation_id FROM gateway_operations WHERE state='issued' " +
              "AND issued_boot_session_id=? AND issued_fencing_token=? ORDER BY operation_id",
          ).all(this.bootSessionId, this.#fencingToken) as Array<{
            operation_id: string;
          }>;
          const abandonedClaims = this.#db.prepare(
            "SELECT operation_id FROM gateway_operations WHERE state='claimed_before_send' " +
              "AND claimed_boot_session_id=? AND claimed_fencing_token=? ORDER BY operation_id",
          ).all(this.bootSessionId, this.#fencingToken) as Array<{
            operation_id: string;
          }>;
          const now = this.#advanceClock(meta);
          this.#db.prepare(
            "UPDATE gateway_challenge_reservations SET state='cancelled'," +
              "terminal_at_ms=?,cancellation_reason_sha256=? " +
              "WHERE state='reserved' AND gateway_boot_id=? " +
              "AND gateway_fencing_token=?",
          ).run(
            now,
            BOOT_CLOSED_REASON_SHA256,
            this.bootSessionId,
            this.#fencingToken,
          );
          this.#db.prepare(
            "UPDATE gateway_operations SET state='cancelled_before_send',terminal_at_ms=?," +
              "network_attempts=0,retry_count=0,redirect_count=0,cancellation_reason_sha256=? " +
              "WHERE state='issued' AND issued_boot_session_id=? AND issued_fencing_token=?",
          ).run(
            now,
            BOOT_CLOSED_REASON_SHA256,
            this.bootSessionId,
            this.#fencingToken,
          );
          this.#db.prepare(
            "UPDATE gateway_operations SET state='unknown_after_crash',terminal_at_ms=?," +
              "terminal_outcome='unknown_after_crash',network_attempts=1,retry_count=0," +
              "redirect_count=0 WHERE state='claimed_before_send' " +
              "AND claimed_boot_session_id=? AND claimed_fencing_token=?",
          ).run(now, this.bootSessionId, this.#fencingToken);
          setMeta(this.#db, "active_boot_session_id", "");
          setMeta(this.#db, "clean_shutdown", "1");
          appendEvent(this.#db, this.#secret, {
            event_type: "boot_session_closed",
            boot_session_id: this.bootSessionId,
            operation_id: null,
            recorded_at_ms: now,
            payload: {
              fencing_token: this.#fencingToken,
              cancelled_gateway_sequences: reservedChallenges.map(
                (row) => row.gateway_sequence,
              ),
              cancelled_operation_ids: issued.map((row) => row.operation_id),
              unknown_operation_ids: abandonedClaims.map(
                (row) => row.operation_id,
              ),
            },
          });
          setMeta(
            this.#db,
            "projection_hmac_sha256",
            computeProjectionHmac(this.#db, this.#secret),
          );
          checkpoint = this.#checkpointFromMeta(this.#verifyAll());
          this.#db.exec("COMMIT");
        } catch (error) {
          try {
            this.#db.exec("ROLLBACK");
          } catch {}
          failure = error;
        }
      }
    } finally {
      this.#forceClose();
    }
    if (failure) throw failure;
    return checkpoint;
  }

  #forceClose() {
    if (!this.#closed) {
      this.#db.close();
      this.#closed = true;
    }
    this.#secret.fill(0);
  }
}
