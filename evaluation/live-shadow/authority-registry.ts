import type { KeyObject } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import { DatabaseSync } from "node:sqlite";
import type { AnchorCheckpoint, AnchorPort } from "./anchor-port.ts";
import { AnchorError } from "./anchor-port.ts";
import {
  LIVE_CALL_SLOTS,
  LiveCallSlotSchema,
  LiveDispatchIntentSchema,
  LiveRuntimeManifestSchema,
  verifyLiveConsent,
  verifyLocalAnchorReceipt,
} from "./contracts.ts";
import type {
  LiveCallSlot,
  LiveDispatchIntent,
} from "./contracts.ts";
import {
  canonicalJson,
  computeMediaPairCommitment,
  hmacSha256Bytes,
  hmacSha256Canonical,
  publicKeyId,
  secretKeyId,
  sha256Bytes,
  sha256Canonical,
} from "./crypto.ts";
import {
  computeAnchorAuthorizationClaimObjectSha256,
  computeLiveSlotKey,
} from "./local-anchor-stub.ts";
import {
  inspectOfflineCanonicalRequest,
} from "./offline-request.ts";
import type { OfflineCanonicalRequestEnvelope } from "./offline-request.ts";

const AUTHORITY_SCHEMA_VERSION = "checkback.live-shadow.authority.v1";
const AUTHORITY_APPLICATION_ID = 0x43424c52;
const AUTHORITY_USER_VERSION = 1;
const ZERO_HASH = "0".repeat(64);
const SQLITE_HEADER = Buffer.from("SQLite format 3\0", "binary");
const META_DOMAIN = "checkback.live-shadow.authority-meta.v1";
const AUDIT_DOMAIN = "checkback.live-shadow.authority-audit.v1";
const REQUEST_DOMAIN = "checkback.live-shadow.request-commitment.v1";
const RESULT_DOMAIN = "checkback.live-shadow.result-commitment.v1";
const PROJECTION_DOMAIN = "checkback.live-shadow.authority-projection.v1";

const AUTHORITY_SCHEMA_STATEMENTS = [
  "CREATE TABLE authority_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
  "CREATE TABLE authorizations(" +
    "authorization_id TEXT PRIMARY KEY,authorization_fingerprint_sha256 TEXT NOT NULL UNIQUE," +
    "signed_consent_sha256 TEXT NOT NULL,runtime_manifest_sha256 TEXT NOT NULL," +
    "expires_at_ms INTEGER NOT NULL,retention_until_ms INTEGER NOT NULL," +
    "state TEXT NOT NULL CHECK(state IN ('prepared','active','review_required'))," +
    "anchor_receipt_json TEXT)",
  "CREATE TABLE executions(" +
    "execution_id TEXT PRIMARY KEY,authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id)," +
    "position INTEGER NOT NULL,media_scope_id TEXT NOT NULL," +
    "pair_commitment_hmac_sha256 TEXT NOT NULL," +
    "UNIQUE(authorization_id,position))",
  "CREATE TABLE call_slots(" +
    "slot_key_sha256 TEXT PRIMARY KEY,authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id)," +
    "execution_id TEXT NOT NULL REFERENCES executions(execution_id)," +
    "slot TEXT NOT NULL CHECK(slot IN ('primary','flash','plus'))," +
    "ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 3)," +
    "state TEXT NOT NULL CHECK(state IN ('allocated','prepared','dispatching','result','anchor_ambiguous','unknown_after_crash','abandoned_before_anchor'))," +
    "operation_id TEXT UNIQUE,dispatch_intent_sha256 TEXT,request_commitment_hmac_sha256 TEXT," +
    "anchor_receipt_json TEXT,outcome TEXT,result_commitment_hmac_sha256 TEXT," +
    "prepared_at_ms INTEGER,dispatched_at_ms INTEGER,completed_at_ms INTEGER," +
    "UNIQUE(execution_id,slot),UNIQUE(execution_id,ordinal))",
  "CREATE TABLE authority_events(" +
    "sequence INTEGER PRIMARY KEY,previous_event_hash TEXT NOT NULL,event_type TEXT NOT NULL," +
    "authorization_id TEXT,execution_id TEXT,slot TEXT,recorded_at_ms INTEGER NOT NULL," +
    "payload_json TEXT NOT NULL,event_hash TEXT NOT NULL)",
  "CREATE TRIGGER authority_events_no_update BEFORE UPDATE ON authority_events " +
    "BEGIN SELECT RAISE(ABORT,'authority events append only'); END",
  "CREATE TRIGGER authority_events_no_delete BEFORE DELETE ON authority_events " +
    "BEGIN SELECT RAISE(ABORT,'authority events append only'); END",
] as const;

type AuthorityState = "ready" | "active" | "quarantined";
const TERMINAL_OUTCOMES = new Set([
  "success",
  "request_error",
  "timeout",
  "invalid_output",
]);

type SlotState =
  | "allocated"
  | "prepared"
  | "dispatching"
  | "result"
  | "anchor_ambiguous"
  | "unknown_after_crash"
  | "abandoned_before_anchor";

type SlotRow = {
  slot_key_sha256: string;
  authorization_id: string;
  execution_id: string;
  slot: LiveCallSlot;
  ordinal: number;
  state: SlotState;
  operation_id: string | null;
  dispatch_intent_sha256: string | null;
  request_commitment_hmac_sha256: string | null;
};

type PermitData = {
  registry_id: string;
  operation_id: string;
  intent_sha256: string;
  used: boolean;
};

const DISPATCH_PERMITS = new WeakMap<object, PermitData>();

export class AuthorityError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "AuthorityError";
    this.code = code;
  }
}

function requirePersistentPath(path: string) {
  if (!path || path === ":memory:") {
    throw new AuthorityError("authority_persistent_database_path_required");
  }
}

function assertExistingSqliteFile(path: string) {
  requirePersistentPath(path);
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    throw new AuthorityError("authority_database_missing");
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new AuthorityError("authority_database_path_invalid");
  }
  if (stat.size === 0) throw new AuthorityError("authority_database_empty");
  const descriptor = openSync(path, fsConstants.O_RDONLY);
  try {
    const header = Buffer.alloc(SQLITE_HEADER.length);
    const read = readSync(descriptor, header, 0, header.length, 0);
    if (read !== header.length || !header.equals(SQLITE_HEADER)) {
      throw new AuthorityError("authority_database_header_invalid");
    }
  } finally {
    closeSync(descriptor);
  }
}

function readMeta(db: DatabaseSync): Record<string, string> {
  const rows = db.prepare("SELECT key,value FROM authority_meta").all() as {
    key: string;
    value: string;
  }[];
  return Object.fromEntries(rows.map((row) => [row.key, row.value]));
}

function schemaFingerprint(db: DatabaseSync): string {
  const rows = db.prepare(
    "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' " +
      "ORDER BY type,name",
  ).all() as { type: string; name: string; sql: string }[];
  return sha256Canonical(rows);
}

function parseIntegerMeta(meta: Record<string, string>, key: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(meta[key] ?? "")) {
    throw new AuthorityError("authority_meta_invalid");
  }
  return Number(meta[key]);
}

function checkpointFromMeta(meta: Record<string, string>): AnchorCheckpoint {
  return {
    registry_sequence: parseIntegerMeta(meta, "registry_sequence"),
    registry_head_sha256: meta.registry_head_sha256,
    active_session_id: meta.active_session_id || null,
    fencing_token: parseIntegerMeta(meta, "fencing_token"),
  };
}

function checkpointsEqual(left: AnchorCheckpoint, right: AnchorCheckpoint) {
  return (
    left.registry_sequence === right.registry_sequence &&
    left.registry_head_sha256 === right.registry_head_sha256 &&
    left.active_session_id === right.active_session_id &&
    left.fencing_token === right.fencing_token
  );
}

function setMeta(db: DatabaseSync, key: string, value: string | number | null) {
  db.prepare("UPDATE authority_meta SET value=? WHERE key=?").run(
    value === null ? "" : String(value),
    key,
  );
}

function computeAuthorityProjectionHmac(
  db: DatabaseSync,
  authoritySecret: Uint8Array,
): string {
  return hmacSha256Canonical(authoritySecret, PROJECTION_DOMAIN, {
    meta: db.prepare(
      "SELECT key,value FROM authority_meta " +
        "WHERE key<>'projection_hmac_sha256' ORDER BY key",
    ).all(),
    authorizations: db.prepare(
      "SELECT * FROM authorizations ORDER BY authorization_id",
    ).all(),
    executions: db.prepare(
      "SELECT * FROM executions ORDER BY execution_id",
    ).all(),
    call_slots: db.prepare(
      "SELECT * FROM call_slots ORDER BY slot_key_sha256",
    ).all(),
  });
}

export class LiveAuthorityRegistry {
  readonly registryId: string;
  readonly authorityKeyId: string;
  readonly anchorRealmId: string;
  readonly anchorKeyId: string;
  #db: DatabaseSync;
  #authoritySecret: Buffer;
  #consentPublicKey: KeyObject;
  #anchorPublicKey: KeyObject;
  #anchor: AnchorPort;
  #clock: () => number;
  #closed = false;
  #fatal = false;

  private constructor(input: {
    database_path: string;
    authority_secret: Uint8Array;
    consent_public_key: KeyObject;
    anchor_public_key: KeyObject;
    anchor: AnchorPort;
    expected_registry_id: string;
    now?: () => number;
  }) {
    this.#authoritySecret = Buffer.from(input.authority_secret);
    this.#consentPublicKey = input.consent_public_key;
    this.#anchorPublicKey = input.anchor_public_key;
    this.#anchor = input.anchor;
    this.#clock = input.now ?? Date.now;
    this.#db = new DatabaseSync(input.database_path, { readOnly: false });
    try {
      this.#configureDatabase();
      const meta = this.#verifyDatabase(input.expected_registry_id);
      this.registryId = meta.registry_id;
      this.authorityKeyId = meta.authority_key_id;
      this.anchorRealmId = meta.anchor_realm_id;
      this.anchorKeyId = meta.anchor_key_id;
    } catch (error) {
      try {
        this.#db.close();
      } catch {
      } finally {
        this.#closed = true;
        this.#authoritySecret.fill(0);
      }
      throw error;
    }
  }

  static initialize(input: {
    database_path: string;
    registry_id: string;
    authority_secret: Uint8Array;
    consent_public_key: KeyObject;
    anchor_public_key: KeyObject;
    anchor: AnchorPort;
    now?: () => number;
  }): void {
    requirePersistentPath(input.database_path);
    if (!/^registry_[a-f0-9]{64}$/.test(input.registry_id)) {
      throw new AuthorityError("authority_registry_id_invalid");
    }
    const authorityKeyId = secretKeyId(input.authority_secret);
    const anchorKeyId = publicKeyId(input.anchor_public_key);
    if (
      input.anchor.mode !== "offline_local_stub" ||
      input.anchor.keyId !== anchorKeyId
    ) {
      throw new AuthorityError("authority_anchor_key_mismatch");
    }
    let descriptor: number;
    try {
      descriptor = openSync(
        input.database_path,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
        0o600,
      );
    } catch {
      throw new AuthorityError("authority_database_already_exists");
    }
    closeSync(descriptor);
    const db = new DatabaseSync(input.database_path, { readOnly: false });
    try {
      db.exec("PRAGMA journal_mode=WAL");
      db.exec("PRAGMA synchronous=FULL");
      db.exec("PRAGMA foreign_keys=ON");
      db.exec("BEGIN IMMEDIATE");
      db.exec(`PRAGMA application_id=${AUTHORITY_APPLICATION_ID}`);
      db.exec(`PRAGMA user_version=${AUTHORITY_USER_VERSION}`);
      for (const statement of AUTHORITY_SCHEMA_STATEMENTS) db.exec(statement);
      const physicalSchemaSha256 = schemaFingerprint(db);
      const identity = {
        schema_version: AUTHORITY_SCHEMA_VERSION,
        physical_schema_sha256: physicalSchemaSha256,
        registry_id: input.registry_id,
        authority_key_id: authorityKeyId,
        consent_key_id: publicKeyId(input.consent_public_key),
        anchor_mode: input.anchor.mode,
        anchor_realm_id: input.anchor.realmId,
        anchor_key_id: anchorKeyId,
      };
      const identityMac = hmacSha256Canonical(
        input.authority_secret,
        META_DOMAIN,
        identity,
      );
      const insert = db.prepare(
        "INSERT INTO authority_meta(key,value) VALUES(?,?)",
      );
      for (const [key, value] of Object.entries(identity)) {
        insert.run(key, value);
      }
      for (const [key, value] of Object.entries({
        identity_hmac_sha256: identityMac,
        registry_sequence: "0",
        registry_head_sha256: ZERO_HASH,
        active_session_id: "",
        fencing_token: "0",
        authority_state: "initializing",
        audit_sequence: "0",
        audit_head_sha256: ZERO_HASH,
      })) {
        insert.run(key, value);
      }
      insert.run(
        "projection_hmac_sha256",
        computeAuthorityProjectionHmac(db, input.authority_secret),
      );
      db.exec("COMMIT");
      const now = input.now?.() ?? Date.now();
      const receipt = input.anchor.registerRegistry({
        authority_registry_id: input.registry_id,
        authority_key_id: authorityKeyId,
        recorded_at_ms: now,
      });
      const verified = verifyLocalAnchorReceipt(
        input.anchor_public_key,
        receipt,
      );
      if (
        verified.payload.event_type !== "register_registry" ||
        verified.payload.authority_registry_id !== input.registry_id ||
        verified.payload.anchor_realm_id !== input.anchor.realmId ||
        verified.payload.previous_registry_head_sha256 !== ZERO_HASH
      ) {
        throw new AuthorityError("authority_anchor_registration_invalid");
      }
      db.exec("BEGIN IMMEDIATE");
      setMeta(db, "registry_sequence", verified.payload.registry_sequence);
      setMeta(db, "registry_head_sha256", verified.payload.registry_head_sha256);
      setMeta(db, "active_session_id", null);
      setMeta(db, "fencing_token", verified.payload.fencing_token);
      setMeta(db, "authority_state", "ready");
      const eventValue = {
        sequence: 1,
        previous_event_hash: ZERO_HASH,
        event_type: "registry_initialized",
        authorization_id: null,
        execution_id: null,
        slot: null,
        recorded_at_ms: now,
        payload: { anchor_receipt_sha256: sha256Canonical(verified) },
      };
      const eventHash = hmacSha256Canonical(
        input.authority_secret,
        AUDIT_DOMAIN,
        eventValue,
      );
      db.prepare("INSERT INTO authority_events VALUES(?,?,?,?,?,?,?,?,?)").run(
        1,
        ZERO_HASH,
        "registry_initialized",
        null,
        null,
        null,
        now,
        canonicalJson(eventValue.payload),
        eventHash,
      );
      setMeta(db, "audit_sequence", 1);
      setMeta(db, "audit_head_sha256", eventHash);
      setMeta(
        db,
        "projection_hmac_sha256",
        computeAuthorityProjectionHmac(db, input.authority_secret),
      );
      db.exec("COMMIT");
      db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    } catch (error) {
      try {
        db.exec("ROLLBACK");
      } catch {}
      throw error;
    } finally {
      db.close();
    }
  }

  static openExisting(input: {
    database_path: string;
    expected_registry_id: string;
    authority_secret: Uint8Array;
    consent_public_key: KeyObject;
    anchor_public_key: KeyObject;
    anchor: AnchorPort;
    session_id: string;
    now?: () => number;
  }): LiveAuthorityRegistry {
    assertExistingSqliteFile(input.database_path);
    if (!/^session_[a-f0-9]{64}$/.test(input.session_id)) {
      throw new AuthorityError("authority_session_id_invalid");
    }
    const registry = new LiveAuthorityRegistry(input);
    try {
      registry.#acquireSession(input.session_id);
      return registry;
    } catch (error) {
      registry.#forceClose();
      throw error;
    }
  }

  #assertOpen() {
    if (this.#closed) throw new AuthorityError("authority_closed");
  }

  #now() {
    const value = this.#clock();
    if (!Number.isInteger(value) || value < 0) {
      throw new AuthorityError("authority_clock_invalid");
    }
    return value;
  }

  #configureDatabase() {
    this.#db.exec("PRAGMA journal_mode=WAL");
    this.#db.exec("PRAGMA synchronous=FULL");
    this.#db.exec("PRAGMA foreign_keys=ON");
    this.#db.exec("PRAGMA busy_timeout=10000");
  }

  #verifyDatabase(expectedRegistryId: string) {
    const applicationId = this.#db.prepare("PRAGMA application_id").get() as {
      application_id: number;
    };
    const userVersion = this.#db.prepare("PRAGMA user_version").get() as {
      user_version: number;
    };
    const integrity = this.#db.prepare("PRAGMA integrity_check").get() as {
      integrity_check: string;
    };
    if (
      applicationId.application_id !== AUTHORITY_APPLICATION_ID ||
      userVersion.user_version !== AUTHORITY_USER_VERSION ||
      integrity.integrity_check !== "ok" ||
      this.#db.prepare("PRAGMA foreign_key_check").all().length !== 0
    ) {
      throw new AuthorityError("authority_integrity_check_failed");
    }
    const meta = readMeta(this.#db);
    const identity = {
      schema_version: meta.schema_version,
      physical_schema_sha256: meta.physical_schema_sha256,
      registry_id: meta.registry_id,
      authority_key_id: meta.authority_key_id,
      consent_key_id: meta.consent_key_id,
      anchor_mode: meta.anchor_mode,
      anchor_realm_id: meta.anchor_realm_id,
      anchor_key_id: meta.anchor_key_id,
    };
    if (
      identity.schema_version !== AUTHORITY_SCHEMA_VERSION ||
      identity.physical_schema_sha256 !== schemaFingerprint(this.#db)
    ) {
      throw new AuthorityError("authority_schema_mismatch");
    }
    if (
      identity.registry_id !== expectedRegistryId ||
      identity.authority_key_id !== secretKeyId(this.#authoritySecret) ||
      identity.consent_key_id !== publicKeyId(this.#consentPublicKey)
    ) {
      throw new AuthorityError("authority_identity_or_key_mismatch");
    }
    if (
      identity.anchor_mode !== this.#anchor.mode ||
      identity.anchor_realm_id !== this.#anchor.realmId ||
      identity.anchor_key_id !== this.#anchor.keyId ||
      identity.anchor_key_id !== publicKeyId(this.#anchorPublicKey)
    ) {
      throw new AuthorityError("authority_anchor_identity_mismatch");
    }
    const expectedIdentityMac = hmacSha256Canonical(
      this.#authoritySecret,
      META_DOMAIN,
      identity,
    );
    if (meta.identity_hmac_sha256 !== expectedIdentityMac) {
      throw new AuthorityError("authority_identity_mac_invalid");
    }
    this.#verifyProjectionHmac(meta);
    if (meta.authority_state !== "ready") {
      throw new AuthorityError(
        meta.authority_state === "initializing"
          ? "authority_initialization_incomplete"
          : "authority_not_cleanly_closed",
      );
    }
    this.#verifyAuditChain(meta);
    return meta;
  }

  #verifyAuditChain(meta: Record<string, string>) {
    const rows = this.#db.prepare(
      "SELECT sequence,previous_event_hash,event_type,authorization_id,execution_id,slot," +
        "recorded_at_ms,payload_json,event_hash FROM authority_events ORDER BY sequence",
    ).all() as {
      sequence: number;
      previous_event_hash: string;
      event_type: string;
      authorization_id: string | null;
      execution_id: string | null;
      slot: string | null;
      recorded_at_ms: number;
      payload_json: string;
      event_hash: string;
    }[];
    let sequence = 0;
    let previous = ZERO_HASH;
    for (const row of rows) {
      sequence += 1;
      let payload: unknown;
      try {
        payload = JSON.parse(row.payload_json);
      } catch {
        throw new AuthorityError("authority_audit_payload_invalid");
      }
      const value = {
        sequence: row.sequence,
        previous_event_hash: row.previous_event_hash,
        event_type: row.event_type,
        authorization_id: row.authorization_id,
        execution_id: row.execution_id,
        slot: row.slot,
        recorded_at_ms: row.recorded_at_ms,
        payload,
      };
      if (
        row.sequence !== sequence ||
        row.previous_event_hash !== previous ||
        row.event_hash !==
          hmacSha256Canonical(this.#authoritySecret, AUDIT_DOMAIN, value)
      ) {
        throw new AuthorityError("authority_audit_chain_invalid");
      }
      previous = row.event_hash;
    }
    if (
      parseIntegerMeta(meta, "audit_sequence") !== sequence ||
      meta.audit_head_sha256 !== previous
    ) {
      throw new AuthorityError("authority_audit_head_invalid");
    }
  }

  #verifyProjectionHmac(meta = readMeta(this.#db)) {
    if (meta.physical_schema_sha256 !== schemaFingerprint(this.#db)) {
      throw new AuthorityError("authority_schema_mismatch");
    }
    const expected = computeAuthorityProjectionHmac(
      this.#db,
      this.#authoritySecret,
    );
    if (meta.projection_hmac_sha256 !== expected) {
      throw new AuthorityError("authority_projection_hmac_invalid");
    }
  }

  #verifyCurrentState() {
    this.#assertOpen();
    if (this.#fatal) {
      throw new AuthorityError("authority_fatal_quarantine");
    }
    const meta = readMeta(this.#db);
    this.#verifyProjectionHmac(meta);
    this.#verifyAuditChain(meta);
  }

  #transaction<T>(callback: () => T): T {
    this.#verifyCurrentState();
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const lockedMeta = readMeta(this.#db);
      this.#verifyProjectionHmac(lockedMeta);
      this.#verifyAuditChain(lockedMeta);
      const output = callback();
      setMeta(
        this.#db,
        "projection_hmac_sha256",
        computeAuthorityProjectionHmac(this.#db, this.#authoritySecret),
      );
      this.#db.exec("COMMIT");
      return output;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }

  #appendEvent(input: {
    event_type: string;
    recorded_at_ms: number;
    authorization_id?: string;
    execution_id?: string;
    slot?: LiveCallSlot;
    payload?: unknown;
  }) {
    const meta = readMeta(this.#db);
    const sequence = parseIntegerMeta(meta, "audit_sequence") + 1;
    const previous = meta.audit_head_sha256;
    const payload = input.payload ?? {};
    const value = {
      sequence,
      previous_event_hash: previous,
      event_type: input.event_type,
      authorization_id: input.authorization_id ?? null,
      execution_id: input.execution_id ?? null,
      slot: input.slot ?? null,
      recorded_at_ms: input.recorded_at_ms,
      payload,
    };
    const eventHash = hmacSha256Canonical(
      this.#authoritySecret,
      AUDIT_DOMAIN,
      value,
    );
    this.#db.prepare("INSERT INTO authority_events VALUES(?,?,?,?,?,?,?,?,?)").run(
      sequence,
      previous,
      input.event_type,
      input.authorization_id ?? null,
      input.execution_id ?? null,
      input.slot ?? null,
      input.recorded_at_ms,
      canonicalJson(payload),
      eventHash,
    );
    setMeta(this.#db, "audit_sequence", sequence);
    setMeta(this.#db, "audit_head_sha256", eventHash);
  }

  #state(): AuthorityState {
    const value = readMeta(this.#db).authority_state;
    if (value !== "ready" && value !== "active" && value !== "quarantined") {
      throw new AuthorityError("authority_state_invalid");
    }
    return value;
  }

  #checkpoint(): AnchorCheckpoint {
    return checkpointFromMeta(readMeta(this.#db));
  }

  #verifyReceipt(
    input: unknown,
    eventType: string,
    previous: AnchorCheckpoint,
  ) {
    const receipt = verifyLocalAnchorReceipt(this.#anchorPublicKey, input);
    if (
      receipt.payload.authority_registry_id !== this.registryId ||
      receipt.payload.anchor_realm_id !== this.anchorRealmId ||
      receipt.payload.event_type !== eventType ||
      receipt.payload.registry_sequence !== previous.registry_sequence + 1 ||
      receipt.payload.previous_registry_head_sha256 !==
        previous.registry_head_sha256
    ) {
      throw new AuthorityError("authority_anchor_receipt_binding_invalid");
    }
    return receipt;
  }

  #storeCheckpoint(input: {
    receipt: ReturnType<typeof verifyLocalAnchorReceipt>;
    active_session_id: string | null;
    state?: AuthorityState;
  }) {
    setMeta(
      this.#db,
      "registry_sequence",
      input.receipt.payload.registry_sequence,
    );
    setMeta(
      this.#db,
      "registry_head_sha256",
      input.receipt.payload.registry_head_sha256,
    );
    setMeta(this.#db, "active_session_id", input.active_session_id);
    setMeta(this.#db, "fencing_token", input.receipt.payload.fencing_token);
    if (input.state) setMeta(this.#db, "authority_state", input.state);
  }

  #acquireSession(sessionId: string) {
    const now = this.#now();
    const localCheckpoint = this.#checkpoint();
    let remoteCheckpoint: AnchorCheckpoint | null;
    try {
      remoteCheckpoint = this.#anchor.inspectRegistry(this.registryId);
    } catch {
      throw new AuthorityError("authority_anchor_unavailable");
    }
    if (!remoteCheckpoint || !checkpointsEqual(localCheckpoint, remoteCheckpoint)) {
      throw new AuthorityError("authority_clone_or_rollback_detected");
    }
    let rawReceipt;
    try {
      rawReceipt = this.#anchor.acquireSession({
        authority_registry_id: this.registryId,
        expected_checkpoint: localCheckpoint,
        session_id: sessionId,
        recorded_at_ms: now,
      });
    } catch (error) {
      if (error instanceof AnchorError) {
        throw new AuthorityError(
          error.code === "anchor_checkpoint_mismatch"
            ? "authority_clone_or_rollback_detected"
            : "authority_anchor_session_failed",
        );
      }
      throw new AuthorityError("authority_anchor_session_failed");
    }
    const receipt = this.#verifyReceipt(
      rawReceipt,
      "acquire_session",
      localCheckpoint,
    );
    this.#transaction(() => {
      this.#storeCheckpoint({
        receipt,
        active_session_id: sessionId,
        state: "active",
      });
      this.#appendEvent({
        event_type: "session_acquired",
        recorded_at_ms: now,
        payload: {
          session_id_sha256: sha256Canonical(sessionId),
          anchor_receipt_sha256: sha256Canonical(receipt),
        },
      });
    });
  }

  importAuthorization(input: {
    signed_consent: unknown;
    runtime_manifest: unknown;
  }) {
    this.#verifyCurrentState();
    if (this.#state() !== "active") {
      throw new AuthorityError("authority_not_active");
    }
    const now = this.#now();
    const signedConsent = verifyLiveConsent(
      this.#consentPublicKey,
      input.signed_consent,
    );
    const consent = signedConsent.payload;
    const runtime = LiveRuntimeManifestSchema.parse(input.runtime_manifest);
    const fingerprint = sha256Canonical(signedConsent);
    const runtimeSha256 = sha256Canonical(runtime);
    if (now < consent.not_before_ms || now >= consent.expires_at_ms) {
      throw new AuthorityError("authority_consent_expired_or_not_yet_valid");
    }
    if (
      consent.runtime_manifest_sha256 !== runtimeSha256 ||
      consent.provider_id !== runtime.provider_id ||
      consent.anchor_realm_id !== this.anchorRealmId ||
      runtime.authority_registry_id !== this.registryId ||
      runtime.anchor_realm_id !== this.anchorRealmId ||
      runtime.anchor_key_id !== this.anchorKeyId ||
      consent.media_scopes.some(
        (scope) =>
          scope.preprocessing_config_sha256 !==
          runtime.preprocessing_config_sha256,
      )
    ) {
      throw new AuthorityError("authority_consent_runtime_binding_invalid");
    }
    try {
      this.#transaction(() => {
        if (
          this.#db.prepare(
            "SELECT authorization_id FROM authorizations WHERE authorization_id=? " +
              "OR authorization_fingerprint_sha256=?",
          ).get(consent.authorization_id, fingerprint)
        ) {
          throw new AuthorityError("authority_authorization_already_imported");
        }
        this.#db.prepare(
          "INSERT INTO authorizations VALUES(?,?,?,?,?,?,?,NULL)",
        ).run(
          consent.authorization_id,
          fingerprint,
          sha256Canonical(signedConsent),
          runtimeSha256,
          consent.expires_at_ms,
          consent.sanitized_record_delete_by_ms,
          "prepared",
        );
        const insertExecution = this.#db.prepare(
          "INSERT INTO executions VALUES(?,?,?,?,?)",
        );
        const insertSlot = this.#db.prepare(
          "INSERT INTO call_slots(slot_key_sha256,authorization_id,execution_id,slot,ordinal,state) " +
            "VALUES(?,?,?,?,?,'allocated')",
        );
        consent.authorized_executions.forEach((execution, position) => {
          insertExecution.run(
            execution.execution_id,
            consent.authorization_id,
            position + 1,
            execution.media_scope_id,
            execution.pair_commitment_hmac_sha256,
          );
          LIVE_CALL_SLOTS.forEach((slot, slotIndex) => {
            insertSlot.run(
              computeLiveSlotKey({
                authorization_id: consent.authorization_id,
                execution_id: execution.execution_id,
                slot,
              }),
              consent.authorization_id,
              execution.execution_id,
              slot,
              slotIndex + 1,
            );
          });
        });
        this.#appendEvent({
          event_type: "authorization_prepared",
          authorization_id: consent.authorization_id,
          recorded_at_ms: now,
          payload: {
            authorization_fingerprint_sha256: fingerprint,
            execution_count: consent.max_executions,
            call_cap: consent.max_provider_calls,
          },
        });
      });
    } catch (error) {
      if (error instanceof AuthorityError) throw error;
      throw new AuthorityError("authority_local_authorization_prepare_failed");
    }
    const checkpoint = this.#checkpoint();
    const anchorClaim = {
      authority_registry_id: this.registryId,
      expected_checkpoint: checkpoint,
      session_id: checkpoint.active_session_id!,
      fencing_token: checkpoint.fencing_token,
      authorization_id: consent.authorization_id,
      authorization_fingerprint_sha256: fingerprint,
      signed_consent_sha256: sha256Canonical(signedConsent),
      runtime_manifest_sha256: runtimeSha256,
      expires_at_ms: consent.expires_at_ms,
      executions: consent.authorized_executions.map((execution) => ({
        execution_id: execution.execution_id,
        media_scope_id: execution.media_scope_id,
        pair_commitment_hmac_sha256:
          execution.pair_commitment_hmac_sha256,
      })),
      recorded_at_ms: now,
    };
    let rawReceipt;
    try {
      rawReceipt = this.#anchor.claimAuthorization(anchorClaim);
    } catch (error) {
      this.#transaction(() => {
        this.#db.prepare(
          "UPDATE authorizations SET state='review_required' WHERE authorization_id=?",
        ).run(consent.authorization_id);
        this.#appendEvent({
          event_type: "authorization_anchor_rejected",
          authorization_id: consent.authorization_id,
          recorded_at_ms: now,
          payload: {
            reason_code:
              error instanceof AnchorError ? error.code : "anchor_unknown_error",
          },
        });
        if (!(error instanceof AnchorError) || error.outcomeMayBeCommitted) {
          setMeta(this.#db, "authority_state", "quarantined");
        }
      });
      throw new AuthorityError("authority_anchor_authorization_claim_failed");
    }
    let receipt;
    try {
      receipt = this.#verifyReceipt(
        rawReceipt,
        "claim_authorization",
        checkpoint,
      );
      if (
        receipt.payload.object_key_sha256 !==
          computeAnchorAuthorizationClaimObjectSha256(anchorClaim) ||
        receipt.payload.session_id !== checkpoint.active_session_id
      ) {
        throw new AuthorityError(
          "authority_anchor_authorization_receipt_invalid",
        );
      }
    } catch {
      this.#quarantine(now, "authorization_anchor_receipt_invalid");
      throw new AuthorityError("authority_anchor_authorization_receipt_invalid");
    }
    try {
      this.#transaction(() => {
        this.#storeCheckpoint({
          receipt,
          active_session_id: checkpoint.active_session_id,
        });
        this.#db.prepare(
          "UPDATE authorizations SET state='active',anchor_receipt_json=? WHERE authorization_id=?",
        ).run(canonicalJson(receipt), consent.authorization_id);
        this.#appendEvent({
          event_type: "authorization_activated",
          authorization_id: consent.authorization_id,
          recorded_at_ms: now,
          payload: { anchor_receipt_sha256: sha256Canonical(receipt) },
        });
      });
    } catch {
      this.#quarantine(now, "anchor_claimed_local_activation_failed");
      throw new AuthorityError(
        "authority_local_authorization_activation_failed",
      );
    }
    return {
      authorization_id: consent.authorization_id,
      authorization_fingerprint_sha256: fingerprint,
      max_executions: consent.max_executions,
      max_provider_calls: consent.max_provider_calls,
    };
  }

  prepareDispatch(input: {
    request_envelope: OfflineCanonicalRequestEnvelope;
    operation_id: string;
  }): LiveDispatchIntent {
    this.#verifyCurrentState();
    if (this.#state() !== "active") {
      throw new AuthorityError("authority_not_active");
    }
    const now = this.#now();
    let canonicalRequest;
    try {
      canonicalRequest = inspectOfflineCanonicalRequest(
        input.request_envelope,
      );
    } catch {
      throw new AuthorityError("authority_request_envelope_invalid");
    }
    const plan = canonicalRequest.execution_plan;
    const runtime = canonicalRequest.runtime_manifest;
    const slot = canonicalRequest.slot;
    const requestSha256 = sha256Bytes(canonicalRequest.request_bytes);
    let mediaPairCommitment: string;
    try {
      mediaPairCommitment = computeMediaPairCommitment(
        this.#authoritySecret,
        {
          before_bytes: canonicalRequest.before_bytes,
          after_bytes: canonicalRequest.after_bytes,
          preprocessing_config_sha256:
            runtime.preprocessing_config_sha256,
        },
      );
    } finally {
      canonicalRequest.before_bytes.fill(0);
      canonicalRequest.after_bytes.fill(0);
      canonicalRequest.request_bytes.fill(0);
    }
    if (!/^op_[a-f0-9]{64}$/.test(input.operation_id)) {
      throw new AuthorityError("authority_operation_id_invalid");
    }
    const authorization = this.#db.prepare(
      "SELECT authorization_fingerprint_sha256,signed_consent_sha256,runtime_manifest_sha256," +
        "expires_at_ms,state FROM authorizations WHERE authorization_id=?",
    ).get(plan.authorization_id) as
      | {
          authorization_fingerprint_sha256: string;
          signed_consent_sha256: string;
          runtime_manifest_sha256: string;
          expires_at_ms: number;
          state: string;
        }
      | undefined;
    if (!authorization || authorization.state !== "active") {
      throw new AuthorityError("authority_authorization_not_active");
    }
    const execution = this.#db.prepare(
      "SELECT authorization_id,media_scope_id,pair_commitment_hmac_sha256 " +
        "FROM executions WHERE execution_id=?",
    ).get(plan.execution_id) as
      | {
          authorization_id: string;
          media_scope_id: string;
          pair_commitment_hmac_sha256: string;
        }
      | undefined;

    const runtimeSha256 = sha256Canonical(runtime);
    if (
      plan.authority_registry_id !== this.registryId ||
      plan.anchor_realm_id !== this.anchorRealmId ||
      plan.authorization_fingerprint_sha256 !==
        authorization.authorization_fingerprint_sha256 ||
      plan.signed_consent_sha256 !== authorization.signed_consent_sha256 ||
      plan.runtime_manifest_sha256 !== authorization.runtime_manifest_sha256 ||
      runtimeSha256 !== authorization.runtime_manifest_sha256 ||
      runtime.authority_registry_id !== this.registryId ||
      runtime.anchor_realm_id !== this.anchorRealmId ||
      !execution ||
      execution.authorization_id !== plan.authorization_id ||
      execution.media_scope_id !== plan.media_scope_id ||
      execution.pair_commitment_hmac_sha256 !==
        plan.pair_commitment_hmac_sha256 ||
      mediaPairCommitment !== execution.pair_commitment_hmac_sha256
    ) {
      throw new AuthorityError("authority_execution_plan_binding_invalid");
    }
    if (
      now < plan.created_at_ms ||
      now >= plan.expires_at_ms ||
      plan.expires_at_ms !== authorization.expires_at_ms
    ) {
      throw new AuthorityError("authority_execution_plan_expired");
    }
    const ordinal = LIVE_CALL_SLOTS.indexOf(slot) + 1;
    const requestCommitment = hmacSha256Canonical(
      this.#authoritySecret,
      REQUEST_DOMAIN,
      {
        request_sha256: requestSha256,
        media_pair_commitment_hmac_sha256: mediaPairCommitment,
        runtime_manifest_sha256: runtimeSha256,
        execution_id: plan.execution_id,
        slot,
      },
    );
    const intent = LiveDispatchIntentSchema.parse({
      schema_version: "checkback.live-shadow.dispatch-intent.v1",
      authority_registry_id: this.registryId,
      anchor_realm_id: this.anchorRealmId,
      authorization_id: plan.authorization_id,
      authorization_fingerprint_sha256:
        plan.authorization_fingerprint_sha256,
      execution_id: plan.execution_id,
      media_scope_id: plan.media_scope_id,
      pair_commitment_hmac_sha256: mediaPairCommitment,
      slot,
      ordinal,
      operation_id: input.operation_id,
      request_commitment_hmac_sha256: requestCommitment,
      runtime_manifest_sha256: runtimeSha256,
      created_at_ms: now,
      expires_at_ms: plan.expires_at_ms,
    });
    const intentSha256 = sha256Canonical(intent);
    this.#transaction(() => {
      const row = this.#slot(plan.execution_id, slot);
      if (
        row.authorization_id !== plan.authorization_id ||
        row.state !== "allocated"
      ) {
        throw new AuthorityError("authority_slot_not_available");
      }
      const incompletePrior = this.#db.prepare(
        "SELECT COUNT(*) AS count FROM call_slots WHERE execution_id=? " +
          "AND ordinal<? AND state<>'result'",
      ).get(plan.execution_id, ordinal) as { count: number };
      if (incompletePrior.count !== 0) {
        throw new AuthorityError("authority_slot_order_invalid");
      }
      this.#db.prepare(
        "UPDATE call_slots SET state='prepared',operation_id=?,dispatch_intent_sha256=?," +
          "request_commitment_hmac_sha256=?,prepared_at_ms=? WHERE slot_key_sha256=?",
      ).run(
        input.operation_id,
        intentSha256,
        requestCommitment,
        now,
        row.slot_key_sha256,
      );
      this.#appendEvent({
        event_type: "dispatch_prepared",
        authorization_id: plan.authorization_id,
        execution_id: plan.execution_id,
        slot,
        recorded_at_ms: now,
        payload: {
          operation_id_sha256: sha256Canonical(input.operation_id),
          dispatch_intent_sha256: intentSha256,
          request_commitment_hmac_sha256: requestCommitment,
        },
      });
    });
    return intent;
  }

  burnDispatch(intentInput: unknown): object {
    this.#verifyCurrentState();
    if (this.#state() !== "active") {
      throw new AuthorityError("authority_not_active");
    }
    const now = this.#now();
    const intent = LiveDispatchIntentSchema.parse(intentInput);
    if (now < intent.created_at_ms || now >= intent.expires_at_ms) {
      throw new AuthorityError("authority_dispatch_intent_expired");
    }
    const row = this.#slot(intent.execution_id, intent.slot);
    const intentSha256 = sha256Canonical(intent);
    if (
      row.state !== "prepared" ||
      row.operation_id !== intent.operation_id ||
      row.dispatch_intent_sha256 !== intentSha256 ||
      row.request_commitment_hmac_sha256 !==
        intent.request_commitment_hmac_sha256
    ) {
      throw new AuthorityError("authority_dispatch_intent_mismatch");
    }
    const checkpoint = this.#checkpoint();
    let rawReceipt;
    try {
      rawReceipt = this.#anchor.consumeSlot({
        authority_registry_id: this.registryId,
        expected_checkpoint: checkpoint,
        session_id: checkpoint.active_session_id!,
        fencing_token: checkpoint.fencing_token,
        intent,
        recorded_at_ms: now,
      });
    } catch (error) {
      this.#transaction(() => {
        this.#db.prepare(
          "UPDATE call_slots SET state='anchor_ambiguous',completed_at_ms=? WHERE slot_key_sha256=?",
        ).run(now, row.slot_key_sha256);
        setMeta(this.#db, "authority_state", "quarantined");
        this.#appendEvent({
          event_type: "dispatch_anchor_ambiguous",
          authorization_id: intent.authorization_id,
          execution_id: intent.execution_id,
          slot: intent.slot,
          recorded_at_ms: now,
          payload: {
            reason_code:
              error instanceof AnchorError ? error.code : "anchor_unknown_error",
          },
        });
      });
      throw new AuthorityError("authority_anchor_slot_consume_failed");
    }
    let receipt;
    try {
      receipt = this.#verifyReceipt(rawReceipt, "consume_slot", checkpoint);
      if (
        receipt.payload.object_key_sha256 !== sha256Canonical(intent) ||
        receipt.payload.session_id !== checkpoint.active_session_id
      ) {
        throw new AuthorityError("authority_anchor_slot_receipt_invalid");
      }
    } catch {
      this.#transaction(() => {
        this.#db.prepare(
          "UPDATE call_slots SET state='anchor_ambiguous',completed_at_ms=? WHERE slot_key_sha256=?",
        ).run(now, row.slot_key_sha256);
        setMeta(this.#db, "authority_state", "quarantined");
        this.#appendEvent({
          event_type: "dispatch_anchor_receipt_invalid",
          authorization_id: intent.authorization_id,
          execution_id: intent.execution_id,
          slot: intent.slot,
          recorded_at_ms: now,
        });
      });
      throw new AuthorityError("authority_anchor_slot_receipt_invalid");
    }
    try {
      this.#transaction(() => {
        this.#storeCheckpoint({
          receipt,
          active_session_id: checkpoint.active_session_id,
        });
        this.#db.prepare(
          "UPDATE call_slots SET state='dispatching',anchor_receipt_json=?,dispatched_at_ms=? " +
            "WHERE slot_key_sha256=?",
        ).run(canonicalJson(receipt), now, row.slot_key_sha256);
        this.#appendEvent({
          event_type: "dispatch_capability_issued",
          authorization_id: intent.authorization_id,
          execution_id: intent.execution_id,
          slot: intent.slot,
          recorded_at_ms: now,
          payload: { anchor_receipt_sha256: sha256Canonical(receipt) },
        });
      });
    } catch {
      this.#quarantine(now, "anchor_consumed_local_persist_failed");
      throw new AuthorityError("authority_dispatch_persist_failed");
    }
    const capability = Object.freeze({});
    DISPATCH_PERMITS.set(capability, {
      registry_id: this.registryId,
      operation_id: intent.operation_id,
      intent_sha256: intentSha256,
      used: false,
    });
    return capability;
  }

  completeDispatch(input: {
    capability: object;
    outcome: "success" | "request_error" | "timeout" | "invalid_output";
    result_bytes: Uint8Array;
  }) {
    this.#verifyCurrentState();
    if (this.#state() !== "active") {
      throw new AuthorityError("authority_not_active");
    }
    const permit = DISPATCH_PERMITS.get(input.capability);
    if (!permit || permit.registry_id !== this.registryId || permit.used) {
      throw new AuthorityError("authority_dispatch_capability_invalid");
    }
    if (!TERMINAL_OUTCOMES.has(input.outcome)) {
      throw new AuthorityError("authority_dispatch_outcome_invalid");
    }
    if (
      !(input.result_bytes instanceof Uint8Array) ||
      input.result_bytes.byteLength > 16 * 1024 * 1024
    ) {
      throw new AuthorityError("authority_result_bytes_invalid");
    }
    const now = this.#now();
    const row = this.#db.prepare(
      "SELECT slot_key_sha256,authorization_id,execution_id,slot,state,operation_id," +
        "dispatch_intent_sha256 FROM call_slots WHERE operation_id=?",
    ).get(permit.operation_id) as
      | (SlotRow & { dispatch_intent_sha256: string | null })
      | undefined;
    if (
      !row ||
      row.state !== "dispatching" ||
      row.dispatch_intent_sha256 !== permit.intent_sha256
    ) {
      throw new AuthorityError("authority_dispatch_state_invalid");
    }
    permit.used = true;
    try {
      const resultCommitment = hmacSha256Bytes(
        this.#authoritySecret,
        RESULT_DOMAIN,
        input.result_bytes,
      );
      this.#transaction(() => {
        this.#db.prepare(
          "UPDATE call_slots SET state='result',outcome=?,result_commitment_hmac_sha256=?," +
            "completed_at_ms=? WHERE slot_key_sha256=?",
        ).run(input.outcome, resultCommitment, now, row.slot_key_sha256);
        this.#appendEvent({
          event_type: "dispatch_result_recorded",
          authorization_id: row.authorization_id,
          execution_id: row.execution_id,
          slot: row.slot,
          recorded_at_ms: now,
          payload: {
            outcome: input.outcome,
            result_commitment_hmac_sha256: resultCommitment,
          },
        });
      });
      return {
        outcome: input.outcome,
        result_commitment_hmac_sha256: resultCommitment,
      };
    } catch {
      this.#quarantine(now, "dispatch_result_persist_failed");
      throw new AuthorityError("authority_result_persist_failed");
    }
  }

  #slot(executionId: string, slot: LiveCallSlot): SlotRow {
    const row = this.#db.prepare(
      "SELECT slot_key_sha256,authorization_id,execution_id,slot,ordinal,state,operation_id," +
        "dispatch_intent_sha256,request_commitment_hmac_sha256 FROM call_slots " +
        "WHERE execution_id=? AND slot=?",
    ).get(executionId, slot) as SlotRow | undefined;
    if (!row) throw new AuthorityError("authority_slot_not_found");
    return row;
  }

  #quarantine(now: number, reasonCode: string) {
    try {
      this.#transaction(() => {
        setMeta(this.#db, "authority_state", "quarantined");
        this.#appendEvent({
          event_type: "authority_quarantined",
          recorded_at_ms: now,
          payload: { reason_code: reasonCode },
        });
      });
    } catch {
      this.#fatal = true;
    }
  }

  status() {
    this.#verifyCurrentState();
    const checkpoint = this.#checkpoint();
    const counts = this.#db.prepare(
      "SELECT state,COUNT(*) AS count FROM call_slots GROUP BY state ORDER BY state",
    ).all() as { state: SlotState; count: number }[];
    return Object.freeze({
      mode: "offline_local_stub" as const,
      registry_id: this.registryId,
      authority_state: this.#state(),
      checkpoint: Object.freeze({ ...checkpoint }),
      slot_counts: Object.freeze(
        Object.fromEntries(counts.map((item) => [item.state, item.count])),
      ),
    });
  }

  slotState(executionId: string, slotInput: unknown): SlotState {
    this.#verifyCurrentState();
    const slot = LiveCallSlotSchema.parse(slotInput);
    return this.#slot(executionId, slot).state;
  }

  close() {
    if (this.#closed) return;
    try {
      this.#verifyCurrentState();
      const now = this.#now();
    const state = this.#state();
    if (state === "active") {
      const inflight = this.#db.prepare(
        "SELECT COUNT(*) AS count FROM call_slots WHERE state='dispatching'",
      ).get() as { count: number };
      if (inflight.count > 0) {
        this.#transaction(() => {
          this.#db.prepare(
            "UPDATE call_slots SET state='unknown_after_crash',completed_at_ms=? " +
              "WHERE state='dispatching'",
          ).run(now);
          setMeta(this.#db, "authority_state", "quarantined");
          this.#appendEvent({
            event_type: "inflight_dispatch_quarantined",
            recorded_at_ms: now,
            payload: { count: inflight.count },
          });
        });
      } else {
        this.#transaction(() => {
          this.#db.prepare(
            "UPDATE call_slots SET state='abandoned_before_anchor',completed_at_ms=? " +
              "WHERE state='prepared'",
          ).run(now);
        });
        const checkpoint = this.#checkpoint();
        let rawReceipt;
        try {
          rawReceipt = this.#anchor.releaseSession({
            authority_registry_id: this.registryId,
            expected_checkpoint: checkpoint,
            session_id: checkpoint.active_session_id!,
            recorded_at_ms: now,
          });
          const receipt = this.#verifyReceipt(
            rawReceipt,
            "release_session",
            checkpoint,
          );
          this.#transaction(() => {
            this.#storeCheckpoint({
              receipt,
              active_session_id: null,
              state: "ready",
            });
            this.#appendEvent({
              event_type: "session_released",
              recorded_at_ms: now,
              payload: { anchor_receipt_sha256: sha256Canonical(receipt) },
            });
          });
        } catch {
          this.#quarantine(now, "anchor_session_release_failed");
        }
      }
    }
    } finally {
      this.#forceClose();
    }
  }

  #forceClose() {
    if (this.#closed) return;
    try {
      this.#db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    } catch {}
    try {
      this.#db.close();
    } catch {
    } finally {
      this.#closed = true;
      this.#authoritySecret.fill(0);
    }
  }
}
