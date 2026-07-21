import { timingSafeEqual } from "node:crypto";
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
  hmacSha256Bytes,
  hmacSha256Canonical,
  sha256Bytes,
  sha256Canonical,
} from "../live-shadow/crypto.ts";
import {
  VaultObjectBindingSchema,
  vaultAadSha256,
  type VaultDeletionReason,
  type VaultObjectBinding,
} from "./vault-contracts.ts";
import {
  RetentionVaultCheckpointSchema,
  RetentionVaultProfileSchema,
  type RetentionVaultCheckpoint,
  type RetentionVaultProfile,
} from "./retention-vault-contracts.ts";

const SCHEMA_VERSION = "checkback.live-shadow.retention-vault-store.v1";
const APPLICATION_ID = 0x43425256;
const USER_VERSION = 1;
const ZERO_HASH = "0".repeat(64);
const SQLITE_HEADER = Buffer.from("SQLite format 3\0", "binary");
const IDENTITY_DOMAIN = "checkback.live-shadow.retention-vault.identity.v1";
const PROJECTION_DOMAIN = "checkback.live-shadow.retention-vault.projection.v1";
const AUDIT_DOMAIN = "checkback.live-shadow.retention-vault.audit.v1";
const CHECKPOINT_DOMAIN = "checkback.live-shadow.retention-vault.checkpoint.v1";
const KEY_MATERIAL_DOMAIN = "checkback.live-shadow.retention-vault.key-material.v1";

export type RetentionVaultObjectState =
  | "staging"
  | "sealed"
  | "deleting"
  | "key_reference_removed"
  | "tombstoned";

export interface RetentionVaultObjectRow {
  object_id: string;
  object_key_id: string;
  seal_ticket_id: string;
  seal_ticket_sha256: string;
  pair_ticket_id: string;
  reservation_key: string;
  state: RetentionVaultObjectState;
  binding_json: string;
  binding_sha256: string;
  aad_sha256: string;
  nonce_base64: string;
  nonce_sha256: string;
  authentication_tag_base64: string;
  ciphertext_sha256: string;
  ciphertext_length: number;
  plaintext_hmac_sha256: string;
  key_material: Uint8Array | null;
  key_material_hmac_sha256: string | null;
  created_at_ms: number;
  delete_by_ms: number;
  deletion_reason: VaultDeletionReason | null;
  deletion_requested_at_ms: number | null;
  deletion_intent_sha256: string | null;
  key_reference_removed_at_ms: number | null;
  tombstoned_at_ms: number | null;
  tombstone_receipt_json: string | null;
}

const SCHEMA_STATEMENTS = [
  "CREATE TABLE retention_vault_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
  "CREATE TABLE retention_vault_objects(" +
    "object_id TEXT PRIMARY KEY,object_key_id TEXT NOT NULL UNIQUE," +
    "seal_ticket_id TEXT NOT NULL UNIQUE,seal_ticket_sha256 TEXT NOT NULL UNIQUE," +
    "pair_ticket_id TEXT NOT NULL,reservation_key TEXT NOT NULL UNIQUE," +
    "state TEXT NOT NULL CHECK(state IN ('staging','sealed','deleting','key_reference_removed','tombstoned'))," +
    "binding_json TEXT NOT NULL,binding_sha256 TEXT NOT NULL,aad_sha256 TEXT NOT NULL," +
    "nonce_base64 TEXT NOT NULL,nonce_sha256 TEXT NOT NULL UNIQUE," +
    "authentication_tag_base64 TEXT NOT NULL,ciphertext_sha256 TEXT NOT NULL," +
    "ciphertext_length INTEGER NOT NULL,plaintext_hmac_sha256 TEXT NOT NULL," +
    "key_material BLOB,key_material_hmac_sha256 TEXT," +
    "created_at_ms INTEGER NOT NULL,delete_by_ms INTEGER NOT NULL," +
    "deletion_reason TEXT,deletion_requested_at_ms INTEGER,deletion_intent_sha256 TEXT," +
    "key_reference_removed_at_ms INTEGER,tombstoned_at_ms INTEGER," +
    "tombstone_receipt_json TEXT)",
  "CREATE TRIGGER retention_vault_objects_no_terminal_delete BEFORE DELETE ON retention_vault_objects " +
    "WHEN OLD.state<>'staging' BEGIN SELECT RAISE(ABORT,'retention vault terminal rows are append only'); END",
  "CREATE TABLE retention_vault_events(" +
    "sequence INTEGER PRIMARY KEY,previous_event_hmac_sha256 TEXT NOT NULL," +
    "event_type TEXT NOT NULL,object_id TEXT,recorded_at_ms INTEGER NOT NULL," +
    "payload_json TEXT NOT NULL,event_hmac_sha256 TEXT NOT NULL)",
  "CREATE TRIGGER retention_vault_events_no_update BEFORE UPDATE ON retention_vault_events " +
    "BEGIN SELECT RAISE(ABORT,'retention vault events are append only'); END",
  "CREATE TRIGGER retention_vault_events_no_delete BEFORE DELETE ON retention_vault_events " +
    "BEGIN SELECT RAISE(ABORT,'retention vault events are append only'); END",
] as const;

const SCHEMA_SHA256 = sha256Canonical(SCHEMA_STATEMENTS);
const IDENTITY_KEYS = [
  "schema_version",
  "schema_sha256",
  "physical_schema_sha256",
  "custody_id",
  "object_store_id",
  "authority_key_id",
  "receipt_key_id",
  "vault_build_sha256",
  "ledger_key_id",
] as const;
const META_KEYS = new Set([
  ...IDENTITY_KEYS,
  "identity_hmac_sha256",
  "audit_sequence",
  "audit_head_hmac_sha256",
  "clock_watermark_ms",
  "projection_hmac_sha256",
]);

export class RetentionVaultPersistenceError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "RetentionVaultPersistenceError";
    this.code = code;
  }
}

function requirePersistentPath(path: string) {
  if (!path || path === ":memory:") {
    throw new RetentionVaultPersistenceError(
      "retention_vault_persistent_database_path_required",
    );
  }
}

function validateSecret(secret: Uint8Array) {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 32) {
    throw new RetentionVaultPersistenceError(
      "retention_vault_ledger_secret_too_short",
    );
  }
}

function assertExistingSqliteFile(path: string) {
  requirePersistentPath(path);
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    throw new RetentionVaultPersistenceError("retention_vault_database_missing");
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0) {
    throw new RetentionVaultPersistenceError(
      "retention_vault_database_path_invalid",
    );
  }
  const descriptor = openSync(
    path,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
  );
  try {
    const header = Buffer.alloc(SQLITE_HEADER.length);
    const bytesRead = readSync(descriptor, header, 0, header.length, 0);
    if (bytesRead !== header.length || !header.equals(SQLITE_HEADER)) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_database_header_invalid",
      );
    }
  } finally {
    closeSync(descriptor);
  }
}

function configure(db: DatabaseSync) {
  db.exec("PRAGMA journal_mode=WAL");
  db.exec("PRAGMA synchronous=FULL");
  db.exec("PRAGMA foreign_keys=ON");
  db.exec("PRAGMA secure_delete=ON");
  db.exec("PRAGMA temp_store=MEMORY");
  db.exec("PRAGMA busy_timeout=10000");
}

function schemaFingerprint(db: DatabaseSync): string {
  return sha256Canonical(
    db.prepare(
      "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
    ).all(),
  );
}

function readMeta(db: DatabaseSync): Record<string, string> {
  const rows = db.prepare(
    "SELECT key,value FROM retention_vault_meta",
  ).all() as Array<{ key: string; value: string }>;
  return Object.fromEntries(rows.map((row) => [row.key, row.value]));
}

function parseInteger(meta: Record<string, string>, key: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(meta[key] ?? "")) {
    throw new RetentionVaultPersistenceError("retention_vault_meta_invalid");
  }
  const value = Number(meta[key]);
  if (!Number.isSafeInteger(value)) {
    throw new RetentionVaultPersistenceError("retention_vault_meta_invalid");
  }
  return value;
}

function setMeta(db: DatabaseSync, key: string, value: string | number) {
  const result = db.prepare(
    "UPDATE retention_vault_meta SET value=? WHERE key=?",
  ).run(String(value), key);
  if (result.changes !== 1) {
    throw new RetentionVaultPersistenceError("retention_vault_meta_missing");
  }
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

function ledgerKeyId(secret: Uint8Array): string {
  const domain = Buffer.from(
    "checkback.live-shadow.retention-vault-ledger-key.v1\0",
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

function identityObject(meta: Record<string, string>) {
  return Object.fromEntries(IDENTITY_KEYS.map((key) => [key, meta[key]]));
}

function keyMaterialHmac(secret: Uint8Array, keyMaterial: Uint8Array): string {
  return hmacSha256Bytes(secret, KEY_MATERIAL_DOMAIN, keyMaterial);
}

function objectProjectionRows(db: DatabaseSync) {
  return db.prepare(
    "SELECT object_id,object_key_id,seal_ticket_id,seal_ticket_sha256,pair_ticket_id," +
      "reservation_key,state,binding_json,binding_sha256,aad_sha256,nonce_base64," +
      "nonce_sha256,authentication_tag_base64,ciphertext_sha256,ciphertext_length," +
      "plaintext_hmac_sha256,key_material_hmac_sha256,created_at_ms,delete_by_ms," +
      "deletion_reason,deletion_requested_at_ms,deletion_intent_sha256," +
      "key_reference_removed_at_ms,tombstoned_at_ms,tombstone_receipt_json " +
      "FROM retention_vault_objects ORDER BY object_id",
  ).all();
}

function computeProjectionHmac(db: DatabaseSync, secret: Uint8Array): string {
  return hmacSha256Canonical(secret, PROJECTION_DOMAIN, {
    meta: db.prepare(
      "SELECT key,value FROM retention_vault_meta WHERE key<>'projection_hmac_sha256' ORDER BY key",
    ).all(),
    objects: objectProjectionRows(db),
    events: db.prepare(
      "SELECT * FROM retention_vault_events ORDER BY sequence",
    ).all(),
  });
}

function appendEvent(
  db: DatabaseSync,
  secret: Uint8Array,
  input: {
    event_type: string;
    object_id: string | null;
    recorded_at_ms: number;
    payload: unknown;
  },
) {
  const meta = readMeta(db);
  const sequence = parseInteger(meta, "audit_sequence") + 1;
  const previous = meta.audit_head_hmac_sha256;
  if (!/^[a-f0-9]{64}$/.test(previous)) {
    throw new RetentionVaultPersistenceError(
      "retention_vault_audit_head_invalid",
    );
  }
  const payloadJson = canonicalJson(input.payload);
  const event = {
    sequence,
    previous_event_hmac_sha256: previous,
    event_type: input.event_type,
    object_id: input.object_id,
    recorded_at_ms: input.recorded_at_ms,
    payload_json: payloadJson,
  };
  const eventHmac = hmacSha256Canonical(secret, AUDIT_DOMAIN, event);
  db.prepare(
    "INSERT INTO retention_vault_events(" +
      "sequence,previous_event_hmac_sha256,event_type,object_id,recorded_at_ms," +
      "payload_json,event_hmac_sha256) VALUES(?,?,?,?,?,?,?)",
  ).run(
    sequence,
    previous,
    input.event_type,
    input.object_id,
    input.recorded_at_ms,
    payloadJson,
    eventHmac,
  );
  setMeta(db, "audit_sequence", sequence);
  setMeta(db, "audit_head_hmac_sha256", eventHmac);
}

function cloneRow(value: unknown): RetentionVaultObjectRow {
  const row = value as RetentionVaultObjectRow;
  return {
    ...row,
    key_material:
      row.key_material === null ? null : Buffer.from(row.key_material),
  };
}

function parseCanonicalBinding(row: RetentionVaultObjectRow): VaultObjectBinding {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.binding_json);
  } catch {
    throw new RetentionVaultPersistenceError(
      "retention_vault_binding_json_invalid",
    );
  }
  const binding = VaultObjectBindingSchema.parse(parsed);
  if (
    canonicalJson(binding) !== row.binding_json ||
    row.binding_sha256 !== sha256Canonical(binding) ||
    row.aad_sha256 !== vaultAadSha256(binding) ||
    row.ciphertext_length !== binding.plaintext_length ||
    row.delete_by_ms !== binding.delete_by_ms
  ) {
    throw new RetentionVaultPersistenceError(
      "retention_vault_binding_record_invalid",
    );
  }
  return binding;
}

export function retentionVaultReservationKey(binding: VaultObjectBinding): string {
  return sha256Canonical({
    authorization_fingerprint_sha256:
      binding.authorization_fingerprint_sha256,
    execution_id: binding.execution_id,
    media_scope_id: binding.media_scope_id,
    pair_commitment_hmac_sha256: binding.pair_commitment_hmac_sha256,
    preprocessing_config_sha256: binding.preprocessing_config_sha256,
    part: binding.part,
  });
}

export function retentionVaultPlaintextHmac(
  secret: Uint8Array,
  plaintext: Uint8Array,
): string {
  return hmacSha256Bytes(
    secret,
    "checkback.live-shadow.retention-vault.plaintext.v1",
    plaintext,
  );
}

export class RetentionVaultSqliteStore {
  readonly profile: RetentionVaultProfile;
  #db: DatabaseSync;
  #secret: Buffer;
  #clock: () => number;
  #expectedPhysicalSchemaSha256 = "";
  #closed = false;

  private constructor(input: {
    database_path: string;
    ledger_secret: Uint8Array;
    profile: RetentionVaultProfile;
    now?: () => number;
    minimum_checkpoint?: RetentionVaultCheckpoint;
  }) {
    validateSecret(input.ledger_secret);
    this.profile = RetentionVaultProfileSchema.parse(input.profile);
    this.#secret = Buffer.from(input.ledger_secret);
    this.#clock = input.now ?? Date.now;
    this.#db = new DatabaseSync(input.database_path, { readOnly: false });
    try {
      configure(this.#db);
      this.read(() => {
        if (input.minimum_checkpoint) {
          this.#verifyMinimumCheckpoint(input.minimum_checkpoint);
        }
      });
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
    profile: RetentionVaultProfile;
    now?: () => number;
  }): void {
    requirePersistentPath(input.database_path);
    validateSecret(input.ledger_secret);
    const profile = RetentionVaultProfileSchema.parse(input.profile);
    let descriptor: number;
    try {
      descriptor = openSync(
        input.database_path,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
        0o600,
      );
    } catch {
      throw new RetentionVaultPersistenceError(
        "retention_vault_database_already_exists",
      );
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
        ...profile,
        ledger_key_id: ledgerKeyId(secret),
      };
      const identityHmac = hmacSha256Canonical(
        secret,
        IDENTITY_DOMAIN,
        identity,
      );
      const insert = db.prepare(
        "INSERT INTO retention_vault_meta(key,value) VALUES(?,?)",
      );
      for (const [key, value] of Object.entries(identity)) {
        insert.run(key, value);
      }
      insert.run("identity_hmac_sha256", identityHmac);
      insert.run("audit_sequence", "0");
      insert.run("audit_head_hmac_sha256", ZERO_HASH);
      insert.run("projection_hmac_sha256", ZERO_HASH);
      const now = input.now?.() ?? Date.now();
      if (!Number.isSafeInteger(now) || now < 0) {
        throw new RetentionVaultPersistenceError(
          "retention_vault_clock_invalid",
        );
      }
      insert.run("clock_watermark_ms", String(now));
      appendEvent(db, secret, {
        event_type: "retention_vault_initialized",
        object_id: null,
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
    profile: RetentionVaultProfile;
    now?: () => number;
    minimum_checkpoint?: RetentionVaultCheckpoint;
  }): RetentionVaultSqliteStore {
    assertExistingSqliteFile(input.database_path);
    return new RetentionVaultSqliteStore(input);
  }

  get secretForInternalUse(): Uint8Array {
    this.#assertOpen();
    return this.#secret;
  }

  recordOpened(): void {
    this.mutate(
      {
        type: "retention_vault_opened",
        object_id: null,
        payload: () => ({ custody_id: this.profile.custody_id }),
      },
      () => undefined,
    );
  }

  mutate<T>(
    event: {
      type: string | ((result: T) => string);
      object_id: string | null;
      payload: (result: T) => unknown;
    },
    callback: (db: DatabaseSync, now: number) => T,
  ): T {
    this.#assertOpen();
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const meta = this.#verifyAll();
      const now = this.#advanceClock(meta);
      const result = callback(this.#db, now);
      appendEvent(this.#db, this.#secret, {
        event_type:
          typeof event.type === "function" ? event.type(result) : event.type,
        object_id: event.object_id,
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

  read<T>(callback: (db: DatabaseSync, meta: Record<string, string>) => T): T {
    this.#assertOpen();
    this.#db.exec("BEGIN");
    try {
      const meta = this.#verifyAll();
      const result = callback(this.#db, meta);
      this.#db.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }

  getObject(objectId: string): RetentionVaultObjectRow {
    return this.read((db) => {
      const value = db.prepare(
        "SELECT * FROM retention_vault_objects WHERE object_id=?",
      ).get(objectId);
      if (!value) {
        throw new RetentionVaultPersistenceError(
          "retention_vault_object_missing",
        );
      }
      return cloneRow(value);
    });
  }

  listObjects(): RetentionVaultObjectRow[] {
    return this.read((db) =>
      (db.prepare(
        "SELECT * FROM retention_vault_objects ORDER BY object_id",
      ).all() as unknown[]).map(cloneRow),
    );
  }

  checkpoint(): RetentionVaultCheckpoint {
    return this.read((_db, meta) => this.#checkpointFromMeta(meta));
  }

  close(): RetentionVaultCheckpoint | null {
    if (this.#closed) return null;
    let checkpoint: RetentionVaultCheckpoint | null = null;
    try {
      this.mutate(
        {
          type: "retention_vault_closed",
          object_id: null,
          payload: () => ({ custody_id: this.profile.custody_id }),
        },
        () => undefined,
      );
      checkpoint = this.checkpoint();
    } finally {
      this.#db.close();
      this.#closed = true;
      this.#secret.fill(0);
    }
    return checkpoint;
  }

  forceCloseForCrashTest(): void {
    if (!this.#closed) {
      this.#db.close();
      this.#closed = true;
      this.#secret.fill(0);
    }
  }

  #assertOpen() {
    if (this.#closed) {
      throw new RetentionVaultPersistenceError("retention_vault_store_closed");
    }
  }

  #now(): number {
    const value = this.#clock();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new RetentionVaultPersistenceError("retention_vault_clock_invalid");
    }
    return value;
  }

  #advanceClock(meta: Record<string, string>): number {
    const now = this.#now();
    const watermark = parseInteger(meta, "clock_watermark_ms");
    if (now < watermark) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_clock_rollback_detected",
      );
    }
    setMeta(this.#db, "clock_watermark_ms", now);
    return now;
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
      throw new RetentionVaultPersistenceError(
        "retention_vault_integrity_check_failed",
      );
    }
  }

  #verifyIdentity(): Record<string, string> {
    const meta = readMeta(this.#db);
    if (
      Object.keys(meta).length !== META_KEYS.size ||
      Object.keys(meta).some((key) => !META_KEYS.has(key))
    ) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_meta_shape_invalid",
      );
    }
    const expectedHmac = hmacSha256Canonical(
      this.#secret,
      IDENTITY_DOMAIN,
      identityObject(meta),
    );
    if (!secureHexEqual(meta.identity_hmac_sha256, expectedHmac)) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_identity_hmac_invalid",
      );
    }
    if (
      meta.schema_version !== SCHEMA_VERSION ||
      meta.schema_sha256 !== SCHEMA_SHA256 ||
      meta.custody_id !== this.profile.custody_id ||
      meta.object_store_id !== this.profile.object_store_id ||
      meta.authority_key_id !== this.profile.authority_key_id ||
      meta.receipt_key_id !== this.profile.receipt_key_id ||
      meta.vault_build_sha256 !== this.profile.vault_build_sha256 ||
      meta.ledger_key_id !== ledgerKeyId(this.#secret)
    ) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_identity_mismatch",
      );
    }
    if (!this.#expectedPhysicalSchemaSha256) {
      this.#expectedPhysicalSchemaSha256 = meta.physical_schema_sha256;
    }
    if (
      meta.physical_schema_sha256 !== this.#expectedPhysicalSchemaSha256 ||
      schemaFingerprint(this.#db) !== this.#expectedPhysicalSchemaSha256
    ) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_schema_mismatch",
      );
    }
    parseInteger(meta, "audit_sequence");
    parseInteger(meta, "clock_watermark_ms");
    return meta;
  }

  #verifyAudit(meta: Record<string, string>) {
    const rows = this.#db.prepare(
      "SELECT * FROM retention_vault_events ORDER BY sequence",
    ).all() as Array<{
      sequence: number;
      previous_event_hmac_sha256: string;
      event_type: string;
      object_id: string | null;
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
        throw new RetentionVaultPersistenceError(
          "retention_vault_audit_chain_invalid",
        );
      }
      let payload: unknown;
      try {
        payload = JSON.parse(row.payload_json);
      } catch {
        throw new RetentionVaultPersistenceError(
          "retention_vault_audit_payload_invalid",
        );
      }
      if (canonicalJson(payload) !== row.payload_json) {
        throw new RetentionVaultPersistenceError(
          "retention_vault_audit_payload_invalid",
        );
      }
      const expected = hmacSha256Canonical(this.#secret, AUDIT_DOMAIN, {
        sequence: row.sequence,
        previous_event_hmac_sha256: row.previous_event_hmac_sha256,
        event_type: row.event_type,
        object_id: row.object_id,
        recorded_at_ms: row.recorded_at_ms,
        payload_json: row.payload_json,
      });
      if (!secureHexEqual(row.event_hmac_sha256, expected)) {
        throw new RetentionVaultPersistenceError(
          "retention_vault_audit_hmac_invalid",
        );
      }
      previous = row.event_hmac_sha256;
    }
    if (
      sequence !== parseInteger(meta, "audit_sequence") ||
      previous !== meta.audit_head_hmac_sha256
    ) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_audit_head_invalid",
      );
    }
  }

  #verifyObjects() {
    const rows = this.#db.prepare(
      "SELECT * FROM retention_vault_objects ORDER BY object_id",
    ).all() as unknown[];
    for (const value of rows) {
      const row = cloneRow(value);
      try {
        if (
          !/^vaultobj_[a-f0-9]{64}$/.test(row.object_id) ||
          !/^vkey_[a-f0-9]{64}$/.test(row.object_key_id) ||
          !/^vaultticket_[a-f0-9]{64}$/.test(row.seal_ticket_id) ||
          !/^vaultpair_[a-f0-9]{64}$/.test(row.pair_ticket_id)
        ) {
          throw new RetentionVaultPersistenceError(
            "retention_vault_object_identifier_invalid",
          );
        }
        for (const hash of [
          row.seal_ticket_sha256,
          row.reservation_key,
          row.binding_sha256,
          row.aad_sha256,
          row.nonce_sha256,
          row.ciphertext_sha256,
          row.plaintext_hmac_sha256,
        ]) {
          if (!/^[a-f0-9]{64}$/.test(hash)) {
            throw new RetentionVaultPersistenceError(
              "retention_vault_object_hash_invalid",
            );
          }
        }
        const binding = parseCanonicalBinding(row);
        if (retentionVaultReservationKey(binding) !== row.reservation_key) {
          throw new RetentionVaultPersistenceError(
            "retention_vault_reservation_binding_invalid",
          );
        }
        const nonce = Buffer.from(row.nonce_base64, "base64");
        const tag = Buffer.from(row.authentication_tag_base64, "base64");
        try {
          if (
            nonce.byteLength !== 12 ||
            nonce.toString("base64") !== row.nonce_base64 ||
            sha256Bytes(nonce) !== row.nonce_sha256 ||
            tag.byteLength !== 16 ||
            tag.toString("base64") !== row.authentication_tag_base64 ||
            !Number.isSafeInteger(row.created_at_ms) ||
            !Number.isSafeInteger(row.delete_by_ms) ||
            row.created_at_ms < 0 ||
            row.created_at_ms >= row.delete_by_ms
          ) {
            throw new RetentionVaultPersistenceError(
              "retention_vault_crypto_metadata_invalid",
            );
          }
        } finally {
          nonce.fill(0);
          tag.fill(0);
        }
        const keyRequired =
          row.state === "staging" ||
          row.state === "sealed" ||
          row.state === "deleting";
        if (keyRequired) {
          if (
            row.key_material === null ||
            row.key_material.byteLength !== 32 ||
            row.key_material_hmac_sha256 === null ||
            !secureHexEqual(
              row.key_material_hmac_sha256,
              keyMaterialHmac(this.#secret, row.key_material),
            )
          ) {
            throw new RetentionVaultPersistenceError(
              "retention_vault_key_material_invalid",
            );
          }
        } else if (
          row.key_material !== null ||
          row.key_material_hmac_sha256 !== null
        ) {
          throw new RetentionVaultPersistenceError(
            "retention_vault_removed_key_reference_present",
          );
        }
        const deletionStarted =
          row.state === "deleting" ||
          row.state === "key_reference_removed" ||
          row.state === "tombstoned";
        if (
          deletionStarted !==
            (row.deletion_reason !== null &&
              row.deletion_requested_at_ms !== null &&
              row.deletion_intent_sha256 !== null) ||
          (row.state === "tombstoned") !==
            (row.tombstoned_at_ms !== null &&
              row.tombstone_receipt_json !== null) ||
          ((row.state === "key_reference_removed" ||
            row.state === "tombstoned") !==
            (row.key_reference_removed_at_ms !== null))
        ) {
          throw new RetentionVaultPersistenceError(
            "retention_vault_state_metadata_invalid",
          );
        }
      } finally {
        if (row.key_material !== null) row.key_material.fill(0);
      }
    }
  }

  #verifyProjection(meta: Record<string, string>) {
    const expected = computeProjectionHmac(this.#db, this.#secret);
    if (!secureHexEqual(meta.projection_hmac_sha256, expected)) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_projection_hmac_invalid",
      );
    }
  }

  #verifyAll(): Record<string, string> {
    this.#assertOpen();
    this.#verifyPhysicalDatabase();
    const meta = this.#verifyIdentity();
    this.#verifyAudit(meta);
    this.#verifyObjects();
    this.#verifyProjection(meta);
    return meta;
  }

  #checkpointFromMeta(meta: Record<string, string>): RetentionVaultCheckpoint {
    const body = {
      schema_version:
        "checkback.live-shadow.retention-vault-checkpoint.v1" as const,
      custody_id: this.profile.custody_id,
      object_store_id: this.profile.object_store_id,
      audit_sequence: parseInteger(meta, "audit_sequence"),
      audit_head_hmac_sha256: meta.audit_head_hmac_sha256,
      clock_watermark_ms: parseInteger(meta, "clock_watermark_ms"),
    };
    return RetentionVaultCheckpointSchema.parse({
      ...body,
      checkpoint_hmac_sha256: hmacSha256Canonical(
        this.#secret,
        CHECKPOINT_DOMAIN,
        body,
      ),
    });
  }

  #verifyMinimumCheckpoint(checkpointInput: RetentionVaultCheckpoint) {
    const checkpoint = RetentionVaultCheckpointSchema.parse(checkpointInput);
    const { checkpoint_hmac_sha256: supplied, ...body } = checkpoint;
    const expected = hmacSha256Canonical(
      this.#secret,
      CHECKPOINT_DOMAIN,
      body,
    );
    if (!secureHexEqual(supplied, expected)) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_checkpoint_hmac_invalid",
      );
    }
    if (
      checkpoint.custody_id !== this.profile.custody_id ||
      checkpoint.object_store_id !== this.profile.object_store_id
    ) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_checkpoint_identity_mismatch",
      );
    }
    const meta = readMeta(this.#db);
    const sequence = parseInteger(meta, "audit_sequence");
    const watermark = parseInteger(meta, "clock_watermark_ms");
    const checkpointEvent =
      checkpoint.audit_sequence === 0
        ? null
        : (this.#db.prepare(
            "SELECT event_hmac_sha256 FROM retention_vault_events WHERE sequence=?",
          ).get(checkpoint.audit_sequence) as
            | { event_hmac_sha256: string }
            | undefined);
    if (
      sequence < checkpoint.audit_sequence ||
      watermark < checkpoint.clock_watermark_ms ||
      (checkpoint.audit_sequence === 0
        ? checkpoint.audit_head_hmac_sha256 !== ZERO_HASH
        : checkpointEvent?.event_hmac_sha256 !==
          checkpoint.audit_head_hmac_sha256)
    ) {
      throw new RetentionVaultPersistenceError(
        "retention_vault_checkpoint_rollback_detected",
      );
    }
  }
}

export function retentionVaultCloneRow(value: unknown): RetentionVaultObjectRow {
  return cloneRow(value);
}

export function retentionVaultKeyMaterialHmac(
  secret: Uint8Array,
  keyMaterial: Uint8Array,
): string {
  return keyMaterialHmac(secret, keyMaterial);
}
