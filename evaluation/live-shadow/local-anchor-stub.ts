import {
  closeSync,
  constants as fsConstants,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import type { KeyObject } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  LIVE_CALL_SLOTS,
  LiveDispatchIntentSchema,
  signLocalAnchorReceipt,
  verifyLocalAnchorReceipt,
} from "./contracts.ts";
import type {
  LocalAnchorReceipt,
  LocalAnchorReceiptPayload,
} from "./contracts.ts";
import {
  canonicalJson,
  publicKeyId,
  sha256Bytes,
  sha256Canonical,
  signCanonicalEd25519,
  verifyCanonicalEd25519,
} from "./crypto.ts";
import {
  AnchorError,
} from "./anchor-port.ts";
import type {
  AnchorCheckpoint,
  AnchorClaimAuthorizationInput,
  AnchorConsumeSlotInput,
  AnchorPort,
  AnchorSessionInput,
} from "./anchor-port.ts";

const ANCHOR_SCHEMA_VERSION = "checkback.live-shadow.local-anchor-stub.v1";
const ANCHOR_APPLICATION_ID = 0x43424c41;
const ANCHOR_USER_VERSION = 1;
const ZERO_HASH = "0".repeat(64);
const SQLITE_HEADER = Buffer.from("SQLite format 3\0", "binary");
const META_DOMAIN = "checkback.live-shadow.local-anchor-meta.v1";

const ANCHOR_SCHEMA_STATEMENTS = [
  "CREATE TABLE anchor_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
  "CREATE TABLE registries(" +
    "registry_id TEXT PRIMARY KEY,authority_key_id TEXT NOT NULL," +
    "registry_sequence INTEGER NOT NULL,registry_head_sha256 TEXT NOT NULL," +
    "active_session_id TEXT,fencing_token INTEGER NOT NULL," +
    "state TEXT NOT NULL CHECK(state IN ('active','quarantined')))",
  "CREATE TABLE authorizations(" +
    "authorization_id TEXT PRIMARY KEY,authorization_fingerprint_sha256 TEXT NOT NULL UNIQUE," +
    "registry_id TEXT NOT NULL REFERENCES registries(registry_id)," +
    "signed_consent_sha256 TEXT NOT NULL,runtime_manifest_sha256 TEXT NOT NULL," +
    "expires_at_ms INTEGER NOT NULL,state TEXT NOT NULL CHECK(state='consumed'))",
  "CREATE TABLE execution_ids(" +
    "execution_id TEXT PRIMARY KEY,authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id)," +
    "registry_id TEXT NOT NULL REFERENCES registries(registry_id),position INTEGER NOT NULL," +
    "media_scope_id TEXT NOT NULL,pair_commitment_hmac_sha256 TEXT NOT NULL," +
    "UNIQUE(authorization_id,position))",
  "CREATE TABLE call_slots(" +
    "slot_key_sha256 TEXT PRIMARY KEY,authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id)," +
    "execution_id TEXT NOT NULL REFERENCES execution_ids(execution_id)," +
    "slot TEXT NOT NULL CHECK(slot IN ('primary','flash','plus'))," +
    "ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 3)," +
    "state TEXT NOT NULL CHECK(state IN ('allocated','consumed'))," +
    "operation_id TEXT UNIQUE,request_commitment_hmac_sha256 TEXT,dispatch_intent_sha256 TEXT," +
    "dispatch_intent_json TEXT,consumed_registry_sequence INTEGER," +
    "UNIQUE(execution_id,slot),UNIQUE(execution_id,ordinal))",
  "CREATE TRIGGER authorizations_no_update BEFORE UPDATE ON authorizations " +
    "BEGIN SELECT RAISE(ABORT,'authorizations immutable'); END",
  "CREATE TRIGGER authorizations_no_delete BEFORE DELETE ON authorizations " +
    "BEGIN SELECT RAISE(ABORT,'authorizations immutable'); END",
  "CREATE TRIGGER execution_ids_no_update BEFORE UPDATE ON execution_ids " +
    "BEGIN SELECT RAISE(ABORT,'execution ids immutable'); END",
  "CREATE TRIGGER execution_ids_no_delete BEFORE DELETE ON execution_ids " +
    "BEGIN SELECT RAISE(ABORT,'execution ids immutable'); END",
  "CREATE TRIGGER call_slots_no_delete BEFORE DELETE ON call_slots " +
    "BEGIN SELECT RAISE(ABORT,'call slots immutable'); END",
  "CREATE TRIGGER call_slots_monotonic BEFORE UPDATE ON call_slots " +
    "WHEN NOT (OLD.state='allocated' AND NEW.state='consumed' " +
    "AND OLD.slot_key_sha256=NEW.slot_key_sha256 " +
    "AND OLD.authorization_id=NEW.authorization_id " +
    "AND OLD.execution_id=NEW.execution_id AND OLD.slot=NEW.slot " +
    "AND OLD.ordinal=NEW.ordinal AND OLD.operation_id IS NULL " +
    "AND NEW.operation_id IS NOT NULL " +
    "AND OLD.request_commitment_hmac_sha256 IS NULL " +
    "AND NEW.request_commitment_hmac_sha256 IS NOT NULL " +
    "AND OLD.dispatch_intent_sha256 IS NULL " +
    "AND NEW.dispatch_intent_sha256 IS NOT NULL " +
    "AND OLD.dispatch_intent_json IS NULL " +
    "AND NEW.dispatch_intent_json IS NOT NULL " +
    "AND OLD.consumed_registry_sequence IS NULL " +
    "AND NEW.consumed_registry_sequence IS NOT NULL) " +
    "BEGIN SELECT RAISE(ABORT,'call slot transition invalid'); END",
  "CREATE TABLE anchor_events(" +
    "global_sequence INTEGER PRIMARY KEY,registry_id TEXT NOT NULL REFERENCES registries(registry_id)," +
    "registry_sequence INTEGER NOT NULL,event_type TEXT NOT NULL,object_key_sha256 TEXT NOT NULL," +
    "receipt_json TEXT NOT NULL,registry_head_sha256 TEXT NOT NULL," +
    "UNIQUE(registry_id,registry_sequence))",
  "CREATE TRIGGER anchor_events_no_update BEFORE UPDATE ON anchor_events " +
    "BEGIN SELECT RAISE(ABORT,'anchor events append only'); END",
  "CREATE TRIGGER anchor_events_no_delete BEFORE DELETE ON anchor_events " +
    "BEGIN SELECT RAISE(ABORT,'anchor events append only'); END",
] as const;

const ANCHOR_SCHEMA_SHA256 = sha256Canonical(ANCHOR_SCHEMA_STATEMENTS);

type RegistryRow = {
  registry_id: string;
  authority_key_id: string;
  registry_sequence: number;
  registry_head_sha256: string;
  active_session_id: string | null;
  fencing_token: number;
  state: "active" | "quarantined";
};

function requirePersistentPath(path: string) {
  if (!path || path === ":memory:") {
    throw new AnchorError("anchor_persistent_database_path_required");
  }
}

function assertExistingSqliteFile(path: string) {
  requirePersistentPath(path);
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    throw new AnchorError("anchor_database_missing");
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new AnchorError("anchor_database_path_invalid");
  }
  if (stat.size === 0) throw new AnchorError("anchor_database_empty");
  const descriptor = openSync(path, fsConstants.O_RDONLY);
  try {
    const header = Buffer.alloc(SQLITE_HEADER.length);
    const read = readSync(descriptor, header, 0, header.length, 0);
    if (read !== header.length || !header.equals(SQLITE_HEADER)) {
      throw new AnchorError("anchor_database_header_invalid");
    }
  } finally {
    closeSync(descriptor);
  }
}

function schemaFingerprint(db: DatabaseSync): string {
  const rows = db.prepare(
    "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' " +
      "ORDER BY type,name",
  ).all() as { type: string; name: string; sql: string }[];
  return sha256Canonical(rows);
}

function validateHighEntropyId(prefix: string, value: string) {
  if (!new RegExp(`^${prefix}_[a-f0-9]{64}$`).test(value)) {
    throw new AnchorError(`anchor_${prefix}_id_invalid`);
  }
}

function validateHex64(code: string, value: string) {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new AnchorError(code);
}

export function computeLiveSlotKey(input: {
  authorization_id: string;
  execution_id: string;
  slot: string;
}): string {
  return sha256Bytes(
    `checkback.live-shadow.slot.v1\0${input.authorization_id}\0${input.execution_id}\0${input.slot}`,
  );
}

export function computeAnchorAuthorizationClaimObjectSha256(
  input: Pick<
    AnchorClaimAuthorizationInput,
    | "authority_registry_id"
    | "authorization_id"
    | "authorization_fingerprint_sha256"
    | "signed_consent_sha256"
    | "runtime_manifest_sha256"
    | "expires_at_ms"
    | "executions"
  >,
): string {
  return sha256Canonical({
    schema_version: "checkback.live-shadow.anchor-authorization-claim.v1",
    authority_registry_id: input.authority_registry_id,
    authorization_id: input.authorization_id,
    authorization_fingerprint_sha256:
      input.authorization_fingerprint_sha256,
    signed_consent_sha256: input.signed_consent_sha256,
    runtime_manifest_sha256: input.runtime_manifest_sha256,
    expires_at_ms: input.expires_at_ms,
    executions: input.executions.map((execution, position) => ({
      position: position + 1,
      execution_id: execution.execution_id,
      media_scope_id: execution.media_scope_id,
      pair_commitment_hmac_sha256:
        execution.pair_commitment_hmac_sha256,
      slots: LIVE_CALL_SLOTS.map((slot, slotIndex) => ({
        slot,
        ordinal: slotIndex + 1,
        slot_key_sha256: computeLiveSlotKey({
          authorization_id: input.authorization_id,
          execution_id: execution.execution_id,
          slot,
        }),
      })),
    })),
  });
}

export class LocalAnchorStub implements AnchorPort {
  readonly mode = "offline_local_stub" as const;
  readonly realmId: string;
  readonly keyId: string;
  #databasePath: string;
  #db: DatabaseSync;
  #privateKey: KeyObject;
  #publicKey: KeyObject;
  #clock: () => number;
  #expectedPhysicalSchemaSha256!: string;
  #closed = false;

  private constructor(input: {
    database_path: string;
    realm_id: string;
    private_key: KeyObject;
    public_key: KeyObject;
    now?: () => number;
  }) {
    this.#databasePath = input.database_path;
    this.realmId = input.realm_id;
    this.#privateKey = input.private_key;
    this.#publicKey = input.public_key;
    this.keyId = publicKeyId(input.public_key);
    this.#clock = input.now ?? Date.now;
    this.#db = new DatabaseSync(input.database_path, { readOnly: false });
    try {
      this.#configureAndVerify();
    } catch (error) {
      if (!this.#closed) {
        this.#db.close();
        this.#closed = true;
      }
      throw error;
    }
  }

  static initialize(input: {
    database_path: string;
    realm_id: string;
    private_key: KeyObject;
    public_key: KeyObject;
    now?: () => number;
  }): void {
    requirePersistentPath(input.database_path);
    validateHighEntropyId("realm", input.realm_id);
    if (
      publicKeyId(input.private_key) !== publicKeyId(input.public_key) ||
      input.private_key.asymmetricKeyType !== "ed25519"
    ) {
      throw new AnchorError("anchor_signing_key_mismatch");
    }
    let descriptor: number;
    try {
      descriptor = openSync(
        input.database_path,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
        0o600,
      );
    } catch {
      throw new AnchorError("anchor_database_already_exists");
    }
    closeSync(descriptor);
    const db = new DatabaseSync(input.database_path, { readOnly: false });
    try {
      db.exec("PRAGMA journal_mode=WAL");
      db.exec("PRAGMA synchronous=FULL");
      db.exec("PRAGMA foreign_keys=ON");
      db.exec("BEGIN IMMEDIATE");
      db.exec(`PRAGMA application_id=${ANCHOR_APPLICATION_ID}`);
      db.exec(`PRAGMA user_version=${ANCHOR_USER_VERSION}`);
      for (const statement of ANCHOR_SCHEMA_STATEMENTS) db.exec(statement);
      const keyId = publicKeyId(input.public_key);
      const identity = {
        schema_version: ANCHOR_SCHEMA_VERSION,
        schema_sha256: ANCHOR_SCHEMA_SHA256,
        physical_schema_sha256: schemaFingerprint(db),
        anchor_mode: "offline_local_stub",
        realm_id: input.realm_id,
        anchor_key_id: keyId,
      };
      const signature = signCanonicalEd25519(
        input.private_key,
        META_DOMAIN,
        identity,
      );
      const insert = db.prepare(
        "INSERT INTO anchor_meta(key,value) VALUES(?,?)",
      );
      for (const [key, value] of Object.entries(identity)) {
        insert.run(key, value);
      }
      insert.run("identity_signature_base64", signature);
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
    realm_id: string;
    private_key: KeyObject;
    public_key: KeyObject;
    now?: () => number;
  }): LocalAnchorStub {
    assertExistingSqliteFile(input.database_path);
    return new LocalAnchorStub(input);
  }

  #assertOpen() {
    if (this.#closed) throw new AnchorError("anchor_closed");
  }

  #now() {
    const value = this.#clock();
    if (!Number.isInteger(value) || value < 0) {
      throw new AnchorError("anchor_clock_invalid");
    }
    return value;
  }

  #configureAndVerify() {
    this.#db.exec("PRAGMA journal_mode=WAL");
    this.#db.exec("PRAGMA synchronous=FULL");
    this.#db.exec("PRAGMA foreign_keys=ON");
    this.#db.exec("PRAGMA busy_timeout=10000");
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
      applicationId.application_id !== ANCHOR_APPLICATION_ID ||
      userVersion.user_version !== ANCHOR_USER_VERSION ||
      integrity.integrity_check !== "ok" ||
      this.#db.prepare("PRAGMA foreign_key_check").all().length !== 0
    ) {
      this.#db.close();
      this.#closed = true;
      throw new AnchorError("anchor_integrity_check_failed");
    }
    const rows = this.#db.prepare("SELECT key,value FROM anchor_meta").all() as {
      key: string;
      value: string;
    }[];
    const meta = Object.fromEntries(rows.map((row) => [row.key, row.value]));
    const identity = {
      schema_version: meta.schema_version,
      schema_sha256: meta.schema_sha256,
      physical_schema_sha256: meta.physical_schema_sha256,
      anchor_mode: meta.anchor_mode,
      realm_id: meta.realm_id,
      anchor_key_id: meta.anchor_key_id,
    };
    if (
      identity.schema_version !== ANCHOR_SCHEMA_VERSION ||
      identity.schema_sha256 !== ANCHOR_SCHEMA_SHA256 ||
      identity.physical_schema_sha256 !== schemaFingerprint(this.#db) ||
      identity.anchor_mode !== "offline_local_stub"
    ) {
      throw new AnchorError("anchor_schema_mismatch");
    }
    if (
      identity.realm_id !== this.realmId ||
      identity.anchor_key_id !== this.keyId ||
      publicKeyId(this.#privateKey) !== this.keyId
    ) {
      throw new AnchorError("anchor_identity_mismatch");
    }
    if (
      !meta.identity_signature_base64 ||
      !verifyCanonicalEd25519(
        this.#publicKey,
        META_DOMAIN,
        identity,
        meta.identity_signature_base64,
      )
    ) {
      throw new AnchorError("anchor_identity_signature_invalid");
    }
    this.#expectedPhysicalSchemaSha256 = identity.physical_schema_sha256;
    this.#verifyEventChain();
    this.#verifyProjection();
  }

  #transaction<T>(callback: () => T): T {
    this.#assertOpen();
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      this.#verifyEventChain();
      this.#verifyProjection();
      const output = callback();
      this.#db.exec("COMMIT");
      return output;
    } catch (error) {
      try {
        this.#db.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }

  #registry(registryId: string): RegistryRow {
    const row = this.#db.prepare(
      "SELECT registry_id,authority_key_id,registry_sequence,registry_head_sha256," +
        "active_session_id,fencing_token,state FROM registries WHERE registry_id=?",
    ).get(registryId) as RegistryRow | undefined;
    if (!row) throw new AnchorError("anchor_registry_not_found");
    return row;
  }

  #assertCheckpoint(row: RegistryRow, expected: AnchorCheckpoint) {
    if (
      row.registry_sequence !== expected.registry_sequence ||
      row.registry_head_sha256 !== expected.registry_head_sha256 ||
      row.active_session_id !== expected.active_session_id ||
      row.fencing_token !== expected.fencing_token
    ) {
      throw new AnchorError("anchor_checkpoint_mismatch");
    }
  }

  #assertActiveSession(
    row: RegistryRow,
    sessionId: string,
    fencingToken: number,
  ) {
    if (
      row.state !== "active" ||
      row.active_session_id !== sessionId ||
      row.fencing_token !== fencingToken
    ) {
      throw new AnchorError("anchor_session_fenced");
    }
  }

  #appendEvent(input: {
    registry: RegistryRow;
    event_type: LocalAnchorReceiptPayload["event_type"];
    object_key_sha256: string;
    session_id: string | null;
    recorded_at_ms: number;
  }): LocalAnchorReceipt {
    const latest = this.#db.prepare(
      "SELECT COALESCE(MAX(global_sequence),0) AS value FROM anchor_events",
    ).get() as { value: number };
    const globalSequence = latest.value + 1;
    const registrySequence = input.registry.registry_sequence + 1;
    const head = sha256Canonical({
      previous_registry_head_sha256: input.registry.registry_head_sha256,
      authority_registry_id: input.registry.registry_id,
      global_sequence: globalSequence,
      registry_sequence: registrySequence,
      event_type: input.event_type,
      object_key_sha256: input.object_key_sha256,
      session_id: input.session_id,
      fencing_token: input.registry.fencing_token,
      recorded_at_ms: input.recorded_at_ms,
    });
    const receipt = signLocalAnchorReceipt(this.#privateKey, {
      schema_version: "checkback.live-shadow.anchor-receipt.v1",
      anchor_mode: "offline_local_stub",
      anchor_realm_id: this.realmId,
      anchor_key_id: this.keyId,
      authority_registry_id: input.registry.registry_id,
      global_sequence: globalSequence,
      registry_sequence: registrySequence,
      previous_registry_head_sha256: input.registry.registry_head_sha256,
      registry_head_sha256: head,
      event_type: input.event_type,
      object_key_sha256: input.object_key_sha256,
      session_id: input.session_id,
      fencing_token: input.registry.fencing_token,
      recorded_at_ms: input.recorded_at_ms,
    });
    this.#db.prepare(
      "INSERT INTO anchor_events(global_sequence,registry_id,registry_sequence,event_type," +
        "object_key_sha256,receipt_json,registry_head_sha256) VALUES(?,?,?,?,?,?,?)",
    ).run(
      globalSequence,
      input.registry.registry_id,
      registrySequence,
      input.event_type,
      input.object_key_sha256,
      canonicalJson(receipt),
      head,
    );
    this.#db.prepare(
      "UPDATE registries SET registry_sequence=?,registry_head_sha256=? WHERE registry_id=?",
    ).run(registrySequence, head, input.registry.registry_id);
    return receipt;
  }

  #verifyEventChain() {
    if (
      this.#expectedPhysicalSchemaSha256 !== schemaFingerprint(this.#db)
    ) {
      throw new AnchorError("anchor_schema_mismatch");
    }
    const globalEvents = this.#db.prepare(
      "SELECT global_sequence FROM anchor_events ORDER BY global_sequence",
    ).all() as { global_sequence: number }[];
    globalEvents.forEach((event, index) => {
      if (event.global_sequence !== index + 1) {
        throw new AnchorError("anchor_global_sequence_invalid");
      }
    });
    const registries = this.#db.prepare(
      "SELECT registry_id,authority_key_id,registry_sequence,registry_head_sha256," +
        "active_session_id,fencing_token,state FROM registries",
    ).all() as {
      registry_id: string;
      authority_key_id: string;
      registry_sequence: number;
      registry_head_sha256: string;
      active_session_id: string | null;
      fencing_token: number;
      state: "active" | "quarantined";
    }[];
    for (const registry of registries) {
      const events = this.#db.prepare(
        "SELECT global_sequence,registry_sequence,event_type,object_key_sha256," +
          "receipt_json,registry_head_sha256 FROM anchor_events " +
          "WHERE registry_id=? ORDER BY registry_sequence",
      ).all(registry.registry_id) as {
        global_sequence: number;
        registry_sequence: number;
        event_type: string;
        object_key_sha256: string;
        receipt_json: string;
        registry_head_sha256: string;
      }[];
      if (events.length === 0) {
        throw new AnchorError("anchor_registry_projection_invalid");
      }
      let previous = ZERO_HASH;
      let sequence = 0;
      let derivedActiveSession: string | null = null;
      let derivedFencingToken = 0;
      for (const event of events) {
        const receipt = verifyLocalAnchorReceipt(
          this.#publicKey,
          JSON.parse(event.receipt_json),
        );
        sequence += 1;
        const expectedHead = sha256Canonical({
          previous_registry_head_sha256: previous,
          authority_registry_id: registry.registry_id,
          global_sequence: event.global_sequence,
          registry_sequence: sequence,
          event_type: event.event_type,
          object_key_sha256: event.object_key_sha256,
          session_id: receipt.payload.session_id,
          fencing_token: receipt.payload.fencing_token,
          recorded_at_ms: receipt.payload.recorded_at_ms,
        });
        if (
          event.registry_sequence !== sequence ||
          receipt.payload.anchor_realm_id !== this.realmId ||
          receipt.payload.anchor_key_id !== this.keyId ||
          receipt.payload.authority_registry_id !== registry.registry_id ||
          receipt.payload.global_sequence !== event.global_sequence ||
          receipt.payload.registry_sequence !== sequence ||
          receipt.payload.previous_registry_head_sha256 !== previous ||
          receipt.payload.event_type !== event.event_type ||
          receipt.payload.object_key_sha256 !== event.object_key_sha256 ||
          receipt.payload.registry_head_sha256 !== event.registry_head_sha256 ||
          receipt.payload.registry_head_sha256 !== expectedHead
        ) {
          throw new AnchorError("anchor_event_chain_invalid");
        }
        switch (receipt.payload.event_type) {
          case "register_registry":
            if (
              sequence !== 1 ||
              receipt.payload.session_id !== null ||
              receipt.payload.fencing_token !== 0 ||
              receipt.payload.object_key_sha256 !==
                sha256Canonical({
                  authority_registry_id: registry.registry_id,
                  authority_key_id: registry.authority_key_id,
                })
            ) {
              throw new AnchorError("anchor_registry_event_transition_invalid");
            }
            break;
          case "acquire_session":
            if (
              derivedActiveSession !== null ||
              receipt.payload.session_id === null ||
              receipt.payload.fencing_token !== derivedFencingToken + 1
            ) {
              throw new AnchorError("anchor_session_event_transition_invalid");
            }
            derivedActiveSession = receipt.payload.session_id;
            derivedFencingToken = receipt.payload.fencing_token;
            break;
          case "claim_authorization":
          case "consume_slot":
            if (
              derivedActiveSession === null ||
              receipt.payload.session_id !== derivedActiveSession ||
              receipt.payload.fencing_token !== derivedFencingToken
            ) {
              throw new AnchorError("anchor_session_event_transition_invalid");
            }
            break;
          case "release_session":
            if (
              derivedActiveSession === null ||
              receipt.payload.session_id !== derivedActiveSession ||
              receipt.payload.fencing_token !== derivedFencingToken
            ) {
              throw new AnchorError("anchor_session_event_transition_invalid");
            }
            derivedActiveSession = null;
            break;
        }
        if (
          sequence === 1 &&
          receipt.payload.event_type !== "register_registry"
        ) {
          throw new AnchorError("anchor_registry_event_transition_invalid");
        }
        previous = receipt.payload.registry_head_sha256;
      }
      if (
        registry.registry_sequence !== sequence ||
        registry.registry_head_sha256 !== previous ||
        registry.active_session_id !== derivedActiveSession ||
        registry.fencing_token !== derivedFencingToken ||
        registry.state !== "active"
      ) {
        throw new AnchorError("anchor_event_head_invalid");
      }
    }
  }

  #verifyProjection() {
    const authorizations = this.#db.prepare(
      "SELECT authorization_id,authorization_fingerprint_sha256,registry_id," +
        "signed_consent_sha256,runtime_manifest_sha256,expires_at_ms " +
        "FROM authorizations ORDER BY authorization_id",
    ).all() as {
      authorization_id: string;
      authorization_fingerprint_sha256: string;
      registry_id: string;
      signed_consent_sha256: string;
      runtime_manifest_sha256: string;
      expires_at_ms: number;
    }[];
    const claimEvents = this.#db.prepare(
      "SELECT registry_id,object_key_sha256 FROM anchor_events " +
        "WHERE event_type='claim_authorization'",
    ).all() as { registry_id: string; object_key_sha256: string }[];
    const consumeEvents = this.#db.prepare(
      "SELECT registry_id,registry_sequence,object_key_sha256 FROM anchor_events " +
        "WHERE event_type='consume_slot'",
    ).all() as {
      registry_id: string;
      registry_sequence: number;
      object_key_sha256: string;
    }[];
    if (claimEvents.length !== authorizations.length) {
      throw new AnchorError("anchor_authorization_projection_invalid");
    }
    const claimCounts = new Map<string, number>();
    for (const event of claimEvents) {
      const key = `${event.registry_id}\0${event.object_key_sha256}`;
      claimCounts.set(key, (claimCounts.get(key) ?? 0) + 1);
    }
    const consumeBySequence = new Map(
      consumeEvents.map((event) => [
        `${event.registry_id}\0${event.registry_sequence}`,
        event,
      ]),
    );
    const usedConsumeSequences = new Set<string>();
    let consumedSlotCount = 0;
    for (const authorization of authorizations) {
      const executions = this.#db.prepare(
        "SELECT execution_id,authorization_id,registry_id,position,media_scope_id," +
          "pair_commitment_hmac_sha256 FROM execution_ids " +
          "WHERE authorization_id=? ORDER BY position",
      ).all(authorization.authorization_id) as {
        execution_id: string;
        authorization_id: string;
        registry_id: string;
        position: number;
        media_scope_id: string;
        pair_commitment_hmac_sha256: string;
      }[];
      if (executions.length < 1 || executions.length > 100) {
        throw new AnchorError("anchor_execution_projection_invalid");
      }
      const claimHash = computeAnchorAuthorizationClaimObjectSha256({
        authority_registry_id: authorization.registry_id,
        authorization_id: authorization.authorization_id,
        authorization_fingerprint_sha256:
          authorization.authorization_fingerprint_sha256,
        signed_consent_sha256: authorization.signed_consent_sha256,
        runtime_manifest_sha256: authorization.runtime_manifest_sha256,
        expires_at_ms: authorization.expires_at_ms,
        executions: executions.map((execution) => ({
          execution_id: execution.execution_id,
          media_scope_id: execution.media_scope_id,
          pair_commitment_hmac_sha256:
            execution.pair_commitment_hmac_sha256,
        })),
      });
      if (
        claimCounts.get(`${authorization.registry_id}\0${claimHash}`) !== 1
      ) {
        throw new AnchorError("anchor_authorization_projection_invalid");
      }
      executions.forEach((execution, executionIndex) => {
        if (
          execution.authorization_id !== authorization.authorization_id ||
          execution.registry_id !== authorization.registry_id ||
          execution.position !== executionIndex + 1
        ) {
          throw new AnchorError("anchor_execution_projection_invalid");
        }
        const slots = this.#db.prepare(
          "SELECT slot_key_sha256,authorization_id,execution_id,slot,ordinal,state," +
            "operation_id,request_commitment_hmac_sha256,dispatch_intent_sha256," +
            "dispatch_intent_json,consumed_registry_sequence FROM call_slots WHERE execution_id=? " +
            "ORDER BY ordinal",
        ).all(execution.execution_id) as {
          slot_key_sha256: string;
          authorization_id: string;
          execution_id: string;
          slot: string;
          ordinal: number;
          state: "allocated" | "consumed";
          operation_id: string | null;
          request_commitment_hmac_sha256: string | null;
          dispatch_intent_sha256: string | null;
          dispatch_intent_json: string | null;
          consumed_registry_sequence: number | null;
        }[];
        if (slots.length !== LIVE_CALL_SLOTS.length) {
          throw new AnchorError("anchor_slot_projection_invalid");
        }
        slots.forEach((slot, slotIndex) => {
          const expectedSlot = LIVE_CALL_SLOTS[slotIndex];
          const expectedKey = computeLiveSlotKey({
            authorization_id: authorization.authorization_id,
            execution_id: execution.execution_id,
            slot: expectedSlot,
          });
          if (
            slot.slot_key_sha256 !== expectedKey ||
            slot.authorization_id !== authorization.authorization_id ||
            slot.execution_id !== execution.execution_id ||
            slot.slot !== expectedSlot ||
            slot.ordinal !== slotIndex + 1
          ) {
            throw new AnchorError("anchor_slot_projection_invalid");
          }
          if (slot.state === "allocated") {
            if (
              slot.operation_id !== null ||
              slot.request_commitment_hmac_sha256 !== null ||
              slot.dispatch_intent_sha256 !== null ||
              slot.dispatch_intent_json !== null ||
              slot.consumed_registry_sequence !== null
            ) {
              throw new AnchorError("anchor_slot_projection_invalid");
            }
            return;
          }
          if (
            slot.state !== "consumed" ||
            !slot.operation_id ||
            !slot.request_commitment_hmac_sha256 ||
            !slot.dispatch_intent_sha256 ||
            !slot.dispatch_intent_json ||
            !Number.isInteger(slot.consumed_registry_sequence) ||
            slot.consumed_registry_sequence! < 1
          ) {
            throw new AnchorError("anchor_slot_projection_invalid");
          }
          let persistedIntent;
          try {
            persistedIntent = LiveDispatchIntentSchema.parse(
              JSON.parse(slot.dispatch_intent_json),
            );
          } catch {
            throw new AnchorError("anchor_dispatch_intent_projection_invalid");
          }
          if (
            canonicalJson(persistedIntent) !== slot.dispatch_intent_json ||
            sha256Canonical(persistedIntent) !== slot.dispatch_intent_sha256 ||
            persistedIntent.authority_registry_id !== authorization.registry_id ||
            persistedIntent.anchor_realm_id !== this.realmId ||
            persistedIntent.authorization_id !== authorization.authorization_id ||
            persistedIntent.authorization_fingerprint_sha256 !==
              authorization.authorization_fingerprint_sha256 ||
            persistedIntent.execution_id !== execution.execution_id ||
            persistedIntent.media_scope_id !== execution.media_scope_id ||
            persistedIntent.pair_commitment_hmac_sha256 !==
              execution.pair_commitment_hmac_sha256 ||
            persistedIntent.slot !== slot.slot ||
            persistedIntent.ordinal !== slot.ordinal ||
            persistedIntent.operation_id !== slot.operation_id ||
            persistedIntent.request_commitment_hmac_sha256 !==
              slot.request_commitment_hmac_sha256 ||
            persistedIntent.runtime_manifest_sha256 !==
              authorization.runtime_manifest_sha256 ||
            persistedIntent.expires_at_ms !== authorization.expires_at_ms
          ) {
            throw new AnchorError("anchor_dispatch_intent_projection_invalid");
          }
          const consumeSequenceKey =
            `${authorization.registry_id}\0${slot.consumed_registry_sequence}`;
          const consumeEvent = consumeBySequence.get(consumeSequenceKey);
          if (
            !consumeEvent ||
            usedConsumeSequences.has(consumeSequenceKey) ||
            consumeEvent.object_key_sha256 !== slot.dispatch_intent_sha256
          ) {
            throw new AnchorError("anchor_slot_event_projection_invalid");
          }
          usedConsumeSequences.add(consumeSequenceKey);
          consumedSlotCount += 1;
        });
      });
    }
    if (
      consumeEvents.length !== consumedSlotCount ||
      usedConsumeSequences.size !== consumeEvents.length
    ) {
      throw new AnchorError("anchor_slot_event_projection_invalid");
    }
  }

  inspectRegistry(authorityRegistryId: string): AnchorCheckpoint | null {
    this.#assertOpen();
    this.#verifyEventChain();
    this.#verifyProjection();
    validateHighEntropyId("registry", authorityRegistryId);
    const row = this.#db.prepare(
      "SELECT registry_sequence,registry_head_sha256,active_session_id,fencing_token " +
        "FROM registries WHERE registry_id=?",
    ).get(authorityRegistryId) as AnchorCheckpoint | undefined;
    return row ?? null;
  }

  registerRegistry(input: {
    authority_registry_id: string;
    authority_key_id: string;
    recorded_at_ms: number;
  }): LocalAnchorReceipt {
    validateHighEntropyId("registry", input.authority_registry_id);
    validateHex64("anchor_authority_key_id_invalid", input.authority_key_id);
    const now = this.#now();
    return this.#transaction(() => {
      if (this.inspectRegistry(input.authority_registry_id)) {
        throw new AnchorError("anchor_registry_already_registered");
      }
      this.#db.prepare(
        "INSERT INTO registries VALUES(?,?,?,?,?,?,?)",
      ).run(
        input.authority_registry_id,
        input.authority_key_id,
        0,
        ZERO_HASH,
        null,
        0,
        "active",
      );
      return this.#appendEvent({
        registry: this.#registry(input.authority_registry_id),
        event_type: "register_registry",
        object_key_sha256: sha256Canonical({
          authority_registry_id: input.authority_registry_id,
          authority_key_id: input.authority_key_id,
        }),
        session_id: null,
        recorded_at_ms: now,
      });
    });
  }

  acquireSession(input: AnchorSessionInput): LocalAnchorReceipt {
    validateHighEntropyId("session", input.session_id);
    const now = this.#now();
    return this.#transaction(() => {
      const row = this.#registry(input.authority_registry_id);
      this.#assertCheckpoint(row, input.expected_checkpoint);
      if (row.active_session_id !== null) {
        throw new AnchorError("anchor_session_already_active");
      }
      this.#db.prepare(
        "UPDATE registries SET active_session_id=?,fencing_token=fencing_token+1 " +
          "WHERE registry_id=?",
      ).run(input.session_id, input.authority_registry_id);
      return this.#appendEvent({
        registry: this.#registry(input.authority_registry_id),
        event_type: "acquire_session",
        object_key_sha256: sha256Bytes(input.session_id),
        session_id: input.session_id,
        recorded_at_ms: now,
      });
    });
  }

  claimAuthorization(
    input: AnchorClaimAuthorizationInput,
  ): LocalAnchorReceipt {
    const now = this.#now();
    validateHighEntropyId("auth", input.authorization_id);
    validateHex64(
      "anchor_authorization_fingerprint_invalid",
      input.authorization_fingerprint_sha256,
    );
    validateHex64("anchor_signed_consent_hash_invalid", input.signed_consent_sha256);
    validateHex64(
      "anchor_runtime_manifest_hash_invalid",
      input.runtime_manifest_sha256,
    );
    if (input.executions.length < 1 || input.executions.length > 100) {
      throw new AnchorError("anchor_execution_count_invalid");
    }
    const executionIds = input.executions.map((item) => item.execution_id);
    if (new Set(executionIds).size !== executionIds.length) {
      throw new AnchorError("anchor_execution_id_duplicate");
    }
    return this.#transaction(() => {
      const row = this.#registry(input.authority_registry_id);
      this.#assertCheckpoint(row, input.expected_checkpoint);
      this.#assertActiveSession(row, input.session_id, input.fencing_token);
      const existingAuthorization = this.#db.prepare(
        "SELECT authorization_id FROM authorizations WHERE authorization_id=? " +
          "OR authorization_fingerprint_sha256=?",
      ).get(
        input.authorization_id,
        input.authorization_fingerprint_sha256,
      );
      if (existingAuthorization) {
        throw new AnchorError("anchor_authorization_already_claimed");
      }
      for (const execution of input.executions) {
        validateHighEntropyId("exec", execution.execution_id);
        validateHighEntropyId("scope", execution.media_scope_id);
        validateHex64(
          "anchor_pair_commitment_invalid",
          execution.pair_commitment_hmac_sha256,
        );
        if (
          this.#db.prepare(
            "SELECT execution_id FROM execution_ids WHERE execution_id=?",
          ).get(execution.execution_id)
        ) {
          throw new AnchorError("anchor_execution_already_claimed");
        }
      }
      if (
        !Number.isInteger(input.expires_at_ms) ||
        input.expires_at_ms <= now
      ) {
        throw new AnchorError("anchor_authorization_expiry_invalid");
      }
      this.#db.prepare(
        "INSERT INTO authorizations VALUES(?,?,?,?,?,?,?)",
      ).run(
        input.authorization_id,
        input.authorization_fingerprint_sha256,
        input.authority_registry_id,
        input.signed_consent_sha256,
        input.runtime_manifest_sha256,
        input.expires_at_ms,
        "consumed",
      );
      const insertExecution = this.#db.prepare(
        "INSERT INTO execution_ids VALUES(?,?,?,?,?,?)",
      );
      const insertSlot = this.#db.prepare(
        "INSERT INTO call_slots(slot_key_sha256,authorization_id,execution_id,slot,ordinal,state) " +
          "VALUES(?,?,?,?,?,'allocated')",
      );
      input.executions.forEach((execution, position) => {
        insertExecution.run(
          execution.execution_id,
          input.authorization_id,
          input.authority_registry_id,
          position + 1,
          execution.media_scope_id,
          execution.pair_commitment_hmac_sha256,
        );
        LIVE_CALL_SLOTS.forEach((slot, slotIndex) => {
          insertSlot.run(
            computeLiveSlotKey({
              authorization_id: input.authorization_id,
              execution_id: execution.execution_id,
              slot,
            }),
            input.authorization_id,
            execution.execution_id,
            slot,
            slotIndex + 1,
          );
        });
      });
      return this.#appendEvent({
        registry: this.#registry(input.authority_registry_id),
        event_type: "claim_authorization",
        object_key_sha256:
          computeAnchorAuthorizationClaimObjectSha256(input),
        session_id: input.session_id,
        recorded_at_ms: now,
      });
    });
  }

  consumeSlot(input: AnchorConsumeSlotInput): LocalAnchorReceipt {
    const now = this.#now();
    const intent = LiveDispatchIntentSchema.parse(input.intent);
    return this.#transaction(() => {
      const row = this.#registry(input.authority_registry_id);
      this.#assertCheckpoint(row, input.expected_checkpoint);
      this.#assertActiveSession(row, input.session_id, input.fencing_token);
      if (
        intent.authority_registry_id !== input.authority_registry_id ||
        intent.anchor_realm_id !== this.realmId
      ) {
        throw new AnchorError("anchor_dispatch_identity_mismatch");
      }
      const slotKey = computeLiveSlotKey(intent);
      const slot = this.#db.prepare(
        "SELECT s.state,s.authorization_id,s.execution_id,s.slot,s.ordinal," +
          "e.media_scope_id,e.pair_commitment_hmac_sha256," +
          "a.authorization_fingerprint_sha256,a.runtime_manifest_sha256,a.expires_at_ms " +
          "FROM call_slots s JOIN execution_ids e ON e.execution_id=s.execution_id " +
          "JOIN authorizations a ON a.authorization_id=s.authorization_id " +
          "WHERE s.slot_key_sha256=?",
      ).get(slotKey) as
        | {
            state: "allocated" | "consumed";
            authorization_id: string;
            execution_id: string;
            slot: string;
            ordinal: number;
            media_scope_id: string;
            pair_commitment_hmac_sha256: string;
            authorization_fingerprint_sha256: string;
            runtime_manifest_sha256: string;
            expires_at_ms: number;
          }
        | undefined;
      if (!slot) throw new AnchorError("anchor_slot_not_allocated");
      if (slot.state !== "allocated") {
        throw new AnchorError("anchor_slot_already_consumed");
      }
      const unconsumedPrior = this.#db.prepare(
        "SELECT COUNT(*) AS count FROM call_slots WHERE execution_id=? " +
          "AND ordinal<? AND state<>'consumed'",
      ).get(slot.execution_id, slot.ordinal) as { count: number };
      if (unconsumedPrior.count !== 0) {
        throw new AnchorError("anchor_slot_order_invalid");
      }
      if (
        slot.authorization_id !== intent.authorization_id ||
        slot.execution_id !== intent.execution_id ||
        slot.slot !== intent.slot ||
        slot.ordinal !== intent.ordinal ||
        slot.media_scope_id !== intent.media_scope_id ||
        slot.pair_commitment_hmac_sha256 !==
          intent.pair_commitment_hmac_sha256 ||
        slot.authorization_fingerprint_sha256 !==
          intent.authorization_fingerprint_sha256 ||
        slot.runtime_manifest_sha256 !== intent.runtime_manifest_sha256 ||
        intent.expires_at_ms !== slot.expires_at_ms ||
        now < intent.created_at_ms ||
        now >= intent.expires_at_ms ||
        now >= slot.expires_at_ms
      ) {
        throw new AnchorError("anchor_slot_binding_mismatch");
      }
      const nextSequence = row.registry_sequence + 1;
      this.#db.prepare(
        "UPDATE call_slots SET state='consumed',operation_id=?," +
          "request_commitment_hmac_sha256=?,dispatch_intent_sha256=?," +
          "dispatch_intent_json=?,consumed_registry_sequence=? WHERE slot_key_sha256=?",
      ).run(
        intent.operation_id,
        intent.request_commitment_hmac_sha256,
        sha256Canonical(intent),
        canonicalJson(intent),
        nextSequence,
        slotKey,
      );
      return this.#appendEvent({
        registry: this.#registry(input.authority_registry_id),
        event_type: "consume_slot",
        object_key_sha256: sha256Canonical(intent),
        session_id: input.session_id,
        recorded_at_ms: now,
      });
    });
  }

  releaseSession(input: AnchorSessionInput): LocalAnchorReceipt {
    const now = this.#now();
    return this.#transaction(() => {
      const row = this.#registry(input.authority_registry_id);
      this.#assertCheckpoint(row, input.expected_checkpoint);
      this.#assertActiveSession(
        row,
        input.session_id,
        input.expected_checkpoint.fencing_token,
      );
      this.#db.prepare(
        "UPDATE registries SET active_session_id=NULL WHERE registry_id=?",
      ).run(input.authority_registry_id);
      return this.#appendEvent({
        registry: this.#registry(input.authority_registry_id),
        event_type: "release_session",
        object_key_sha256: sha256Bytes(input.session_id),
        session_id: input.session_id,
        recorded_at_ms: now,
      });
    });
  }

  close() {
    if (this.#closed) return;
    try {
      this.#db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    } catch {}
    try {
      this.#db.close();
    } finally {
      this.#closed = true;
    }
  }
}
