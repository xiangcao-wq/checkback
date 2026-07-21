import type { LocalAnchorReceipt, LiveDispatchIntent } from "./contracts.ts";

export type AnchorCheckpoint = {
  registry_sequence: number;
  registry_head_sha256: string;
  active_session_id: string | null;
  fencing_token: number;
};

export type AnchorExecutionClaim = {
  execution_id: string;
  media_scope_id: string;
  pair_commitment_hmac_sha256: string;
};

export type AnchorSessionInput = {
  authority_registry_id: string;
  expected_checkpoint: AnchorCheckpoint;
  session_id: string;
  recorded_at_ms: number;
};

export type AnchorClaimAuthorizationInput = {
  authority_registry_id: string;
  expected_checkpoint: AnchorCheckpoint;
  session_id: string;
  fencing_token: number;
  authorization_id: string;
  authorization_fingerprint_sha256: string;
  signed_consent_sha256: string;
  runtime_manifest_sha256: string;
  expires_at_ms: number;
  executions: readonly AnchorExecutionClaim[];
  recorded_at_ms: number;
};

export type AnchorConsumeSlotInput = {
  authority_registry_id: string;
  expected_checkpoint: AnchorCheckpoint;
  session_id: string;
  fencing_token: number;
  intent: LiveDispatchIntent;
  recorded_at_ms: number;
};

export interface AnchorPort {
  readonly mode: "offline_local_stub";
  readonly realmId: string;
  readonly keyId: string;
  inspectRegistry(authorityRegistryId: string): AnchorCheckpoint | null;
  registerRegistry(input: {
    authority_registry_id: string;
    authority_key_id: string;
    recorded_at_ms: number;
  }): LocalAnchorReceipt;
  acquireSession(input: AnchorSessionInput): LocalAnchorReceipt;
  claimAuthorization(
    input: AnchorClaimAuthorizationInput,
  ): LocalAnchorReceipt;
  consumeSlot(input: AnchorConsumeSlotInput): LocalAnchorReceipt;
  releaseSession(input: AnchorSessionInput): LocalAnchorReceipt;
}

export class AnchorError extends Error {
  readonly code: string;
  readonly outcomeMayBeCommitted: boolean;

  constructor(code: string, outcomeMayBeCommitted = false) {
    super(code);
    this.name = "AnchorError";
    this.code = code;
    this.outcomeMayBeCommitted = outcomeMayBeCommitted;
  }
}
