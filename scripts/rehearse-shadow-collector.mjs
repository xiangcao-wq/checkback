import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ShadowCollectorLedger } from "../evaluation/collector/ledger.ts";
import { createOfflineRehearsalBundle } from "../evaluation/collector/rehearsal-fixture.ts";
import { runOfflineShadowExecution } from "../evaluation/collector/runner.ts";

function batch(ids) {
  return {
    verifications: ids.map((id) => ({
      id,
      verdict: "confirmed_missing",
      certainty: "high",
      current_location: null,
    })),
  };
}

export async function runRehearsal(options = {}) {
  const now = options.now ?? Date.now();
  const directory = await mkdtemp(join(tmpdir(), "checkback-rehearsal-"));
  const bundle = createOfflineRehearsalBundle({
    numeric_id: options.numericId ?? 9001,
    execution_count: 1,
    created_at_ms: now,
    lifetime_ms: 60_000,
  });
  const ledger = new ShadowCollectorLedger({
    database_path: join(directory, "ledger.sqlite"),
    signer: bundle.signer,
    now: () => now,
  });
  try {
    ledger.createRound({
      signed_manifest: bundle.signed_manifest,
      consent_grant: bundle.consent_grant,
    });
    ledger.armRound(bundle.manifest.round_id);
    const ids = ["item-0001", "item-0002"];
    const providerScript = {
      primary: {
        outcome: "success",
        latency_ms: 5,
        candidate_ids: ids,
      },
      flash: {
        outcome: "success",
        latency_ms: 6,
        batch: batch(ids),
      },
      plus: {
        outcome: "success",
        latency_ms: 7,
        batch: batch(ids),
      },
    };
    await runOfflineShadowExecution({
      ledger,
      execution_plan: bundle.execution_plans[0],
      provider_script: providerScript,
      signer: bundle.signer,
      now: () => now,
      ground_truth: ({ candidate_ids }) => ({
        truth_source: "staged_protocol",
        truth_locked_before_output: true,
        labeler_count: 2,
        adjudication: "agreed",
        items: candidate_ids.map((id) => ({
          id,
          state: "missing",
          observability: "supported",
          expected_zone: null,
        })),
      }),
    });
    ledger.completeRound(bundle.manifest.round_id);
    const suite = ledger.exportSuite(bundle.manifest.round_id);
    const status = ledger.getRoundStatus(bundle.manifest.round_id);
    return {
      run_mode: "rehearsal",
      provider: "fake_local",
      network_calls: 0,
      executions: suite.cases.length,
      provider_call_slots: status.reserved_provider_calls,
      audit_chain_valid: ledger.verifyAuditChain(),
      export_split: suite.cases[0].split,
    };
  } finally {
    ledger.close();
    bundle.signer.dispose();
    await rm(directory, { recursive: true, force: true });
  }
}

async function main() {
  if (process.argv.slice(2).length > 0) {
    process.stderr.write(
      "Offline rehearsal accepts no arguments, photo paths, endpoints, or keys.\n",
    );
    process.exitCode = 2;
    return;
  }
  try {
    const summary = await runRehearsal();
    process.stdout.write(JSON.stringify(summary) + "\n");
  } catch {
    process.stderr.write("Offline rehearsal failed closed.\n");
    process.exitCode = 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main();
}