import { runOfflineLiveShadowSafetyRehearsal } from "../evaluation/live-shadow/offline-rehearsal.ts";

if (process.argv.length !== 2) {
  throw new Error("offline_live_shadow_rehearsal_accepts_no_arguments");
}

const summary = await runOfflineLiveShadowSafetyRehearsal();
process.stdout.write(`${JSON.stringify(summary)}\n`);
