# CheckBack Shadow Evaluation

This directory contains an offline, privacy-minimized evaluation harness for the
Qwen Flash verifier experiment. It does not call a model, read photos, or change
runtime configuration.

## Scope

Schema version `checkback.shadow-eval.v1` is verifier-only. Each trial begins
with an already selected primary missing-candidate batch and manually locked,
anonymous ground truth.

It can measure:

- confirmed-missing precision and supported-missing recall inside the candidate set;
- unsafe confirmations, actionable-item clears, false issues, wrong-zone locations, and resolved unsupported items;
- Flash/Plus agreement, simulated Active regressions, and truth accuracy;
- fast acceptance, fallback, unresolved, and structured-result rates;
- paired Plus-only, observed Shadow, simulated Active, and worst-window model-path latency.

It cannot measure primary candidate recall, whole-scene decision coverage, or
case-level unsafe clear. Passing its verifier gates never makes Active release
ready.

## Pinned configuration

The suite records the primary, Flash, Plus, verifier-prompt version, and a SHA-256
fingerprint of the exact Qwen verifier system prompt, ordered user-message template,
and inference settings. Release gates require an exact match
with `app/lib/qwen-model-config.ts`, including Primary/Fast/Plus timeouts and
zero retries. A result from a different model snapshot, request profile, or prompt
can still be inspected, but it cannot pass the verifier gate.

Each case is additionally bound to the canonical SHA-256 of that suite's
declared configuration and a strict execution record: one Primary call, one
Flash call, one Plus call, zero retries, and three total calls. Execution IDs
must be unique. Honest results from a different configuration therefore parse
for inspection but fail the pinned-config gate; internally mismatched or
over-budget records are rejected. These self-reported fields do not prove
authenticity. Real Shadow still requires an atomic append-only ledger and an
external audit.

## Privacy rules

Fixtures are strict. They may contain only controlled enums, numeric timings,
and anonymous numeric identifiers:

- `case-0001`, `scene-0001`, `trial-0001`, and `item-0001`;
- distinct `plan-0001` and `plan-0002` identifiers for frozen sampling plans;
- `zone-0001` for a sanitized moved-item region;
- `day-001` plus `morning`, `midday`, or `evening` for an anonymous time bucket.

Do not add:

- images, paths, URLs, photo hashes, or data URLs;
- object labels, evidence text, prompts, raw model output, or raw location text;
- API keys, request headers, raw errors, user identity, or exact personal timestamps.

Unknown fields and semantic entity/location identifiers are rejected by the
schema.

## Splits

- `smoke`: synthetic or developer cases used to test the evaluator.
- `gate`: tuning and pre-holdout cases.
- `holdout`: frozen cases not reviewed while changing policy, prompts, or models.

A release-gate suite must contain only `holdout` cases. Any `smoke` or `gate`
case makes the verifier gate fail, even when custom development thresholds are
used. Keep the three splits in separate suite files.

Every holdout case also has a frozen cohort:

- `representative`: collected under a sampling plan locked before collection;
  only this cohort controls fast/fallback rates, structured success, and latency;
- `challenge`: risk-enriched missing, same-place, elsewhere, and not-comparable
  cases; only this cohort controls precision, recall, coverage, and truth accuracy.

The suite stores anonymous IDs for both plans and `locked_before_collection`.
Every case must carry the plan ID assigned to its cohort, and one scene cannot
cross representative and challenge cohorts. Changing the plan or cohort after
seeing model output is rejected.

## Run

From `web/`, generate the bundled synthetic report:

```powershell
npm run eval:shadow
```

Evaluate another suite without enforcing release gates:

```powershell
npm run eval:shadow -- path\to\suite.json
```

Enforce verifier gates with a meaningful exit code:

```powershell
npm run eval:shadow:gate -- path\to\holdout-suite.json
```

A valid report exits 0. Enforced gate failure exits 1. Invalid JSON, schema, or
CLI usage exits 2.

The bundled synthetic suite intentionally includes a Flash false confirmation,
timeout, invalid Plus output, and non-comparable case. It must fail the release
gates; this proves the evaluator detects unsafe results.

## Ground truth

Lock ground truth before reviewing model output. Plus is a comparison baseline,
never truth.

For every anonymous candidate, record:

- physical state: `missing`, `same_place`, or `elsewhere`;
- observability: `supported` only when visual evidence safely supports a
  decision, otherwise `not_comparable`;
- `expected_zone`: required only for a supported `elsewhere` item, using an
  anonymous `zone-0001` identifier; it must be null in every other case.

Each case records `truth_source`, `truth_locked_before_output`, `labeler_count`,
and `adjudication`. Allowed sources are staged protocol, direct inventory, or an
operator log; model output cannot be encoded as truth. Holdout requires truth to
be locked before output review and at least two independent labelers with
agreement or adjudication. These are non-overridable gates, but the external
labeling evidence must still be audited.

A resolved decision on `not_comparable` ground truth is not credited as coverage;
it is counted as an unsupported resolution and must be zero for a gate pass.

## Default verifier gates

The default profile is deliberately conservative:

- at least 1,000 frozen holdout trials and no smoke/gate cases;
- at least 700 representative trials and 300 challenge trials, from plans frozen
  before collection with independently locked and adjudicated truth;
- representative: at least 50 independent scenes, no scene above 5%, seven full
  anonymous day buckets, all 21 day/period windows, and at least 30 trials per window;
- challenge: at least 50 unique scenes; no scene may exceed 5% of challenge trials or candidate items;
- challenge: at least 125 supported missing candidates across 20 scenes;
- challenge: at least 150 supported non-missing hard negatives across 100 trials
  and 20 scenes, including at least 75 `same_place` and 75 `elsewhere` candidates;
- challenge: at least 150 `not_comparable` candidates across 100 trials and 20 scenes;
- at least 10 independent scenes in each of `desk`, `lab`, and `shared_tools`;
- for each of those three scenarios: at least 100 representative trials, plus
  challenge missing, hard-negative, and not-comparable coverage across at least
  five scenes per class;
- at least 600 simulated fast accepts in the representative cohort, with candidate-weighted fast acceptance at least 65%;
- exact pinned model snapshots, timeouts, zero-retry setting, verifier prompt version, and canonical verifier prompt/template/settings SHA-256;
- challenge confirmed-missing precision at least 99%, supported-missing recall at least 90%, supported decision coverage at least 95%, and supported-item truth accuracy at least 99%;
- zero unsafe confirmations, actionable-item clears, truly missing items reported
  elsewhere, false issues, wrong-zone locations, unsupported resolved decisions,
  and truth regressions versus Plus;
- representative Flash/Plus batch validity at least 99%/99.5%;
- representative case and candidate fast accept at least 65%, fallback at most 35%, terminal unresolved cases at most 1%, item decision coverage at least 95%, supported-missing recall at least 90%, and truth accuracy at least 99%;
- representative overall, worst-window, and each-scenario simulated Active p95 at most 20 seconds; each representative scene and time window is also scored for item-level and case-macro quality;
- in each scenario, both representative and challenge supported-missing recall at least 90%, decision coverage at least 95%, and truth accuracy at least 99%;
- representative and challenge macro-by-scene decision coverage at least 95%, truth accuracy at least 99%, and missing recall at least 90%; no supported scene may fall below 80% decision coverage, 90% truth accuracy, or 80% missing recall; representative time windows use the same macro/floor rules at both item and case-macro levels;
- median paired improvement at least 20% and p95 improvement at least 15%.

The safety-critical zero-event checks, pinned configuration, frozen sampling plan,
truth-lock/independent-labeling requirements, and holdout-only requirement cannot
be relaxed through custom thresholds.

Even if every verifier gate passes, `active_release_ready` remains false until
an end-to-end labeled suite, consent/privacy work, controlled cohort routing,
credential rotation, and operational validation are complete.

## Live Shadow boundary

Do not set `CHECKBACK_FAST_VERIFIER_MODE=shadow` on the public site. A real
Shadow execution can send the same photo pair for the primary call, Flash
verification, and Plus control call: up to three provider calls per execution.
Qwen SDK implicit retries must remain disabled, and retries are forbidden inside
a Shadow execution. A rerun must use a new execution ID, count again toward N,
and receive its own maximum of three pre-reserved provider calls. The ledger must
enforce both per-execution calls <= 3 and total calls <= 3N. The future isolated
collector must also bind each record to the resolved provider, endpoint profile,
client version, exact request candidates, and configuration; the offline JSON
schema cannot authenticate those facts by itself.

Before a real execution:

1. use author-owned non-sensitive photos or obtain explicit opt-in;
2. authorize the number of executions and total provider calls, counting every repeated run;
3. disclose the provider's processing/retention terms and withdrawal boundary;
4. lock ground truth before viewing model output;
5. use an isolated environment, not public traffic;
6. retain only the sanitized fixture format and verify photo cleanup;
7. rotate the previously exposed provider credential before public testing.

See `LIVE_SHADOW_PROTOCOL.md` for the execution and consent checklist.
