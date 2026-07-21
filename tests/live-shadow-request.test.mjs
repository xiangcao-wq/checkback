import assert from "node:assert/strict";
import test from "node:test";
import {
  copyOfflineCanonicalRequestBytes,
  createOfflineCanonicalRequest,
  disposeOfflineCanonicalRequest,
  inspectOfflineCanonicalRequest,
} from "../evaluation/live-shadow/offline-request.ts";
import {
  createLiveContractFixture,
  fixtureId,
} from "./helpers/live-shadow-fixture.mjs";

test("offline request envelopes are opaque and reject forged objects", () => {
  assert.throws(() => inspectOfflineCanonicalRequest({}));
  assert.throws(() => copyOfflineCanonicalRequestBytes(Object.freeze({})));
});

test("offline request snapshots media and returns independent inspection copies", () => {
  const fixture = createLiveContractFixture({ count: 1 });
  const before = Buffer.from("AUTHORIZED_BEFORE_SNAPSHOT", "utf8");
  const after = Buffer.from("AUTHORIZED_AFTER_SNAPSHOT", "utf8");
  const envelope = createOfflineCanonicalRequest({
    execution_plan: fixture.plan,
    runtime_manifest: fixture.runtime,
    slot: "primary",
    before_bytes: before,
    after_bytes: after,
  });
  before.fill(0);
  after.fill(0);
  const first = inspectOfflineCanonicalRequest(envelope);
  assert.equal(first.before_bytes.toString("utf8"), "AUTHORIZED_BEFORE_SNAPSHOT");
  assert.equal(first.after_bytes.toString("utf8"), "AUTHORIZED_AFTER_SNAPSHOT");
  first.before_bytes.fill(0);
  first.after_bytes.fill(0);
  first.request_bytes.fill(0);
  first.execution_plan.execution_id = fixtureId("exec", "mutated-copy");
  const second = inspectOfflineCanonicalRequest(envelope);
  assert.equal(second.before_bytes.toString("utf8"), "AUTHORIZED_BEFORE_SNAPSHOT");
  assert.equal(second.after_bytes.toString("utf8"), "AUTHORIZED_AFTER_SNAPSHOT");
  assert.equal(second.execution_plan.execution_id, fixture.plan.execution_id);
  const requestCopy = copyOfflineCanonicalRequestBytes(envelope);
  requestCopy.fill(0);
  assert.notEqual(copyOfflineCanonicalRequestBytes(envelope)[0], 0);
  disposeOfflineCanonicalRequest(envelope);
  assert.throws(() => inspectOfflineCanonicalRequest(envelope));
});

test("offline request creation reads every caller-controlled field exactly once", () => {
  const fixture = createLiveContractFixture({ count: 1 });
  const counts = new Map();
  const once = (name, value) => ({
    configurable: false,
    enumerable: true,
    get() {
      counts.set(name, (counts.get(name) ?? 0) + 1);
      return value;
    },
  });
  const input = Object.defineProperties({}, {
    execution_plan: once("execution_plan", fixture.plan),
    runtime_manifest: once("runtime_manifest", fixture.runtime),
    slot: once("slot", "primary"),
    before_bytes: once("before_bytes", fixture.mediaPairs[0].before_bytes),
    after_bytes: once("after_bytes", fixture.mediaPairs[0].after_bytes),
  });
  const envelope = createOfflineCanonicalRequest(input);
  assert.deepEqual(
    Object.fromEntries(counts),
    {
      execution_plan: 1,
      runtime_manifest: 1,
      slot: 1,
      before_bytes: 1,
      after_bytes: 1,
    },
  );
  disposeOfflineCanonicalRequest(envelope);
});
