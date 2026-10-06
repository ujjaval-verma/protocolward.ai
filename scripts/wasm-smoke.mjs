// Smoke-test the globalThis.ward surface of a built ward.wasm in Node.
// Usage: node scripts/wasm-smoke.mjs dist/wasm   (or: make wasm-smoke)
// No dependencies; not part of `make ci` because node is optional for
// Go contributors.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const dir = process.argv[2] ?? "dist/wasm";
await import(pathToFileURL(`${dir}/wasm_exec.js`).href);
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(await readFile(`${dir}/ward.wasm`), go.importObject);
go.run(instance);
const { ward } = globalThis;

// Bad init input returns {ok:false, error}, never throws. The error text
// must be friendly: no Go runtime internals.
const throwing = { get decoys() { throw new Error("boom"); } };
const trap = new Proxy({}, { get() { throw new Error("boom"); } });
const revoked = (() => { const r = Proxy.revocable({}, {}); r.revoke(); return r.proxy; })();
const badInits = [null, 42, "x", [], 10n, Symbol("s"), () => 1, { decoys: "nas.lan" }, { blocklist: [1] },
  { blocklist: [10n] }, { decoys: 10n }, { decoys: ["exämple.lan"] }, { decoys: ["nas!.lan"] },
  throwing, trap, revoked, { blocklist: new Proxy([], { get() { throw new Error("boom"); } }) }];
for (const [i, bad] of badInits.entries()) {
  const r = ward.init(bad);
  assert.equal(r.ok, false, `badInits[${i}]`);
  assert.equal(typeof r.error, "string");
  assert.ok(!/bad type flag|goroutine|internal error|syscall\/js/.test(r.error), r.error);
}
assert.equal(ward.init(10n, 1).ok, false);
assert.equal(ward.init({ allowlist: Array(10001).fill("a.test") }).ok, false);

assert.deepEqual(
  ward.init({
    decoys: ["nas-backup.home.arpa", "both.example.net"],
    blocklist: ["ads.example.com", "both.example.net"],
    allowlist: ["cdn.ads.example.com", "both.example.net"],
  }),
  { ok: true },
);

// Dataplane order: decoy -> allowlist -> blocklist -> forward.
assert.deepEqual(ward.decide("NAS-Backup.Home.Arpa."), { action: "block", source: "decoy", matched: "nas-backup.home.arpa", alert: true });
assert.deepEqual(ward.decide("both.example.net"), { action: "block", source: "decoy", matched: "both.example.net", alert: true });
assert.deepEqual(ward.decide("x.ads.example.com"), { action: "block", source: "blocklist", matched: "ads.example.com", alert: false });
assert.deepEqual(ward.decide("cdn.ads.example.com"), { action: "forward", source: "allowlist", matched: "cdn.ads.example.com", alert: false });
assert.deepEqual(ward.decide("github.com"), { action: "forward", source: "forward", matched: "", alert: false });

// Input validation returns {error}.
assert.deepEqual(ward.decide(42), { error: "decide: expected one string argument" });
for (const bad of [10n, Symbol("s"), {}, null]) {
  const r = ward.decide(bad);
  assert.deepEqual(r, { error: "decide: expected one string argument" });
  assert.deepEqual(ward.assess(bad), { error: "assess: expected one string argument" });
}
assert.deepEqual(ward.decide(), { error: "decide: expected one string argument" });
assert.deepEqual(ward.decide(""), { error: "not a valid hostname" });
assert.deepEqual(ward.assess("x".repeat(10000)), { error: "not a valid hostname" });

const a = ward.assess("github.com");
assert.ok(["benign", "telemetry", "malicious"].includes(a.verdict));
assert.ok(a.score >= 0 && a.score <= 1);
assert.ok(Array.isArray(a.reasons));

// Invariant 6.
const yaml = ward.exportConfig();
assert.equal(typeof yaml, "string");
assert.ok(!yaml.includes("nas-backup"), yaml);
assert.ok(!yaml.toLowerCase().includes("decoy"), yaml);

console.log("wasm-smoke: ok");
process.exit(0);
