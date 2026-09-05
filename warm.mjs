// Pre-warm the verdict cache before a demo.
//
// Run this once, well ahead of presenting. It triages every alert against live inference and
// persists each verdict to cache/. If you then present with "Replay cache" ON, the walkthrough
// runs instantly and cannot be derailed by rate limits, quota or a flaky network — while
// enrichment and the policy gate still run live, so every switch behaves normally.
//
//   node warm.mjs            warm every alert that is not already cached
//   node warm.mjs --force    re-triage everything

const B = "http://localhost:8787";
const force = process.argv.includes("--force");

const boot = await fetch(`${B}/api/bootstrap`).then((r) => r.json());
const cached = new Set(boot.state.cachedIds || []);
const todo = boot.alerts.filter((a) => force || !cached.has(a.id));

if (!todo.length) {
  console.log(`Cache already warm: ${cached.size}/${boot.alerts.length} alerts. Use --force to re-triage.`);
  process.exit(0);
}

// Warming must use live inference, so make sure replay is off.
await fetch(`${B}/api/state`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ replayCache: false, tiFeedOffline: false }) });

console.log(`Warming ${todo.length} alert(s) against live inference. Expect roughly 20–70 s each.\n`);
let ok = 0, failed = [];

for (const [i, a] of todo.entries()) {
  process.stdout.write(`  [${i + 1}/${todo.length}] ${a.id} … `);
  try {
    const text = await fetch(`${B}/api/triage?id=${a.id}`).then((r) => r.text());
    const done = text.split("\n\n").filter(Boolean)
      .map((b) => ({ ev: b.match(/^event: (.+)$/m)?.[1], data: JSON.parse(b.match(/^data: (.+)$/m)[1]) }))
      .find((e) => e.ev === "done");
    const c = done?.data?.case;
    if (c?.status === "complete") {
      ok++;
      console.log(`${c.verdict.classification} → ${c.policy.disposition}  (${Math.round(c.timings.totalMs / 1000)}s)`);
    } else {
      failed.push(a.id);
      console.log(`FAILED — ${(c?.error || "no result").split("\n")[0].slice(0, 90)}`);
      if (c?.quotaExhausted) { console.log("\n  The endpoint is rate-limiting after retries. Wait a minute, then re-run: node warm.mjs"); break; }
    }
  } catch (e) {
    failed.push(a.id);
    console.log(`ERROR — ${e.message}`);
  }
  await new Promise((r) => setTimeout(r, 1200)); // be polite to the endpoint
}

const after = await fetch(`${B}/api/metrics`).then((r) => r.json());
console.log(`\nCached ${(after.state.cachedIds || []).length}/${boot.alerts.length} alerts. ${ok} warmed this run.`);
if (failed.length) console.log(`Not cached: ${failed.join(", ")} — re-run when the quota window resets.`);
else console.log(`Ready. Turn on "Replay cache" in the console for a quota-proof walkthrough.`);
