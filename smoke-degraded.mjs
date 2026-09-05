// Verifies the two scripted failure-mode beats in the demo script.
const B = "http://localhost:8787";
const set = (p) => fetch(`${B}/api/state`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(p) }).then((r) => r.json());
const run = async (id) => {
  const t = await fetch(`${B}/api/triage?id=${id}`).then((r) => r.text());
  const d = t.split("\n\n").filter(Boolean).map((b) => ({ ev: b.match(/^event: (.+)$/m)?.[1], data: JSON.parse(b.match(/^data: (.+)$/m)[1]) })).find((e) => e.ev === "done");
  const c = d?.data?.case;
  if (!c || c.status !== "complete") {
    console.log(`  !! ${id} did not complete: ${c?.status || "no done event"} — ${c?.error || ""}`);
    return null;
  }
  return c;
};
const show = (label, c) => {
  if (!c) return false;
  console.log(`  ${label} → ${c.verdict.classification} @ ${c.verdict.confidence} → policy ${c.policy.confidence} (threshold ${c.policy.threshold}) → ${c.policy.disposition}`);
  return true;
};

console.log("── Beat 6a: threat-intel feed offline ──");
await set({ tiFeedOffline: false });
let c = await run("ALT-1042");
show("feed ONLINE ", c);

await set({ tiFeedOffline: true });
c = await run("ALT-1042");
if (show("feed OFFLINE", c)) {
  console.log(`  data gaps     ${c.enrichment.dataGaps.map((g) => g.source).join(", ") || "none"}`);
  console.log(`  TI source     ${c.enrichment.sources.threatIntel.status}`);
  console.log(`  adjustments   ${c.policy.confidenceNotes.join(" ") || "none"}`);
}
await set({ tiFeedOffline: false });

console.log("\n── Beat 6b: global actions-disabled switch ──");
await set({ actionsEnabled: false });
c = await run("ALT-1041");
if (c) console.log(`  actions OFF   → ${c.policy.disposition}; ${c.policy.actions.map((a) => `${a.action}: ${a.executed ? "EXECUTED" : "WITHHELD"} — ${a.reason}`).join(" | ")}`);
await set({ actionsEnabled: true });

console.log("\n── Beat 6c: per-wave kill switch ──");
await set({ killSwitch: { 1: true } });
c = await run("ALT-1044");
if (c) console.log(`  wave 1 KILLED → ${c.policy.disposition} (would have been ${c.policy.wouldHaveBeen}); ${c.policy.dispositionReason}`);
await set({ killSwitch: { 1: false } });

console.log("\n── Beat 5: promoting wave 4 to autonomous ──");
await set({ waveAutonomy: { 4: "autonomous" } });
c = await run("ALT-4003");
if (c) console.log(`  wave 4 AUTO   → ${c.policy.disposition}; triggers ${c.policy.triggers.map((t) => t.id).join(" ")}`);
await set({ waveAutonomy: { 4: "shadow" } });
