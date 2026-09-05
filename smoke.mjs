// Smoke test: drive the triage pipeline for a set of alerts and print what happened.
// Usage:  node smoke.mjs [ALT-1041 ALT-2012 ...]
const ids = process.argv.slice(2);
const targets = ids.length ? ids : ["ALT-1041", "ALT-1042", "ALT-1043", "ALT-2012", "ALT-3009", "ALT-4003"];

for (const id of targets) {
  const res = await fetch(`http://localhost:8787/api/triage?id=${id}`);
  const text = await res.text();
  const events = text.split("\n\n").filter(Boolean).map((b) => {
    const ev = b.match(/^event: (.+)$/m)?.[1];
    const data = b.match(/^data: (.+)$/m)?.[1];
    return { ev, data: data ? JSON.parse(data) : null };
  });
  const done = events.find((e) => e.ev === "done");
  const stages = events.filter((e) => e.ev === "stage").map((e) => e.data.stage);
  if (!done || done.data.case.status !== "complete") {
    console.log(`\n${id}  ✗ ${done ? done.data.case.status + " — " + done.data.case.error : "no result"}`);
    continue;
  }
  const c = done.data.case;
  const LABEL = { facts: "evidence", verdict: "verdict", policy: "evidence" };
  const t = c.policy.triggers.map((x) => `${x.id}(${LABEL[x.determinedBy] || x.determinedBy})`).join(" ");
  console.log(`
${id}  ${c.title.slice(0, 68)}
  stages     ${stages.join(" → ")}
  verdict    ${c.verdict.classification} @ ${c.verdict.confidence} → policy confidence ${c.policy.confidence} (threshold ${c.policy.threshold})
  DISPOSITION ${c.policy.disposition}${c.policy.wouldHaveBeen ? ` (would have been ${c.policy.wouldHaveBeen})` : ""}
  triggers   ${t || "none"}
  human said ${c.humanVerdict}  →  ${c.verdict.classification === c.humanVerdict ? "AGREE" : "DISAGREE"}${c.humanVerdict === "True Positive" && c.policy.disposition === "CLOSE" ? "   *** FALSE NEGATIVE — S1 ***" : ""}
  package    ${c.package ? c.package.completeness + "% of " + c.package.sectionCount + " sections" + (c.package.missing.length ? " MISSING: " + c.package.missing.join(", ") : "") : "n/a"}
  chain      ${c.verdict.reasoning_chain.length} hypotheses · ${c.verdict.attack_mapping.length} ATT&CK techniques · injection=${c.verdict.injection_attempt_detected}
  actions    ${c.policy.actions.map((a) => (a.executed ? "EXECUTED " : "withheld ") + a.action).join("; ") || "none"}
  timings    pickup ${c.timings.pickupMs}ms · enrich ${c.timings.enrichmentMs}ms · reason ${c.timings.reasoningMs}ms · total ${c.timings.totalMs}ms · ${c.usage?.totalTokenCount || 0} tokens`);
}

const m = await fetch("http://localhost:8787/api/metrics").then((r) => r.json());
console.log("\n──── metrics ────");
console.log(JSON.stringify(m.metrics, (k, v) => (k === "confidenceDistribution" ? undefined : v), 1));
