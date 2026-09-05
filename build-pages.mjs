// Generates the data behind the static GitHub Pages build.
//
// The point of this script is that it invents nothing. It drives the real server over the real
// API and records exactly what came back — the bootstrap payload, and every SSE event of a real
// triage run for each alert. The Pages shim then replays that recording, so the static site is a
// recording of the pipeline rather than a second implementation of it.
//
// Usage:  node server.js          (in one terminal)
//         node build-pages.mjs    (in another)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = process.env.SOC_BUILD_BASE || "http://localhost:8787";

async function api(p) {
  const res = await fetch(`${BASE}${p}`);
  if (!res.ok) throw new Error(`GET ${p} → ${res.status}`);
  return res.json();
}

/** Runs one alert through the real pipeline and keeps every event in order. */
async function record(id) {
  const text = await fetch(`${BASE}/api/triage?id=${encodeURIComponent(id)}`).then((r) => r.text());
  const events = text.split("\n\n").filter(Boolean).map((block) => ({
    event: block.match(/^event: (.+)$/m)?.[1],
    data: JSON.parse(block.match(/^data: ([\s\S]+)$/m)[1])
  }));
  const done = events.find((e) => e.event === "done");
  if (!done) throw new Error(`${id} produced no done event`);
  if (done.data.case.status !== "complete") {
    throw new Error(`${id} did not complete: ${done.data.case.error || done.data.case.status}. Is a verdict cached for it?`);
  }
  return {
    stages: events.filter((e) => e.event === "stage").map((e) => e.data),
    enrichSources: events.filter((e) => e.event === "enrich-source").map((e) => e.data),
    case: done.data.case
  };
}

console.log(`\n  Recording the pipeline from ${BASE}\n`);

let bootstrap;
try {
  bootstrap = await api("/api/bootstrap");
} catch (err) {
  console.error(`  Could not reach the server at ${BASE}.`);
  console.error(`  Start it first:  node server.js\n`);
  process.exit(1);
}

async function setFeed(offline) {
  await fetch(`${BASE}/api/state`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tiFeedOffline: offline, role: "supervisor" })
  });
}

/**
 * Both paths are recorded, so "Break a data source" still works on the static site.
 * With the feed down the verdict is the same replayed model output, but enrichment records a data
 * gap and the policy gate runs live over it — which is the whole point of the beat, and it would be
 * a lie to ship a toggle that quietly did nothing.
 */
async function recordAll(label, offline) {
  await fetch(`${BASE}/api/reset`, { method: "POST" });
  await setFeed(offline);
  const out = {};
  for (const alert of bootstrap.alerts) {
    process.stdout.write(`  ${label.padEnd(9)} ${alert.id} … `);
    out[alert.id] = await record(alert.id);
    const c = out[alert.id].case;
    console.log(`${c.policy.disposition} · ${c.verdict.classification} @ ${c.policy.confidence}`);
  }
  return out;
}

await fetch(`${BASE}/api/reset`, { method: "POST" });
bootstrap = await api("/api/bootstrap");

const runs = await recordAll("healthy", false);
const runsDegraded = await recordAll("feed-down", true);

await setFeed(false);
const lessons = (await api("/api/lessons")).lessons;

// cases are replayed per alert as the visitor runs them, so the recorded bootstrap must start empty.
const out = {
  recordedAt: new Date().toISOString(),
  bootstrap: { ...bootstrap, cases: {}, state: { ...bootstrap.state, tiFeedOffline: false } },
  lessons,
  runs,
  runsDegraded
};

const file = path.join(__dirname, "pages-data.json");
fs.writeFileSync(file, JSON.stringify(out));
const kb = Math.round(fs.statSync(file).size / 1024);
console.log(`\n  Wrote pages-data.json — ${bootstrap.alerts.length} alerts, ${kb} KB\n`);
