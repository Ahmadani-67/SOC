// Verdict cache.
//
// Live inference is subject to rate limits and quota. A demo that dies mid-sentence because a
// third-party endpoint returned 429 proves nothing about the capability, so every successful
// triage is persisted and can be replayed exactly.
//
// Replay is never silent: a replayed case is flagged in the record and badged in the UI.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "cache");

export function writeCache(id, record) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(record, null, 1));
  } catch { /* cache is an optimisation, never a dependency */ }
}

export function readCache(id) {
  try {
    const f = path.join(dir, `${id}.json`);
    return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : null;
  } catch { return null; }
}

export function cachedIds() {
  try { return fs.readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => f.replace(/\.json$/, "")); }
  catch { return []; }
}
