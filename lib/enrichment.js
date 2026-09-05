// Parallel enrichment layer — BRD 6.2 steps 3–8, FR-020 to FR-030.
//
// Two properties matter here and both are demonstrated:
//   1. Every source is queried for every alert, concurrently. Enrichment is never skipped.
//   2. A source that is unavailable is RECORDED as a data gap and reduces confidence.
//      It is never silently dropped (FR-027, FR-028, NFR-016).

import {
  identityDirectory, assetInventory, threatIntel, historicalDispositions,
  vipUsers, privilegedAccounts, businessCriticalAssets, playbooks
} from "../data/context.js";
import { alerts as allAlerts } from "../data/alerts.js";

const NEGATION = /\b(no|not|none|never|without|zero)\b/i;

/**
 * Matches a pattern against an alert's evidence, clause by clause, honouring negation — so
 * "no persistence was created" never counts as persistence. Returns the matching clause, or null.
 */
export function clauseMatch(alert, re) {
  for (const clause of alert.rawEvidence.flatMap((l) => l.split(/[,;]/))) {
    const m = clause.match(re);
    if (m && !NEGATION.test(clause.slice(0, m.index))) return clause;
  }
  return null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jitter = (lo, hi) => lo + Math.floor(Math.random() * (hi - lo));

/** Deduplication and correlation — FR-010 to FR-013. */
export function correlate(alert, universe = allAlerts) {
  const observables = new Set([
    ...alert.entities.ips, ...alert.entities.domains,
    ...alert.entities.hashes, ...alert.entities.hosts
  ]);
  const related = [];
  for (const other of universe) {
    if (other.id === alert.id) continue;
    const shared = [];
    for (const o of [...other.entities.ips, ...other.entities.domains, ...other.entities.hashes, ...other.entities.hosts]) {
      if (observables.has(o)) shared.push(o);
    }
    const sharedUsers = other.entities.users.filter((u) => alert.entities.users.includes(u));
    if (shared.length || sharedUsers.length) {
      related.push({
        id: other.id, title: other.title, alertType: other.alertType,
        sharedObservables: shared, sharedUsers,
        crossDomain: other.source !== alert.source
      });
    }
  }

  // Campaign detection.
  //
  // Sharing an indicator is not the same as sharing ATTACKER infrastructure. Two user-reported
  // alerts about the same legitimate newsletter share a domain, and that is not a campaign — it is
  // a coincidence, and treating it as a trigger sends benign alerts to a human for no reason.
  // An indicator every threat-intel feed calls benign is therefore excluded from the assessment.
  const knownBenign = (o) => {
    const hits = threatIntel[o];
    return !!hits?.length && hits.every((h) => h.verdict === "Benign");
  };
  related.forEach((r) => {
    r.benignShared = r.sharedObservables.filter(knownBenign);
    r.suspectShared = r.sharedObservables.filter((o) => !knownBenign(o));
  });
  const infraShared = related.filter((r) => r.suspectShared.length > 0);

  let campaign = null;
  if (infraShared.length >= 1 && infraShared.some((r) => r.crossDomain)) {
    campaign = `Shared attacker infrastructure observed across DIFFERENT detection domains: ${infraShared
      .map((r) => `${r.id} (${r.suspectShared.join(", ")})`).join("; ")}. This is a campaign indicator, not an isolated event.`;
  } else if (infraShared.length >= 1) {
    campaign = `Shared infrastructure with ${infraShared.map((r) => `${r.id} (${r.suspectShared.join(", ")})`).join(", ")} — the same non-benign indicator reused across alerts.`;
  } else if (/(\d+)\s+(distinct\s+)?accounts targeted/i.test(alert.rawEvidence.join(" "))) {
    const m = alert.rawEvidence.join(" ").match(/(\d+)\s+(?:distinct\s+)?accounts targeted/i);
    if (m && Number(m[1]) >= 10) campaign = `Single alert already spans ${m[1]} distinct accounts — pattern across multiple entities.`;
  }

  return { related, campaign, duplicates: [] };
}

async function enrichIdentity(alert) {
  await sleep(jitter(180, 420));
  const out = {};
  for (const u of alert.entities.users) {
    out[u] = identityDirectory[u] || { note: "Identity not found in directory — unresolved principal." };
  }
  const flags = [];
  for (const u of alert.entities.users) {
    if (vipUsers.includes(u)) flags.push(`${u} is on the VIP / high-risk list`);
    if (privilegedAccounts.includes(u)) flags.push(`${u} is a PRIVILEGED or service account`);
  }
  return { source: "Identity provider + HR / identity governance", status: "ok", data: out, flags };
}

async function enrichAsset(alert) {
  await sleep(jitter(150, 380));
  const out = {};
  const flags = [];
  for (const h of alert.entities.hosts) {
    out[h] = assetInventory[h] || { note: "Asset not present in CMDB — coverage gap." };
    if (businessCriticalAssets.includes(h)) flags.push(`${h} is a BUSINESS-CRITICAL asset`);
    if (!assetInventory[h]) flags.push(`${h} is not in the CMDB — asset context is incomplete`);
  }
  const status = alert.entities.hosts.some((h) => !assetInventory[h]) ? "partial" : "ok";
  return { source: "CMDB / asset inventory + EDR device inventory", status, data: out, flags };
}

async function enrichThreatIntel(alert, opts) {
  await sleep(jitter(260, 700));
  if (opts.tiFeedOffline) {
    return {
      source: "Threat intelligence feeds", status: "unavailable",
      data: null, flags: ["All configured threat-intelligence feeds returned a timeout."],
      gap: "Threat intelligence unavailable — no indicator reputation, campaign attribution or first-seen data was retrieved for this alert."
    };
  }
  const observables = [
    ...alert.entities.domains, ...alert.entities.urls.map((u) => { try { return new URL(u).hostname; } catch { return u; } }),
    ...alert.entities.ips, ...alert.entities.hashes
  ];
  const out = {};
  let conflict = null;
  for (const o of new Set(observables)) {
    const hits = threatIntel[o];
    if (hits) {
      out[o] = hits;
      const verdicts = new Set(hits.map((h) => h.verdict));
      if (verdicts.size > 1) {
        conflict = `Feeds DISAGREE on ${o}: ${hits.map((h) => `${h.source} says ${h.verdict} (${h.confidence})`).join("; ")}. Recorded as a conflict; not silently resolved.`;
      }
    } else {
      out[o] = [{ source: "All feeds", verdict: "No data", confidence: 0, firstSeen: "—", campaign: "—" }];
    }
  }
  return { source: "Threat intelligence feeds", status: "ok", data: out, conflict, flags: conflict ? [conflict] : [] };
}

async function enrichHistorical(alert) {
  await sleep(jitter(220, 560));
  const keys = [
    ...alert.entities.users.map((u) => `${alert.alertType}|${u}`),
    ...alert.entities.hosts.map((h) => `${alert.alertType}|${h}`),
    ...alert.entities.domains.map((d) => `${alert.alertType}|${d}`)
  ];
  const out = {};
  let misclassificationWarning = null;
  for (const k of keys) {
    if (historicalDispositions[k]) {
      out[k] = historicalDispositions[k];
      for (const h of historicalDispositions[k]) {
        if (h.laterFoundMisclassified) {
          misclassificationWarning = `A prior disposition for this pattern was LATER FOUND TO BE WRONG: ${h.date} was closed as "${h.disposition}" — ${h.misclassificationNote}`;
        }
      }
    }
  }
  const found = Object.keys(out).length > 0;
  return {
    source: "Historical alert archive (12 months)", status: "ok",
    data: found ? out : { note: "No prior occurrence of this pattern on these entities in 12 months of retained history." },
    misclassificationWarning, flags: misclassificationWarning ? [misclassificationWarning] : []
  };
}

/** Behavioural baseline comparison with quantified deviations — FR-026. */
async function enrichBehavioural(alert) {
  await sleep(jitter(200, 500));
  const deviations = [];
  const hour = new Date(alert.createdAt).getUTCHours();

  for (const u of alert.entities.users) {
    const id = identityDirectory[u];
    if (!id || !id.typicalHours) continue;
    const m = id.typicalHours.match(/(\d{2}):(\d{2})\D+(\d{2}):(\d{2})/);
    if (m) {
      const start = Number(m[1]), end = Number(m[3]);
      if (hour < start || hour >= end) {
        deviations.push({
          dimension: "Time of day", severity: "Medium",
          detail: `Activity at ${String(hour).padStart(2, "0")}:00 UTC falls outside the established working window for ${u} (${id.typicalHours}).`
        });
      }
    }
  }

  // Scan clause by clause and honour negation. "No mailbox rules created" must NOT be read as
  // "mailbox rule created" — a fabricated deviation contradicts the raw evidence, and an agent
  // that is working properly will refuse to close on self-contradicting telemetry.
  const clauses = alert.rawEvidence.flatMap((l) => l.split(/[,;]/));
  const NEGATION = /\b(no|not|none|never|without|zero)\b/i;
  const clauseMatches = (re) => clauses.some((cl) => {
    const m = cl.match(re);
    if (!m) return false;
    return !NEGATION.test(cl.slice(0, m.index));
  });

  const markers = [
    [/unmanaged|unrecognised|unrecognized/i, "Device", "High", "Sign-in or execution occurred from a device that is not managed or not previously seen for this principal."],
    [/tor exit node|anonymis/i, "Source network", "High", "Source address is anonymising infrastructure with no prior history for this principal."],
    [/unsigned/i, "Process lineage", "High", "An unsigned binary is involved — outside the established software baseline for the asset."],
    [/first seen on the estate/i, "Process lineage", "High", "The binary is new to the estate, so no behavioural baseline exists for it."],
    [/anonymous (get|read|access)/i, "Data access", "High", "Anonymous external access was exercised against the resource."],
    [/(\d+) denied mfa/i, "Authentication", "High", "Repeated authentication denials preceding an approval — outside any normal authentication pattern."],
    [/(\d+) distinct accounts targeted|accounts targeted/i, "Breadth", "High", "Authentication activity spans far more accounts than any single principal's baseline."],
    [/inbox rule created|mailbox rule/i, "Post-authentication", "High", "A mail-handling rule was created immediately after authentication — a known BEC staging behaviour."],
    [/new mfa|new device registered|new authenticator/i, "Post-authentication", "High", "A new authentication factor was registered immediately after a suspicious sign-in."]
  ];
  for (const [re, dimension, severity, detail] of markers) {
    if (clauseMatches(re)) deviations.push({ dimension, severity, detail });
  }

  if (!deviations.length) {
    deviations.push({ dimension: "Overall", severity: "None", detail: "Observed activity is consistent with the established baseline for these entities on every dimension measured." });
  }

  const highCount = deviations.filter((d) => d.severity === "High").length;
  return {
    source: "UEBA behavioural baselines", status: "ok",
    data: { deviations, highSeverityDeviationCount: highCount },
    flags: highCount ? [`${highCount} high-severity behavioural deviation(s) from baseline`] : []
  };
}

/** Runs every enrichment source concurrently and reports per-source timing. */
export async function enrichAll(alert, opts, onSourceDone = () => {}) {
  const tasks = [
    ["identity", enrichIdentity(alert)],
    ["asset", enrichAsset(alert)],
    ["threatIntel", enrichThreatIntel(alert, opts)],
    ["historical", enrichHistorical(alert)],
    ["behavioural", enrichBehavioural(alert)]
  ];
  const started = Date.now();
  const results = {};
  await Promise.all(tasks.map(async ([key, p]) => {
    const r = await p;
    r.latencyMs = Date.now() - started;
    results[key] = r;
    onSourceDone(key, r);
  }));

  const dataGaps = [];
  for (const [key, r] of Object.entries(results)) {
    if (r.status === "unavailable") dataGaps.push({ source: r.source, effect: "Mandatory enrichment source unavailable. Confidence reduced by 20 and full confidence is withheld (FR-028).", penalty: 20, detail: r.gap });
    else if (r.status === "partial") dataGaps.push({ source: r.source, effect: "Source returned incomplete data. Confidence reduced by 8.", penalty: 8, detail: r.flags.join("; ") });
  }

  return {
    results,
    dataGaps,
    playbook: playbooks[alert.alertType] || null,
    totalLatencyMs: Date.now() - started
  };
}
