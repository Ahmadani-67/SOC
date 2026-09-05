// Autonomous Tier 1 — demo console.
// Node 18+ only, no dependencies.  Run:  node server.js

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { alerts, waveNames } from "./data/alerts.js";
import { seedLessons, ACTION_CONFIDENCE, vipUsers, privilegedAccounts, businessCriticalAssets, playbooks } from "./data/context.js";
import { correlate, enrichAll } from "./lib/enrichment.js";
import { buildPrompt, callModel, applyPolicy, buildEscalationPackage, hardTriggers, siemRecord } from "./lib/agent.js";
import { writeCache, readCache, cachedIds } from "./lib/cache.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Configuration comes from config.json, from the environment, or from both.
 *
 * config.json is gitignored precisely because it holds a key, which means a fresh clone does not
 * have one. That is not a reason to crash on startup: the capability is designed to fail safe when
 * the reasoning layer is unreachable, so it must be able to start and demonstrate exactly that.
 * Any alert with a cached verdict still replays in full.
 */
function loadConfig() {
  const file = path.join(__dirname, "config.json");
  let f = {};
  if (fs.existsSync(file)) {
    try {
      f = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (err) {
      console.error(`\n  config.json is not valid JSON — ${err.message}`);
      console.error(`  Fix it, or delete it and use the SOC_* environment variables instead.\n`);
      process.exit(1);
    }
  }
  const num = (v, fallback) => (Number.isFinite(Number(v)) && v !== "" && v != null ? Number(v) : fallback);
  return {
    port: num(process.env.SOC_PORT, num(f.port, 8787)),
    provider: process.env.SOC_PROVIDER || f.provider || "inference endpoint",
    baseUrl: process.env.SOC_BASE_URL || f.baseUrl || "",
    model: process.env.SOC_MODEL || f.model || "",
    fallbackModels: f.fallbackModels || [],
    apiKey: process.env.SOC_API_KEY || f.apiKey || "",
    inferenceTimeoutMs: num(process.env.SOC_TIMEOUT_MS, num(f.inferenceTimeoutMs, 90000)),
    maxCompletionTokens: num(process.env.SOC_MAX_TOKENS, num(f.maxCompletionTokens, 16000)),
    reasoningEffort: process.env.SOC_REASONING_EFFORT || f.reasoningEffort
  };
}

const cfg = loadConfig();

// Versioned artefacts recorded against every verdict — BRD NFR-041, NFR-058.
const CAPABILITY_VERSION = {
  agent: "tier1-triage-agent 0.9.3",
  promptLibrary: "prompts@2026.08.29-1",
  playbookLibrary: "playbooks@4.2.0",
  policyEngine: "policy@1.4.0",
  decoding: "temperature=0.1, top_p=0.9 (pinned)"
};

// Roles and what each may actually do. This is the BRD decision authority matrix (Table 17)
// implemented as a control rather than described in a document: a Tier 2 analyst cannot change an
// autonomy setting here, and the server refuses the request even if the UI is bypassed.
export const ROLES = {
  tier2: {
    id: "tier2", name: "Tier 2 Analyst", short: "Tier 2",
    identity: "human:r.salamanca (Tier 2 Analyst)",
    who: "Mid-level analyst, 2–5 years. Investigates what the agent escalates.",
    lands: "Your escalations — cases the agent handed to you, each with a complete evidence package.",
    job: "You no longer triage. You pick up cases that already arrive enriched, scoped and explained, and you decide what happened and what to do about it.",
    can: [
      "Open any case and read the full 16-section evidence package",
      "Read the reasoning chain — every hypothesis the agent tested",
      "Override any verdict at any time",
      "Submit feedback, which becomes a candidate lesson"
    ],
    cannot: [
      "Approve a lesson — that is Security Administrator authority",
      "Change autonomy, thresholds or scope — SOC Manager authority",
      "Use the kill switch or the actions-disabled switch — SOC Manager authority"
    ],
    perms: { override: true, review: false, lessonApprove: false, config: false }
  },
  supervisor: {
    id: "supervisor", name: "AI Supervisor", short: "Supervisor",
    identity: "human:a.dupont (AI Supervisor, rotating Tier 2 duty)",
    who: "A rotating duty performed by Tier 2 analysts. Not a new headcount.",
    lands: "Your review queue — the daily sample of autonomous closures, plus every alert the agent held for a human.",
    job: "You supervise the agent instead of doing its job. You check a sample of what it closed, decide the cases it was not confident enough to close, and teach it when it is wrong.",
    can: [
      "Everything a Tier 2 analyst can do",
      "Review the daily sample of autonomous closures (control C-07)",
      "Adjudicate held alerts the agent routed for a human decision",
      "Monitor agent health, hold rate and confidence distribution"
    ],
    cannot: [
      "Approve a lesson — that is Security Administrator authority",
      "Change autonomy, thresholds or scope — SOC Manager authority",
      "Use the kill switch or the actions-disabled switch — SOC Manager authority"
    ],
    perms: { override: true, review: true, lessonApprove: false, config: false }
  }
};

const can = (role, perm) => !!ROLES[role]?.perms?.[perm];

/** Deterministic sampling so the demo behaves the same every run. */
function inSample(id, rate) {
  let h = 0;
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return (h % 100) < rate * 100;
}

const freshState = () => ({
  // Per-alert-type autonomy: Wave 1 has earned autonomous closure, the rest still need approval.
  waveAutonomy: { 1: "autonomous", 2: "supervised", 3: "supervised", 4: "supervised" },
  killSwitch: { 1: false, 2: false, 3: false, 4: false },
  actionsEnabled: true,
  tiFeedOffline: false,
  // On by default: the twelve built-in alerts replay their cached verdicts so the demo is instant.
  // Anything without a cached verdict — every alert written in the console — still runs live.
  replayCache: true,
  // FR-095: the sample size is configurable. A real SOC closing thousands of alerts a day reviews
  // a statistically valid fraction. Twelve alerts is not a population you can sample from, so the
  // demo reviews every closure and says so rather than pretending 50% of three is a sample.
  reviewSampleRate: 1.0,
  customAlerts: [],
  cases: {},
  audit: [],
  lessons: JSON.parse(JSON.stringify(seedLessons)),
  agentHealth: "Healthy"
});
let state = freshState();

/** Built-in stream plus anything created in the console during the demo. */
const getAllAlerts = () => [...alerts, ...state.customAlerts];

function audit(actor, action, target, detail, extra = {}) {
  const entry = { seq: state.audit.length + 1, ts: new Date().toISOString(), actor, action, target, detail, ...extra };
  state.audit.push(entry);
  return entry;
}

// ─────────────────────────────── metrics (BRD 8.8) ───────────────────────────────
function metrics() {
  const cases = Object.values(state.cases);
  const done = cases.filter((c) => c.status === "complete");
  const n = done.length;
  const by = (d) => done.filter((c) => c.policy.disposition === d).length;
  const times = done.map((c) => c.timings.totalMs).sort((a, b) => a - b);
  const p = (q) => (times.length ? times[Math.min(times.length - 1, Math.floor(times.length * q))] : 0);

  // Shadow-mode agreement against the retained human verdict — autonomy gate criterion 1.
  const agree = done.filter((c) => c.verdict.classification === c.humanVerdict).length;
  const maliciousTruth = done.filter((c) => c.humanVerdict === "True Positive");
  // A false negative is a genuinely malicious alert the agent CLOSED. This is the critical safety metric.
  const falseNegatives = maliciousTruth.filter((c) => c.policy.disposition === "CLOSE");
  // Escalations Tier 2 would judge unnecessary (ground truth benign but escalated) — NFR-022.
  const fpEscalations = done.filter((c) => c.policy.disposition === "ESCALATE" && c.humanVerdict !== "True Positive");

  const overrides = done.filter((c) => c.override);
  const autonomouslyHandled = done.filter((c) => ["CLOSE", "ESCALATE"].includes(c.policy.disposition) && !c.override);

  return {
    triaged: n,
    dispositions: { CLOSE: by("CLOSE"), ESCALATE: by("ESCALATE"), HOLD: by("HOLD"), SHADOW: by("SHADOW") },
    mttt: { p50: p(0.5), p95: p(0.95), max: times[times.length - 1] || 0 },
    holdRatePct: n ? Math.round((by("HOLD") / n) * 100) : 0,
    escalationRatePct: n ? Math.round((by("ESCALATE") / n) * 100) : 0,
    noHumanTouchPct: n ? Math.round((autonomouslyHandled.length / n) * 100) : 0,
    agreementPct: n ? Math.round((agree / n) * 100) : 0,
    falseNegatives: falseNegatives.map((c) => c.alertId),
    falseNegativeRatePct: maliciousTruth.length ? Math.round((falseNegatives.length / maliciousTruth.length) * 1000) / 10 : 0,
    fpEscalationRatePct: by("ESCALATE") ? Math.round((fpEscalations.length / by("ESCALATE")) * 100) : 0,
    overrideRatePct: n ? Math.round((overrides.length / n) * 100) : 0,
    review: {
      pending: done.filter((c) => c.review?.status === "pending").length,
      reviewed: done.filter((c) => c.review?.status === "reviewed").length,
      notSampled: done.filter((c) => c.review?.status === "not-sampled").length,
      heldPending: done.filter((c) => c.policy.disposition === "HOLD" && !c.adjudication).length,
      sampleRatePct: Math.round(state.reviewSampleRate * 100)
    },
    confidenceDistribution: done.map((c) => ({ id: c.alertId, confidence: c.policy.confidence, disposition: c.policy.disposition })),
    packageCompleteness: done.filter((c) => c.package).every((c) => c.package.completeness === 100) ? 100
      : Math.min(...done.filter((c) => c.package).map((c) => c.package.completeness), 100),
    inference: {
      totalCalls: done.length,
      avgReasoningMs: done.length ? Math.round(done.reduce((s, c) => s + c.timings.reasoningMs, 0) / done.length) : 0,
      totalTokens: done.reduce((s, c) => s + (c.usage?.totalTokenCount || 0), 0)
    },
    agentHealth: state.agentHealth
  };
}

// ─────────────────────────────── the triage pipeline ───────────────────────────────
async function triage(alert, send) {
  const t0 = Date.now();
  const timings = {};

  send("stage", { stage: "pickup", label: "Alert picked up from the stream", detail: `No queue, no analyst selection, no severity filter. Severity "${alert.severity}" affects escalation priority only, never whether the alert is triaged (FR-002).` });
  timings.pickupMs = Date.now() - t0;

  send("stage", { stage: "parse", label: "Parsed and normalised", detail: `Detection rule, rule intent, ${Object.values(alert.entities).flat().length} entities and ${alert.rawEvidence.length} pieces of raw evidence extracted into the internal representation (FR-005).` });

  const correlation = correlate(alert, getAllAlerts());
  send("stage", {
    stage: "correlate", label: "Deduplicated and correlated",
    detail: correlation.related.length
      ? `${correlation.related.length} related alert(s) found: ${correlation.related.map((r) => r.id).join(", ")}.${correlation.campaign ? " Campaign indicator raised." : ""}`
      : "No related alerts in the correlation window.",
    data: correlation
  });

  send("stage", { stage: "enrich-start", label: "Enrichment — all five sources queried concurrently", detail: "Identity, asset, threat intelligence, historical disposition and behavioural baseline. Enrichment is never skipped (FR-020)." });

  const enrichment = await enrichAll(alert, { tiFeedOffline: state.tiFeedOffline }, (key, r) => {
    send("enrich-source", { key, source: r.source, status: r.status, latencyMs: r.latencyMs, flags: r.flags || [] });
  });
  timings.enrichmentMs = enrichment.totalLatencyMs;
  send("stage", { stage: "enrich-done", label: "Enrichment complete", detail: `${enrichment.totalLatencyMs} ms wall clock for all five sources in parallel.${enrichment.dataGaps.length ? ` ${enrichment.dataGaps.length} data gap recorded.` : ""}`, data: { dataGaps: enrichment.dataGaps } });

  // Playbook §3 — the fifteen hard triggers are evaluated in code BEFORE the model is asked
  // anything. Nothing it says can add one or argue one away.
  const triggers = hardTriggers(alert, enrichment, correlation);
  send("stage", {
    stage: "triggers",
    label: triggers.length ? `Playbook check — ${triggers.length} hard trigger(s) fired` : "Playbook check — no hard triggers",
    detail: triggers.length
      ? `${triggers.map((t) => `Trigger ${t.n}: ${t.short}`).join(" · ")}. These override everything and are decided before the model is consulted.`
      : "None of the fifteen 'never close these' triggers apply, so the outcome rests on the analysis."
  });

  const prompt = buildPrompt(alert, enrichment, correlation, state.lessons, triggers);
  const cached = readCache(alert.id);
  let replayed = false;

  let modelResult;
  if (state.replayCache && cached?.verdict) {
    // Only the model's output is replayed. Enrichment ran live a moment ago and the policy gate
    // below runs live too, so every switch — autonomy, kill switch, actions, feed outage — still
    // behaves exactly as it would against live inference.
    replayed = true;
    send("stage", { stage: "reason-start", label: "Thinking — replayed from cache", detail: `Working through the playbook against the evidence. The verdict was cached on ${new Date(cached.decidedAt).toLocaleString()}; enrichment above and the policy gate below both ran live just now.` });
    // Replay is instant, which makes the agent look like it is not doing anything. Pace it so the
    // work is legible — still a fraction of the real 60–160s, and clearly labelled as cached.
    await new Promise((r) => setTimeout(r, 2200 + Math.random() * 1600));
    modelResult = { verdict: cached.verdict, latencyMs: cached.timings.reasoningMs, usage: cached.usage, modelVersion: cached.versions.model };
  } else {
  send("stage", { stage: "reason-start", label: "Reasoning", detail: `Hypotheses formed and tested against the assembled evidence. ${prompt.length.toLocaleString()} characters of evidence sent to the reasoning layer.` });

  try {
    modelResult = await callModel(prompt, cfg,
      (attempt, status, model) => {
        send("stage", { stage: "retry", label: `${model} returned ${status} — retrying (${attempt}/3)`, detail: "Transient failure. The alert is held, not dropped; if the retries are exhausted the capability is declared degraded and the alert routes to the human queue (GP-05, NFR-013)." });
      },
      (from, to, why) => {
        send("stage", { stage: "fallback", label: `${from} ${why} — falling back to ${to}`, detail: "Whichever deployment actually produces the verdict is recorded against it, so the decision stays reproducible and explainable months later (NFR-041, NFR-058)." });
        audit("system", "MODEL_FALLBACK", alert.id, `${from} → ${to} (${why})`);
      });
    state.agentHealth = "Healthy";
  } catch (err) {
    // Fail safe, fail loud — GP-05, NFR-011, NFR-012.
    state.agentHealth = "DEGRADED";
    audit("system", "AGENT_DEGRADED", alert.id, err.message);
    const quota = err.status === 429;
    const refused = err.status === 422;
    send("stage", {
      stage: "error", label: "Reasoning layer unavailable — failing safe",
      detail: `${err.message}\n\nThe alert has been routed to the HUMAN QUEUE and an operational alarm raised to the SOC on-call. No alert is lost and nothing is silently closed (GP-05, NFR-011/012/013).${
        quota ? "\n\nThis is the inference endpoint rate-limiting us after several retries, not a defect in the capability — and note that it produced exactly the designed behaviour." : ""}${
        refused ? "\n\nThe model produced no usable verdict — a refusal, a content-filter block, or a truncated answer. A partial verdict is not a verdict, so it is treated as a failure rather than guessed at." : ""}${
        cached ? " A cached verdict is available: switch on Replay cache to continue the walkthrough." : ""}`
    });
    const failCase = {
      alertId: alert.id, status: "failed-safe", humanVerdict: alert.humanVerdict,
      error: err.message, quotaExhausted: quota, cacheAvailable: !!cached,
      timings: { ...timings, totalMs: Date.now() - t0 }
    };
    state.cases[alert.id] = failCase;
    send("done", { case: failCase, metrics: metrics(), health: state.agentHealth });
    return;
  }
  }

  timings.reasoningMs = modelResult.latencyMs;
  const verdict = modelResult.verdict;
  send("stage", {
    stage: "reason-done", label: "Verdict produced", detail: `${verdict.classification} at confidence ${verdict.confidence}. ${verdict.reasoning_chain.length} hypotheses tested in ${modelResult.latencyMs} ms.${verdict.injection_attempt_detected ? " PROMPT-INJECTION ATTEMPT DETECTED IN ALERT CONTENT." : ""}`,
    data: { classification: verdict.classification, confidence: verdict.confidence, injection: verdict.injection_attempt_detected }
  });

  const policy = applyPolicy({ alert, enrichment, correlation, verdict, state, triggers });
  policy.totalMs = Date.now() - t0;
  const siem = { ...siemRecord({ alert, verdict, policy }), writtenAt: new Date().toISOString(), writtenBy: "agent:tier1-triage-agent" };
  send("stage", {
    stage: "policy", label: "Policy gate applied", detail: `${policy.triggers.length} escalation trigger(s) evaluated against enrichment facts in deterministic code. Disposition: ${policy.disposition}.`,
    data: policy
  });

  // The package is assembled whenever the case would go to Tier 2 — including in shadow mode,
  // where it is recorded but not delivered. Gate criterion 5 requires 100% package completeness
  // to be demonstrated BEFORE autonomy is granted, so it has to be measurable during shadow.
  const wouldEscalate = policy.disposition === "ESCALATE" || policy.wouldHaveBeen === "ESCALATE";
  const pkg = wouldEscalate ? buildEscalationPackage({ alert, enrichment, correlation, verdict, policy }) : null;
  if (pkg) {
    send("stage", {
      stage: "package", label: `Escalation package assembled${policy.disposition === "SHADOW" ? " (recorded, not delivered — shadow mode)" : ""}`,
      detail: `${pkg.sectionCount} mandatory sections, completeness ${pkg.completeness}%.${pkg.missing.length ? ` MISSING: ${pkg.missing.join(", ")} — this is a defect, not an edge case.` : ""}`
    });
  }

  timings.totalMs = Date.now() - t0;

  const record = {
    alertId: alert.id, status: "complete", wave: alert.wave, alertType: alert.alertType,
    title: alert.title, severity: alert.severity,
    verdict, policy, package: pkg, siem, correlation, enrichment: {
      dataGaps: enrichment.dataGaps,
      sources: Object.fromEntries(Object.entries(enrichment.results).map(([k, v]) => [k, { source: v.source, status: v.status, latencyMs: v.latencyMs, flags: v.flags }])),
      playbook: enrichment.playbook
    },
    timings, usage: modelResult.usage,
    versions: { ...CAPABILITY_VERSION, model: modelResult.modelVersion },
    humanVerdict: alert.humanVerdict, humanNote: alert.humanNote,
    decidedAt: new Date().toISOString(), override: null, prompt, replayed,
    // What the AI Supervisor is required to look at. An autonomous closure is not the end of the
    // story: a sample is reviewed daily (C-07), and anything touching a VIP, a privileged account
    // or a critical asset is reviewed every time (C-08).
    review: policy.disposition === "CLOSE"
      ? (() => {
          const sensitive = alert.entities.users.some((u) => vipUsers.includes(u) || privilegedAccounts.includes(u))
            || alert.entities.hosts.some((h) => businessCriticalAssets.includes(h));
          const sampled = sensitive || inSample(alert.id, state.reviewSampleRate);
          return sampled
            ? { required: true, status: "pending", basis: sensitive ? "C-08 — mandatory: a VIP, privileged account or business-critical asset is involved" : (state.reviewSampleRate >= 1 ? "C-07 — daily closure review. Set to every closure here; in production it is a statistically valid sample of a far larger population" : `C-07 — in today's ${Math.round(state.reviewSampleRate * 100)}% random sample of closures`) }
            : { required: false, status: "not-sampled", basis: `Not in today's ${Math.round(state.reviewSampleRate * 100)}% sample. Still fully logged, still reversible, still counted in the accuracy metrics.` };
        })()
      : null
  };
  state.cases[alert.id] = record;
  if (!replayed) writeCache(alert.id, record);

  audit("agent:tier1-triage-agent (machine identity)", `DISPOSITION_${policy.disposition}`, alert.id,
    `${verdict.classification} @ confidence ${policy.confidence}. ${policy.dispositionReason}`,
    { triggers: policy.triggers.map((t) => t.id), versions: record.versions });
  for (const a of policy.actions) {
    audit("agent:tier1-triage-agent (machine identity)", a.executed ? "ACTION_EXECUTED" : "ACTION_WITHHELD", alert.id,
      `${a.label} — ${a.reason}`, { reversal: a.reversal || null });
  }
  if (verdict.injection_attempt_detected) {
    audit("system", "INJECTION_ATTEMPT_DETECTED", alert.id, verdict.injection_evidence);
  }

  send("done", { case: record, metrics: metrics(), health: state.agentHealth });
}

// ───────────────────────────────── http plumbing ─────────────────────────────────
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml" };

function json(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(b) });
  res.end(b);
}

/**
 * Playbook §4 — a disposition you did not record did not happen. When a human changes the outcome,
 * the incident record has to change with it, attributed to them rather than to the agent.
 */
function rewriteSiem(c, who, at) {
  const alert = getAllAlerts().find((a) => a.id === c.alertId);
  if (!alert) return;
  c.siem = { ...siemRecord({ alert, verdict: c.verdict, policy: c.policy }), writtenAt: at, writtenBy: who };
}

/** Accepts an array, or a string split on a separator. Used by the alert composer. */
function toList(v, sep = ",") {
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  if (typeof v === "string") return v.split(sep).map((x) => x.trim()).filter(Boolean);
  return [];
}

function readBody(req) {
  return new Promise((resolve) => {
    let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => { try { resolve(JSON.parse(d || "{}")); } catch { resolve({}); } });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;

  try {
    if (p === "/api/bootstrap") {
      return json(res, 200, {
        alerts: getAllAlerts().map(({ humanVerdict, humanNote, untrustedContent, ...a }) => ({
          ...a, hasUntrustedContent: !!untrustedContent,
          threshold: ACTION_CONFIDENCE,
          hasPlaybook: !!playbooks[a.alertType]
        })),
        // Cases already decided in this session. The browser forgets them on reload; the server
        // does not. Without this the dashboard counts work the alert list cannot show.
        cases: state.cases,
        waveNames, roles: ROLES, alertTypes: Object.keys(playbooks),
        state: publicState(), metrics: metrics(), versions: CAPABILITY_VERSION,
        model: cfg.model, provider: cfg.provider || "inference endpoint",
        actionThreshold: ACTION_CONFIDENCE
      });
    }

    // Create an alert during the demo and watch the agent triage it live.
    if (p === "/api/alerts" && req.method === "POST") {
      const a = await readBody(req);
      const n = state.customAlerts.length + 1;
      const alert = {
        id: `MINE-${String(n).padStart(3, "0")}`, custom: true,
        wave: Number(a.wave) || 1,
        alertType: (a.alertType || "").trim() || "custom.uncategorised",
        title: (a.title || "Untitled alert").slice(0, 200),
        detectionRule: (a.detectionRule || "Manually created in the triage console").slice(0, 200),
        ruleIntent: (a.ruleIntent || "No rule intent was recorded for this detection.").slice(0, 500),
        severity: ["Low", "Medium", "High"].includes(a.severity) ? a.severity : "Medium",
        createdAt: new Date().toISOString(),
        source: a.source || "Manually created",
        entities: {
          users: toList(a.users), mailboxes: toList(a.mailboxes), hosts: toList(a.hosts),
          ips: toList(a.ips), domains: toList(a.domains), urls: toList(a.urls), hashes: toList(a.hashes)
        },
        rawEvidence: toList(a.rawEvidence, "\n").length ? toList(a.rawEvidence, "\n") : ["No evidence lines were supplied."],
        untrustedContent: (a.untrustedContent || "").trim() || null,
        flags: { postExploitation: !!a.postExploitation, relatesToOpenIncident: !!a.relatesToOpenIncident },
        proposedAction: a.proposedAction || null,
        humanVerdict: a.humanVerdict || "Not assessed",
        humanNote: a.humanNote || "No human verdict was recorded — this alert was created in the console, so there is no ground truth to measure agreement against."
      };
      state.customAlerts.push(alert);
      audit(ROLES[a.role]?.identity || "human:unknown", "ALERT_CREATED", alert.id, `${alert.severity} · ${alert.alertType} · ${alert.title}`);
      return json(res, 200, { alert: { ...alert, hasUntrustedContent: !!alert.untrustedContent, threshold: ACTION_CONFIDENCE, hasPlaybook: !!playbooks[alert.alertType] } });
    }

    if (p === "/api/state" && req.method === "POST") {
      const patch = await readBody(req);
      // Replaying cached verdicts and simulating a feed outage are demo-harness controls, not SOC
      // decisions, so anyone may use them. Autonomy, kill switches and the actions switch are
      // governance decisions and are gated.
      const governance = ["waveAutonomy", "killSwitch", "actionsEnabled"].some((k) => k in patch);
      if (governance && !can(patch.role, "config")) {
        return json(res, 403, {
          error: "Not your call.",
          authority: "Changing a confidence threshold, an autonomy setting or a kill switch is SOC Manager authority, via change control (BRD Table 17). The server refuses this even if the interface lets you click it — which is the point of implementing the decision authority matrix rather than describing it.",
          yourRole: ROLES[patch.role]?.name || "unknown"
        });
      }
      const before = JSON.stringify(publicState());
      if (patch.waveAutonomy) Object.assign(state.waveAutonomy, patch.waveAutonomy);
      if (patch.killSwitch) Object.assign(state.killSwitch, patch.killSwitch);
      if (typeof patch.actionsEnabled === "boolean") state.actionsEnabled = patch.actionsEnabled;
      if (typeof patch.tiFeedOffline === "boolean") state.tiFeedOffline = patch.tiFeedOffline;
      if (typeof patch.replayCache === "boolean") state.replayCache = patch.replayCache;
      audit(ROLES[patch.role]?.identity || "human:unknown", governance ? "CONFIG_CHANGE" : "DEMO_CONTROL", "triage-capability", `${before} → ${JSON.stringify(publicState())}`);
      return json(res, 200, { state: publicState(), audit: state.audit.slice(-40) });
    }

    if (p === "/api/triage") {
      const alert = getAllAlerts().find((a) => a.id === url.searchParams.get("id"));
      if (!alert) return json(res, 404, { error: "unknown alert" });
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
      const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      await triage(alert, send);
      res.end();
      return;
    }

    // The AI Supervisor's verdict on the agent's work: correct, or wrong.
    // "Wrong" is not a complaint — the reviewer has to say what it should have been, what should
    // happen to the alert now, and why. Without the why there is nothing to learn from.
    if (p === "/api/review" && req.method === "POST") {
      const { id, outcome, reason, classification, action, role } = await readBody(req);
      if (!can(role, "review")) {
        return json(res, 403, {
          error: "Not your call.",
          authority: "Checking the agent's work is the AI Supervisor duty (BRD Section 12).",
          yourRole: ROLES[role]?.name || "unknown"
        });
      }
      const c = state.cases[id];
      if (!c || c.status !== "complete") return json(res, 404, { error: "no completed case" });
      const who = ROLES[role].identity;

      // Once an alert is with Tier 2 it is out of the supervisor's hands. Pulling a case back from
      // an analyst who may already be working it would be worse than leaving it with them.
      if (c.policy.disposition === "ESCALATE") {
        return json(res, 400, { error: "This alert is already with Tier 2, so it can no longer be changed here." });
      }

      // A held alert is not a judgement on the agent — the agent declined to decide and asked for
      // help. The supervisor supplies the decision, and escalating hands it to Tier 2 for real.
      if (outcome === "close" || outcome === "escalate") {
        if (c.policy.disposition !== "HOLD") return json(res, 400, { error: "That alert is not waiting for a decision." });
        const to = outcome === "escalate" ? "ESCALATE" : "CLOSE";
        const at = new Date().toISOString();
        c.policy.disposition = to;
        c.policy.dispositionReason = to === "ESCALATE"
          ? "The AI was not sure enough to decide, so a supervisor sent it to Tier 2 to investigate."
          : "The AI was not sure enough to decide, so a supervisor reviewed it and closed it.";
        c.decidedByHuman = { by: who, at, to };
        c.adjudication = { outcome, by: who, at, reason: String(reason || "").trim() };
        rewriteSiem(c, who, at);
        audit(who, to === "ESCALATE" ? "HELD_ALERT_ESCALATED" : "HELD_ALERT_CLOSED", id, c.policy.dispositionReason);
        return json(res, 200, { case: c, metrics: metrics(), audit: state.audit.slice(-40) });
      }

      const wrong = outcome === "wrong";

      if (wrong && !String(reason || "").trim()) {
        return json(res, 400, { error: "Say why it was wrong — that reason is what the agent learns from." });
      }

      const record = { outcome, reason: String(reason || "").trim(), by: who, at: new Date().toISOString() };
      if (wrong) {
        // Marking a closure wrong has to actually undo it. The only sensible destinations are
        // "a person investigates it" or "a person looks at it" — closing it again is what was wrong.
        record.correctedTo = classification;
        record.humanAction = action === "HOLD" ? "HOLD" : "ESCALATE";
        c.override = { from: c.verdict.classification, to: classification, reason: record.reason, analyst: who, at: record.at };
        c.policy.disposition = record.humanAction;
        c.policy.dispositionReason = record.humanAction === "ESCALATE"
          ? "A supervisor judged the AI's decision wrong and sent it to Tier 2 to investigate."
          : "A supervisor judged the AI's decision wrong and put it back for a person to look at.";
        c.decidedByHuman = { by: who, at: record.at, to: record.humanAction };
        rewriteSiem(c, who, record.at);
      }

      // A "wrong" that lands the alert back on hold is not the end of the story — someone still has
      // to decide it. So it is recorded separately and the alert stays open for a decision.
      if (wrong) c.markedWrong = record;
      else c.review = { ...c.review, status: "reviewed", ...record };

      audit(who, wrong ? "MARKED_WRONG" : "MARKED_CORRECT", id,
        wrong ? `Should have been ${classification}; ${record.humanAction === "ESCALATE" ? "sent to Tier 2" : "put on hold"}. ${record.reason}` : "AI's decision confirmed.");

      // Wrong verdicts become candidate lessons — reviewed before the agent learns anything.
      if (wrong) {
        const lesson = {
          id: `LSN-${String(1000 + state.lessons.length).slice(1)}`, status: "Pending review", version: 1,
          submittedBy: who, approvedBy: null, scope: c.alertType, text: record.reason, derivedFrom: id,
          conflictsWith: state.lessons.filter((l) => l.scope === c.alertType && l.status === "Approved").map((l) => l.id)
        };
        state.lessons.push(lesson);
        audit("system", "LESSON_CANDIDATE_CREATED", lesson.id, `From ${id}. Pending review.`);
      }
      return json(res, 200, { case: c, lessons: state.lessons, metrics: metrics(), audit: state.audit.slice(-40) });
    }

    if (p === "/api/override" && req.method === "POST") {
      const { id, classification, reason, role } = await readBody(req);
      const c = state.cases[id];
      if (!c || c.status !== "complete") return json(res, 404, { error: "no completed case" });
      c.override = { from: c.verdict.classification, to: classification, reason, analyst: ROLES[role]?.identity || "human:unknown", at: new Date().toISOString() };
      audit(c.override.analyst, "HUMAN_OVERRIDE", id, `Classification changed ${c.override.from} → ${classification}. Reason: ${reason}`);
      // Feedback becomes a candidate lesson — it is NOT adopted until reviewed (GP-06, FR-093, 11.4).
      const lesson = {
        id: `LSN-${String(1000 + state.lessons.length).slice(1)}`, status: "Pending review", version: 1,
        submittedBy: c.override.analyst, approvedBy: null, scope: c.alertType,
        text: reason, derivedFrom: id, conflictsWith: state.lessons.filter((l) => l.scope === c.alertType && l.status === "Approved").map((l) => l.id)
      };
      state.lessons.push(lesson);
      audit("system", "LESSON_CANDIDATE_CREATED", lesson.id, `Derived from override on ${id}. Status: Pending review. ${lesson.conflictsWith.length ? `Potential conflict with ${lesson.conflictsWith.join(", ")} — flagged for a named administrator, not silently merged.` : "No conflict with existing lessons."}`);
      return json(res, 200, { case: c, lessons: state.lessons, metrics: metrics(), audit: state.audit.slice(-40) });
    }

    if (p === "/api/lesson" && req.method === "POST") {
      const { id, action, role } = await readBody(req);
      if (!can(role, "lessonApprove")) {
        return json(res, 403, {
          error: "Not your call.",
          authority: "Approving or rejecting an agent lesson is Security Administrator authority (BRD Table 17). An analyst submits feedback; a named administrator decides whether the agent learns from it. That separation is the whole of control C-17.",
          yourRole: ROLES[role]?.name || "unknown"
        });
      }
      const l = state.lessons.find((x) => x.id === id);
      if (!l) return json(res, 404, { error: "no lesson" });
      const who = ROLES[role].identity;
      if (action === "approve") { l.status = "Approved"; l.approvedBy = who; }
      if (action === "reject") { l.status = "Rejected"; l.approvedBy = who; }
      if (action === "reverse") { l.status = "Reversed"; }
      audit(who, `LESSON_${action.toUpperCase()}`, id, `${l.text.slice(0, 160)}`);
      return json(res, 200, { lessons: state.lessons, audit: state.audit.slice(-40) });
    }

    if (p === "/api/lessons") return json(res, 200, { lessons: state.lessons });
    if (p === "/api/audit") return json(res, 200, { audit: state.audit });
    if (p === "/api/metrics") return json(res, 200, { metrics: metrics(), state: publicState() });
    if (p === "/api/evidence-pack") {
      const c = state.cases[url.searchParams.get("id")];
      if (!c) return json(res, 404, { error: "no case" });
      // Audit evidence pack on demand — FR-104, NFR-053.
      return json(res, 200, {
        generatedAt: new Date().toISOString(), alertId: c.alertId, versions: c.versions,
        verdict: c.verdict, policy: c.policy, enrichment: c.enrichment, package: c.package,
        timings: c.timings, override: c.override,
        auditTrail: state.audit.filter((a) => a.target === c.alertId),
        promptSentToModel: c.prompt
      });
    }
    if (p === "/api/reset" && req.method === "POST") { state = freshState(); return json(res, 200, { ok: true, state: publicState(), metrics: metrics() }); }

    // static
    const file = p === "/" ? "/index.html" : p;
    const full = path.join(__dirname, "public", file);
    if (!full.startsWith(path.join(__dirname, "public"))) { res.writeHead(403); return res.end("forbidden"); }
    if (fs.existsSync(full)) {
      // No caching: during a demo you edit the CSS and reload, and a stale copy is confusing.
      res.writeHead(200, { "content-type": MIME[path.extname(full)] || "application/octet-stream", "cache-control": "no-store" });
      return res.end(fs.readFileSync(full));
    }
    res.writeHead(404); res.end("not found");
  } catch (err) {
    console.error(err);
    if (!res.headersSent) json(res, 500, { error: String(err) });
    else res.end();
  }
});

function publicState() {
  return {
    waveAutonomy: state.waveAutonomy, killSwitch: state.killSwitch,
    actionsEnabled: state.actionsEnabled, tiFeedOffline: state.tiFeedOffline,
    replayCache: state.replayCache, cachedIds: cachedIds(),
    reviewSampleRate: state.reviewSampleRate,
    agentHealth: state.agentHealth, lessons: state.lessons
  };
}

server.listen(cfg.port, () => {
  const configured = cfg.baseUrl && cfg.model && cfg.apiKey;
  const cached = cachedIds();
  console.log(`\n  AI Tier 1 Analyst — demo console`);
  if (configured) {
    console.log(`  Reasoning layer: ${cfg.model} on ${cfg.provider}`);
  } else {
    const missing = [!cfg.baseUrl && "baseUrl", !cfg.model && "model", !cfg.apiKey && "apiKey"].filter(Boolean);
    console.log(`  Reasoning layer: NOT CONFIGURED — missing ${missing.join(", ")}`);
    console.log(`  Copy config.example.json to config.json and fill it in, or set SOC_BASE_URL, SOC_MODEL and SOC_API_KEY.`);
    console.log(cached.length
      ? `  ${cached.length} cached verdict(s) available (${cached.join(", ")}), so those alerts still replay in full.`
      : `  With no cached verdicts, every alert will fail safe to the human queue — which is itself worth seeing.`);
  }
  console.log(`  http://localhost:${cfg.port}\n`);
});

