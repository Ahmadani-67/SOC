/* ═══════════════════════════════════════════════════════════════════════════════════════════════
   Static replay shim for GitHub Pages.

   GitHub Pages has no server, so the console's API calls have nowhere to go. This intercepts them
   and answers from pages-data.json — a recording of the real server's real responses, produced by
   build-pages.mjs driving the actual pipeline.

   What is genuinely replayed: every triage run, stage by stage, including the recorded degraded run
   used when the threat-intel feed is switched off. Those are real outputs of the real code.

   What is re-implemented here: metrics(), siemRecord() and the /api/review branch, ported from
   server.js so the dashboard and the supervisor's decisions still work. They are a second
   implementation and can drift from the server — the banner says so, and Render runs the real one.

   Loaded as a classic script BEFORE public/app.js (a deferred module), so the patches are in place
   before boot() runs.
   ═══════════════════════════════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  var nativeFetch = window.fetch.bind(window);
  var loading = nativeFetch("pages-data.json").then(function (r) {
    if (!r.ok) throw new Error("pages-data.json " + r.status);
    return r.json();
  });

  var D = null;                       // the recording
  var S = null;                       // this visitor's session
  var clone = function (v) { return JSON.parse(JSON.stringify(v)); };
  var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

  function fresh() {
    return {
      cases: {},
      lessons: clone(D.lessons || []),
      audit: [],
      tiFeedOffline: false,
      replayCache: true
    };
  }

  function ready() {
    return loading.then(function (data) {
      if (!D) { D = data; S = fresh(); }
      return D;
    });
  }

  var ROLES = function () { return (D.bootstrap && D.bootstrap.roles) || {}; };
  var can = function (role, perm) {
    var r = ROLES()[role];
    return !!(r && r.perms && r.perms[perm]);
  };

  function audit(actor, action, target, detail) {
    S.audit.push({ seq: S.audit.length + 1, ts: new Date().toISOString(), actor: actor, action: action, target: target, detail: detail });
  }

  function publicState() {
    var base = clone(D.bootstrap.state || {});
    base.tiFeedOffline = S.tiFeedOffline;
    base.replayCache = S.replayCache;
    base.lessons = S.lessons;
    base.agentHealth = "Healthy";
    return base;
  }

  /* ── metrics(), ported from server.js ───────────────────────────────────────────────────────── */
  function metrics() {
    var all = Object.keys(S.cases).map(function (k) { return S.cases[k]; });
    var done = all.filter(function (c) { return c.status === "complete"; });
    var n = done.length;
    var by = function (d) { return done.filter(function (c) { return c.policy.disposition === d; }).length; };
    var times = done.map(function (c) { return c.timings.totalMs; }).sort(function (a, b) { return a - b; });
    var p = function (q) { return times.length ? times[Math.min(times.length - 1, Math.floor(times.length * q))] : 0; };

    var agree = done.filter(function (c) { return c.verdict.classification === c.humanVerdict; }).length;
    var maliciousTruth = done.filter(function (c) { return c.humanVerdict === "True Positive"; });
    var falseNegatives = maliciousTruth.filter(function (c) { return c.policy.disposition === "CLOSE"; });
    var fpEscalations = done.filter(function (c) { return c.policy.disposition === "ESCALATE" && c.humanVerdict !== "True Positive"; });
    var overrides = done.filter(function (c) { return c.override; });
    var autonomous = done.filter(function (c) { return ["CLOSE", "ESCALATE"].indexOf(c.policy.disposition) >= 0 && !c.override; });
    var withPkg = done.filter(function (c) { return c.package; });

    return {
      triaged: n,
      dispositions: { CLOSE: by("CLOSE"), ESCALATE: by("ESCALATE"), HOLD: by("HOLD"), SHADOW: by("SHADOW") },
      mttt: { p50: p(0.5), p95: p(0.95), max: times[times.length - 1] || 0 },
      holdRatePct: n ? Math.round((by("HOLD") / n) * 100) : 0,
      escalationRatePct: n ? Math.round((by("ESCALATE") / n) * 100) : 0,
      noHumanTouchPct: n ? Math.round((autonomous.length / n) * 100) : 0,
      agreementPct: n ? Math.round((agree / n) * 100) : 0,
      falseNegatives: falseNegatives.map(function (c) { return c.alertId; }),
      falseNegativeRatePct: maliciousTruth.length ? Math.round((falseNegatives.length / maliciousTruth.length) * 1000) / 10 : 0,
      fpEscalationRatePct: by("ESCALATE") ? Math.round((fpEscalations.length / by("ESCALATE")) * 100) : 0,
      overrideRatePct: n ? Math.round((overrides.length / n) * 100) : 0,
      review: {
        pending: done.filter(function (c) { return c.review && c.review.status === "pending"; }).length,
        reviewed: done.filter(function (c) { return c.review && c.review.status === "reviewed"; }).length,
        notSampled: done.filter(function (c) { return c.review && c.review.status === "not-sampled"; }).length,
        heldPending: done.filter(function (c) { return c.policy.disposition === "HOLD" && !c.adjudication; }).length,
        sampleRatePct: 100
      },
      confidenceDistribution: done.map(function (c) { return { id: c.alertId, confidence: c.policy.confidence, disposition: c.policy.disposition }; }),
      packageCompleteness: withPkg.every(function (c) { return c.package.completeness === 100; })
        ? 100
        : Math.min.apply(null, withPkg.map(function (c) { return c.package.completeness; }).concat([100])),
      inference: {
        totalCalls: done.length,
        avgReasoningMs: done.length ? Math.round(done.reduce(function (s, c) { return s + c.timings.reasoningMs; }, 0) / done.length) : 0,
        totalTokens: done.reduce(function (s, c) { return s + ((c.usage && c.usage.totalTokenCount) || 0); }, 0)
      },
      agentHealth: "Healthy"
    };
  }

  /* ── siemRecord(), ported from lib/agent.js ─────────────────────────────────────────────────── */
  function siemRecord(verdict, policy) {
    var d = policy.disposition;
    var fp = policy.closeKind === "False positive";
    if (d === "CLOSE") {
      return {
        Resolution: fp ? "FalsePositive" : "TruePositive",
        Status: "Manually Cleared",
        "Cleared Reason": (fp ? "Why the rule was wrong: " : "Authorised activity: ") + verdict.innocent_explanation,
        Comments: "Both explanations, the evidence, and the deciding fact — recorded on the incident.",
        Tag: ["Disposition:" + policy.closeKind, fp ? "tuning" : null, policy.playbookVersion].filter(Boolean).join(" · "),
        Case: "No"
      };
    }
    if (d === "HOLD") {
      return {
        Resolution: "Open", Status: "Active", "Cleared Reason": "Not set",
        Comments: "Waiting for: " + (policy.hold && policy.hold.waitingFor) + ". Owed by: " + (policy.hold && policy.hold.whoCanAnswer) + ". Expires: " + (policy.hold && policy.hold.expiresAt) + ". On expiry it escalates.",
        Tag: ["Disposition:Hold", policy.playbookVersion].join(" · "),
        Case: "No"
      };
    }
    return {
      Resolution: "InProgress", Status: "Active", "Cleared Reason": "Not set",
      Comments: "Both explanations, the evidence, the deciding fact, plus a pointer to the escalation package.",
      Tag: ["Disposition:Escalate", policy.triggers.length ? "Trigger:" + policy.triggers.map(function (t) { return t.n; }).join("/") : "Reason:PlaybookCloseTestFailed", policy.playbookVersion].join(" · "),
      Case: "Create one and assign to Tier 2"
    };
  }

  function rewriteSiem(c, who, at) {
    c.siem = siemRecord(c.verdict, c.policy);
    c.siem.writtenAt = at;
    c.siem.writtenBy = who;
  }

  /* ── the routes ─────────────────────────────────────────────────────────────────────────────── */
  function reply(status, obj) {
    return new Response(JSON.stringify(obj), {
      status: status,
      headers: { "content-type": "application/json; charset=utf-8" }
    });
  }

  function bootstrap() {
    var b = clone(D.bootstrap);
    b.cases = clone(S.cases);
    b.state = publicState();
    b.metrics = metrics();
    return b;
  }

  function handleReview(body) {
    var role = body.role;
    if (!can(role, "review")) {
      return reply(403, {
        error: "Not your call.",
        authority: "Checking the agent's work is the AI Supervisor duty (BRD Section 12).",
        yourRole: (ROLES()[role] && ROLES()[role].name) || "unknown"
      });
    }
    var c = S.cases[body.id];
    if (!c || c.status !== "complete") return reply(404, { error: "no completed case" });
    var who = ROLES()[role].identity;

    if (c.policy.disposition === "ESCALATE") {
      return reply(400, { error: "This alert is already with Tier 2, so it can no longer be changed here." });
    }

    if (body.outcome === "close" || body.outcome === "escalate") {
      if (c.policy.disposition !== "HOLD") return reply(400, { error: "That alert is not waiting for a decision." });
      var to = body.outcome === "escalate" ? "ESCALATE" : "CLOSE";
      var at = new Date().toISOString();
      c.policy.disposition = to;
      c.policy.dispositionReason = to === "ESCALATE"
        ? "The AI was not sure enough to decide, so a supervisor sent it to Tier 2 to investigate."
        : "The AI was not sure enough to decide, so a supervisor reviewed it and closed it.";
      c.decidedByHuman = { by: who, at: at, to: to };
      c.adjudication = { outcome: body.outcome, by: who, at: at, reason: String(body.reason || "").trim() };
      rewriteSiem(c, who, at);
      audit(who, to === "ESCALATE" ? "HELD_ALERT_ESCALATED" : "HELD_ALERT_CLOSED", body.id, c.policy.dispositionReason);
      return reply(200, { case: c, metrics: metrics(), audit: S.audit.slice(-40) });
    }

    var wrong = body.outcome === "wrong";
    if (wrong && !String(body.reason || "").trim()) {
      return reply(400, { error: "Say why it was wrong — that reason is what the agent learns from." });
    }

    var rec = { outcome: body.outcome, reason: String(body.reason || "").trim(), by: who, at: new Date().toISOString() };
    if (wrong) {
      rec.correctedTo = body.classification;
      rec.humanAction = body.action === "HOLD" ? "HOLD" : "ESCALATE";
      c.override = { from: c.verdict.classification, to: body.classification, reason: rec.reason, analyst: who, at: rec.at };
      c.policy.disposition = rec.humanAction;
      c.policy.dispositionReason = rec.humanAction === "ESCALATE"
        ? "A supervisor judged the AI's decision wrong and sent it to Tier 2 to investigate."
        : "A supervisor judged the AI's decision wrong and put it back for a person to look at.";
      c.decidedByHuman = { by: who, at: rec.at, to: rec.humanAction };
      rewriteSiem(c, who, rec.at);
      c.markedWrong = rec;
    } else {
      c.review = Object.assign({}, c.review, { status: "reviewed" }, rec);
    }

    audit(who, wrong ? "MARKED_WRONG" : "MARKED_CORRECT", body.id,
      wrong ? "Should have been " + body.classification + ". " + rec.reason : "AI's decision confirmed.");

    if (wrong) {
      var lesson = {
        id: "LSN-" + String(1000 + S.lessons.length).slice(1),
        status: "Pending review", version: 1, submittedBy: who, approvedBy: null,
        scope: c.alertType, text: rec.reason, derivedFrom: body.id,
        conflictsWith: S.lessons.filter(function (l) { return l.scope === c.alertType && l.status === "Approved"; }).map(function (l) { return l.id; })
      };
      S.lessons.push(lesson);
      audit("system", "LESSON_CANDIDATE_CREATED", lesson.id, "From " + body.id + ". Pending review.");
    }
    return reply(200, { case: c, lessons: S.lessons, metrics: metrics(), audit: S.audit.slice(-40) });
  }

  function route(pathname, init) {
    var method = (init && init.method) || "GET";
    var body = {};
    if (init && init.body) { try { body = JSON.parse(init.body); } catch (e) { body = {}; } }

    if (pathname === "/api/bootstrap") return reply(200, bootstrap());
    if (pathname === "/api/metrics") return reply(200, { metrics: metrics(), state: publicState() });
    if (pathname === "/api/audit") return reply(200, { audit: S.audit });
    if (pathname === "/api/lessons") return reply(200, { lessons: S.lessons });

    if (pathname === "/api/reset" && method === "POST") {
      S = fresh();
      return reply(200, { ok: true, state: publicState(), metrics: metrics() });
    }

    if (pathname === "/api/state" && method === "POST") {
      var governance = ["waveAutonomy", "killSwitch", "actionsEnabled"].some(function (k) { return k in body; });
      if (governance && !can(body.role, "config")) {
        return reply(403, {
          error: "Not your call.",
          authority: "Changing a confidence threshold, an autonomy setting or a kill switch is SOC Manager authority, via change control (BRD Table 17). The server refuses this even if the interface lets you click it.",
          yourRole: (ROLES()[body.role] && ROLES()[body.role].name) || "unknown"
        });
      }
      if (typeof body.tiFeedOffline === "boolean") S.tiFeedOffline = body.tiFeedOffline;
      if (typeof body.replayCache === "boolean") S.replayCache = body.replayCache;
      return reply(200, { state: publicState(), audit: S.audit.slice(-40) });
    }

    if (pathname === "/api/review" && method === "POST") return handleReview(body);

    if (pathname === "/api/override" && method === "POST") {
      var c = S.cases[body.id];
      if (!c || c.status !== "complete") return reply(404, { error: "no completed case" });
      c.override = {
        from: c.verdict.classification, to: body.classification, reason: body.reason,
        analyst: (ROLES()[body.role] && ROLES()[body.role].identity) || "human:unknown",
        at: new Date().toISOString()
      };
      return reply(200, { case: c, lessons: S.lessons, metrics: metrics(), audit: S.audit.slice(-40) });
    }

    if (pathname === "/api/evidence-pack") {
      var ec = S.cases[new URLSearchParams(pathname.split("?")[1] || "").get("id")];
      return reply(ec ? 200 : 404, ec || { error: "no case" });
    }

    return reply(404, { error: "not found in the static build" });
  }

  window.fetch = function (input, init) {
    var url = typeof input === "string" ? input : (input && input.url) || String(input);
    var pathname;
    try { pathname = new URL(url, location.href).pathname; } catch (e) { pathname = url; }
    // Pages serves the site under /SOC/, so match on the suffix rather than an absolute path.
    var idx = pathname.indexOf("/api/");
    if (idx === -1) return nativeFetch(input, init);
    var apiPath = pathname.slice(idx);
    return ready().then(function () { return route(apiPath, init); });
  };

  /* ── EventSource replacement for /api/triage ────────────────────────────────────────────────── */
  // Pacing only. app.js queues stages and drains them on its own timer, so this just needs to feed
  // them in order, with a pause where the model would really have been thinking.
  var GAP = 190, THINK = 1500;

  function StaticEventSource(url) {
    this._listeners = {};
    this._closed = false;
    this.onerror = null;
    var self = this;
    ready().then(function () { return self._run(url); }).catch(function () {
      if (self.onerror) self.onerror(new Event("error"));
    });
  }
  StaticEventSource.prototype.addEventListener = function (type, fn) {
    (this._listeners[type] = this._listeners[type] || []).push(fn);
  };
  StaticEventSource.prototype.removeEventListener = function (type, fn) {
    var l = this._listeners[type] || [];
    var i = l.indexOf(fn);
    if (i >= 0) l.splice(i, 1);
  };
  StaticEventSource.prototype.close = function () { this._closed = true; };
  StaticEventSource.prototype._emit = function (type, data) {
    if (this._closed) return;
    (this._listeners[type] || []).forEach(function (fn) {
      fn({ data: JSON.stringify(data), type: type });
    });
  };
  StaticEventSource.prototype._run = function (url) {
    var self = this;
    var id;
    try { id = new URL(url, location.href).searchParams.get("id"); } catch (e) { id = null; }

    var set = S.tiFeedOffline ? D.runsDegraded : D.runs;
    var run = (set && set[id]) || (D.runs && D.runs[id]);
    if (!run) {
      // An alert with no recording cannot be replayed. Say so rather than hanging.
      self._emit("stage", {
        stage: "error",
        label: "Not available in the static preview",
        detail: "This alert has no recorded run in the Pages build. Run the project locally or open the hosted console to triage it for real."
      });
      self._emit("done", {
        case: { alertId: id, status: "failed-safe", error: "No recorded run for this alert in the static preview.", timings: { totalMs: 0 } },
        metrics: metrics(),
        health: "Healthy"
      });
      return Promise.resolve();
    }

    var chain = Promise.resolve();
    run.stages.forEach(function (s) {
      chain = chain.then(function () {
        if (self._closed) return;
        return sleep(s.stage === "reason-done" ? THINK : GAP).then(function () { self._emit("stage", s); });
      });
    });
    return chain.then(function () {
      if (self._closed) return;
      var c = clone(run.case);
      S.cases[c.alertId] = c;
      self._emit("done", { case: c, metrics: metrics(), health: "Healthy" });
    });
  };

  window.EventSource = StaticEventSource;
})();
