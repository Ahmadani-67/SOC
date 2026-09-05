const $ = (s) => document.querySelector(s);
const el = (t, c, h) => { const n = document.createElement(t); if (c) n.className = c; if (h != null) n.innerHTML = h; return n; };
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));
const secs = (n) => (n >= 1000 ? (n / 1000).toFixed(1) + "s" : n + "ms");

let DATA = { alerts: [], roles: {}, state: {}, metrics: {} };
let cases = {}, role = null, selected = null, tab = "summary", filter = "all";
let busy = false, streaming = false, watch = false;
let query = "", sortBy = "new";
const opened = new Set();

/** Everything about an alert you might reasonably search for. */
const haystack = (a) => [a.id, a.title, a.alertType, a.severity, ...Object.values(a.entities || {}).flat()]
  .join(" ").toLowerCase();

const ENT_LABEL = { users: "People", mailboxes: "Mailboxes", hosts: "Devices", ips: "Addresses",
  domains: "Web addresses", urls: "Links", hashes: "Files" };

/* ── plain english ─────────────────────────────────────────────────────────
   Everything a non-specialist reads is in the first column. The security term
   is kept as small secondary text so an analyst still sees the real word. */
const VERDICT = {
  "True Positive":          { s: "Real threat",          d: "This is genuine malicious activity." },
  "False Positive":         { s: "False alarm",          d: "The alarm fired, but nothing actually happened." },
  "Benign True Positive":   { s: "Real but allowed",     d: "It did happen, and it was authorised." },
  "Duplicate":              { s: "Already covered",      d: "Another alert already covers this." },
  "Insufficient Information": { s: "Not enough to tell", d: "The evidence does not support a confident answer." }
};
/* Three outcomes, named the same way everywhere: Escalated, Hold, Closed. */
const OUTCOME = {
  ESCALATE: { ic: "▲", t: "Escalated", d: "A person needs to look at this. It arrives with the full background already gathered." },
  CLOSE:    { ic: "✓", t: "Closed",    d: "Nothing needed a person. The reasoning is kept and a sample gets checked." },
  HOLD:     { ic: "⏸", t: "Hold",      d: "The AI was not sure enough to decide on its own, so it is waiting for a person." },
  FAILED:   { ic: "✕", t: "Stopped safely", d: "The AI could not answer, so it handed the alert to a person and raised an alarm." }
};
const BLURB = {
  tier2: "You investigate what the AI sends you.",
  supervisor: "You check the AI's work and decide the cases it wasn't sure about."
};
/* A small mark per role, so the three sign-in cards read as three different jobs at a glance. */
const ROLE_ICON = {
  tier2: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4.3-4.3"/></svg>',
  supervisor: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1.5 12S5 5 12 5s10.5 7 10.5 7-3.5 7-10.5 7S1.5 12 1.5 12z"/><circle cx="12" cy="12" r="3"/></svg>'
};
const initials = (s) => String(s).split(/\s+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase();
const DOMAIN = { email: "Email", identity: "Accounts", endpoint: "Devices", cloud: "Cloud", custom: "Custom" };
const domainOf = (t) => DOMAIN[String(t).split(".")[0]] || "Other";
// The playbook's seven steps, condensed into what the screen can show.
const STEPS = ["Received", "Linked up", "Background checks", "Never-close rules", "Thinking", "Decision"];
const STEP_AT = { pickup: 0, parse: 0, correlate: 1, "enrich-start": 2, "enrich-done": 2, triggers: 3,
  "reason-start": 4, retry: 4, fallback: 4, "reason-done": 4, policy: 5, package: 5 };

/* ── boot ── */
async function boot() {
  DATA = await fetch("/api/bootstrap").then((r) => r.json());
  // Pick up anything already triaged in this session, so the alert list and the dashboard
  // never disagree about what has happened.
  cases = DATA.cases || {};
  $("#loginFoot").textContent = `${DATA.alerts.length} alerts · ${DATA.model}`;
  $("#roleCards").innerHTML = "";
  for (const r of Object.values(DATA.roles)) {
    const c = el("button", "rc", `<div class="ri">${ROLE_ICON[r.id] || ""}</div>
      <h3>${esc(r.name)}</h3><p>${esc(BLURB[r.id])}</p>
      <div class="go">Sign in <span>→</span></div>`);
    c.onclick = () => signIn(r.id);
    $("#roleCards").append(c);
  }
}

function signIn(id) {
  role = DATA.roles[id];
  filter = id === "tier2" ? "all" : id === "supervisor" ? "todo" : "all";
  $("#login").hidden = true; $("#app").hidden = false;
  $("#roleName").textContent = role.name;
  $("#roleInitial").textContent = initials(role.name);
  selected = null; $("#case").hidden = true;
  go("dash"); drawEmpty(); drawQueue(); drawSide();
}
$("#switchRole").onclick = () => { $("#app").hidden = true; $("#login").hidden = false; };
$("#helpBtn").onclick = () => showHelp();

/* ── pages ── */
let page = "dash";
function go(p, opts = {}) {
  page = p;
  $("#pageDash").hidden = p !== "dash";
  $("#pageAlerts").hidden = p !== "alerts";
  $("#nav").querySelectorAll("[data-p]").forEach((b) => b.classList.toggle("on", b.dataset.p === p));
  if (p === "dash") drawDash();
  else { if (opts.filter) filter = opts.filter; drawQueue(); if (opts.openId) open(opts.openId); }
}
$("#nav").querySelectorAll("[data-p]").forEach((b) => b.onclick = () => go(b.dataset.p));

/* ── collapsible panels ── */
const panes = { L: false, R: false };
function togglePane(side) {
  panes[side] = !panes[side];
  $("#grid").classList.toggle("no" + side, panes[side]);
  const b = $(side === "L" ? "#tglLeft" : "#tglRight");
  b.classList.toggle("off", panes[side]);
  b.title = `${panes[side] ? "Show" : "Hide"} the ${side === "L" ? "list" : "panel"} (press ${side === "L" ? "[" : "]"} )`;
}
$("#tglLeft").onclick = () => togglePane("L");
$("#tglRight").onclick = () => togglePane("R");

/* ── queue ── */
const needsMe = (a) => {
  const c = cases[a.id];
  if (!c || c.status !== "complete") return false;
  // Anything on hold still needs a decision, including one a supervisor put back there.
  return c.policy.disposition === "HOLD" || c.review?.status === "pending";
};
// Tier 2 sees only what was sent to them. The raw stream is no longer a human queue.
const mine = () => role.id !== "tier2" ? DATA.alerts
  : DATA.alerts.filter((a) => cases[a.id] && (cases[a.id].policy?.disposition === "ESCALATE" || cases[a.id].status === "failed-safe"));

function drawQueue() {
  const vis = mine();
  const n = (d) => vis.filter((a) => cases[a.id]?.policy?.disposition === d).length;
  const counts = { all: vis.length, todo: vis.filter(needsMe).length, new: vis.filter((a) => !cases[a.id]).length,
    ESCALATE: n("ESCALATE"), CLOSE: n("CLOSE"), HOLD: n("HOLD") };
  const defs = role.id === "tier2" ? [["all", "All"]]
    : [["todo", "Needs me"], ["all", "All"], ["ESCALATE", "Escalated"], ["HOLD", "Hold"], ["CLOSE", "Closed"]];
  if (!defs.some(([k]) => k === filter)) filter = defs[0][0];

  $("#filters").innerHTML = defs.map(([k, l]) =>
    `<button class="fc ${filter === k ? "on" : ""}" data-f="${k}">${l}<b>${counts[k] ?? 0}</b></button>`).join("");
  $("#filters").querySelectorAll("[data-f]").forEach((b) => b.onclick = () => { filter = b.dataset.f; drawQueue(); });

  const SEV = { High: 3, Medium: 2, Low: 1 };
  const list = vis.filter((a) => {
    if (query && !haystack(a).includes(query)) return false;
    if (filter === "all") return true;
    if (filter === "todo") return needsMe(a);
    if (filter === "new") return !cases[a.id];
    return cases[a.id]?.policy?.disposition === filter;
  }).sort((a, b) => {
    if (sortBy === "sev") return (SEV[b.severity] - SEV[a.severity]) || (new Date(b.createdAt) - new Date(a.createdAt));
    if (sortBy === "conf") return (cases[a.id]?.policy.confidence ?? 999) - (cases[b.id]?.policy.confidence ?? 999);
    return new Date(b.createdAt) - new Date(a.createdAt);
  });

  const box = $("#queueList"); box.innerHTML = "";

  if (role.id === "tier2") {
    const done = DATA.alerts.filter((a) => cases[a.id]?.status === "complete").length;
    if (done) box.append(el("div", "note green", `<b>${counts.ESCALATE} of ${done}</b> alerts reached you. The AI dealt with the rest.`));
  }
  if (!list.length) {
    box.append(el("p", "pt", query ? `Nothing matches "${esc(query)}".` : "Nothing here yet."));
    $("#navCount").textContent = mine().length || "";
    return;
  }

  for (const a of list) {
    const c = cases[a.id];
    const d = c?.status === "failed-safe" ? "FAILED" : c?.policy?.disposition;
    const node = el("div", `card ${selected === a.id ? "on " : ""}${d || ""}`);
    node.dataset.id = a.id;
    node.innerHTML = `
      <div class="r1"><span class="id">${a.id}</span><span class="tag ${a.severity}">${a.severity}</span>
        <span class="tag dom">${domainOf(a.alertType)}</span>${a.custom ? '<span class="tag mine">yours</span>' : ""}
        ${d ? `<span class="tag ${d}" style="margin-left:auto">${OUTCOME[d].t.toUpperCase()}</span>` : ""}</div>
      <div class="t">${esc(a.title)}</div>
      <div class="r2"><span>${new Date(a.createdAt).toISOString().slice(11, 16)}</span>
        ${c?.status === "complete" ? `<span>·</span><span>${c.policy.confidence}% sure</span><span>·</span><span>${secs(c.timings.totalMs)}</span>` : ""}</div>
      ${needsMe(a) ? `<div class="todo">▸ ${c.policy.disposition === "HOLD" ? "Needs your decision" : "Needs your check"}</div>` : ""}`;
    node.onclick = () => open(a.id);
    box.append(node);
  }
  $("#navCount").textContent = mine().length || "";
}

/* ── search & sort ── */
$("#q").oninput = (e) => { query = e.target.value.trim().toLowerCase(); drawQueue(); };
$("#sort").onchange = (e) => { sortBy = e.target.value; drawQueue(); };

function open(id) {
  selected = id; opened.add(id);
  const a = DATA.alerts.find((x) => x.id === id);
  $("#empty").hidden = true; $("#case").hidden = false;
  $("#crumbs").innerHTML = `<span class="id" style="font-family:var(--mono);font-size:12px;color:var(--dim)">${a.id}</span>
    <span class="tag ${a.severity}">${a.severity}</span><span class="tag dom">${domainOf(a.alertType)}</span>
    ${a.custom ? '<span class="tag mine">yours</span>' : ""}`;
  $("#caseTitle").textContent = a.title;
  $("#pipe").innerHTML = ""; $("#livePanel").hidden = true;
  const c = cases[id];
  if (c?.status === "complete") { drawSteps(9); drawProcess(c); drawCase(c); }
  else if (c) { drawSteps(3, 3); drawFailed(c); }
  else { drawSteps(-1); drawNotRun(a); }
  drawQueue(); drawSide();
}

/* ── pipeline ── */
function drawSteps(at, bad) {
  $("#steps").innerHTML = STEPS.map((l, i) =>
    `<div class="st ${bad === i ? "bad" : at > i ? "done" : at === i ? "now" : ""}">
      <div class="d">${bad === i ? "✕" : at > i ? "✓" : ""}</div><div class="l">${l}</div></div>`).join("");
}

function drawNotRun(a) {
  $("#verdictCard").innerHTML = "";
  $("#tabs").innerHTML = "";
  $("#tabBody").innerHTML = "";
  const b = el("div", "empty", `<div class="big">▶</div><h2>Not looked at yet</h2>
    <p>Run the AI over this alert and watch what it does.</p>`);
  const btn = el("button", "btn primary", "Run the AI on this alert");
  btn.onclick = () => runOne(a.id);
  b.append(btn);
  $("#tabBody").append(b);
}

/* The steps after "Thinking" all land within a few milliseconds of each other, so played back at
   full speed the process looks like it stalls on Thinking and then jumps to the answer. Stages are
   queued and drained on a timer so every step is actually legible, and the finished list stays on
   screen instead of vanishing the moment the verdict appears. */
let pipeQ = [], pipeTimer = null, onDrained = null;

function pushStage(s) {
  pipeQ.push(s);
  if (!pipeTimer) pipeTimer = setInterval(drainPipe, 220);
}
function drainPipe() {
  const s = pipeQ.shift();
  if (!s) {
    clearInterval(pipeTimer); pipeTimer = null;
    if (onDrained) { const fn = onDrained; onDrained = null; fn(); }
    return;
  }
  if (s.stage === "error") drawSteps(3, 3);
  else if (STEP_AT[s.stage] != null) drawSteps(STEP_AT[s.stage]);
  $("#pipe").append(el("li", null, `<b>${esc(s.label)}</b>`));
  $("#pipe").scrollTop = $("#pipe").scrollHeight;
}

function runOne(id, quiet = false) {
  if (busy) return Promise.resolve();
  busy = true;
  if (!quiet) {
    pipeQ = []; onDrained = null;
    if (pipeTimer) { clearInterval(pipeTimer); pipeTimer = null; }
    $("#livePanel").hidden = false; $("#pipe").innerHTML = "";
    $("#tabBody").innerHTML = ""; $("#verdictCard").innerHTML = ""; $("#tabs").innerHTML = "";
    drawSteps(0);
  }
  return new Promise((res) => {
    const es = new EventSource(`/api/triage?id=${encodeURIComponent(id)}`);
    es.addEventListener("stage", (e) => { if (!quiet) pushStage(JSON.parse(e.data)); });
    es.addEventListener("done", (e) => {
      const d = JSON.parse(e.data);
      cases[id] = d.case; DATA.metrics = d.metrics; DATA.state.agentHealth = d.health;
      es.close(); busy = false;

      const finish = () => {
        if (!quiet) {
          if (d.case.status === "complete") {
            drawSteps(9);
            $("#pipe").append(el("li", "final", `<b>Decision made — ${OUTCOME[d.case.policy.disposition].t}</b>`));
            $("#pipe").scrollTop = $("#pipe").scrollHeight;
            drawCase(d.case);
          } else { drawSteps(3, 3); drawFailed(d.case); }
        }
        drawQueue();
        if (!streaming) { drawSide(); if (page === "dash") drawDash(); }
        res();
      };
      // Let the queued steps finish playing before the answer appears.
      if (!quiet && (pipeQ.length || pipeTimer)) onDrained = finish; else finish();
    });
    es.onerror = () => { es.close(); busy = false; res(); };
  });
}

/* Re-opening a finished case should still show how it got there. */
function drawProcess(c) {
  const e = c.enrichment.sources;
  const answered = Object.values(e).filter((s) => s.status === "ok").length;
  const lines = [
    ["Received", "picked up the moment it arrived"],
    ["Linked up", c.correlation?.related?.length ? `found ${c.correlation.related.length} related alert(s)` : "no related alerts"],
    ["Background checks", `${answered} of ${Object.keys(e).length} sources answered in ${secs(c.timings.enrichmentMs)}`],
    ["Never-close rules", c.policy.triggers.length ? `${c.policy.triggers.length} fired — trigger ${c.policy.triggers.map((t) => t.n).join(", ")}` : "none of the fifteen applied"],
    ["Thinking", `${c.verdict.reasoning_chain.length} ideas tested in ${secs(c.timings.reasoningMs)}`],
    ["Decision", `${OUTCOME[c.policy.disposition].t} — ${c.policy.confidence}% sure`]
  ];
  $("#pipe").innerHTML = lines.map(([a, b], i) =>
    `<li class="${i === lines.length - 1 ? "final" : ""}"><b>${a}</b> — ${esc(b)}</li>`).join("");
  $("#livePanel").hidden = false;
}

/* ── the case ── */
function drawFailed(c) {
  const o = OUTCOME.FAILED;
  $("#verdictCard").innerHTML = `<div class="verdict FAILED"><div class="ic">${o.ic}</div>
    <div><div class="vt">${o.t}</div><div class="vs">${o.d}</div></div></div>`;
  $("#tabs").innerHTML = "";
  $("#tabBody").innerHTML = `<div class="note red"><b>The AI could not answer.</b> It handed the alert to a person rather than guessing — which is the behaviour that matters most.<br><br><code>${esc(c.error)}</code></div>`;
}

/* How sure it was, drawn against the one line that matters: the score it has to clear before it is
   allowed to act on its own. A number on its own means nothing; a number next to the line does. */
function meter(p) {
  if (typeof p.confidence !== "number" || !p.threshold) return "";
  const over = p.confidence >= p.threshold;
  return `<div class="meter">
    <div class="mtrack"><i id="confBar" data-w="${p.confidence}"></i>
      <span class="mthresh" style="left:${p.threshold}%" title="Acts on its own at ${p.threshold}%"></span></div>
    <div class="mlabels"><span><b>${p.confidence}%</b> sure</span>
      <span>${over ? "clears" : "below"} the ${p.threshold}% line</span></div>
  </div>`;
}

function drawCase(c) {
  const p = c.policy, v = c.verdict, o = OUTCOME[p.disposition] || OUTCOME.HOLD, cls = VERDICT[v.classification] || {};
  $("#verdictCard").innerHTML = `<div class="verdict ${p.disposition}">
    <div class="ic">${o.ic}</div>
    <div style="min-width:0">
      <div class="vt">${o.t}${p.wouldHaveBeen ? ` <span style="opacity:.6;font-weight:400">(would have been ${OUTCOME[p.wouldHaveBeen].t.toLowerCase()})</span>` : ""}</div>
      <div class="vs"><b>${cls.s}</b> — ${cls.d} The AI is <b>${p.confidence}%</b> sure${p.triggers.length ? `, and ${p.triggers.length} safety rule${p.triggers.length > 1 ? "s" : ""} said a person must see it` : ""}.
      <div style="color:var(--dim);font-size:12px;margin-top:5px">${esc(v.classification)}${c.replayed ? " · cached" : ""}</div></div>
      ${meter(p)}
    </div>
    <div class="time"><div class="tv">${secs(c.timings.totalMs)}</div><div class="tl">to decide</div></div>
  </div>`;
  // Grow the bar from zero so the eye is drawn to where it lands relative to the line.
  requestAnimationFrame(() => { const i = $("#confBar"); if (i) i.style.width = i.dataset.w + "%"; });

  // Only the supervisor, whose job is checking the AI's work, gets the reasoning tab.
  const tabs = [["summary", "Summary"], ...(role.id === "supervisor" ? [["how", "How it decided"]] : [])];
  if (!tabs.some(([k]) => k === tab)) tab = "summary";
  $("#tabs").innerHTML = tabs.map(([k, l]) => `<button data-t="${k}" class="${tab === k ? "on" : ""}">${l}</button>`).join("");
  $("#tabs").querySelectorAll("[data-t]").forEach((b) => b.onclick = () => { tab = b.dataset.t; drawCase(c); });
  ({ summary: tabSummary, how: tabHow }[tab] || tabSummary)(c);
}

const blk = (h, body) => `<div class="blk"><h3>${h}</h3>${body}</div>`;

function tabSummary(c) {
  const p = c.policy, v = c.verdict;
  let h = "";

  if (v.injection_attempt_detected) h += `<div class="note red"><b>This message tried to give the AI orders.</b> It contained hidden text telling the AI to close the alert. The AI treated that as proof of bad intent rather than following it.</div>`;
  if (c.enrichment.dataGaps.length) h += `<div class="note amber"><b>Some information was missing.</b> ${c.enrichment.dataGaps.map((g) => esc(g.source)).join(", ")} did not answer, so the AI lowered how sure it was.</div>`;

  h += blk("What happened", `<p class="body">${esc(v.executive_summary)}</p>`);

  // The evidence itself — what the detection actually saw, and what the background checks found.
  const a = DATA.alerts.find((x) => x.id === c.alertId) || {};
  if (a.rawEvidence?.length) {
    h += blk("The evidence", `<ul class="ev-list">${a.rawEvidence.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`);
  }
  const untrusted = (c.prompt.match(/<UNTRUSTED_CONTENT>\n([\s\S]*?)\n<\/UNTRUSTED_CONTENT>/) || [])[1];
  if (untrusted) {
    h += blk("Written by the sender", `<div class="note red">Treated as evidence only. The AI never follows instructions found inside a message.</div>
      <pre class="raw">${esc(untrusted)}</pre>`);
  }
  const findings = Object.entries(c.enrichment.sources)
    .filter(([, s]) => s.flags?.length).flatMap(([, s]) => s.flags);
  if (findings.length) {
    h += blk("What the background checks turned up", `<ul class="ev-list">${findings.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>`);
  }

  // Playbook §3 — the never-close rules, decided in code before the AI was asked anything.
  if (p.triggers?.length) {
    h += blk("Never-close rules that fired", p.triggers.map((t) => `<div class="why"><div class="wi">${t.n}</div>
      <div><div class="wt">${esc(t.short)}<span class="src facts">checked before the AI was asked</span></div>
      <div class="wd">${esc(t.detail)}<br><span style="color:var(--dim)">${esc(t.why)}</span></div></div></div>`).join(""));
  }

  // Playbook §2 — a Hold is not a soft close. It names what, who and when.
  if (p.hold) {
    h += blk("What this hold is waiting for", `<dl class="rows">
      <dt>Waiting for</dt><dd>${esc(p.hold.waitingFor)}</dd>
      <dt>Who can answer</dt><dd>${esc(p.hold.whoCanAnswer)}</dd>
      <dt>Expires</dt><dd>${new Date(p.hold.expiresAt).toLocaleString()}</dd>
      <dt>On expiry</dt><dd>${esc(p.hold.onExpiry)}</dd></dl>`);
  }

  // Playbook §4 — a disposition you did not record did not happen.
  if (c.siem) {
    const stamp = c.siem.writtenAt ? new Date(c.siem.writtenAt).toLocaleTimeString() : "";
    h += blk("Recorded in FortiSIEM", `
      <div class="siem">
        <div class="siemTop"><span class="siemDot"></span>Incident <b>${esc(c.alertId)}</b> updated${stamp ? ` at ${stamp}` : ""}
          ${c.siem.writtenBy ? `<span class="siemBy">by ${esc(String(c.siem.writtenBy).replace(/^human:|^agent:/, ""))}</span>` : `<span class="siemBy">by the AI agent</span>`}</div>
        <div class="siemRows">${["Resolution", "Status", "Cleared Reason", "Comments", "Tag", "Case"]
          .filter((k) => c.siem[k] !== undefined)
          .map((k) => `<div class="siemRow"><span class="sk">${k}</span><span class="sv">${esc(c.siem[k])}</span></div>`).join("")}</div>
      </div>`);
  }

  $("#tabBody").innerHTML = h;
  $("#tabBody").append(actionBar(c));
}

/* Only the supervisor judges the agent, and only two answers exist: correct, or wrong. */
function actionBar(c) {
  const bar = el("div", "actions");
  const p = c.policy;
  const nameOf = (r) => esc(r.by.replace(/^human:/, ""));

  // History first: if a supervisor already overruled the AI, say so wherever the alert ends up.
  if (c.markedWrong) {
    bar.append(el("div", "note amber",
      `<b>Marked wrong</b> by ${nameOf(c.markedWrong)}. Should have been <b>${VERDICT[c.markedWrong.correctedTo]?.s || c.markedWrong.correctedTo}</b>.<br>${esc(c.markedWrong.reason)}`));
  }

  // Escalated means a Tier 2 analyst already has it — nobody else may move it.
  if (p.disposition === "ESCALATE") {
    bar.append(el("div", "note", c.decidedByHuman
      ? `<b>Sent to Tier 2</b> by ${nameOf(c.decidedByHuman)}. It is now in their queue.`
      : "<b>This one is with Tier 2.</b> An analyst is investigating it."));
    return bar;
  }

  // Closed by a person after a hold — finished.
  if (p.disposition === "CLOSE" && c.decidedByHuman) {
    bar.append(el("div", "note green", `<b>Closed</b> by ${nameOf(c.decidedByHuman)}.`));
    return bar;
  }

  // The AI's own closure, already checked — finished.
  if (p.disposition === "CLOSE" && c.review?.status === "reviewed") {
    bar.append(el("div", "note green", `<b>Confirmed correct</b> by ${nameOf(c.review)}.`));
    return bar;
  }

  if (role.id !== "supervisor") return bar;

  // On hold — however it got here, someone still has to decide it.
  if (p.disposition === "HOLD") {
    bar.append(el("div", "note amber", c.markedWrong
      ? "<b>Back on hold for a decision.</b> Close it, or send it to Tier 2 to investigate."
      : "<b>The AI was not sure enough to decide.</b> It is your call: close it, or send it to Tier 2 to investigate."));
    const up = el("button", "btn no", "Send to Tier 2");
    const cl = el("button", "btn ok", "Close it");
    up.onclick = async () => { if (await send(c, { outcome: "escalate" })) toast("good", "<b>Sent to Tier 2.</b> It is now in their queue."); };
    cl.onclick = async () => { if (await send(c, { outcome: "close" })) toast("good", "Closed."); };
    bar.append(up, cl);
    return bar;
  }

  // An AI closure that has not been checked yet.
  const ok = el("button", "btn ok", "✓ Correct");
  const no = el("button", "btn no", "✕ Wrong");
  ok.onclick = () => send(c, { outcome: "correct" });
  no.onclick = () => openWrong(c);
  bar.append(ok, no);
  return bar;
}

async function send(c, body) {
  const r = await post("/api/review", { id: c.alertId, ...body });
  if (!r) return false;
  cases[c.alertId] = r.case; DATA.metrics = r.metrics;
  if (r.lessons) DATA.state.lessons = r.lessons;
  drawQueue(); drawSide(); drawCase(r.case);
  if (page === "dash") drawDash();
  return true;
}

/* Saying "wrong" is not a complaint. You have to say what it should have been, what happens to the
   alert now, and why — the why is the only part the agent can actually learn from. */
function openWrong(c) {
  sheet("What did the AI get wrong?", `
    <label class="fl">What should it have been?</label>
    <select id="wc">${Object.keys(VERDICT).map((k) => `<option value="${k}" ${k === c.verdict.classification ? "selected" : ""}>${VERDICT[k].s}</option>`).join("")}</select>
    <label class="fl">What should happen to this alert now?</label>
    <select id="wa">
      <option value="ESCALATE">Send it to Tier 2 to investigate</option>
      <option value="HOLD">Put it on hold for someone to look at</option>
    </select>
    <label class="fl">Why was the AI wrong? <span style="color:var(--red)">Required</span></label>
    <textarea id="wr" rows="3" placeholder="What did it miss? This becomes a lesson once approved."></textarea>
    <p class="pt" id="wmsg" style="margin-top:8px;color:var(--red)" hidden>Please explain why — the AI cannot learn from a blank box.</p>
    <div class="sheetActions"><button class="btn" id="wx">Cancel</button><button class="btn primary" id="wg" disabled>Save decision</button></div>`);

  const box = $("#wr"), go = $("#wg");
  box.oninput = () => { go.disabled = !box.value.trim(); $("#wmsg").hidden = true; };
  box.focus();
  $("#wx").onclick = closeSheet;
  go.onclick = async () => {
    if (!box.value.trim()) { $("#wmsg").hidden = false; return; }
    const ok = await send(c, { outcome: "wrong", classification: $("#wc").value, action: $("#wa").value, reason: box.value });
    if (ok) { closeSheet(); toast("good", "Saved. Your reason is now a lesson, pending approval."); }
  };
}

/* The AI's working, laid out as the playbook's own seven steps — so a reviewer can check it
   followed the procedure, not just whether they agree with the answer. */
function tabHow(c) {
  const v = c.verdict, p = c.policy;
  const step = (n, title, body) => `<div class="pstep"><div class="pn">${n}</div>
    <div class="pbody"><div class="pt2">${title}</div>${body}</div></div>`;

  let h = `<div class="note">Playbook <b>${esc(p.playbookVersion || "PB-T1-001")}</b> — the AI works the same steps a human Tier 1 analyst does.</div>`;

  h += step(1, "Claim and check scope",
    `<p class="pd2">${c.enrichment.playbook
      ? `In scope: <b>${esc(c.enrichment.playbook.name)}</b> (${esc(c.enrichment.playbook.wave)}).`
      : `<span style="color:var(--red)">No playbook entry for this alert type — trigger 14, straight to a person.</span>`}</p>`);

  const alert = DATA.alerts.find((x) => x.id === c.alertId) || {};
  const ents = Object.entries(alert.entities || {}).filter(([, val]) => val?.length);
  h += step(2, "List the entities",
    ents.length ? `<div class="ents">${ents.flatMap(([, val]) => val).map((x) => `<span class="ent">${esc(x)}</span>`).join("")}</div>`
      : `<p class="pd2">None recorded.</p>`);

  h += step(3, "Enrich — and record what came back clean",
    `<p class="pd2">${Object.values(c.enrichment.sources).filter((s) => s.status === "ok").length} of ${Object.keys(c.enrichment.sources).length} sources answered.
      The playbook insists the clean results are written down too, so Tier 2 never repeats them.</p>
     ${(v.clean_findings || []).length ? `<ul class="ev-list">${v.clean_findings.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>` : ""}`);

  if (v.timeline?.length) {
    h += blk("Timeline", `<dl class="rows">${v.timeline.map((t) => `<dt>${esc(t.timestamp)}</dt><dd>${esc(t.event)}</dd>`).join("")}</dl>`);
  }
  $("#tabBody").innerHTML = h;
}

/* ── empty state ── */
function drawEmpty() {
  const e = $("#empty"); e.hidden = false;
  const left = DATA.alerts.filter((a) => !cases[a.id]).length;

  if (left === DATA.alerts.length) {
    e.innerHTML = `<div class="big">▶</div><h2>Nothing looked at yet</h2>
      <p>${DATA.alerts.length} alerts are waiting.</p>`;
    const b = el("button", "btn primary", `Run the AI on all ${left}`);
    b.onclick = runAll; e.append(b);
    return;
  }
  // Not a blank page: a working overview you can act from.
  const vis = mine().filter((x) => cases[x.id]?.status === "complete");
  const n = (d) => vis.filter((x) => cases[x.id].policy.disposition === d).length;
  const recent = vis.sort((x, y) => new Date(cases[y.id].decidedAt) - new Date(cases[x.id].decidedAt));

  e.innerHTML = `<div class="ov" style="text-align:left">
      <h2 style="text-align:left;margin-bottom:4px">${vis.length} alert${vis.length === 1 ? "" : "s"} handled</h2>
      <p style="text-align:left;margin-bottom:18px">Open one to see the decision and the reasoning behind it.</p>
      <div class="ovStats">
        <button class="ovStat e" data-jump="ESCALATE"><div class="ovv">${n("ESCALATE")}</div><div class="ovl">Escalated</div></button>
        <button class="ovStat h" data-jump="HOLD"><div class="ovv">${n("HOLD")}</div><div class="ovl">Hold</div></button>
        <button class="ovStat c" data-jump="CLOSE"><div class="ovv">${n("CLOSE")}</div><div class="ovl">Closed</div></button>
      </div>
      <div class="ovList">${recent.slice(0, 8).map((x) => {
        const c = cases[x.id];
        return `<div class="ovRow ${c.policy.disposition}" data-open="${x.id}"><div class="od"></div>
          <div class="ot">${esc(x.title)}</div>
          <div class="om">${c.policy.confidence}% · ${secs(c.timings.totalMs)}</div></div>`;
      }).join("")}</div>
      <p class="pt" style="text-align:left;margin-top:14px">
        <kbd>j</kbd> <kbd>k</kbd> move · <kbd>[</kbd> <kbd>]</kbd> hide panels · <kbd>?</kbd> all shortcuts</p>
    </div>`;
  e.querySelectorAll("[data-jump]").forEach((b) => b.onclick = () => { filter = b.dataset.jump; drawQueue(); });
  e.querySelectorAll("[data-open]").forEach((b) => b.onclick = () => open(b.dataset.open));
}

/* ── side ── */
function drawSide() {
  const s = $("#side"); s.innerHTML = "";
  const m = DATA.metrics || {};
  const ok = (DATA.state.agentHealth || "Healthy") === "Healthy";
  $("#health").className = "health" + (ok ? "" : " bad");
  $("#healthText").textContent = ok ? "Working" : "Stopped — alerts going to people";
  const left = DATA.alerts.filter((a) => !cases[a.id]).length;

  // With a case open the panel becomes the case's context: the facts, and everything it touches.
  const c = selected ? cases[selected] : null;
  const a = selected ? DATA.alerts.find((x) => x.id === selected) : null;

  if (a && c?.status === "complete") {
    s.append(el("div", "panel", `<h3>This alert</h3><div class="facts">
      <div class="factRow"><span class="fk">Decision</span><span class="fv" style="color:var(--${c.policy.disposition === "ESCALATE" ? "red" : c.policy.disposition === "HOLD" ? "amber" : "green"})">${OUTCOME[c.policy.disposition].t}</span></div>
      <div class="factRow"><span class="fk">Verdict</span><span class="fv">${VERDICT[c.verdict.classification]?.s || c.verdict.classification}</span></div>
      <div class="factRow"><span class="fk">How sure</span><span class="fv">${c.policy.confidence}%</span></div>
      <div class="factRow"><span class="fk">Urgency</span><span class="fv">${a.severity}</span></div>
      <div class="factRow"><span class="fk">Arrived</span><span class="fv">${new Date(a.createdAt).toISOString().slice(11, 16)}</span></div>
      <div class="factRow"><span class="fk">Took</span><span class="fv">${secs(c.timings.totalMs)}</span></div>
    </div>`));

    const groups = Object.entries(a.entities || {}).filter(([, v]) => v.length);
    if (groups.length) {
      const p = el("div", "panel", `<h3>Involved</h3>`);
      for (const [k, vals] of groups) {
        p.append(el("div", "entGroup", `<div class="eh">${ENT_LABEL[k] || k}</div>
          <div class="ents">${[...new Set(vals)].map((v) => `<button class="ent" data-ent="${esc(v)}" title="Find every alert involving ${esc(v)}">${esc(v)}</button>`).join("")}</div>`));
      }
      p.append(el("p", "pt", "Click any of these to find every alert that touches it."));
      s.append(p);
    }
  }

  const dp = el("div", "panel", `<h3>Demo</h3>
    ${left ? `<button class="btn primary wide" id="runAll">Run the AI on ${left} alerts</button>
      <label class="sw" style="margin-top:10px"><input type="checkbox" id="watch" ${watch ? "checked" : ""}><i></i>Watch it work</label>
      <div class="prog" id="prog" hidden></div>` : ""}
    <label class="sw" style="margin-top:10px"><input type="checkbox" id="replay" ${DATA.state.replayCache ? "checked" : ""}><i></i>Fast mode (cached)</label>
    <label class="sw" style="margin-top:9px"><input type="checkbox" id="ti" ${DATA.state.tiFeedOffline ? "checked" : ""}><i></i>Break a data source</label>
    <button class="btn sm wide" id="reset" style="margin-top:12px">Reset</button>`);
  s.append(dp);

  wire();
}

function wire() {
  // Clicking an entity searches for it — the fastest way to answer "what else touched this?"
  $("#side").querySelectorAll("[data-ent]").forEach((b) => b.onclick = () => {
    query = b.dataset.ent.toLowerCase();
    $("#q").value = b.dataset.ent;
    filter = "all";
    drawQueue();
    const hits = document.querySelectorAll("#queueList .card").length;
    toast("good", `<b>${hits} alert${hits === 1 ? "" : "s"}</b> involve ${esc(b.dataset.ent)}.`);
  });
  const g = (id) => $("#" + id);
  if (g("runAll")) g("runAll").onclick = runAll;
  if (g("watch")) g("watch").onchange = (e) => { watch = e.target.checked; };
  if (g("replay")) g("replay").onchange = (e) => patch({ replayCache: e.target.checked });
  if (g("ti")) g("ti").onchange = (e) => patch({ tiFeedOffline: e.target.checked });
  if (g("reset")) g("reset").onclick = async () => {
    await fetch("/api/reset", { method: "POST" });
    selected = null; opened.clear();
    DATA = await fetch("/api/bootstrap").then((r) => r.json());
    cases = DATA.cases || {};
    $("#case").hidden = true; drawEmpty(); drawQueue(); drawSide();
    if (page === "dash") drawDash();
  };
  if (g("log")) fetch("/api/audit").then((r) => r.json()).then((r) => {
    g("log").innerHTML = r.audit.slice(-40).reverse().map((a) =>
      `<div><b>${esc(a.action)}</b> ${esc(a.target)}<br>${new Date(a.ts).toLocaleTimeString()} · ${esc(a.actor.replace(/^human:|^agent:/, ""))}</div>`).join("") || "Nothing yet.";
  });
}

/* ── dashboard page ───────────────────────────────────────────────────────
   Each role sees only the numbers it can act on, and every number is a link:
   click it and you land in the alert list already filtered to what it counts. */
function drawDash() {
  const m = DATA.metrics || {};
  const d = m.dispositions || {};
  const done = m.triaged || 0, esc_ = d.ESCALATE || 0, hold = d.HOLD || 0;
  const miss = (m.falseNegatives || []).length;
  const left = DATA.alerts.length - done;
  const waiting = DATA.alerts.filter(needsMe).length;
  const p = $("#pageDash");

  p.innerHTML = `<div class="dashHead">
      <div><h1>${role.name}</h1><p>${BLURB[role.id]}</p></div>
      ${left ? `<button class="btn primary" id="dashRun">Run the AI on ${left} alert${left > 1 ? "s" : ""}</button>` : ""}
    </div>`;

  if (!done) {
    p.append(el("div", "emptyDash", `<h2>Nothing has been looked at yet</h2>
      <p>${DATA.alerts.length} alerts are waiting. Let the AI work through them and the numbers appear here.</p>`));
    const b = el("button", "btn primary", `Run the AI on all ${DATA.alerts.length}`);
    b.onclick = runAll; p.querySelector(".emptyDash").append(b);
    if ($("#dashRun")) $("#dashRun").onclick = runAll;
    return;
  }

  const kpi = (v, label, hint, cls, jump, suffix) =>
    `<div class="kpi ${cls || ""} ${jump ? "click" : ""}" ${jump ? `data-jump="${jump}"` : ""}>
      ${jump ? '<span class="arrow">→</span>' : ""}
      <div class="kv"><span data-count="${v}">0</span>${suffix || ""}</div>
      <div class="kl">${label}</div>${hint ? `<div class="kh">${hint}</div>` : ""}</div>`;

  const feed = (list, title) => `<div class="box"><h3>${title}</h3><div class="feed">${
    list.length ? list.map((a) => {
      const c = cases[a.id];
      return `<div class="feedRow ${c.policy.disposition}" data-open="${a.id}"><div class="fd"></div>
        <div class="fmain"><div class="ftitle">${esc(a.title)}</div>
        <div class="fmeta">${OUTCOME[c.policy.disposition].t} · ${c.policy.confidence}% sure · ${secs(c.timings.totalMs)}</div></div></div>`;
    }).join("") : `<p class="pt">Nothing here.</p>`}</div></div>`;

  // ── Tier 2: this is a work list. What is on my plate, and what did I not have to touch? ──
  if (role.id === "tier2") {
    const open_ = mine().filter((a) => !cases[a.id].override);
    const secsAvg = Math.round((m.mttt?.p95 || 0) / 1000);
    p.append(el("div", "big4",
      kpi(open_.length, "cases on your plate", "everything else was handled without you", open_.length ? "b" : "g", "all")
      + kpi(done - esc_, "never reached you", `${done} alerts came in, ${esc_} needed a person`, "g")
      + kpi(done ? m.packageCompleteness : 0, "% arrived complete", "no re-gathering the background yourself", "g", null, "%")
      + kpi(secsAvg, "sec to reach you at worst", "a person triaging by hand needs 20–45 min", "b", null, "s")));

    // Full width under the KPIs — this list is the job, so give it the whole page.
    p.insertAdjacentHTML("beforeend", feed(mine(), "Your cases"));
    return wireDash(p);
  }

  // ── Supervisor: can I trust it? Where is it near the line, and how often am I overruling it? ──
  {
    const checks = DATA.alerts.map((a) => cases[a.id]?.adjudication || (cases[a.id]?.review?.status === "reviewed" ? cases[a.id].review : null)).filter(Boolean);
    const wrong = checks.filter((c) => c.outcome === "wrong").length;
    p.append(el("div", "big4",
      kpi(waiting, "waiting for you to check", waiting ? "held cases and closures" : "you are up to date", waiting ? "a" : "g", "todo")
      + kpi(miss, "attacks missed", miss ? "act on this now" : "the number that matters most", miss ? "r" : "g")
      + kpi(m.agreementPct || 0, "% matched an expert", "gate needs 95% before it is trusted further", (m.agreementPct || 0) >= 95 ? "g" : "a", null, "%")
      + kpi(checks.length ? Math.round((wrong / checks.length) * 100) : 0, "% you marked wrong", `${wrong} of ${checks.length} you have checked`, wrong ? "a" : "g", null, "%")));

    // Where its confidence sits relative to the line at which it is allowed to act.
    const bands = [[95, 100], [85, 94], [70, 84], [0, 69]];
    const dist = (m.confidenceDistribution || []);
    const cols = el("div", "cols");
    cols.append(el("div", "box", `<h3>How sure it was — it may only act at ${DATA.actionThreshold}% and above</h3>
      <div class="flow">${bands.map(([lo, hi]) => {
        const n = dist.filter((x) => x.confidence >= lo && x.confidence <= hi).length;
        const cls = lo >= 85 ? "c" : lo >= 70 ? "h" : "e";
        return `<div class="flowRow ${cls}"><div class="fl2">${lo}–${hi}%</div>
          <div class="ft"><i data-w="${done ? (n / done) * 100 : 0}" style="width:0"></i></div><div class="fn">${n}</div></div>`;
      }).join("")}</div>
      <p class="pt" style="margin-top:12px">${hold} of ${done} fell below the line, so the AI asked instead of guessing.</p>`));
    cols.insertAdjacentHTML("afterbegin", feed(DATA.alerts.filter(needsMe).slice(0, 6), "Needs your decision"));
    p.append(cols);
    return wireDash(p);
  }
}

function wireDash(p) {
  if ($("#dashRun")) $("#dashRun").onclick = runAll;
  p.querySelectorAll("[data-jump]").forEach((n) => n.onclick = () => go("alerts", { filter: n.dataset.jump }));
  p.querySelectorAll("[data-open]").forEach((n) => n.onclick = () => go("alerts", { openId: n.dataset.open }));
  requestAnimationFrame(() => {
    p.querySelectorAll(".ft i").forEach((i) => { i.style.width = i.dataset.w + "%"; });
    p.querySelectorAll("[data-count]").forEach(countUp);
  });
}

/** Numbers land better when you watch them arrive. */
function countUp(node) {
  const to = Number(node.dataset.count) || 0;
  if (to === 0) { node.textContent = "0"; return; }
  const t0 = performance.now(), dur = 550;
  const tick = (now) => {
    const k = Math.min(1, (now - t0) / dur);
    node.textContent = Math.round(to * (1 - Math.pow(1 - k, 3)));
    if (k < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

/* ── run everything ── */
async function runAll() {
  if (streaming) return;
  const todo = DATA.alerts.filter((a) => !cases[a.id]);
  if (!todo.length) return;
  streaming = true;
  const back = selected;
  const btn = $("#runAll"); if (btn) btn.disabled = true;
  const prog = $("#prog");

  // The run is usually kicked off from the dashboard, so show progress where the eyes are.
  const showProgress = (i) => {
    if (prog) { prog.hidden = false; prog.innerHTML = `<div class="pb"><i style="width:${((i + 1) / todo.length) * 100}%"></i></div>
      <div class="pt"><span class="spin"></span> ${i + 1} of ${todo.length}${watch ? "" : " — running in the background"}</div>`; }
    const dr = $("#dashRun");
    if (dr) { dr.disabled = true; dr.innerHTML = `<span class="spin"></span> ${i + 1} of ${todo.length}`; }
  };

  for (const [i, a] of todo.entries()) {
    showProgress(i);
    if (watch) { go("alerts"); open(a.id); }
    await runOne(a.id, !watch);
    // Let the dashboard fill in as each answer lands rather than sitting empty until the end.
    if (page === "dash") { drawDash(); showProgress(i); }
  }

  streaming = false;
  if (prog) prog.hidden = true;
  if (!watch) { if (back && cases[back]) open(back); else { $("#case").hidden = true; drawEmpty(); } }
  drawQueue(); drawSide(); if (page === "dash") drawDash();
  const sent = DATA.alerts.filter((a) => cases[a.id]?.policy?.disposition === "ESCALATE").length;
  toast("good", `<b>${sent} of ${todo.length} need a person.</b> The rest were handled without one.`);
}

/* ── plumbing ── */
async function post(url, body) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...body, role: role.id }) });
  const j = await res.json();
  if (res.status === 403) { toast("bad", `<b>Not your call.</b> ${esc(j.authority.split(".")[0])}.`); return null; }
  if (!res.ok) { toast("bad", esc(j.error || "That did not work.")); return null; }
  return j;
}
async function patch(p) { const r = await post("/api/state", p); if (r) { DATA.state = { ...DATA.state, ...r.state }; drawSide(); drawQueue(); } }

function sheet(title, html) { $("#modalTitle").textContent = title; $("#modalBody").innerHTML = html; $("#modal").hidden = false; }
function closeSheet() { $("#modal").hidden = true; }
$("#modalClose").onclick = closeSheet;
$("#modal").onclick = (e) => { if (e.target.id === "modal") closeSheet(); };
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSheet(); });

/* ── keyboard ──
   Small thing, but it turns the demo from clicking into driving. */
document.addEventListener("keydown", (e) => {
  if (!role || $("#app").hidden) return;
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;

  if (e.key === "?") return showHelp();
  if (e.key === "d") return go("dash");
  if (e.key === "a") return go("alerts");
  if (page !== "alerts") return;
  if (e.key === "[") return togglePane("L");
  if (e.key === "]") return togglePane("R");
  if (e.key === "/") { e.preventDefault(); $("#q").focus(); return; }
  if (e.key === "Escape" && query) { query = ""; $("#q").value = ""; drawQueue(); return; }

  // j / k or the arrow keys walk the visible queue.
  if (["j", "k", "ArrowDown", "ArrowUp"].includes(e.key)) {
    const list = [...document.querySelectorAll("#queueList .card")].map((n) => n.dataset.id);
    if (!list.length) return;
    e.preventDefault();
    const down = e.key === "j" || e.key === "ArrowDown";
    const at = list.indexOf(selected);
    const next = at === -1 ? 0 : Math.min(list.length - 1, Math.max(0, at + (down ? 1 : -1)));
    open(list[next]);
    document.querySelector(`#queueList .card.on`)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
});

function showHelp() {
  sheet("Keyboard shortcuts", `<div class="facts">
    <div class="factRow"><span class="fk">Dashboard</span><span class="fv"><kbd>d</kbd></span></div>
    <div class="factRow"><span class="fk">Alerts</span><span class="fv"><kbd>a</kbd></span></div>
    <div class="factRow"><span class="fk">Move through the list</span><span class="fv"><kbd>j</kbd> <kbd>k</kbd> or <kbd>↑</kbd> <kbd>↓</kbd></span></div>
    <div class="factRow"><span class="fk">Search</span><span class="fv"><kbd>/</kbd></span></div>
    <div class="factRow"><span class="fk">Clear the search</span><span class="fv"><kbd>Esc</kbd></span></div>
    <div class="factRow"><span class="fk">Hide the list</span><span class="fv"><kbd>[</kbd></span></div>
    <div class="factRow"><span class="fk">Hide the panel</span><span class="fv"><kbd>]</kbd></span></div>
    <div class="factRow"><span class="fk">This help</span><span class="fv"><kbd>?</kbd></span></div>
  </div>`);
}

function toast(kind, html) {
  const t = el("div", "toast " + kind, html);
  $("#toasts").append(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .3s"; setTimeout(() => t.remove(), 320); }, 6000);
}

boot();
