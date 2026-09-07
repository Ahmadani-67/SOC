# AI Tier 1 Analyst — a working demo

An autonomous Tier 1 SOC analyst that actually runs. Alerts arrive, five enrichment sources are
queried concurrently, a language model reasons over the assembled evidence, and then a
deterministic policy gate decides what happens to the alert.

The one idea the whole thing exists to demonstrate:

> **The model classifies. Code decides.**

The reasoning layer produces a classification, a confidence score, a rationale and an auditable
chain of tested hypotheses. It does not choose the disposition. The fifteen "never close these"
hard triggers are evaluated in `lib/agent.js → hardTriggers()` against enrichment facts *before the
model is asked anything*, and the model has no vote on them. It can suggest one and be overruled;
it cannot argue one away.

That is the answer to the question every manager, auditor and regulator asks first: *what stops
this thing from confidently closing a real attack?*

## Run it

```bash
git clone https://github.com/Ahmadani-67/SOC.git
cd SOC
npm start          # or: node server.js
# http://localhost:8787
```

Node 18+. **No dependencies, no build step, and no API key required to try it** — the three
built-in alerts ship with cached verdicts, so a fresh clone replays the entire walkthrough out of
the box. Enrichment and the policy gate still run live; only the model output is replayed, and
replayed cases are labelled as cached rather than passed off as fresh.

### Pointing it at your own model

To reason about alerts live, give it any OpenAI-compatible `chat/completions` endpoint:

```bash
cp config.example.json config.json    # then fill in baseUrl, model and apiKey
```

`config.json` is gitignored. If you would rather not write a key to disk, set the environment
variables instead and leave the file out entirely:

| Variable | Purpose |
|---|---|
| `SOC_BASE_URL` | Endpoint base, e.g. `https://your-resource.services.ai.azure.com/openai/v1/` |
| `SOC_MODEL` | Deployment or model name |
| `SOC_API_KEY` | Sent as the `api-key` header |
| `SOC_PORT` | Listen port (default `8787`) |
| `SOC_TIMEOUT_MS` | Inference timeout (default `90000`) |
| `SOC_MAX_TOKENS` | `max_completion_tokens` (default `16000`) |

Turn **Fast mode (cached)** off in the right-hand panel to reason live. The only provider-aware code
is `callOne()` in `lib/agent.js` — swapping providers is one function.

Typical end-to-end when running live: **8–25 seconds** per alert, against a human baseline of
20–45 minutes.

### Hosting it so a team can just open a link

`render.yaml` deploys this straight from the repository — on Render, *New → Blueprint*, point it at
this repo, and it picks the file up. There is also a `Dockerfile` for Azure Container Apps, Fly.io,
Cloud Run or a plain VM.

Both deploy with **no inference key**, which is the point: the committed verdict cache carries the
whole walkthrough, so a hosted instance has no quota to burn and no secret to leak. Enrichment and
the policy gate still run live on every request. Add `SOC_API_KEY` in the host's environment
settings — never in `render.yaml`, which is public — only if you want live reasoning.

Two things to know before you put a URL in front of people:

- **There is no authentication.** The role picker is client-side and every endpoint takes `role`
  from the request body, so anyone with the link can act as any role. That is fine for a demo you
  are sharing deliberately and wrong for anything else.
- **State is global and in memory.** Every visitor shares the same cases, audit log and switches,
  and anyone can press **Reset**. For a walkthrough with a handful of people that is usually fine;
  for a larger audience, expect them to interfere with each other.

On Render's free plan the service sleeps after inactivity, so the first visit after a quiet spell
takes about a minute to wake.

## What you are looking at

Three alerts, chosen to land on one of each possible outcome. These are the actual verified results:

| Alert | What it is | Verdict | Disposition |
|---|---|---|---|
| `ALT-01` | A newsletter someone reported as suspicious | False Positive @ 97 | **CLOSE** — no human needed |
| `ALT-02` | A fake invoice phishing for credentials | True Positive @ 98 | **ESCALATE** + malicious mail soft-deleted |
| `ALT-03` | Sign-in from Lisbon 67 minutes after London | Insufficient Information @ 78 | **HOLD** — only she can answer |

Zero false negatives. Escalation package completeness 100% of 16 sections on both escalations.

`ALT-03` is the most interesting of the three and the reason the demo is worth watching. Every
piece of evidence is consistent with both a stolen password and a holiday, and nothing in the
telemetry can separate them — HR leave records are not connected to the security tooling. The agent
does not guess. It names the deciding fact it could not obtain, says who can answer it
(*the user*), and holds. The human verdict recorded afterwards was Benign True Positive: a
supervisor messaged her, and she was in Portugal checking her rota.

So the console reports **67% agreement**, and that is honest rather than embarrassing. The agent did
not agree with the human because it *could not have* — the deciding fact did not exist in any system
it can read. A Hold that names what it is waiting for and who owes the answer is the correct
outcome, not a failure. Do not paper over it when demonstrating this; it is a better answer than a
demo that agrees three times out of three.

### Two seats, and the console is a different tool in each

| Role | Lands on | Can | Cannot |
|---|---|---|---|
| **Tier 2 Analyst** | Your escalations, each with a complete evidence package | Read any case, override any verdict, submit feedback | Review closures, adjudicate holds, approve lessons |
| **AI Supervisor** *(rotating Tier 2 duty)* | Your review queue — held alerts and sampled closures | All of the above, plus judge the agent's work and see *How it decided* | Approve lessons, change autonomy |

This is not cosmetic. `ROLES` and `can()` in `server.js` enforce it **server-side** — sign in as
Tier 2, call `/api/review`, and you get a 403 explaining whose call it is, even if you bypass the
interface entirely. Each role also only *sees* what it should: the reasoning tab is supervisor-only,
because checking the agent's work is the supervisor's job and nobody else's.

## The pipeline

Every alert goes through the same sequence, streamed to the browser over SSE as it happens:

1. **Pick-up** — no queue, no severity filter. Severity affects escalation priority only, never
   whether an alert is triaged at all.
2. **Parse** — rule, rule intent, every entity, every raw evidence line.
3. **Correlate** — shared entities and infrastructure across alerts. Indicators that every feed
   calls benign are excluded, so two people reporting the same legitimate newsletter is a
   coincidence, not a campaign.
4. **Enrich** — five sources concurrently: identity/HR, CMDB/asset, three threat-intel feeds,
   12-month history, and UEBA behavioural baselines. A source that does not answer is **recorded as
   a data gap** that costs 20 confidence points and caps the result at 90. It is never silently
   dropped.
5. **Hard triggers** — the fifteen never-close rules, in code, before the model is consulted.
6. **Reasoning** — the model, constrained by a strict JSON schema.
7. **Policy gate** — the disposition is decided here, not by the model.
8. **Escalation package** — 16 mandatory sections, with completeness validated.

### The verdict schema is a control, not a request

`VERDICT_SCHEMA` in `lib/agent.js` is sent as `response_format: json_schema` with `strict: true`.
The agent physically cannot return a classification outside the closed set of five, cannot omit its
reasoning chain, and cannot answer with prose where a confidence score belongs.

Refusals, content-filter blocks and truncated answers are all treated as **failures to triage**.
A partial verdict is not a verdict, so the alert routes to a human and an alarm is raised rather
than the silence being read as "nothing to see here".

### The close test

`applyPolicy()` will only close an alert when **every one** of these holds. Any single failure
blocks it:

- the playbook permits Tier 1 to close this alert type at all;
- the verdict is benign;
- a *specific* innocent explanation was given — "no bad indicators" is explicitly not enough;
- the deciding fact was named, was actually obtained, and supports the innocent explanation;
- no hard trigger applies;
- every enrichment source answered;
- confidence is at or above the 85% bar to act alone.

Anything left over escalates. A **Hold** is not a soft close: it records what is being waited for,
who owes the answer, and when it expires — and on expiry it escalates. It never closes on expiry
and never just ages.

### The playbook

The agent works to **PB-T1-001 v0.10**, in `data/context.js`. Four waves, **57 alert types**, and
the fifteen never-close hard triggers of §3.

An alert type there is a *behaviour*, not a tool — several sensors raise the same behaviour, so
each Wave 3 entry names the sensors that can produce it and the entry governs regardless of which
console fired first. Eleven of the 57 carry **"Close only if: Never"**: uncontained malware,
security-control tampering, ransomware, an allowed connection to a known-bad destination, an
exploit that got a successful response, and every class B XDR incident. That is a property of the
alert type, so no verdict and no confidence score reaches it — `applyPolicy()` fixes the
disposition at ESCALATE before the close test is even considered.

## Try breaking it

- **Break a data source** (right-hand panel) and re-run `ALT-01`. Threat intel returns UNAVAILABLE,
  it is recorded as a data gap, confidence drops by 20 and is capped at 90, and the clean auto-close
  flips to **HOLD**. A missing source degrades confidence; the agent never claims full confidence on
  incomplete evidence.
- **Run with no API key at all.** Every alert without a cached verdict fails safe to the human
  queue with an alarm raised. Nothing is lost and nothing is silently closed.
- **Read the prompt.** `ALT-01` and `ALT-02` both carry attacker-written text, quarantined inside an
  `<UNTRUSTED_CONTENT>` fence you can read in the case view rather than take on trust. If such text
  tries to instruct the agent, the agent is told to treat its presence as evidence of malice, quote
  it, and reason as though the instruction were not there.

## How the code is laid out

```
server.js            HTTP + SSE, state, roles, metrics, audit log, the triage pipeline
config.example.json  template — copy to config.json, or use SOC_* env vars
lib/enrichment.js    five sources in parallel, correlation, data gaps, negation-aware matching
lib/agent.js         prompt, verdict schema, model chain + fallback, POLICY GATE, escalation package
lib/cache.js         verdict cache for quota-proof replay
data/alerts.js       the three alerts + retained human verdicts (never shown to the model)
data/context.js      identity, CMDB, TI feeds, history, playbooks, hard triggers, lessons
public/              the console UI — vanilla JS, no framework
cache/               cached verdicts; delete and re-warm to rebuild
```

| Where | What it implements |
|---|---|
| `lib/agent.js → hardTriggers` | Playbook §3 — the fifteen never-close rules, from evidence, before the model |
| `lib/agent.js → VERDICT_SCHEMA` | Closed classification set, numeric confidence, mandatory reasoning chain |
| `lib/agent.js → buildPrompt` | Instruction/data separation, the `<UNTRUSTED_CONTENT>` fence |
| `lib/agent.js → callOne` | The only provider-aware code |
| `lib/agent.js → applyPolicy` | The policy gate: close test, hold reasons, confidence penalties |
| `lib/agent.js → buildEscalationPackage` | Playbook §5 — all 16 sections, with completeness validation |
| `lib/agent.js → siemRecord` | Playbook §4 — what gets written back to the SIEM |
| `lib/enrichment.js → clauseMatch` | Negation scoped per clause, so "no persistence created" does not fire |
| `server.js → ROLES` + `can()` | Decision authority, enforced server-side |
| `server.js → metrics()` | Agreement, false negatives, hold rate, package completeness |
| `server.js → audit()` | Append-only log; `/api/evidence-pack` exports a case on demand |

### The agent found a bug in the enrichment layer

Worth thirty seconds of any governance conversation. During development an alert whose every
closure criterion was met kept refusing to close, returning Insufficient Information instead.

The agent was right and the code was wrong. A regex in `lib/enrichment.js` matched the evidence line
*"**No** mailbox rules created"* while ignoring the negation, and fabricated a high-severity
"mailbox rule created" deviation. The agent noticed the behavioural enrichment contradicted the raw
detection evidence, said so, and refused to close on self-contradicting telemetry.

A tired analyst at 03:00 skims two lines that disagree and closes the alert; nothing is recorded and
nobody finds out. Here the disagreement was surfaced, written down and resolved upward — which is
how the defect got found at all. `clauseMatch()` now scopes negation per clause.

## What is real and what is staged

Say this part out loud in the room; it protects the credibility of everything else.

**Real:** the pipeline, the concurrency, the reasoning, the structured verdict, the policy gate,
package assembly and validation, the metrics, the audit log, the role enforcement, the switches, and
every latency figure on screen.

**Staged:** the alerts and the five enrichment sources are realistic fixtures, not live SIEM/EDR/
identity connectors. Every identity, host and domain is fictional (`northbank.example`). Alert
pick-up is instant here; in production it is bounded by how quickly detections surface into the SIEM.

**Different from a production design:** this demo calls a hosted frontier model. A bank running this
for real would very likely want a self-hosted open-weight model on owned infrastructure with no
outbound path — data sovereignty, version control and fixed cost at volume. Expect slower tokens and
weaker reasoning from a smaller open-weight model; that trade-off is a real question to measure
against your own historical alerts, not to assume away.

What does *not* change is the part that makes it safe. The policy gate, the hard triggers, the
package schema and the audit trail are all provider-independent, which is why the reasoning layer
can be replaced without re-litigating the governance.

## Known gaps

This is a demo, and these are the places where it is scaffolding rather than a finished capability.
Listed here rather than left to be discovered by a reader of the source:

- **Per-wave autonomy and the kill switches are inert.** `waveAutonomy` and `killSwitch` are stored
  in server state, gated by role and exposed over the API, but `applyPolicy()` never reads them, so
  changing one has no effect on any disposition. Only `actionsEnabled` is honoured.
- **No role holds `config` or `lessonApprove`.** The SOC Manager and Security Administrator seats
  are not implemented, so `/api/state` governance changes and `/api/lesson` always return 403.
- **`SHADOW` is counted but never produced.** `metrics()` reports a shadow bucket that no code path
  currently fills.
- **Three endpoints have no UI.** `/api/override`, `/api/alerts` (the alert composer) and
  `/api/lesson` work server-side but nothing in `public/app.js` calls them.
- **The CLI harnesses are stale.** `smoke.mjs`, `smoke-degraded.mjs` and `warm.mjs` reference alert
  IDs from an earlier, larger alert set and will 404 against the current three. `smoke.mjs` also
  reads trigger fields that no longer exist.
- **`autoCloseThresholds` is unused.** `ACTION_CONFIDENCE` (85) is the only threshold in play.
- **State is in memory.** Restarting the server clears every case, lesson and audit entry. Only the
  verdict cache survives.

## Security

Do not put a real API key in `config.json` and commit it — the file is gitignored for that reason,
and no key has ever been committed to this repository. For anything beyond a desk demo, prefer the
`SOC_API_KEY` environment variable, a secrets manager, or token-based auth over a static key.

The cached verdicts in `cache/` are committed deliberately. They contain model output over fictional
data and no key material, and they are what lets this repository be cloned and run without an
inference endpoint.
