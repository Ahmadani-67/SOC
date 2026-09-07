// Three alerts, written so anyone can follow them, and chosen to land on one of each outcome:
// one the AI closes, one it escalates, and one it refuses to decide and hands to a person.
//
// humanVerdict is what a human expert concluded. It is NEVER shown to the AI — it exists only so
// the console can measure whether the AI agreed, and whether it ever missed a real attack.

export const alerts = [
  // ─────────────────────────── CLOSED — a false alarm ───────────────────────────
  {
    id: "ALT-01", wave: 1, alertType: "email.user_reported_phish",
    title: "Staff member reported a newsletter as suspicious",
    detectionRule: "Someone pressed the Report Phishing button",
    ruleIntent:
      "Fires whenever an employee reports an email. It tells us the person was suspicious — it tells us nothing about whether the email is actually dangerous.",
    severity: "Low", createdAt: "2026-08-29T08:31:00Z", source: "Email security",
    entities: {
      users: ["m.iqbal@northbank.example"], mailboxes: ["m.iqbal@northbank.example"],
      hosts: ["NB-RES-045"], ips: [], domains: ["marketwatchdaily.example"],
      urls: ["https://marketwatchdaily.example/reports/q3-benchmark"], hashes: []
    },
    rawEvidence: [
      "Sent by: newsletter@marketwatchdaily.example",
      "The sender has been emailing this company for three years without incident",
      "All three sender-identity checks passed, so the email really is from who it claims to be",
      "There is no attachment, and the only link goes to a normal marketing page with nothing to fill in",
      "The same newsletter went to 62 people here as a normal subscription",
      "Mail logs confirm nobody clicked the link and nobody replied to the message",
      "This exact sender has been reported six times before, and every time it turned out to be harmless",
      "The person who reported it said they simply did not recognise the sender's name"
    ],
    untrustedContent:
      "From: MarketWatch Daily <newsletter@marketwatchdaily.example>\nSubject: Your Q3 industry benchmark report is ready\n\nYour quarterly sector benchmark is now available to view online. You are receiving this because you subscribed. Unsubscribe at any time using the link below.",
    flags: { postExploitation: false, relatesToOpenIncident: false },
    proposedAction: null,
    humanVerdict: "False Positive",
    humanNote: "A genuine newsletter the person had forgotten subscribing to. Closed, as it has been six times before."
  },

  // ────────────────────── ESCALATED — a real attack ──────────────────────
  {
    id: "ALT-02", wave: 1, alertType: "email.user_reported_phish",
    title: "Fake invoice email trying to steal a password",
    detectionRule: "Someone pressed the Report Phishing button",
    ruleIntent:
      "Fires whenever an employee reports an email. It tells us the person was suspicious — it tells us nothing about whether the email is actually dangerous.",
    severity: "Medium", createdAt: "2026-08-29T08:12:00Z", source: "Email security",
    entities: {
      users: ["p.langley@northbank.example"], mailboxes: ["p.langley@northbank.example"],
      hosts: ["NB-FIN-021"], ips: [], domains: ["invoice-review-secure.cc"],
      urls: ["https://invoice-review-secure.cc/auth/verify?id=NB88421"],
      hashes: ["a41f0c9d2e77b3aa9d4c1f6e8b02d5417c9ee3b1a06f4d2c8e5b7a930f1c62d4"]
    },
    rawEvidence: [
      "Sent by: billing@invoice-review-secure.cc, pretending to be our own Accounts Payable team",
      "The sender's web address was registered 11 days ago and has never contacted us before",
      "All three sender-identity checks failed, so the email is not from who it claims to be",
      "Opening the link in a safe test environment shows a pixel-perfect copy of our staff sign-in page, which sends whatever you type straight to the attacker",
      "The attachment is disguised: it is named like a PDF but is actually a small program",
      "Every security checker we use says this web address is dangerous, and links it to a known campaign against banks",
      "The same email was delivered to 14 people across Finance and Procurement",
      "Nobody has clicked it yet, and the person who reported it did not enter their password"
    ],
    untrustedContent:
      "From: Northbank Accounts Payable <billing@invoice-review-secure.cc>\nSubject: Outstanding Invoice 88421 — action required\n\nOur records show invoice 88421 remains unpaid. Review and approve it within 24 hours to avoid supplier suspension. Sign in with your Northbank credentials to view the statement.",
    flags: { postExploitation: false, relatesToOpenIncident: false },
    proposedAction: "soft_delete_email",
    humanVerdict: "True Positive",
    humanNote: "A real password-stealing attack. Removed from all 14 mailboxes before anyone clicked."
  },

  // ──────────── HOLD — answerable, but only by asking someone ────────────
  // Playbook §2: "Hold means the alert is answerable, but not by you, right now." The one fact that
  // would settle this is whether the person is actually abroad, and only they can say.
  {
    // Wave 1 under v0.10: identity sits alongside email, because both are about the person.
    id: "ALT-03", wave: 1, alertType: "identity.impossible_travel",
    title: "Staff member signed in from Portugal an hour after signing in from London",
    detectionRule: "Sign-in from two places too far apart for the time between them",
    ruleIntent:
      "Fires when someone signs in from two locations they could not physically travel between in the time available. Catches stolen passwords — and fires constantly on holidays, roaming phones and VPNs.",
    severity: "Medium", createdAt: "2026-08-29T09:26:00Z", source: "Sign-in monitoring",
    entities: {
      users: ["s.novak@northbank.example"], mailboxes: [], hosts: ["NB-OPS-052"],
      ips: ["213.13.146.90"], domains: [], urls: [], hashes: []
    },
    rawEvidence: [
      "Signed in at 08:19 from London, then again at 09:26 from Lisbon — 67 minutes apart",
      "Both sign-ins came from NB-OPS-052, the same company laptop she always uses, and it is fully up to date",
      "Both sign-ins passed the second security check on her own registered phone",
      "The Lisbon address belongs to a mobile phone network, which is what roaming abroad normally looks like — but we do not hold a record of who has roaming enabled",
      "Nothing else happened in either session: no mail rules created, no files accessed unusually, no settings changed",
      "She is an ordinary staff member with no special access",
      "Her calendar is private to her team, so we cannot see whether she is travelling",
      "HR holiday records are not connected to the security tools"
    ],
    untrustedContent: null,
    flags: { postExploitation: false, relatesToOpenIncident: false },
    proposedAction: null,
    humanVerdict: "Benign True Positive",
    humanNote: "The supervisor messaged her. She was on holiday in Portugal and had signed in to check her rota. Two minutes of human time — but nothing in the evidence could have told the AI that."
  }
];

// PB-T1-001 v0.10 §6. Four merged waves, each a rollout unit that earns autonomy on its own.
// Note this is not one wave per tool: an alert type is a behaviour, and several sensors can raise
// the same behaviour. Identity moved into Wave 1 in v0.10 — the person and their account together.
export const waveNames = {
  1: "Email & identity",
  2: "Endpoint",
  3: "Network & cloud",
  4: "XDR"
};
