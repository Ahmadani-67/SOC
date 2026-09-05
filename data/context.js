// Enrichment sources the agent queries. Stands in for: identity provider + HR feed,
// CMDB / asset inventory, threat-intelligence feeds, historical alert archive, UEBA baselines.
// BRD Section 10 (Table 15).

export const identityDirectory = {
  "p.langley@northbank.example": {
    displayName: "Priya Langley", role: "Accounts Payable Clerk", department: "Finance",
    manager: "Ines Fabre", seniority: "Individual contributor", privilegeLevel: "Standard user",
    groups: ["Finance-AP", "All-Staff"], vip: false, jmlStatus: "Steady (hired 2023-04-11)",
    recentPasswordChange: "None in 180 days", mfaState: "Registered — Authenticator push, no changes in 90 days",
    signInRiskLevel: "Low", typicalHours: "07:30–18:00 GMT", typicalLocations: ["London, GB"],
    typicalDevices: ["NB-FIN-021 (managed)"]
  },
  "j.moreau@northbank.example": {
    displayName: "Julien Moreau", role: "Regional Sales Manager", department: "Commercial",
    manager: "Anne Dupont", seniority: "Manager", privilegeLevel: "Standard user",
    groups: ["Sales-EMEA", "All-Staff"], vip: false, jmlStatus: "Steady (hired 2021-09-06)",
    recentPasswordChange: "None in 120 days", mfaState: "Registered — FIDO2 key + push",
    signInRiskLevel: "Low", typicalHours: "07:00–20:00 CET",
    typicalLocations: ["Paris, FR", "Lyon, FR", "Milan, IT", "Madrid, ES"],
    typicalDevices: ["NB-SAL-088 (managed)"],
    notes: "Travels within EMEA 2–3 weeks per month. Corporate VPN egress in Milan is a known estate egress point."
  },
  "a.becker@northbank.example": {
    displayName: "Anja Becker", role: "Chief Financial Officer", department: "Executive",
    manager: "CEO", seniority: "Executive", privilegeLevel: "Standard user (executive)",
    groups: ["Executive", "Finance-Leadership", "All-Staff"], vip: true,
    jmlStatus: "Steady (hired 2019-02-18)", recentPasswordChange: "None in 60 days",
    mfaState: "Registered — Authenticator push. NEW device registered 14 minutes after the approval in this alert.",
    signInRiskLevel: "High (elevated by identity protection at 02:14)",
    typicalHours: "06:30–21:00 GMT", typicalLocations: ["London, GB", "Frankfurt, DE"],
    typicalDevices: ["NB-EXE-003 (managed)"]
  },
  "d.okafor@northbank.example": {
    displayName: "Daniel Okafor", role: "Senior Platform Engineer", department: "Engineering",
    manager: "Ruth Salamanca", seniority: "Senior", privilegeLevel: "Local admin on own workstation",
    groups: ["Engineering", "Dev-Sandbox", "All-Staff"], vip: false,
    jmlStatus: "Steady (hired 2022-01-10)", recentPasswordChange: "None in 45 days",
    mfaState: "Registered — FIDO2", signInRiskLevel: "Low",
    typicalHours: "09:00–19:00 GMT", typicalLocations: ["Manchester, GB"],
    typicalDevices: ["NB-DEV-114 (managed)"],
    notes: "Runs build and packaging scripts routinely. Encoded PowerShell is common on this host."
  },
  "adm.tvaldez@northbank.example": {
    displayName: "Tomas Valdez (admin)", role: "Domain Administrator", department: "Platform Infrastructure",
    manager: "Ruth Salamanca", seniority: "Senior", privilegeLevel: "TIER-0 — Domain Admin",
    groups: ["Domain Admins", "Tier0-Admins"], vip: false, jmlStatus: "Steady",
    recentPasswordChange: "None in 30 days", mfaState: "Registered — smartcard",
    signInRiskLevel: "Low", typicalHours: "08:00–18:00 GMT", typicalLocations: ["London, GB"],
    typicalDevices: ["NB-PAW-001 (privileged access workstation)"]
  },
  "svc-backup@northbank.example": {
    displayName: "svc-backup", role: "Service account — backup orchestration", department: "Platform Infrastructure",
    manager: "Ruth Salamanca", seniority: "n/a", privilegeLevel: "PRIVILEGED — cross-account storage read/write",
    groups: ["Service-Accounts", "Backup-Operators"], vip: false, jmlStatus: "n/a — non-human identity",
    recentPasswordChange: "n/a (key-based)", mfaState: "n/a — workload identity",
    signInRiskLevel: "n/a", typicalHours: "01:00–04:00 GMT (scheduled window)",
    typicalLocations: ["eu-west-1 control plane"], typicalDevices: ["n/a"]
  },
  "s.novak@northbank.example": {
    displayName: "Sofia Novak", role: "Operations Coordinator", department: "Operations",
    manager: "Colin Reeve", seniority: "Individual contributor", privilegeLevel: "Standard user",
    groups: ["Operations", "All-Staff"], vip: false, jmlStatus: "Steady (hired 2022-08-15)",
    recentPasswordChange: "None in 150 days", mfaState: "Registered — Authenticator push",
    signInRiskLevel: "Low", typicalHours: "08:00–17:00 GMT", typicalLocations: ["London, GB"],
    typicalDevices: ["NB-OPS-052 (managed)"],
    notes: "No record of whether roaming or travel has been arranged for this person. HR travel data is not connected to the SOC."
  },
  "m.iqbal@northbank.example": {
    displayName: "Maryam Iqbal", role: "Market Analyst", department: "Research",
    manager: "Colin Reeve", seniority: "Individual contributor", privilegeLevel: "Standard user",
    groups: ["Research", "All-Staff"], vip: false, jmlStatus: "Steady",
    recentPasswordChange: "None in 200 days", mfaState: "Registered — push",
    signInRiskLevel: "Low", typicalHours: "08:00–17:30 GMT", typicalLocations: ["London, GB"],
    typicalDevices: ["NB-RES-045 (managed)"]
  }
};

export const assetInventory = {
  "NB-FIN-021": {
    owner: "Finance IT", businessCriticality: "Medium", environment: "Production",
    internetExposure: "None (internal only)", os: "Windows 11 23H2", patchState: "Current (last patched 6 days ago)",
    securityAgents: "EDR healthy, DLP healthy", dataClassification: "Confidential — finance"
  },
  "NB-DEV-114": {
    owner: "Engineering", businessCriticality: "Low", environment: "Development",
    internetExposure: "None", os: "Windows 11 23H2", patchState: "Current",
    securityAgents: "EDR healthy", dataClassification: "Internal — source code"
  },
  "NB-DC-01": {
    owner: "Platform Infrastructure", businessCriticality: "CRITICAL — Tier 0", environment: "Production",
    internetExposure: "None (internal only)", os: "Windows Server 2022", patchState: "Current",
    securityAgents: "EDR healthy, credential guard ENABLED", dataClassification: "Tier-0 — identity store (all domain credentials)"
  },
  "NB-JMP-02": {
    owner: "Platform Infrastructure", businessCriticality: "High", environment: "Production",
    internetExposure: "Restricted (bastion, MFA-gated)", os: "Windows Server 2022", patchState: "Current",
    securityAgents: "EDR healthy", dataClassification: "Internal — administrative transit"
  },
  "NB-EXE-003": {
    owner: "Executive IT", businessCriticality: "High", environment: "Production",
    internetExposure: "None", os: "Windows 11 23H2", patchState: "Current",
    securityAgents: "EDR healthy", dataClassification: "Confidential — executive"
  },
  "NB-SAL-088": {
    owner: "Commercial IT", businessCriticality: "Low", environment: "Production",
    internetExposure: "None", os: "Windows 11 23H2", patchState: "Current (last patched 3 days ago)",
    securityAgents: "EDR healthy, compliant with device policy", dataClassification: "Internal — CRM"
  },
  "NB-OPS-052": {
    owner: "Operations IT", businessCriticality: "Low", environment: "Production",
    internetExposure: "None", os: "Windows 11 23H2", patchState: "Current (last patched 5 days ago)",
    securityAgents: "EDR healthy, compliant with device policy", dataClassification: "Internal — operations"
  },
  "NB-RES-045": {
    owner: "Research IT", businessCriticality: "Low", environment: "Production",
    internetExposure: "None", os: "Windows 11 23H2", patchState: "Current",
    securityAgents: "EDR healthy", dataClassification: "Internal — research"
  },
  "NB-PAW-001": {
    owner: "Platform Infrastructure", businessCriticality: "CRITICAL — Tier 0", environment: "Production",
    internetExposure: "None", os: "Windows 11 Enterprise (privileged access workstation)", patchState: "Current",
    securityAgents: "EDR healthy, application allowlisting enforced", dataClassification: "Tier-0 — administrative"
  },
  "s3://nb-analytics-exports": {
    owner: "Data Platform (owner tag stale — last verified 14 months ago)", businessCriticality: "High",
    environment: "Production", internetExposure: "PUBLIC — anonymous read enabled at 03:41",
    os: "n/a — object storage", patchState: "n/a",
    securityAgents: "Cloud posture management enrolled",
    dataClassification: "RESTRICTED — contains customer account exports (PII)"
  }
};

// Multiple feeds, deliberately including one disagreement (BRD FR-024 / E-08).
export const threatIntel = {
  "invoice-review-secure.cc": [
    { source: "Feed A (commercial)", verdict: "Malicious", confidence: 92, firstSeen: "2026-08-19", campaign: "Storm-1567 credential harvesting" },
    { source: "Feed B (ISAC)", verdict: "Malicious", confidence: 88, firstSeen: "2026-08-20", campaign: "Financial-sector invoice lure" },
    { source: "Feed C (open source)", verdict: "Malicious", confidence: 75, firstSeen: "2026-08-21", campaign: "—" }
  ],
  "a41f0c9d2e77b3aa9d4c1f6e8b02d5417c9ee3b1a06f4d2c8e5b7a930f1c62d4": [
    { source: "Feed A (commercial)", verdict: "Malicious", confidence: 95, firstSeen: "2026-08-18", campaign: "Storm-1567 — HTML smuggling dropper" }
  ],
  "marketwatchdaily.example": [
    { source: "Feed A (commercial)", verdict: "Benign", confidence: 90, firstSeen: "2019-03-02", campaign: "—" },
    { source: "Feed B (ISAC)", verdict: "Benign", confidence: 85, firstSeen: "2019-03-02", campaign: "—" },
    { source: "Feed C (open source)", verdict: "Benign", confidence: 80, firstSeen: "2019-05-14", campaign: "—" }
  ],
  "phishprep.example": [
    { source: "Feed A (commercial)", verdict: "Benign", confidence: 88, firstSeen: "2021-06-01", campaign: "— (known security-awareness vendor)" }
  ],
  "cdn-pkg-mirror.net": [
    { source: "Feed A (commercial)", verdict: "Malicious", confidence: 71, firstSeen: "2026-08-27", campaign: "Suspected loader staging (low-confidence attribution)" },
    { source: "Feed B (ISAC)", verdict: "Benign", confidence: 64, firstSeen: "2024-11-03", campaign: "— (categorised as legitimate package mirror)" },
    { source: "Feed C (open source)", verdict: "Unknown", confidence: 0, firstSeen: "—", campaign: "—" }
  ],
  "45.137.202.18": [
    { source: "Feed A (commercial)", verdict: "Malicious", confidence: 84, firstSeen: "2026-08-25", campaign: "Bulletproof hosting — credential spraying infrastructure" },
    { source: "Feed B (ISAC)", verdict: "Malicious", confidence: 79, firstSeen: "2026-08-26", campaign: "Password-spray source pool" }
  ],
  "185.220.101.44": [
    { source: "Feed A (commercial)", verdict: "Malicious", confidence: 81, firstSeen: "2026-06-02", campaign: "Tor exit node / anonymising infrastructure" }
  ],
  "e7c2b81a44f6d093a5e17c8b26f04d99138ae5c0b7f2419d63a8e0c51d7b9f38": [
    { source: "Feed A (commercial)", verdict: "Malicious", confidence: 89, firstSeen: "2026-07-30", campaign: "Commodity credential-dumping tooling (renamed)" }
  ],
  "rmm-quickassist-agent.exe": [
    { source: "Feed A (commercial)", verdict: "Dual-use", confidence: 60, firstSeen: "2020-01-14", campaign: "Legitimate RMM software, frequently abused for persistence" }
  ]
};

// Historical alert archive — the enrichment step humans skip most often (BRD Table 6, step 7).
export const historicalDispositions = {
  "email.user_reported_phish|marketwatchdaily.example": [
    { date: "2026-07-02", disposition: "False Positive", note: "Legitimate subscribed newsletter. Reported by a different user.", laterFoundMisclassified: false },
    { date: "2026-05-19", disposition: "False Positive", note: "Same sender, same template.", laterFoundMisclassified: false },
    { date: "2026-03-11", disposition: "False Positive", note: "Same sender.", laterFoundMisclassified: false },
    { date: "2026-01-28", disposition: "False Positive", note: "Same sender.", laterFoundMisclassified: false },
    { date: "2025-11-04", disposition: "False Positive", note: "Same sender.", laterFoundMisclassified: false },
    { date: "2025-09-16", disposition: "False Positive", note: "Same sender.", laterFoundMisclassified: false }
  ],
  "identity.impossible_travel|j.moreau@northbank.example": [
    { date: "2026-06-24", disposition: "Benign True Positive", note: "Genuine travel Paris→Milan; corporate VPN egress in Milan. MFA satisfied from managed device.", laterFoundMisclassified: false },
    { date: "2026-04-08", disposition: "Benign True Positive", note: "Genuine travel Paris→Madrid.", laterFoundMisclassified: false },
    { date: "2026-02-13", disposition: "Benign True Positive", note: "Genuine travel Paris→Milan.", laterFoundMisclassified: false }
  ],
  "endpoint.encoded_powershell|NB-DEV-114": [
    { date: "2026-08-04", disposition: "Benign True Positive", note: "Build automation script. Engineering confirmed.", laterFoundMisclassified: false },
    { date: "2026-06-17", disposition: "True Positive", note: "Encoded PowerShell on a DIFFERENT dev host resolved to an authorised red-team exercise — but the exercise was NOT declared in advance and cost 4 hours of Tier 2 time.", laterFoundMisclassified: false },
    { date: "2026-05-02", disposition: "Benign True Positive", note: "Packaging script.", laterFoundMisclassified: false }
  ],
  "endpoint.lsass_access|NB-DC-01": [
    { date: "—", disposition: "No prior occurrence on this asset in 12 months of retained history.", note: "First observation of this pattern on a Tier-0 asset.", laterFoundMisclassified: false }
  ],
  "cloud.public_storage_exposure|s3://nb-analytics-exports": [
    { date: "2026-02-20", disposition: "Benign True Positive", note: "Bucket made public briefly during a migration, with an approved change record. Reverted in 20 minutes.", laterFoundMisclassified: true, misclassificationNote: "Re-reviewed in the March control test — the change record referenced a DIFFERENT bucket. Reclassified as a True Positive misconfiguration." }
  ],
  "cloud.iam_key_created|svc-backup@northbank.example": [
    { date: "2026-05-29", disposition: "Benign True Positive", note: "Scheduled 180-day key rotation with change record CHG-40118.", laterFoundMisclassified: false },
    { date: "2025-11-30", disposition: "Benign True Positive", note: "Scheduled key rotation with change record.", laterFoundMisclassified: false }
  ]
};

// VIP / high-risk list, privileged accounts, business-critical assets (BRD E-04, C-08).
export const vipUsers = ["a.becker@northbank.example"];
export const privilegedAccounts = ["adm.tvaldez@northbank.example", "svc-backup@northbank.example"];
export const businessCriticalAssets = ["NB-DC-01", "s3://nb-analytics-exports", "NB-JMP-02"];

/** PB-T1-001 Tier 1 Alert Triage Playbook — the version stamped on every disposition. */
export const PLAYBOOK_VERSION = "PB-T1-001 v0.2";

/**
 * Playbook Section 6 — alert types and how to handle each.
 *
 * "Close only if" is IN ADDITION to the Close rules in Section 2, never instead of them.
 * An alert type that is not in this table is trigger 14: it goes to a human.
 */
export const playbooks = {
  // ── Wave 1 — Email and collaboration ──
  "email.user_reported_phish": {
    name: "User-reported phishing", wave: "Wave 1 — Email and collaboration",
    check: "Sender history and domain age; whether anyone clicked; how many recipients got it; the URL and any attachment; whether similar mail was reported before",
    closeOnlyIf: "It is spam or marketing, or the URL and attachment are both clean and nobody clicked and nobody replied",
    alwaysEscalateIf: "Anyone clicked or entered credentials; the sender is a spoofed internal or partner domain; it targets finance or executives"
  },
  "email.phish_delivered": {
    name: "Malicious URL clicked", wave: "Wave 1 — Email and collaboration",
    check: "Proxy or DNS logs for what happened after the click; whether credentials were submitted; site category and reputation; whether the page is a login clone",
    closeOnlyIf: "The click was blocked at the proxy and nothing loaded",
    alwaysEscalateIf: "The page loaded; credentials were submitted; it downloaded a file; the user is privileged"
  },
  "email.malicious_attachment": {
    name: "Malicious attachment detected", wave: "Wave 1 — Email and collaboration",
    check: "Whether it was blocked or delivered; the hash reputation; whether the file was opened; how many mailboxes received it; whether EDR saw anything on the host",
    closeOnlyIf: "It was blocked before delivery and no copy reached a mailbox",
    alwaysEscalateIf: "It was delivered and opened; EDR shows any activity on the host; the same file went to several users"
  },
  "email.mailbox_rule": {
    name: "Suspicious mailbox rule or forwarding", wave: "Wave 1 — Email and collaboration",
    check: "Who created the rule and when; whether it forwards externally; whether it hides mail by moving it to a rarely-read folder; recent logins for that account",
    closeOnlyIf: "The user created it themselves and it is an ordinary organisational rule, confirmed by the change or helpdesk record",
    alwaysEscalateIf: "It forwards to an external address; it deletes or hides mail; you cannot confirm the user created it"
  },

  // ── Wave 2 — Identity ──
  "identity.password_spray": {
    name: "Brute force or password spray", wave: "Wave 2 — Identity",
    check: "Whether any attempt succeeded; how many accounts were targeted; the source IP and its reputation; whether the accounts are real or scanning noise",
    closeOnlyIf: "Every attempt failed, the source is a known scanner, and no targeted account exists or is enabled",
    alwaysEscalateIf: "Any success at all; a privileged account was targeted; the source is internal"
  },
  "identity.impossible_travel": {
    name: "Impossible travel or odd location", wave: "Wave 2 — Identity",
    check: "The two logins and their times; VPN, proxy and mobile-roaming explanations; the device used; whether the account has travelled before",
    closeOnlyIf: "A VPN, proxy or corporate roaming explains it, and the device is a known managed one",
    alwaysEscalateIf: "No infrastructure explanation; a new or unmanaged device; the account is privileged; anything else happened in the session"
  },
  "identity.mfa_fatigue": {
    name: "MFA anomaly — push spam or repeated denials", wave: "Wave 2 — Identity",
    check: "How many prompts and over how long; whether any was approved; where they came from; whether the password is therefore known",
    closeOnlyIf: "The user was genuinely logging in themselves, confirmed out of band",
    alwaysEscalateIf: "Any prompt was approved; the pattern is repeated over hours; the source is unexpected — assume the password is compromised"
  },
  "identity.privilege_change": {
    name: "Privilege change or group membership added", wave: "Wave 2 — Identity",
    check: "Who made the change and whether they were authorised to; whether there is a change record; what the new privilege allows",
    closeOnlyIf: "An approved change record covers this account, this group and this time",
    alwaysEscalateIf: "No change record; self-granted; a highly privileged group; done outside working hours"
  },

  // ── Wave 3 — Endpoint ──
  "endpoint.encoded_powershell": {
    name: "Suspicious script or PowerShell", wave: "Wave 3 — Endpoint",
    check: "The full command line, decoded; the parent process; whether it reaches out to the network; whether it matches an admin or deployment tool",
    closeOnlyIf: "It matches a known admin script or software-deployment job, confirmed against the change or tooling record",
    alwaysEscalateIf: "It is encoded or obfuscated; it downloads anything; the parent is a browser or an Office application"
  },
  "endpoint.malware_quarantined": {
    name: "Malware detected and quarantined", wave: "Wave 3 — Endpoint",
    check: "The hash reputation; how the file arrived; whether the quarantine actually held; whether the same hash is on other hosts",
    closeOnlyIf: "Quarantine held, the file never executed, and the hash appears nowhere else",
    alwaysEscalateIf: "It executed before quarantine; quarantine failed; the same file is on multiple hosts"
  },
  "endpoint.lsass_access": {
    name: "Credential access — LSASS or dumping tools", wave: "Wave 3 — Endpoint",
    check: "The accessing process and its lineage; whether the tool is a known admin utility; what the account is; whether anything was written to disk",
    closeOnlyIf: "It is a signed backup or EDR product doing its normal job, confirmed in the tooling inventory",
    alwaysEscalateIf: "Anything else. Assume credentials are exposed and escalate."
  },
  "endpoint.persistence": {
    name: "Persistence created", wave: "Wave 3 — Endpoint",
    check: "What was created — scheduled task, service, run key, startup item; what it runs; who created it; when",
    closeOnlyIf: "A software install or a deployment tool created it, and the change record confirms it",
    alwaysEscalateIf: "Anything you cannot attribute to a known install; it runs a script or a file from a temp folder"
  },

  // ── Wave 4 — Cloud ──
  "cloud.public_storage_exposure": {
    name: "Storage or resource made public", wave: "Wave 4 — Cloud",
    check: "What is in it; how long it has been exposed; whether it was ever accessed externally; who changed it",
    closeOnlyIf: "It is a deliberate public asset — a website or public dataset — and is documented as such",
    alwaysEscalateIf: "It holds any internal or personal data; there is any external access in the logs; nobody can say why it changed"
  },
  "cloud.iam_key_created": {
    name: "Cloud credential or key exposed", wave: "Wave 4 — Cloud",
    check: "Where it was found; whether it is live; what it can reach; whether it has been used",
    closeOnlyIf: "The key is already revoked and was never used",
    alwaysEscalateIf: "The key is live; it has been used; it can reach production or data"
  },
  "cloud.iam_policy_change": {
    name: "IAM policy or role change", wave: "Wave 4 — Cloud",
    check: "Who changed it and what it now permits; whether a change record exists; whether it widens access or removes logging",
    closeOnlyIf: "An approved change record covers this role and this time",
    alwaysEscalateIf: "No change record; self-granted; it widens access broadly; it disables logging or monitoring"
  }
};

/**
 * Playbook Section 3 — "Never close these". Fifteen hard triggers.
 * These are evaluated in code from the evidence BEFORE the model is asked anything, and no
 * confidence score, clean reputation result or previous closure overrides them.
 *
 * `evidence` is a regex run over the alert's evidence lines with negation honoured, so
 * "no persistence was created" does not fire the persistence trigger.
 */
export const HARD_TRIGGERS = [
  { n: 1, short: "Code actually ran on a device",
    why: "That is past detection. Tier 1 cannot scope the damage.",
    evidence: /\b(executed|ran|execution observed|was run|launched the payload)\b/i },
  { n: 2, short: "A login succeeded after failures, from an odd country, device or network",
    why: "The failures are noise. The success is the alert.",
    evidence: /(succeed\w*|approved)[^.;|]{0,80}(after|following)[^.;|]{0,40}(fail|denial|denied)|(\bsucceeded\b[^.;|]{0,60}\b(unmanaged|unrecognised|unrecognized|never used|tor)\b)/i },
  { n: 3, short: "An admin, service or break-glass account is involved", why: "Being wrong costs far more, and service accounts break every baseline." },
  { n: 4, short: "A crown-jewel asset or critical business service is involved", why: "Over-escalating costs minutes. Under-escalating costs the service." },
  { n: 5, short: "MFA push spam, a new MFA method, or consent to an unknown app",
    why: "Each is a way in that looks like ordinary user activity.",
    evidence: /(new (mfa|authenticator|multi-factor) (method|device) (was )?registered)|(\d+\s+denied\s+mfa)|(push (spam|bombing))|(consent (was )?granted to)/i },
  { n: 6, short: "Data leaving above threshold, or going somewhere unsanctioned",
    why: "You cannot un-send it.",
    evidence: /(exfiltrat\w+)|(data (was )?(uploaded|transferred|copied) to)|(anonymous (get|read|download))/i },
  { n: 7, short: "A security control was tampered with",
    why: "It shows intent, and it destroys the evidence that would disprove it.",
    evidence: /(edr (was )?(disabled|turned off|removed))|(agent (was )?removed)|(logs (were )?cleared)|(audit(ing)? (was )?disabled)/i },
  { n: 8, short: "New persistence was created",
    why: "Rarely innocent, never urgent-looking. The classic miss.",
    evidence: /(scheduled task (was )?created)|(new service (was )?installed)|(run key)|(startup item)|(persistence (was )?(created|established))/i },
  { n: 9, short: "Any sign of ransomware",
    why: "Speed matters more than accuracy here.",
    evidence: /(ransom\w*)|(shadow cop\w+ (were )?deleted)|(mass file (access|encryption))|(files (were )?encrypted)/i },
  { n: 10, short: "The same entity appears in another open incident", why: "Two weak signals on one entity are not two weak signals." },
  { n: 11, short: "The same rule keeps firing on this entity after it was closed before", why: "Either the rule needs tuning or the earlier closes were wrong. Both need a human." },
  { n: 12, short: "The entity is on the watchlist or named in a current advisory", why: "That is what the watchlist is for." },
  { n: 13, short: "The reporting device is unhealthy or its logs stopped",
    why: "The detection is unreliable, and the outage is itself worth looking at.",
    evidence: /(reporting device (is )?unhealthy)|(logs? (have |has )?stopped)|(agent (is )?not reporting)/i },
  { n: 14, short: "The alert does not match anything in this playbook", why: "An unknown alert goes to a human." },
  { n: 15, short: "Someone named is under HR or legal process", why: "Evidence handling is different. Do not touch it." }
];

/** Trigger 12 — the watchlist. Named executives, high-risk roles, anyone in a current advisory. */
export const watchlist = ["a.becker@northbank.example"];

/** Playbook Section 3, trigger 15 — people the SOC has been told are under HR or legal process. */
export const hrLegalHold = [];

/**
 * One number, everywhere (BRD C-02).
 * At or above this the agent acts on its own. Below it, a person decides — whatever the alert is.
 */
export const ACTION_CONFIDENCE = 85;

// Retained for reference and for the per-alert-type view; the decision uses ACTION_CONFIDENCE.
export const autoCloseThresholds = {
  "email.user_reported_phish": 85,
  "email.phish_delivered": 95,
  "identity.impossible_travel": 88,
  "identity.mfa_fatigue": 99,
  "identity.password_spray": 95,
  "endpoint.encoded_powershell": 92,
  "endpoint.lsass_access": 99,
  "endpoint.rmm_tool_install": 95,
  "cloud.public_storage_exposure": 90,
  "cloud.iam_key_created": 92
};

// Approved low-risk autonomous actions (BRD FR-080/081, C-04). Reversible, single-entity only.
export const approvedLowRiskActions = {
  soft_delete_email: { label: "Soft-delete confirmed malicious email from recipient mailboxes", reversal: "Restore from Recoverable Items via ITSM procedure OPS-114. Retention 30 days." },
  quarantine_attachment: { label: "Quarantine confirmed malicious attachment", reversal: "Release from quarantine console, procedure OPS-116." },
  submit_indicator_blocklist: { label: "Submit confirmed malicious indicator to the block list", reversal: "Remove indicator from the custom indicator list, procedure OPS-121." }
};

// Approved organisational lessons derived from analyst feedback (BRD FR-048, FR-092, 11.4).
export const seedLessons = [
  {
    id: "LSN-0007", status: "Approved", version: 3, submittedBy: "r.salamanca (Tier 2)", approvedBy: "SOC Manager",
    scope: "email.user_reported_phish",
    text: "Security-awareness phishing simulations are sent from the domain phishprep.example between 06:00 and 08:00 UTC on the first Tuesday of each month. These are authorised internal exercises: classify as Benign True Positive, do not raise a Tier 2 case, and do not soft-delete."
  },
  {
    id: "LSN-0012", status: "Approved", version: 1, submittedBy: "t.valdez (Tier 3)", approvedBy: "SOC Manager",
    scope: "cloud.public_storage_exposure",
    text: "A change record only justifies a public-exposure alert if it names the exact resource identifier. A change record for a different bucket in the same account is not evidence of authorisation — this caused a misclassification in February 2026."
  },
  {
    id: "LSN-0019", status: "Approved", version: 1, submittedBy: "a.dupont (Tier 2)", approvedBy: "SOC Manager",
    scope: "identity.impossible_travel",
    text: "The Milan egress range 194.62.18.0/24 is a corporate VPN concentrator, not a third-party location. Do not treat it as an unfamiliar location for EMEA sales staff."
  }
];
