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
export const PLAYBOOK_VERSION = "PB-T1-001 v0.10";

/**
 * Playbook Section 6 — alert types and how to handle each.
 *
 * "Close only if" is IN ADDITION to the Close rules in Section 2, never instead of them.
 * An alert type that is not in this table is trigger 14: it goes to a human.
 */
export const playbooks = {
  // ══ Wave 1 — Email and identity (§7). The person and their account. ══

  // §7.1 Email
  "email.user_reported_phish": {
    name: "User-reported phishing", wave: "Wave 1 — Email and identity", section: "7.1",
    check: "Sender history and domain age; whether anyone clicked; how many recipients got it; the URL and any attachment; whether similar mail was reported before",
    closeOnlyIf: "It is spam or marketing, or the URL and attachment are both clean and nobody clicked and nobody replied",
    alwaysEscalateIf: "Anyone clicked or entered credentials; the sender is a spoofed internal or partner domain; it targets finance or executives"
  },
  "email.malicious_attachment": {
    name: "Malicious attachment detected", wave: "Wave 1 — Email and identity", section: "7.1",
    check: "Whether it was blocked or delivered; the hash reputation; whether the file was opened; how many mailboxes received it; whether EDR saw anything on the host",
    closeOnlyIf: "It was blocked before delivery and no copy reached a mailbox",
    alwaysEscalateIf: "It was delivered and opened; EDR shows any activity on the host; the same file went to several users"
  },
  "email.phish_delivered": {
    name: "Malicious URL clicked", wave: "Wave 1 — Email and identity", section: "7.1",
    check: "Proxy or DNS logs for what happened after the click; whether credentials were submitted; site category and reputation; whether the page is a login clone",
    closeOnlyIf: "The click was blocked at the proxy and nothing loaded",
    alwaysEscalateIf: "The page loaded; credentials were submitted; it downloaded a file; the user is privileged"
  },
  "email.impersonation": {
    name: "Impersonation or business email compromise", wave: "Wave 1 — Email and identity", section: "7.1",
    check: "Display-name versus real address; reply-to mismatch; whether it asks for money, gift cards, or a bank-detail change; whether the recipient replied",
    closeOnlyIf: "It is a known lookalike already blocked, and no reply was sent",
    alwaysEscalateIf: "Any reply was sent; it requests a payment or bank-detail change; it impersonates a named executive"
  },
  "email.mailbox_rule": {
    name: "Suspicious mailbox rule or forwarding", wave: "Wave 1 — Email and identity", section: "7.1",
    check: "Who created the rule and when; whether it forwards externally; whether it hides mail by moving it to a rarely-read folder; recent logins for that account",
    closeOnlyIf: "The user created it themselves and it is an ordinary organisational rule, confirmed by the change or helpdesk record",
    alwaysEscalateIf: "It forwards to an external address; it deletes or hides mail; you cannot confirm the user created it"
  },
  "email.mass_file_sharing": {
    name: "Mass or anomalous file sharing", wave: "Wave 1 — Email and identity", section: "7.1",
    check: "How many files; who they were shared with; whether the link is public or anonymous; whether the volume is normal for this user",
    closeOnlyIf: "It matches a known project or migration, and sharing is internal only",
    alwaysEscalateIf: "Anonymous or public links; external recipients on sensitive content; the user is leaving or under notice"
  },

  // §7.2 Identity
  "identity.password_spray": {
    name: "Brute force or password spray", wave: "Wave 1 — Email and identity", section: "7.2",
    check: "Whether any attempt succeeded; how many accounts were targeted; the source IP and its reputation; whether the accounts are real or scanning noise",
    closeOnlyIf: "Every attempt failed, the source is a known scanner, and no targeted account exists or is enabled",
    alwaysEscalateIf: "Any success at all; a privileged account was targeted; the source is internal"
  },
  "identity.impossible_travel": {
    name: "Impossible travel or odd location", wave: "Wave 1 — Email and identity", section: "7.2",
    check: "The two logins and their times; VPN, proxy and mobile-roaming explanations; the device used; whether the account has travelled before",
    closeOnlyIf: "A VPN, proxy or corporate roaming explains it, and the device is a known managed one",
    alwaysEscalateIf: "No infrastructure explanation; a new or unmanaged device; the account is privileged; anything else happened in the session"
  },
  "identity.mfa_fatigue": {
    name: "MFA anomaly — push spam or repeated denials", wave: "Wave 1 — Email and identity", section: "7.2",
    check: "How many prompts and over how long; whether any was approved; where they came from; whether the password is therefore known",
    closeOnlyIf: "The user was genuinely logging in themselves, confirmed out of band",
    alwaysEscalateIf: "Any prompt was approved; the pattern is repeated over hours; the source is unexpected — assume the password is compromised"
  },
  "identity.new_mfa_method": {
    name: "New MFA method registered", wave: "Wave 1 — Email and identity", section: "7.2",
    check: "Who registered it; from what device and location; whether it came after a password reset or a suspicious login",
    closeOnlyIf: "It matches a helpdesk or self-service record from the user's own device",
    alwaysEscalateIf: "It follows a suspicious login or reset; it was done from an unexpected location; the account is privileged"
  },
  "identity.privilege_change": {
    name: "Privilege change or group membership added", wave: "Wave 1 — Email and identity", section: "7.2",
    check: "Who made the change and whether they were authorised to; whether there is a change record; what the new privilege allows",
    closeOnlyIf: "An approved change record covers this account, this group and this time",
    alwaysEscalateIf: "No change record; self-granted; a highly privileged group; done outside working hours"
  },
  "identity.dormant_account": {
    name: "Dormant or disabled account used", wave: "Wave 1 — Email and identity", section: "7.2",
    check: "When the account was last used; whether it is a leaver; whether it is a service account nobody retired",
    closeOnlyIf: "It is a service account with a documented owner and expected use",
    alwaysEscalateIf: "It belongs to a leaver; it authenticated externally; it is disabled but still authenticating"
  },
  "identity.oauth_consent": {
    name: "OAuth consent granted to an app", wave: "Wave 1 — Email and identity", section: "7.2",
    check: "The publisher and app age; what permissions were requested; how many users consented; whether it can read mail or files",
    closeOnlyIf: "The app is on the approved list",
    alwaysEscalateIf: "Unknown publisher; broad mail or file permissions; several users consented in a short window"
  },

  // ══ Wave 2 — Endpoint (§8). The machine. ══
  "endpoint.malware_quarantined": {
    name: "Malware detected and quarantined", wave: "Wave 2 — Endpoint", section: "8",
    check: "The hash reputation; how the file arrived; whether the quarantine actually held; whether the same hash is on other hosts",
    closeOnlyIf: "Quarantine held, the file never executed, and the hash appears nowhere else",
    alwaysEscalateIf: "It executed before quarantine; quarantine failed; the same file is on multiple hosts"
  },
  "endpoint.malware_uncontained": {
    name: "Malware detected, not contained", wave: "Wave 2 — Endpoint", section: "8", neverClose: true,
    check: "What the process did; parent and child processes; network connections made; files written; the user context",
    closeOnlyIf: "Never — this always escalates",
    alwaysEscalateIf: "Always. Uncontained malware is Tier 2 by definition."
  },
  "endpoint.encoded_powershell": {
    name: "Suspicious script or PowerShell", wave: "Wave 2 — Endpoint", section: "8",
    check: "The full command line, decoded; the parent process; whether it reaches out to the network; whether it matches an admin or deployment tool",
    closeOnlyIf: "It matches a known admin script or software-deployment job, confirmed against the change or tooling record",
    alwaysEscalateIf: "It is encoded or obfuscated; it downloads anything; the parent is a browser or an Office application"
  },
  "endpoint.persistence": {
    name: "Persistence created", wave: "Wave 2 — Endpoint", section: "8",
    check: "What was created — scheduled task, service, run key, startup item; what it runs; who created it; when",
    closeOnlyIf: "A software install or a deployment tool created it, and the change record confirms it",
    alwaysEscalateIf: "Anything you cannot attribute to a known install; it runs a script or a file from a temp folder"
  },
  "endpoint.control_tampering": {
    name: "Security control tampered with", wave: "Wave 2 — Endpoint", section: "8", neverClose: true,
    check: "What was disabled or cleared; by which account; whether there is a change record; what happened just before",
    closeOnlyIf: "Never — this always escalates",
    alwaysEscalateIf: "Always. Tampering is intent, and it destroys the evidence."
  },
  "endpoint.ransomware": {
    name: "Ransomware indicators", wave: "Wave 2 — Endpoint", section: "8", neverClose: true,
    check: "Rate of file modification; shadow copy deletion; extension changes; whether it is spreading across hosts",
    closeOnlyIf: "Never — this always escalates",
    alwaysEscalateIf: "Always, immediately. Time to containment beats everything else."
  },
  "endpoint.lsass_access": {
    name: "Credential access — LSASS or dumping tools", wave: "Wave 2 — Endpoint", section: "8",
    check: "The accessing process and its lineage; whether the tool is a known admin utility; what the account is; whether anything was written to disk",
    closeOnlyIf: "It is a signed backup or EDR product doing its normal job, confirmed in the tooling inventory",
    alwaysEscalateIf: "Anything else. Assume credentials are exposed and escalate."
  },
  "endpoint.removable_media": {
    name: "Removable media or device control", wave: "Wave 2 — Endpoint", section: "8",
    check: "Which device and its serial; who connected it and to which host; whether files were copied, how many and how large; whether the device is on the approved list; whether the user is under notice or leaving",
    closeOnlyIf: "An approved device on the documented list, used by its registered owner, with no bulk copy",
    alwaysEscalateIf: "An unapproved device on a host holding sensitive data; bulk copy to removable media; the user is leaving; anything executed from the device"
  },

  // ══ Wave 3 — Network and cloud (§9). The infrastructure and the traffic between them.
  // Two wave-level rules govern everything here and outrank any individual row:
  //   §9.1 A block is not a verdict. "It was blocked" is evidence about the control, never on its
  //        own the innocent explanation the Close test requires.
  //   §9.2 Direction first. Inbound-blocked, outbound-blocked, outbound-allowed and internal-to-
  //        internal carry different default postures. ══

  // §9.3 Firewall
  "network.inbound_denied": {
    name: "Inbound connection denied by policy", wave: "Wave 3 — Network and cloud", section: "9.3",
    sensors: "firewall, IPS",
    check: "Source reputation and whether it is a known scanner; how many destinations and ports it touched; whether that destination is actually exposed; whether anything from the same source was allowed",
    closeOnlyIf: "It is untargeted internet scanning, everything was denied, and nothing from that source got through",
    alwaysEscalateIf: "Anything from the same source was allowed; it hit one host repeatedly; the destination is a published service and the pattern matches exploitation"
  },
  "network.outbound_denied": {
    name: "Outbound connection denied by policy", wave: "Wave 3 — Network and cloud", section: "9.3",
    sensors: "firewall, DNS security, application control",
    check: "Which internal host and user; destination reputation, category and domain age; how many attempts and over what period; which process on the host, if EDR can say",
    closeOnlyIf: "The destination is a plainly mis-categorised legitimate site, and the attempt pattern matches a person browsing",
    alwaysEscalateIf: "The destination is known-bad or newly registered; the attempts repeat on a regular interval; the source is a server, not a workstation"
  },
  "network.rare_destination": {
    name: "New or rare external destination", wave: "Wave 3 — Network and cloud", section: "9.3",
    sensors: "NDR, firewall, DNS security",
    check: "Destination age, reputation, ASN and hosting provider; whether this host talks externally at all in normal operation; which process opened it, if EDR can say; volume and direction",
    closeOnlyIf: "It maps to a documented update service, vendor or SaaS the host legitimately uses, confirmed against the asset or tooling record",
    alwaysEscalateIf: "A newly registered domain; the source is a server with no reason to egress; outbound volume; it repeats on a regular interval"
  },
  "network.allowed_known_bad": {
    name: "Allowed connection to a known-bad destination", wave: "Wave 3 — Network and cloud", section: "9.3",
    sensors: "firewall, NDR, DNS security", neverClose: true,
    check: "What got through and why no rule stopped it; how much data moved and in which direction; the internal host and process; when the destination was added to the feed",
    closeOnlyIf: "Never. Even if the destination turns out to be mis-classified, a control that should have blocked and did not is a finding",
    alwaysEscalateIf: "Always"
  },
  "network.firewall_policy_change": {
    name: "Firewall policy or configuration changed", wave: "Wave 3 — Network and cloud", section: "9.3",
    sensors: "firewall, change management",
    check: "Who changed it, from where, and whether they were authorised; whether a change record covers it; what it now permits that it did not before; whether logging was affected",
    closeOnlyIf: "An approved change record covers this rule, this device and this time",
    alwaysEscalateIf: "No change record; it widens access from the internet; it disables or reduces logging; it was made outside a change window"
  },

  // §9.4 Applications
  "app.unsanctioned": {
    name: "Unsanctioned application detected", wave: "Wave 3 — Network and cloud", section: "9.4",
    sensors: "application control, NDR, cloud access logs",
    check: "Which application and category — cloud storage, file transfer, P2P, streaming, anonymiser; the user and host; whether data moved and how much; whether the user has a stated business need",
    closeOnlyIf: "It is on the documented permitted-with-exception list, used by someone entitled to it, with no bulk data transfer alongside it",
    alwaysEscalateIf: "Cloud storage or file transfer with real volume; Tor or any anonymiser; the user has access to sensitive data; it is on a server"
  },
  "app.remote_access_tool": {
    name: "Remote access or tunnelling tool", wave: "Wave 3 — Network and cloud", section: "9.4",
    sensors: "application control, NDR, EDR",
    check: "Which tool; whether it is the organisation's own remote-support product; who installed it and when; whether a session was actually established and from where; whether a support ticket exists",
    closeOnlyIf: "It is the sanctioned remote-support tool, on a managed host, during a ticketed session you can point to",
    alwaysEscalateIf: "Anything else. Unsanctioned remote access is how both intruders and phone-based social engineering get hands on a machine"
  },

  // §9.5 Traffic. An NDR alert says something changed, not that something is wrong — and an NDR
  // alert no other tool corroborates is the normal case, not a reason to close. If the baseline for
  // that entity is immature, the alert is not triageable: hold it and say so.
  "traffic.ips_inbound_blocked": {
    name: "IPS signature triggered — inbound, blocked", wave: "Wave 3 — Network and cloud", section: "9.5",
    sensors: "IPS, firewall, WAF",
    check: "What the signature targets; whether the destination actually runs that software and version; whether it is a spray across many hosts or one host repeatedly; whether anything from that source was allowed",
    closeOnlyIf: "The target is not vulnerable to what was attempted, the attempt was blocked, and the traffic was untargeted scanning",
    alwaysEscalateIf: "The target runs the affected software; the same source returned; anything from it was allowed"
  },
  "traffic.ips_outbound_internal": {
    name: "IPS signature triggered — outbound or internal", wave: "Wave 3 — Network and cloud", section: "9.5",
    sensors: "IPS, NDR, EDR", neverClose: true,
    check: "Which internal host generated it; what the signature indicates — command-and-control, exploit, attack tooling; whether it repeats; what else that host has done",
    closeOnlyIf: "Never. Traffic matching an attack signature that originated inside your network is a host problem, not a perimeter problem",
    alwaysEscalateIf: "Always"
  },
  "traffic.internal_scanning": {
    name: "Internal scanning or host enumeration", wave: "Wave 3 — Network and cloud", section: "9.5",
    sensors: "NDR, IPS, firewall",
    check: "Source host and account; how many destinations and ports; whether it matches the authorised vulnerability scanner by address and schedule; the time of day",
    closeOnlyIf: "It is the authorised scanner, from its documented address, inside its scheduled window",
    alwaysEscalateIf: "Anything else — including the authorised scanner from an unexpected address, or outside its window"
  },
  "traffic.beaconing": {
    name: "Beaconing or periodic outbound pattern", wave: "Wave 3 — Network and cloud", section: "9.5",
    sensors: "NDR, IPS, firewall, DNS security",
    check: "How regular the interval is and how long it has run; jitter; payload size; destination age and reputation; total bytes and direction; the process on the host; whether it survives a reboot",
    closeOnlyIf: "It maps to a known agent — monitoring, backup, telemetry, update — confirmed in the tooling inventory, not assumed from the destination name",
    alwaysEscalateIf: "The destination is unknown or newly registered; a regular interval with a small payload; large outbound volume at an unusual hour; it started at a time you can tie to something else"
  },
  "traffic.lateral_movement": {
    name: "Unusual east-west connection or lateral movement", wave: "Wave 3 — Network and cloud", section: "9.5",
    sensors: "NDR, EDR, identity logs. Correlated version: Wave 4",
    check: "Source and destination roles; whether that pair has ever communicated; the protocol — SMB, RDP, WinRM, SSH; the account used; whether the connection succeeded; how many destinations followed",
    closeOnlyIf: "An approved change, a documented administrative path or the authorised scanner explains it, from the address and at the time it should be",
    alwaysEscalateIf: "Workstation to workstation; a server reaching a segment it never touches; an administrative protocol from a non-administrative host; a fan-out to many destinations"
  },
  "traffic.protocol_anomaly": {
    name: "Protocol anomaly or tunnelling", wave: "Wave 3 — Network and cloud", section: "9.5",
    sensors: "NDR, IPS, DNS security",
    check: "Which protocol on which port; whether the payload matches the protocol the port implies; whether SSH, DNS or HTTPS is carrying something else; both endpoints and their roles",
    closeOnlyIf: "A documented application legitimately uses that non-standard port, confirmed in the application inventory",
    alwaysEscalateIf: "The payload does not match the protocol; anything tunnelled inside another protocol; encrypted traffic where cleartext is expected and nobody can say why"
  },
  "traffic.encrypted_anomaly": {
    name: "Encrypted traffic anomaly — fingerprint or certificate", wave: "Wave 3 — Network and cloud", section: "9.5",
    sensors: "NDR only",
    check: "The client fingerprint and whether it matches software actually installed on that host; certificate issuer, validity and whether it is self-signed; whether the SNI matches the destination; whether that host even has a browser",
    closeOnlyIf: "The fingerprint maps to known software confirmed present on the asset",
    alwaysEscalateIf: "The fingerprint matches known offensive or remote-access tooling; a self-signed certificate to an external destination; SNI that does not match where the traffic went"
  },
  "traffic.data_staging": {
    name: "Data staging or large internal transfer", wave: "Wave 3 — Network and cloud", section: "9.5",
    sensors: "NDR, EDR, DLP, cloud audit, device control",
    check: "Volume against the baseline for that pair; direction; which share, database or repository was touched; the hour; whether an external transfer, a cloud upload or a USB copy followed within the window",
    closeOnlyIf: "A documented backup, replication or migration job, confirmed against its schedule — not inferred from the fact that it looks like one",
    alwaysEscalateIf: "No scheduled job covers it; any egress followed; an unusual hour; the source is a user workstation rather than a server"
  },
  "traffic.new_listening_service": {
    name: "New listening service on an internal host", wave: "Wave 3 — Network and cloud", section: "9.5",
    sensors: "NDR, EDR, vulnerability scanner",
    check: "Which host and port; what is listening and who started it; whether it appeared alongside a change or an install; whether anything has connected to it and from where",
    closeOnlyIf: "An approved change or a software deployment explains it, and nothing unexpected has connected",
    alwaysEscalateIf: "No change record; it accepts connections from outside its segment; it is a known remote-access, proxy or tunnelling port"
  },

  // §9.6 DNS
  "dns.malicious_domain": {
    name: "Request to a blocked or malicious domain", wave: "Wave 3 — Network and cloud", section: "9.6",
    check: "Which internal host and user; how many requests and over what period; whether a person was browsing at the time or a process made them; what the domain is classified as",
    closeOnlyIf: "It is adware or tracking, the count is low, and it lines up with the user actively browsing",
    alwaysEscalateIf: "The requests repeat with no user activity; the domain is command-and-control or a known malware family; the request came from a server"
  },
  "dns.tunnelling": {
    name: "DNS tunnelling or DGA pattern", wave: "Wave 3 — Network and cloud", section: "9.6",
    check: "Query volume and the randomness of the labels; whether one parent domain owns them all; the requesting host; whether the queries resolve",
    closeOnlyIf: "It matches a product that legitimately uses DNS for telemetry or reputation lookups, confirmed in the tooling inventory",
    alwaysEscalateIf: "Anything else. DNS tunnelling is exfiltration or command-and-control by design, not by accident"
  },
  "dns.new_domain": {
    name: "Newly registered or low-reputation domain resolved", wave: "Wave 3 — Network and cloud", section: "9.6",
    check: "Domain age; which host resolved it; whether it came from a link in an email; whether a connection or download followed the resolution",
    closeOnlyIf: "It is a legitimate new service the user chose to visit, and nothing was downloaded and no credentials were submitted",
    alwaysEscalateIf: "It followed a phishing email; a connection and a download followed; several hosts resolved it inside a short window"
  },

  // §9.7 Web apps — the discriminator is almost always whether the application responded as if it worked.
  "webapp.blocked_exploit": {
    name: "Blocked exploit attempt — injection, traversal, RCE", wave: "Wave 3 — Network and cloud", section: "9.7",
    check: "Whether every request was blocked; source reputation and whether it is a known scanner; how many distinct payloads and endpoints; whether any response differs from the normal one",
    closeOnlyIf: "Single-source automated scanning, everything blocked, and no response suggests anything succeeded",
    alwaysEscalateIf: "Any request was not blocked; the payloads adapt across attempts, which means a person is driving it; the endpoint handles authentication or payment"
  },
  "webapp.successful_exploit": {
    name: "Exploit pattern with a successful response", wave: "Wave 3 — Network and cloud", section: "9.7", neverClose: true,
    check: "The response code and body size against the normal baseline; what that endpoint does; what else came from the same source afterwards; the application's own logs",
    closeOnlyIf: "Never. A matched exploit pattern that returned a normal response is the case where the WAF did not save you",
    alwaysEscalateIf: "Always"
  },
  "webapp.credential_stuffing": {
    name: "Credential stuffing or brute force against the application", wave: "Wave 3 — Network and cloud", section: "9.7",
    check: "Success-to-failure ratio; how many distinct accounts; whether the sources are one address or thousands; whether any login succeeded; whether MFA is enforced on this application",
    closeOnlyIf: "Every attempt failed, the accounts targeted do not exist, and the source is a single known scanner",
    alwaysEscalateIf: "Any success; distributed sources; the accounts are real; the application has no MFA"
  },
  "webapp.bot_scraping": {
    name: "Bot or scraping activity", wave: "Wave 3 — Network and cloud", section: "9.7",
    check: "Request rate and pattern; the user agent and whether it is honest; what is being enumerated; whether it reaches pricing, user data or API endpoints; whether it is affecting availability",
    closeOnlyIf: "It is a known good bot verified by reverse DNS, or a partner integration on the documented list",
    alwaysEscalateIf: "It enumerates user data or an API; it works around rate limits; it appears alongside credential attempts"
  },

  // §9.8 Cloud
  "cloud.anomalous_api": {
    name: "Anomalous API activity", wave: "Wave 3 — Network and cloud", section: "9.8",
    check: "Which principal; from which IP and region; whether the call pattern is new for that principal; whether it is enumeration",
    closeOnlyIf: "It is a known automation or CI principal doing its documented job",
    alwaysEscalateIf: "A human principal behaving like a script; enumeration calls; a region you do not operate in"
  },
  "cloud.iam_policy_change": {
    name: "IAM policy or role change", wave: "Wave 3 — Network and cloud", section: "9.8",
    check: "Who changed it and what it now permits; whether a change record exists; whether it widens access or removes logging",
    closeOnlyIf: "An approved change record covers this role and this time",
    alwaysEscalateIf: "No change record; self-granted; it widens access broadly; it disables logging or monitoring"
  },
  "cloud.public_storage_exposure": {
    name: "Storage or resource made public", wave: "Wave 3 — Network and cloud", section: "9.8",
    check: "What is in it; how long it has been exposed; whether it was ever accessed externally; who changed it",
    closeOnlyIf: "It is a deliberate public asset — a website or public dataset — and is documented as such",
    alwaysEscalateIf: "It holds any internal or personal data; there is any external access in the logs; nobody can say why it changed"
  },
  "cloud.iam_key_created": {
    name: "Cloud credential or key exposed", wave: "Wave 3 — Network and cloud", section: "9.8",
    check: "Where it was found; whether it is live; what it can reach; whether it has been used",
    closeOnlyIf: "The key is already revoked and was never used",
    alwaysEscalateIf: "The key is live; it has been used; it can reach production or data"
  },
  "cloud.new_region": {
    name: "New region or unusual service used", wave: "Wave 3 — Network and cloud", section: "9.8",
    check: "Who enabled it; whether the account operates there; what was spun up; the cost pattern",
    closeOnlyIf: "A project or change record covers it",
    alwaysEscalateIf: "No record; compute-heavy resources — assume cryptomining until shown otherwise; a region you never use"
  },
  "cloud.workload_alert": {
    name: "Cloud workload or container alert", wave: "Wave 3 — Network and cloud", section: "9.8",
    check: "What the workload is; whether the image is from your registry; what the process did; whether the workload is internet-facing",
    closeOnlyIf: "It is a known scanner or agent behaving normally",
    alwaysEscalateIf: "An unknown image; an internet-facing workload; anything reaching the metadata service"
  },

  // ══ Wave 4 — XDR (§10). The story across all of the above.
  // An XDR incident is not a new detection: it is a claim that alerts which already fired belong to
  // one story. The job is to triage that claim, not to re-triage the member alerts. Class A means
  // Tier 1 may dispose of it; class B means Tier 1 assembles the package and escalates, never
  // disposes. The vendor's named chain is a hypothesis, not a finding. ══
  "xdr.single_alert": {
    name: "Single-alert XDR incident", wave: "Wave 4 — XDR", section: "10.5", triageClass: "A — Tier 1 disposes",
    check: "Whether the incident has only one member alert; which domain it came from; whether XDR added anything the source alert did not have",
    closeOnlyIf: "The underlying alert type's own rules in Waves 1 to 3 are met. Treat it as that alert, not as an XDR incident",
    alwaysEscalateIf: "Whatever the underlying alert type would escalate on"
  },
  "xdr.multi_signal_one_entity": {
    name: "Multiple signals, one entity, one domain", wave: "Wave 4 — XDR", section: "10.5", triageClass: "A — Tier 1 disposes",
    check: "How many member alerts and over what period; whether they are the same detection repeating or genuinely different ones; whether the sequence moves forward",
    closeOnlyIf: "They are one detection repeating on a known-benign cause, and every member alert would close on its own rules",
    alwaysEscalateIf: "The member alerts are different detections; the sequence progresses — attempt, then success, then action"
  },
  "xdr.cross_domain_chain": {
    name: "Cross-domain chain on one identity", wave: "Wave 4 — XDR", section: "10.5",
    triageClass: "B — assemble and escalate", neverClose: true,
    check: "The order the domains fired in — email, then identity, then endpoint is the classic chain; the gap between steps; whether each step succeeded; whether any step is missing",
    closeOnlyIf: "Never. Tier 1 does not dispose of this",
    alwaysEscalateIf: "Always. A chain across domains on one identity is the case XDR exists to find"
  },
  "xdr.lateral_movement": {
    name: "Multi-host or lateral movement", wave: "Wave 4 — XDR", section: "10.5",
    triageClass: "B — assemble and escalate", neverClose: true,
    check: "Which hosts, in what order; the account used to move; whether the account differs per host; what was reached; whether it is still moving",
    closeOnlyIf: "Never. Tier 1 does not dispose of this",
    alwaysEscalateIf: "Always, and treat it as a Tier 3 candidate, not only Tier 2"
  },
  "xdr.named_attack_chain": {
    name: "Vendor-named attack chain", wave: "Wave 4 — XDR", section: "10.5",
    triageClass: "B — assemble and escalate", neverClose: true,
    check: "What the correlation logic actually keys on; which member alerts carry the claim; whether removing the shared entity breaks the link; the ATT&CK techniques asserted",
    closeOnlyIf: "Never. If you believe it is over-correlation, say so in the package — do not close it",
    alwaysEscalateIf: "Always. Say explicitly whether the name is supported by two or more independent member alerts, or rests on one"
  },
  "xdr.auto_response_fired": {
    name: "Automated response already fired", wave: "Wave 4 — XDR", section: "10.5",
    triageClass: "B — assemble and escalate", neverClose: true,
    check: "What was contained and when; whether containment held; what happened in the minutes before it fired; whether anything on the entity is still live",
    closeOnlyIf: "Never. Tier 1 does not dispose of this",
    alwaysEscalateIf: "Always. Something already acted on production. A human confirms it was right and that it was enough"
  },
  "xdr.reopens_closed_alerts": {
    name: "Pulls in alerts Tier 1 already closed", wave: "Wave 4 — XDR", section: "10.5",
    triageClass: "B — assemble and escalate", neverClose: true,
    check: "Which closed incidents were pulled in; who closed them and on what reasoning; whether the close was wrong or only incomplete",
    closeOnlyIf: "Never. Tier 1 does not dispose of this",
    alwaysEscalateIf: "Always, and route it to the QA review as well as to Tier 2. This is a false negative announcing itself — the one thing that normally never does"
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
