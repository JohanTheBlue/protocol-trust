# PROTOCOL: TRUST — MVP v0.9.3

Offline, browser-based **security-control** game inspired by document inspection games. English-only UI.

## Run

Open `index.html` in a browser or deploy the root folder to GitHub Pages. No install, backend, accounts, or network connection required for gameplay. `PROTOCOL_TRUST_MVP_v09.html` (distributed separately) is a standalone single-file build.

## Gameplay

- 5 shifts · 7 emails each · 35 synthetic cases.
- Decisions: **Forward**, **Human Review**, **Quarantine**. Review is unlimited, but has a small Operations cost.
- Metrics: **Operations** and **Security**, with delayed consequences for missed high-confidence threats.
- Time: +2 Operations for correct decisions within 90 seconds; small penalty thereafter.
- Inert training URLs and attachments, no execution or links from messages.

## General security controls

| Shift | Area | Training signals |
| --- | --- | --- |
| 1 | Sender | Simulated authentication / spoof detection result |
| 2 | Credentials | Requests for passwords, PIN, MFA or OAuth codes |
| 3 | Applications | Company inventory and unapproved account linking |
| 4 | Links & attachments | Simulated URL/attachment scanning results and requests to bypass Office protections |
| 5 | Access | Independent authorization of sensitive changes; device-code and account-linking misuse |

Rules accumulate across shifts. Priority: **confirmed threat → Quarantine; approval/uncertainty → Human Review; otherwise → Forward**. Each scenario has a stable rule identifier (S1, C1, A1, etc.) shown after the decision.

**Important limits:** This is a *deliberately simplified training model*, not a real email security product. A passed SPF/DKIM/DMARC authentication does not prove an email safe; a failed check alone need not prove a malicious email. The simulated scan chips are invented case data, not actual scans of these fake messages. The company inventory, thresholds and scoring are also fictional. See `SOURCES.md` for actual controls and their source documents.

## Quality checks

`CASE_AUDIT.json` maps every case to its scan evidence, rule and expected action. The 35 correct-path decisions, the incorrect-action branch and a delayed incident were tested using a JavaScript DOM harness. Browser screenshot rendering was not available in the testing environment.

## Keys

A = Forward · S = Human Review · D = Quarantine · P = Policy · Enter = Continue.

## v0.8 UI changes

- Simple player-facing rulebook without internal rule codes. Each rule is tied to one action; default is Forward when none match.
- Review and Quarantine rules accumulate over five shifts. App list is hidden before Shift 3.
- Short, plain-English feedback and scanner badges. Evidence and scoring are optional details.
- Corrected inaccurate Security +1 on an incorrect Human Review of a confirmed threat.
- Technical rule IDs, scoring and 35 cases are kept for internal validation.

## v0.9 visual playbook

- Paper-style checklist grouped as Sender / Sign-in / Apps / Links / Files / Access.
- Each short rule shows the exact decision icon (✓ Forward, ⌕ Human Review, × Quarantine).
- Company app list appears inside the Apps section; allowed uses are displayed in plain English.
- Compact action priority key, final default rule, and short shift updates.
- No gameplay logic or cases changed relative to v0.8.
- Visual design is inspired by the structure of Microsoft phishing-investigation checklists and workflows, **not** a copy of a vendor's UI.

## v0.9.1 quick UI / decision patch
- Removed duplicate app verdict icons from the company app list and app scan badges from the email UI. The inventory itself is the reference.
- Sender authentication PASS alone never overrides malicious findings. Sign-in mention alone is allowed; secret requests and device-code misuse have separate rules.
- Request to link a chat account to another device without other confirmed threats now routes to Human Review (AX-008, AX-032); this is an educational triage choice, not a universal vendor policy.
- Removed redundant introduction / playbook / mail-footer text.
- Future idea (not implemented): optional upgrades that surface app names, sender/domain checks and URL clues.

## v0.9.2 UI and playbook cleanup
- Simple sender labels (Fake / Unknown) and no auto-approved Access badge.
- Choices title, Current rules label; company app list immediately under Apps.
- Access approval uses the manually checked Approved Changes list (`CHG-204`, Zoom research roundtable). Other references are not accepted automatically.
- Email attachment labels omit unnecessary simulation text; messages remain fictional and inert.
- Gameplay kept at 35 cases / 5 shifts; no upgrade shop yet.

### Game-design reference
Lucas Pope's *Papers, Please* uses progressively introduced rules and careful pacing: https://www.gamedeveloper.com/design/designing-the-bleak-genius-of-i-papers-please-i-
Serious-games research advocates challenge/difficulty fit and testing: https://pmc.ncbi.nlm.nih.gov/articles/PMC7414398/

## v0.9.3 — Sender labels and design audit
- Sender statuses: **Trusted**, **Not confirmed**, **Untrusted**. These are simplified in-game identity-verification outcomes, not full mail-safety ratings. In particular, a trusted sender can still send a harmful message (e.g. account compromise).
- No rule behavior, case answers, or scoring changed.
- Rulebook audit: 6 categories, 13 simple rules; compare *Papers, Please* progression. Strengths: gradual rule introduction, time/accuracy tradeoff, delayed outcomes. Next design improvement: more cross-checks between existing records, not more rules.
