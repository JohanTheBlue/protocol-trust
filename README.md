# PROTOCOL: TRUST — v0.17

A compact, offline-friendly email-screening game inspired by the decision workflow in *Papers, Please*. Five shifts, 60 cases per run, three choices: Forward, Human Review, Quarantine.

## v0.17 — Link Check panel

- **LINK CHECK** is available below the current email. Opening it checks the visible subject/body for URLs; it shows `No link found` if none are present.
- A link may show `Threat found`, `Unclear`, or `No threat found`. An absence of alerts is **not** proof of safety.
- The email's old Link scan verdict badge is hidden until the player opens the separate panel.
- The optional third script is now **Link Highlighter**: it only marks domain names and is separate from the Link Check panel.
- The link check uses predefined, fictional **game-case results** and performs **no network requests or real-world URL reputation lookups**. All email links remain disabled.
- No changes to game rules, the 60-case set, or Ops/Sec scoring.

## Publish to GitHub Pages (Termux)

```sh
cd ~/protocol-trust
unzip -o ~/storage/downloads/protocol_trust_v017.zip -d .
git add . && git commit -m "Add Link Check panel v0.17" && git push
```

## Fixes from v0.16

- App Detector recognizes **SharePoint** and **MeetRoomX** as app names when the App Detector script is equipped. Detection is separate from approval; an unlisted app may still be detected.
- Delayed incidents lower **Security only**, not Operations. Incorrect decisions can still affect Operations immediately.

## Changes from v0.14

- Added genuine-looking **password-expiration reminders**: mentioning password renewal is not enough to quarantine. Requests to **send** an actual password are different. Sender status may still require Human Review.
- Upgrades now have a clear selection state. **You can switch your selection until you press START SHIFT**; only then is the script activated.
- The fictional company app inventory varies **per new game**, but remains constant within that playthrough. The same rules consistently determine the outcome. Zoom may require approval; Notion and SafeBox may be authorized or unlisted.
- The **App Detector** and **Request Highlighter** are independent optional helpers, with different colors. The latter highlights full requests instead of isolated everyday words like “send” and “share.” Neither helper automatically decides the case.
- All 6 security categories, the 60-case limit, delayed incidents, Ops/Sec scoring and the underlying case sources otherwise stay as before.

The added password reminders are **fictional examples**, not verbatim PhishingPot emails. `CASE_AUDIT.json` contains the original static case audit; random company policies can change the answer for a few app-approval cases at runtime.

## GitHub Pages deployment (Android Termux)

```sh
cd ~/protocol-trust
unzip -o ~/storage/downloads/protocol_trust_v0161.zip -d .
git add .
git commit -m "Neutral helpers and score cues v0.16.1"
git push
```

GitHub Pages deploys automatically after push. Email links inside the game are inert.

## v0.16 — gameplay balance

- 60 existing emails and 13 playbook rules are unchanged.
- Per-shift order prefers a mix of decision types rather than long runs of identical outcomes. The correct action for any email does not change.
- Operations: correct Forward +1, correct Human Review -1, correct Quarantine 0. Three consecutive correct choices within 90 seconds each give +1 Operations. No time penalty for the first 180 seconds per email.
- A mistaken Human Review costs 2 Operations; an unnecessary Quarantine costs 5. Wrongly forwarding a dangerous message can cause a delayed Security incident.
- Shift reports show change in Operations and Security since the start of the completed shift.
- The 70% / 70% goal and existing scripts remain.
- See `GAMEPLAY_VALIDATION.md` for sources, simulations and limitations.

## v0.16.1 — small UI and helper update

- App Detector marks **all recognized app mentions** in the subject and body, whether approved, unlisted, or irrelevant to the decision. It never decides whether the app is allowed.
- Request Highlighter marks common action requests, including ordinary/benign ones; the mark is **not** a threat warning.
- Link Inspector marks visible link domains and displays their domains without inferring reputation; links remain unclickable.
- The **Company App List** is a simple bullet list of allowed names, without usage tags or decorative row dividers. The randomly chosen list is unchanged for a run.
- Actual positive Operations/Security score changes show a short emoji at the **left** edge of the corresponding metric, losses at the **right** edge. Delayed incidents still affect Security only.
- No changes to the 60 case decisions or the security rulebook.
