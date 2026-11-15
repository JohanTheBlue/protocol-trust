# PROTOCOL: TRUST v0.16 — Gameplay validation notes

## Design references

| Source | Supported lesson | Application |
|---|---|---|
| Lucas Pope's *Papers, Please* development notes, https://dukope.com/devlogs/papers-please/tig-10/ | Clear, centralized reference material supports learning a growing ruleset | Keep the existing short rulebook and introduce controls by shift |
| Lucas Pope interview, https://www.gamedeveloper.com/design/designing-the-bleak-genius-of-i-papers-please-i- | Small, recurring decisions and compact presentation can carry meaningful consequences | Do not add a new mechanic or rule category merely for complexity |
| *Lil' Guardsman* official PlayStation description, https://store.playstation.com/en-us/concept/10004939 | Tools can change how a player investigates decisions | Keep the three elective helper scripts, not automatic decisions |
| Sweetser & Wyeth, *GameFlow* (2005), https://doi.org/10.1145/1077246.1077253 | Enjoyment framework: challenge, clear goals, control, and feedback | Keep the two score goals; display score changes at shift end; moderate unfair time punishment |

These are design inspirations, not evidence that this game is already fun for real players.

## Mechanics audited

- **Case distribution:** each shift still has 12 cases. The generator tries 48 random orders and favors fewer runs of four or more identical answers. It never randomizes the correct answer independently from the clues.
- **Score fairness:** the previous baseline deducted Operations on *every* email and additional Operations after 90 seconds. Even fully correct, thoughtful play could lose solely on time. The revised balance removes the unconditional per-email tax and allows 180 seconds before a minor time penalty.
- **Operations:** correct Forward +1; correct Human Review -1; correct Quarantine 0; unnecessary Human Review -2; blocking a safe email -5 (or a review-needed email -3); three consecutive timely correct decisions +1. After 180 seconds: -1 Operations for a longer delay (up to -2).
- **Security:** correct Review/Quarantine +1; a wrongly released threat produces a delayed Security penalty (not an Operations penalty), as before.
- **Feedback:** shift-end Operations and Security changes, plus alerts if any, without forcing detailed per-email results.
- **Available helpers:** in 500 random deck samples, from shifts 3–5 combined: App Detector has potential matches in 17–23 emails, Link Inspector in 6–10, Request Highlighter in 4–12. A potential match does not necessarily mean the helper was decisive.

## Automated tests (simulated players; *not* human playtests)

150 randomly generated games for each profile, 60 emails per game; results are sample-dependent:

| Profile | Goal met (Ops ≥70 and Sec ≥70) | Mean final Operations | Mean final Security |
|---|---:|---:|---:|
| 100% correct, quick | 100% | ~100 | 100 |
| 100% correct, 105s per email | 100% | ~90 | 100 |
| ~95% correct, quick | ~99% | ~97 | ~97 |
| ~90% correct, quick | ~95% | ~92 | ~92 |
| ~80% correct, quick | ~54% | ~76 | ~80 |
| Forward every email | 0% | 100 | 0 |
| Quarantine every email | 0% | 0 | ~97 |

Additional smoke tests: a complete 60-case run in headless Chromium at 390px mobile and 1365px desktop widths; no page-script errors observed; the shift-upgrade selection can be changed before starting.

**Interpretation:** the baseline 70/70 goal is accessible to careful players, while indiscriminate clicking fails. The existing **Excellent** rank is harder to earn (high scores, 95% accuracy, no incidents). These tests do not measure enjoyment, perceived fairness, or whether particular cases are too predictable; those require real players.

## Recommended human playtest (before v1.0)

Ask 3–5 players to complete one session, and record only: (1) confusing decisions, (2) where the game felt repetitive, (3) whether both scores felt fair, (4) which helper they chose and whether it was useful, (5) one overall fun rating (1–5). Fix recurring problems before adding bosses or forensics.
