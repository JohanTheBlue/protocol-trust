# PROTOCOL: TRUST — v0.18 Alpha Playtest

A small, offline HTML/CSS/JavaScript email-screening game inspired by the decision-making pace of *Papers, Please*. The player operates a fictional AI screening agent.

## Play

- **Quick Demo:** 3 no-score practice emails, then 12 scored cases across 5 short shifts.
- **Full Game:** 60 scored cases across 5 shifts; the original mode remains available.
- **Choices:** Forward, Human Review, Quarantine. Check the short policy manual before deciding.
- **Goal:** finish with Operations and Security both at or above 70%.
- **Link Check:** reads only visible URL-like text in the email. All links are inert; no API or network scanning takes place.
- **Scripts:** choose a visual helper before Shift 3 and Shift 5. Helpers highlight information, not the right answer.

## Changes in v0.18

- Adds a lightweight tutorial and a selectable short demo; the full game is unchanged in length.
- Removes stale link-scan data from cases without a visible link. The URL scan verdict cannot apply to an email that has no URL.
- Raises the time-penalty grace period to **5 minutes per email**, with at most 1 Operations point deducted for an unusually long inspection. Accuracy still matters most.
- Keeps delayed Security incidents, per-shift summaries and the existing security controls.

## GitHub Pages / Termux

Download the GitHub ZIP into Android's Downloads folder, then:

```sh
cd ~/protocol-trust
unzip -o ~/storage/downloads/protocol_trust_v018.zip -d .
git add .
git commit -m "Alpha demo v0.18"
git push
```

Do not execute or open email sample links. All gameplay cases are fictional or adapted and use disabled URL text. Sources and acknowledgements are in `SOURCES.md`.

## Validation

- 1,200 randomized 60-case and 12-case deck pairs, with consistent choices and no phantom URL scans.
- Both playthroughs completed in Chromium at 390 px and 1365 px, including practice, upgrades and switching from demo to full.
- Score strategies and tradeoffs are recorded in `BALANCE_RESULTS.json` (model simulation, not user feedback).

Please test with real players before calling the game stable. See `PLAYTEST_GUIDE.md`.
