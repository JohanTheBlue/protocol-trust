# PROTOCOL: TRUST — v0.12

Static, offline-friendly cyber email triage game. Open `index.html` locally or publish to GitHub Pages. No backend or real emails are processed in the game.

## Gameplay
- **5 shifts**, **60 cases per game** (12 per shift), newly drawn and shuffled whenever a game starts. Rules still unlock in order.
- Six simple categories: Sender, Sign-in, Apps, Links, Files, Access.
- Three decisions: Forward / Human Review / Quarantine.
- Operations and Security scores, time bonus, delayed incidents.
- Per-email result panel **off by default**. Turn it on at the start or between shifts; brief emoji feedback appears beside the score meters.
- Short shift-end summaries and a full final report are always shown.
- 18 fictional scenario templates mix sender status, message requests and link/file scan results between games. They are original examples, not Phishing Pot originals.
- Shift 4 limits obviously decisive scan labels to at most one known malicious URL and one malware detection from the fixed case pool. Neutral scans do not override suspicious requests.
- 31 fictional emails were revised for more natural writing and fewer answer-giving phrases; the six adapted Phishing Pot cases were kept unchanged in this update.
- Minimal visual playbook; shorter inbox flow with optional per-email results.

## Where the email cases came from
- **35** carried-over fictional cases; some are inspired by public incident reports, but no original emails were copied.
- **19** new fictional cases designed to test the current playbook.
- **6** new cases **adapted from real `.eml` samples** in [Phishing Pot](https://github.com/rf-peixoto/phishing_pot). These are significantly rewritten and use fictional senders, safe `.example` URLs, and fictional scan results. They are **not forensic originals**. Attribution and original blob SHAs are in `CASE_SOURCES.json`.
- Source samples from Phishing Pot are licensed **CC BY-NC 4.0**. This game must respect the dataset's attribution and noncommercial terms; review licensing before commercial distribution.

## Source-processing pipeline (offline)
1. Obtain the email samples from the upstream repo yourself, following its license and safety guidance. Do **not** publish its raw `.eml` files in this game repository.
2. Produce **review-only** candidates from a local folder (Python 3 standard library, no dependency):

   `python tools/eml_to_candidates.py /path/to/phishing_pot/email --output imports/candidates.json --limit 40`

3. Inspect the candidate data manually for privacy and safety; a raw phishing sample does **not** automatically tell us what the game verdict should be.
4. Choose an applicable game rule, rewrite the case into the fictional company setting, replace all URLs with inert `.example` placeholders, record the original path and content hash, then add a reviewed case to `BASE_CASES` in `game.js` and `CASE_SOURCES.json`.
5. Check the decision, evidence highlights and source provenance, then test the full game. Only checked examples should go live.

**Safety:** The importer reads only text; it never runs HTML, opens URLs, or saves attachments. However, imported drafts still require manual review. The `imports/` folder and `.eml` files are ignored by Git. No real external URLs are live in the game.

## v0.12 replay logic
- Reviewed base pool: 60 cases (35 original + 19 newly fictional + 6 adapted Phishing Pot).
- Each new game draws 42 base cases and builds 18 fictional variants from 18 manually written scenario templates (60 cases total).
- Day 4 draws seven base cases under scanner-alert caps and five generated variants.
- The game draws **evidence**, not random correct answers. The same public rule engine classifies each combination.
- Scanner “No alert” does not mean the sender or request is safe. A direct request for an authentication code still requires quarantine.
- Some base examples are intentionally easier. The harder challenge comes from mixed signals rather than making every single case ambiguous.
- Template variants are synthetic: they have no direct forensic source and are never labeled as adapted .eml cases.
