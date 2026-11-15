# Development Scorecard — two axes

Score each dimension from **0–2** after a playtest: 0 = failing, 1 = partly working, 2 = working well. Score both axes separately; do not combine them into an overall marketing score. Unrated dimensions must remain unrated until observed.

## GAME / FUN (0–10)

1. **Mechanics** — Easy to learn, meaningful choices, optional helpers that do not decide for the player.
2. **Challenge** — Player must compare evidence; no one label reveals most answers.
3. **Enjoyment** — Player-reported interest over a full run (needs independent feedback).
4. **Visuals / effects** — Legibility on mobile and desktop; restrained effects.
5. **Achievement** — Clear objective, shift feedback and progress; earned success.

**v0.14 changes:** Automatic sender status removes repeated manual lookups. Shift 3/5 helper choice is now Request Highlighter, App Detector or Link Inspector. Shift summaries show best correct-answer run and a perfect-shift marker. The effects and metric scoring rules remain unchanged.

## PROFESSIONAL (0–8)

1. **Coverage** — Multiple relevant security controls and types of cases.
2. **Depth** — Sufficient detail to support each action without showing the answer.
3. **Accuracy** — Consistent, explainable results and correct handling of edge cases.
4. **Evidence** — Sources traceable to individual examples; reconstruction clearly identified.

**v0.14 changes:** None to the rulebook, case collection, source documents, or scoring logic. The game remains an educational abstraction, not a real mail security product.

### Release gate

Before public v1.0: one blind player trial, one full mobile playthrough, audit at least one false positive/false negative per category, and check OPS/SEC balance for both careless and careful runs. Player enjoyment cannot be certified by automated tests.

## v0.15 — Fun / Gameplay
- **Variety:** normal password-expiry notices can be forwarded or reviewed; sending a password remains prohibited.
- **Agency:** upgrade selection is reversible before each shift starts.
- **Clarity:** the two highlighting helpers are visibly independent; action phrases are highlighted rather than generic verbs.
- **Rule comparison:** randomized fictional company app inventory changes app-approval scenarios between games but stays consistent within a game.
- **Professional basis unchanged:** Microsoft/Volexity/Google source framework retained; new password cases are explicitly synthetic. A `Trusted` sender or a clean link scan never proves message safety.
