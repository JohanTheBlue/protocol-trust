# Sources and provenance

## Research background
- Volexity, *Phishing for Codes* (2025): https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
- Google Threat Intelligence, *Distinct Clusters Target Individuals of Interest to Russia* (2026): https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia
- Microsoft Learn: email authentication, Safe Links, Safe Attachments, quarantine, Entra app consent (see `SOURCE` in `game.js`).

## Samples now used

Six *adaptations*, not verbatim email copies, were based on identifiable Phishing Pot `.eml` samples. Links below identify the originals; actual email contents, PII, live URLs and attachments are **not bundled**.

| Game ID | Upstream source | Adaptation |
|---|---|---|
| AX-036 | [sample-10095.eml](https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-10095.eml) | Urgent invoice reminder |
| AX-041 | [sample-7253.eml](https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-7253.eml) | Verification / password request |
| AX-046 | [sample-12766.eml](https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-12766.eml) | Zoom invitation / app approval |
| AX-051 | [sample-4642.eml](https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-4642.eml) | Invoice document-signing lure |
| AX-052 | [sample-6662.eml](https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-6662.eml) | QR-based reward lure |
| AX-056 | [sample-6898.eml](https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-6898.eml) | Urgent account verification |

Source: [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot), licensed CC BY-NC 4.0. Original blob SHA and original-vs-fictional status are tracked in `CASE_SOURCES.json`.

For an alternative already-redacted corpus, see [cw-l/message-corpus](https://github.com/cw-l/message-corpus), with redacted emails and defanged URLs. Those samples are **not yet incorporated**.

The 35 carried-over cases sometimes link to a research report as a **technique reference**, not as evidence that an actual published email was copied. All scan results and case verdicts in the game are fictional, manually defined training data.

## Procedural examples (v0.12)
The 18 scenario templates in `game.js` are original, fictional messages. Sender-check outcomes and scanner outcomes are randomly combined with reviewed message variants. They are not derived from raw .eml samples. Only base cases marked with an `.eml` origin have Phishing Pot provenance. A “No alert” scan is not proof of safety.
