# Evidence and dataset inventory (checked 2026-11-04)

1. Volexity, April 22, 2025 — https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
   - Public evidence: screenshot examples of Signal/WhatsApp outreach and an original phishing email, OAuth flow descriptions, sample URLs and detection advice.
   - Use: story and attack-method reference; *not* a downloadable full raw-email corpus for this operation.
2. Google Threat Intelligence, August 20, 2026 — https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia
   - Public evidence: UNC7005 technical narrative, WhatsApp device-linking workflow, sample infrastructure and IoC table.
   - Use: attack mechanic and indicator research. These are different campaign clusters from the Volexity UTA labels.
3. rf-peixoto/phishing_pot — https://github.com/rf-peixoto/phishing_pot
   - Public evidence: real honeypot phishing samples in EML form. Different threats; do not claim these are UTA0352/UNC7005 originals.
4. cw-l/message-corpus — https://github.com/cw-l/message-corpus
   - Public evidence: redacted EML and messaging samples. Routing headers removed, URLs defanged, spam/scam/phishing not further categorized.
5. malware-traffic-analysis.net — https://malware-traffic-analysis.net/training-exercises.html
   - Public evidence: malware traffic/PCAP training material for advanced mode, not an email corpus specifically about the Russian campaign.

## Handling for the game
- All 35 MVP emails, sender identities, domain names, policy updates, scoring and incidents are fictional training examples inspired by reported methods.
- Keep URL/attachments inert inside game and `.example` hostnames; do not import risky samples directly or preserve live links.
- Pair any future case with a citation, a clear 'original evidence' vs 'reconstructed' label, and a decision rationale.
- Always inspect licensing and redact PII before importing data.

6. Microsoft Learn — phishing recognition and Office internet-macro protections:
   - https://learn.microsoft.com/en-us/windows/security/threat-protection/intelligence/phishing
   - https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked
   - Use: display-name spoofing, password phishing, macro-enabled documents, simulated Office-protection bypass.
7. FBI IC3 — Business Email Compromise:
   - https://www.ic3.gov/CrimeInfo/BEC
   - Use: independently verify requests to modify supplier bank details.

All newly added cases are synthetic, not exact messages from these sources.
