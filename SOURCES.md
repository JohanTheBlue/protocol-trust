# Professional basis and provenance — v0.7

This game **does not** reproduce an actual mail gateway or use real operational data. Its controls are simplified from the following public documentation, and its messages are all fictional reconstructions.

## Security-control foundations

1. **Email authentication and spoofing:** Microsoft Security Operations guide; SPF, DKIM, DMARC, composite authentication and spoof intelligence. Authentication results are not conclusive evidence of safety by themselves.
   https://learn.microsoft.com/en-us/defender-office-365/email-auth-sec-ops-guide
   https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-spoofing-about
2. **High-confidence phishing and quarantines:** Microsoft Defender for Office 365 mail quarantine policies and verdict-based actions.
   https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies
   https://learn.microsoft.com/en-us/defender-office-365/quarantine-about
3. **URLs:** Microsoft Defender Safe Links. Game's URL result is a simulated input, not a live reputation query.
   https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure
4. **Attachments:** Microsoft Defender Safe Attachments and Microsoft 365 Apps internet-macro protections.
   https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about
   https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked
5. **App permissions / reviews:** Microsoft Entra admin consent workflow.
   https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow
6. **High-risk change verification:** FBI IC3 business-email-compromise awareness.
   https://www.ic3.gov/CrimeInfo/BEC

## Inspiration for synthetic attack scenarios

- Volexity (2025), *Phishing for Codes* — diplomatic pretexts and OAuth code capture:
  https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
- Google Threat Intelligence (2026), *Distinct Clusters Target Individuals of Interest to Russia* — WhatsApp account linking and Microsoft device-code tactics:
  https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia

## Optional future training data (not included)

- Phishing Pot: https://github.com/rf-peixoto/phishing_pot
- Message Corpus: https://github.com/cw-l/message-corpus
- Malware traffic samples: https://malware-traffic-analysis.net/training-exercises.html

**All 35 emails, addresses, security scan verdicts, rule configurations, approval records and scores are fabricated training data.** They are not captured original emails from the cited threat campaigns. URLs in the messages are `.example` placeholders and intentionally non-clickable. Keep future sample imports defanged, properly licensed and free of personal information.

## Playbook layout reference (v0.9)

- Microsoft, *Incident response playbooks overview*: https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks
- Microsoft, *Phishing investigation*: https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing
- Microsoft, *Incident response playbook resources* (workflows/checklists): https://www.microsoft.com/en-us/download/details.aspx?id=103129

The visual playbook is an original simplified UI. The real templates describe incident investigation; the game turns the relevant screening checks into short fictional decision rules.

## Gameplay inspiration
- Lucas Pope interview: incremental rules and careful scheduling of new mechanics: https://www.gamedeveloper.com/design/designing-the-bleak-genius-of-i-papers-please-i-
- Serious game design criteria (balance meaningful play and educational goals): https://pmc.ncbi.nlm.nih.gov/articles/PMC7414398/
