# PROTOCOL: TRUST — MVP v0.6

Streamlined, offline cyber-awareness decision game.

## Play

Open `index.html` (or standalone `PROTOCOL_TRUST_MVP_v05.html`) in a modern browser.

- 5 shifts; **35 training emails** (7 per shift); 3 decisions.
- Company policy, app rules, highlighted feedback evidence, delayed incident consequences.
- **Human Review unlimited** where required; it adds a small base processing cost (−1 Operations), offset by +2 for fast, correct routing.
- **Quick correct decision** (<=90 seconds): **+2 Operations** on top of normal decision scoring.
- First 90 seconds are free from time penalty. Longer decisions cost up to 3 Operations.
- Visual Studio Code approval displays **FWD only**, not HOLD. Mixed situations (e.g. WhatsApp chat allowed / device pairing prohibited) explicitly display both applicable options.
- New training cases: external bulletins, maintenance, no-link code requests, routine WhatsApp / Signal chats, external Zoom approvals, macro-enabled Excel attachments, spoofed internal helpdesk, password phishing, billing changes, document security setting bypass, unsolicited MFA prompts.
- Fake `.example` email links are **non-clickable**; only documentary sources in the sources panel are live.
- Emails, business logic, IoCs, app policies and incidents are fictional reconstructions based on publicly documented techniques; not leaked messages.
- Full English user interface.

## Controls

A: Forward; S: Human Review; D: Quarantine; P: Policy; Enter: Continue.

## Source / provenance

See `SOURCES.md`. No backend, no tracking, no external network needed to play.

## v0.6 — Quiet Desk
- Email, policy manual, three decisions and two health indicators remain the primary play surface.
- Removed redundant labels, agent portrait, always-visible system log and long action instructions.
- Activity log is expandable; decision evidence and scoring details appear only on demand.
- Intro and shift notices are concise. The full policy manual and all 35 existing cases are preserved.
- No live message links, no backend, no analytics; works offline and on GitHub Pages.
