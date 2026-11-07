# v0.12 — Scenario template design

**18 original fictional scenario templates** supply one case per shift slot. Each has two reviewed message variants. The sender trust level is randomized, as are scan results for applicable cases. This is a game simulation, **not real forensic evidence**.

| Shift | Base cases | Template cases | New focus |
|---|---:|---:|---|
| 1 | 9 | 3 | Sender trust + ordinary business email |
| 2 | 9 | 3 | Sender + requests for passwords / MFA approval |
| 3 | 9 | 3 | Sender + company app list / device linking |
| 4 | 7 | 5 | Sender + links/files + message request |
| 5 | 8 | 4 | Sender + app/access + message request |

The existing `expectedVerdict()` is the only verdict authority. No random expected verdicts. Known malicious URL and malware scan results are still quarantined. New cases only use `No alert`, `Unclear` or `Not checked` to create more mixed decisions. The capped shift-4 selection gives at most one known malicious URL verdict and one known malware verdict in its selected base cases.
