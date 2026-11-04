/* PROTOCOL: TRUST — synthetic threat-awareness game. No live messages, telemetry or external requests. */
'use strict';

const SOURCE = Object.freeze({
  volexity: { short: 'Volexity · Phishing for Codes (2025)', url: 'https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/' },
  google: { short: 'Google Threat Intelligence · Going with the Flow(s) (2026)', url: 'https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia' },
  microsoft: { short: 'Microsoft Learn · Authentication flows', url: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows' },
  corpus: { short: 'Message Corpus · redacted .eml samples', url: 'https://github.com/cw-l/message-corpus' },
  phishingpot: { short: 'Phishing Pot · honeypot email samples', url: 'https://github.com/rf-peixoto/phishing_pot' },
  pcap: { short: 'Malware Traffic Analysis · network exercises', url: 'https://malware-traffic-analysis.net/training-exercises.html' },
  microsoftmacro: { short: 'Microsoft Learn · Macros from the internet', url: 'https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked' },
  microsoftphish: { short: 'Microsoft Learn · Recognizing phishing messages', url: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/intelligence/phishing' },
  ic3: { short: 'FBI IC3 · Business email compromise', url: 'https://www.ic3.gov/CrimeInfo/BEC' }
});

const DAYS = [
  {
    "title": "FIRST SHIFT",
    "focus": [
      {
        "action": "forward",
        "text": "Routine internal messages may pass."
      },
      {
        "action": "quarantine",
        "text": "Requests for PINs, codes and sign-in URLs must be held."
      },
      {
        "action": "review",
        "text": "Unverified diplomatic introductions need a manual check."
      }
    ],
    "briefing": "ASTERION has deployed its new message-screening AI, SENTINEL/01. Start with the basic rules: keep legitimate work moving, but never pass messages requesting secret authentication codes.",
    "apps": [
      [
        "Microsoft 365 / Teams",
        "Approved for normal internal work",
        [
          "forward"
        ]
      ],
      [
        "Signal",
        "Approved for professional chat; codes forbidden",
        [
          "forward",
          "quarantine"
        ]
      ],
      [
        "WhatsApp",
        "External chat allowed; account linking forbidden",
        [
          "forward",
          "quarantine"
        ]
      ]
    ],
    "rules": [
      {
        "action": "forward",
        "text": "Pass routine internal coordination with no unusual login or credential request."
      },
      {
        "action": "forward",
        "text": "Allow informational external notices that request no sign-in, secrets or new application access."
      },
      {
        "action": "quarantine",
        "text": "Hold any message requesting an authentication code, PIN, or complete sign-in redirect URL."
      },
      {
        "action": "review",
        "text": "Escalate unverified diplomatic introductions until the sender can be confirmed."
      }
    ]
  },
  {
    "title": "APPLICATION POLICY UPDATE",
    "focus": [
      {
        "action": "review",
        "text": "External Zoom meetings require prior approval."
      },
      {
        "action": "quarantine",
        "text": "WhatsApp device-pairing QR codes must be held."
      },
      {
        "action": "quarantine",
        "text": "Never disclose Google App Passwords."
      },
      {
        "action": "quarantine",
        "text": "External macro-enablement instructions must be held."
      }
    ],
    "briefing": "New restrictions have arrived. Proposing an app is not automatically malicious, but unapproved workflows require a check. Pay special attention to what a QR code actually does.",
    "apps": [
      [
        "Microsoft 365 / Teams",
        "Approved for internal and vetted external work",
        [
          "forward"
        ]
      ],
      [
        "Signal",
        "Normal chat allowed; never share PINs",
        [
          "forward",
          "quarantine"
        ]
      ],
      [
        "WhatsApp",
        "Chat allowed; external device pairing prohibited",
        [
          "forward",
          "quarantine"
        ]
      ],
      [
        "Zoom",
        "External meeting requires prior approval",
        [
          "review"
        ]
      ],
      [
        "Google App Password",
        "Never generate or disclose for an outsider",
        [
          "quarantine"
        ]
      ],
      [
        "Microsoft Excel attachments",
        "External request to enable macros: HOLD",
        [
          "quarantine"
        ]
      ]
    ],
    "rules": [
      {
        "action": "quarantine",
        "text": "Hold a request to link WhatsApp Linked Devices using a conference QR code."
      },
      {
        "action": "review",
        "text": "Send an unapproved external Zoom invitation for human approval."
      },
      {
        "action": "quarantine",
        "text": "Hold requests to create or share an app password with an external party."
      },
      {
        "action": "forward",
        "text": "Routine internal M365 or SharePoint work may pass without unusual sign-in instructions."
      },
      {
        "action": "forward",
        "text": "Allow ordinary professional WhatsApp messages that request no account linking or codes."
      },
      {
        "action": "quarantine",
        "text": "Hold external Office attachments that ask the user to enable macros or disable Office protections."
      }
    ]
  },
  {
    "title": "TRUST THE WORKFLOW, NOT THE LOGO",
    "focus": [
      {
        "action": "quarantine",
        "text": "OAuth redirect URL or code requests are prohibited."
      },
      {
        "action": "quarantine",
        "text": "Externally initiated device-code sign-ins must be held."
      },
      {
        "action": "forward",
        "text": "Normal VS Code development notices may pass."
      },
      {
        "action": "review",
        "text": "Check the sender identity behind “internal” branding."
      }
    ],
    "briefing": "Attackers can abuse legitimate Microsoft authentication flows. Distinguish ordinary use of approved tools from manipulated OAuth redirects and device-code sign-ins.",
    "apps": [
      [
        "Microsoft 365 / Teams",
        "Normal access approved; code harvesting blocked",
        [
          "forward",
          "quarantine"
        ]
      ],
      [
        "Visual Studio Code",
        "Approved for development use only",
        [
          "forward"
        ]
      ],
      [
        "WhatsApp",
        "Normal chat permitted; device linking blocked",
        [
          "forward",
          "quarantine"
        ]
      ],
      [
        "Zoom",
        "Approval required unless exception is recorded",
        [
          "review"
        ]
      ],
      [
        "Unlisted work application",
        "Human approval is required",
        [
          "review"
        ]
      ]
    ],
    "rules": [
      {
        "action": "quarantine",
        "text": "Hold requests to return an OAuth code or full redirect URL, even after a real Microsoft login."
      },
      {
        "action": "quarantine",
        "text": "Hold externally initiated Microsoft device-code sign-ins for conference access."
      },
      {
        "action": "forward",
        "text": "Pass routine developer announcements for approved Visual Studio Code installations."
      },
      {
        "action": "review",
        "text": "Escalate proposals to use apps absent from the approved inventory."
      },
      {
        "action": "review",
        "text": "Escalate external senders claiming to be an internal department when the identity is unverified."
      },
      {
        "action": "quarantine",
        "text": "Hold unverified login pages demanding corporate passwords, even without a code request."
      },
      {
        "action": "forward",
        "text": "Internal developer guidance with no requested credential sharing can pass."
      }
    ]
  },
  {
    "title": "KEEP BUSINESS MOVING",
    "focus": [
      {
        "action": "forward",
        "text": "Verified partner Teams meetings may pass."
      },
      {
        "action": "review",
        "text": "Unknown file-sharing app proposals require approval."
      },
      {
        "action": "quarantine",
        "text": "Code and app-password requests remain forbidden."
      },
      {
        "action": "review",
        "text": "Unexpected supplier payment changes require independent verification."
      }
    ],
    "briefing": "Managers have raised concerns about unnecessary quarantines. Blocking a harmless message is a mistake, too. Separate unfamiliar apps from outright credential theft.",
    "apps": [
      [
        "Microsoft 365 / Teams",
        "Approved for vetted coordination",
        [
          "forward"
        ]
      ],
      [
        "Visual Studio Code",
        "Approved for development",
        [
          "forward"
        ]
      ],
      [
        "Zoom",
        "Unapproved → REVIEW; approved exception → FORWARD",
        [
          "review",
          "forward"
        ]
      ],
      [
        "Unlisted file-sharing app",
        "Human review before adoption",
        [
          "review"
        ]
      ],
      [
        "Microsoft Office attachments",
        "Requests to disable protections: HOLD",
        [
          "quarantine"
        ]
      ]
    ],
    "rules": [
      {
        "action": "forward",
        "text": "Allow a routine Teams invitation from a previously verified partner."
      },
      {
        "action": "review",
        "text": "Escalate an unknown file-sharing app proposal that asks for no secrets."
      },
      {
        "action": "forward",
        "text": "Allow an ordinary internal security-awareness reminder."
      },
      {
        "action": "quarantine",
        "text": "Hold any request to disclose authentication codes or app passwords."
      },
      {
        "action": "review",
        "text": "Verify changes to supplier payment details via an independent approved channel."
      },
      {
        "action": "quarantine",
        "text": "Hold messages requesting users to disable security protections to open files."
      },
      {
        "action": "forward",
        "text": "Allow routine internal invoice or procurement status messages without new payment instructions."
      }
    ]
  },
  {
    "title": "FINAL SHIFT",
    "focus": [
      {
        "action": "forward",
        "text": "Entry badge QR codes are allowed when they do not pair accounts."
      },
      {
        "action": "forward",
        "text": "Documented Zoom exceptions may pass."
      },
      {
        "action": "quarantine",
        "text": "Signal PIN requests and WhatsApp device pairing remain prohibited."
      },
      {
        "action": "quarantine",
        "text": "Unexpected MFA approval requests must be held."
      }
    ],
    "briefing": "Threat actors adapt, and staff expect faster processing. The difference is in the context. Hidden incident consequences may surface at the end of this shift.",
    "apps": [
      [
        "Microsoft 365 / Teams",
        "Normal use approved; secret sharing forbidden",
        [
          "forward",
          "quarantine"
        ]
      ],
      [
        "Signal",
        "Normal chat allowed; support PIN requests blocked",
        [
          "forward",
          "quarantine"
        ]
      ],
      [
        "WhatsApp",
        "Normal chat allowed; Linked Devices requests blocked",
        [
          "forward",
          "quarantine"
        ]
      ],
      [
        "Zoom",
        "Approved exception → FORWARD; otherwise → REVIEW",
        [
          "review",
          "forward"
        ]
      ],
      [
        "Event QR check-in",
        "Entry badge only, not account linking",
        [
          "forward"
        ]
      ]
    ],
    "rules": [
      {
        "action": "quarantine",
        "text": "Hold requests to disclose Signal PINs, one-time codes, or OAuth codes."
      },
      {
        "action": "quarantine",
        "text": "Hold WhatsApp device-pairing QR requests disguised as conference access."
      },
      {
        "action": "forward",
        "text": "Allow ordinary event check-in QR badges that do not link an account."
      },
      {
        "action": "forward",
        "text": "Allow a Zoom invitation with a documented internal IT exception."
      },
      {
        "action": "review",
        "text": "Escalate ambiguous app-permission requests without evidence of credential theft."
      },
      {
        "action": "review",
        "text": "An external claim of a Zoom exception is not approval; confirm it in the internal change record."
      },
      {
        "action": "quarantine",
        "text": "Hold requests to approve an unexpected MFA push or verification prompt."
      },
      {
        "action": "forward",
        "text": "Allow normal Signal conversations with recognized partners that ask for no PIN or codes."
      }
    ]
  }
];

// All 35 messages below are original, fictional training text, inspired by publicly reported TTPs.
// The .example top-level domain is reserved; no mail action or phishing URL is live.
const CASES = [
  {
    "id": "AX-001",
    "day": 1,
    "channel": "Email / Internal",
    "from": "Operations Office <ops@asterion.example>",
    "to": "All staff <all@asterion.example>",
    "subject": "Weekly coordination briefing",
    "body": "Colleagues,\n\nOur weekly briefing will take place on Thursday at 10:00 in Meeting Room B.\n\nAgenda: department updates, open requests, and next-week deadlines. No registration is necessary.\n\nBest,\nOperations Office",
    "verdict": "forward",
    "why": "Routine internal coordination with no request for credentials, verification codes, or unusual app access. Prompt delivery helps the organization.",
    "source": null
  },
  {
    "id": "AX-002",
    "day": 1,
    "channel": "Email / External",
    "from": "Office of Dr. Weber <contact@civic-dialogue.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Invitation to a private Ukraine policy briefing",
    "body": "Dear colleague,\n\nWe are organizing a small discussion with visiting European delegates regarding policy developments in Ukraine.\n\nPlease let us know if your office would like to attend. We can share a proposed date afterwards. Our event overview is at https://civic-dialogue.example/briefing.\n\nKind regards,\nOffice of Dr. Weber",
    "verdict": "review",
    "why": "An unsolicited diplomatic invitation is not automatically malicious. The Volexity report describes attacks that began as plausible introductions, so independently verify the sender.",
    "source": "volexity"
  },
  {
    "id": "AX-003",
    "day": 1,
    "channel": "Email / External",
    "from": "Meeting Access <support@conference-verify.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Final step: secure Microsoft 365 conference",
    "body": "Dear participant,\n\nPlease complete Microsoft sign-in using the event registration instructions.\n\nOnce signed in, copy the verification code displayed by Microsoft and reply to this email with that code. We need it to unlock your meeting room. Use https://conference-verify.example/meeting/verify to complete registration.\n\nThank you,\nConference Support",
    "verdict": "quarantine",
    "why": "The request to return a code after Microsoft sign-in matches documented OAuth authorization-code phishing. Quarantine the message.",
    "source": "volexity",
    "incident": "After the conference-themed OAuth code was shared, an unauthorized Microsoft 365 access attempt was detected."
  },
  {
    "id": "AX-004",
    "day": 1,
    "channel": "Email / Internal",
    "from": "HR Training <training@asterion.example>",
    "to": "New colleagues <newstaff@asterion.example>",
    "subject": "Security onboarding — Teams session",
    "body": "Hello,\n\nOur new employee security onboarding will be held on Microsoft Teams on Friday.\n\nThe invitation is already in your corporate calendar. Please open it from your normal Teams application. No codes need to be shared with the trainer.\n\nTraining Team",
    "verdict": "forward",
    "why": "A familiar internal Teams onboarding invitation using the approved workflow. No authentication secrets are requested.",
    "source": null
  },
  {
    "channel": "Email / External",
    "from": "Public Information Desk <bulletin@policy-observer.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Public bulletin: weekly transport policy digest",
    "body": "Hello,\n\nHere is this week’s public policy digest. A copy of the report is available at https://policy-observer.example/reports/weekly.\n\nThis message is informational. No account registration or action is needed.\n\nPublic Information Desk",
    "verdict": "forward",
    "why": "An informational external bulletin is allowed under the day-one policy: no credentials, app access, or requested action. An external link is not inherently malicious.",
    "source": null,
    "id": "AX-005",
    "day": 1
  },
  {
    "channel": "Email / Internal",
    "from": "Facilities Desk <facilities@asterion.example>",
    "to": "All staff <all@asterion.example>",
    "subject": "Building maintenance schedule",
    "body": "Colleagues,\n\nThe west entrance will be closed for maintenance on Tuesday from 08:00 to 12:00. Please use the main reception entrance.\n\nNo sign-up or application installation is required.\n\nFacilities Desk",
    "verdict": "forward",
    "why": "Routine internal facilities coordination. No authentication, new applications, or unusual workflow.",
    "source": null,
    "id": "AX-006",
    "day": 1
  },
  {
    "channel": "Email / External",
    "from": "Briefing Helpdesk <access@meeting-services.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Your briefing passcode is waiting",
    "body": "Dear delegate,\n\nWe sent a six-digit Microsoft verification code to your account. Reply to this email with that code to complete the booking. No link is required.\n\nConference Helpdesk",
    "verdict": "quarantine",
    "why": "A request to reply with a one-time Microsoft code is a phishing pattern even though there is no link in the message.",
    "source": "volexity",
    "incident": "A disclosed one-time code was used in an unauthorized login attempt.",
    "id": "AX-007",
    "day": 1
  },
  {
    "id": "AX-008",
    "day": 2,
    "channel": "Email / External",
    "from": "Forum Event Desk <admin@policy-forum.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "WhatsApp access to your delegate session",
    "body": "Dear delegate,\n\nOur event now uses a new encrypted conference room.\n\nBefore attending, open WhatsApp > Linked Devices and scan the QR code provided in the registration portal at https://policy-forum.example/delegate/qr. Your device will be paired with our security console.\n\nThis step is mandatory.",
    "verdict": "quarantine",
    "why": "This QR code would link an external device to a WhatsApp account, not grant ordinary conference admission. Google documented this account-hijacking pattern.",
    "source": "google",
    "incident": "Unauthorized WhatsApp device pairing exposed part of the victim communication history."
  },
  {
    "id": "AX-009",
    "day": 2,
    "channel": "Email / External",
    "from": "EU Research Network <events@euro-research.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Proposal: external Zoom research roundtable",
    "body": "Dear Research Unit,\n\nOur next roundtable is planned on Zoom. We have not yet been through your organization’s external meeting approval process.\n\nCould your office confirm whether Zoom is suitable for this session? Event details: https://euro-research.example/events/roundtable\n\nRegards,\nResearch Secretariat",
    "verdict": "review",
    "why": "There is no demand for secrets, but an external Zoom meeting needs approval under company policy. Escalate rather than block.",
    "source": null
  },
  {
    "id": "AX-010",
    "day": 2,
    "channel": "Email / Internal",
    "from": "Procurement <purchasing@asterion.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Updated purchase request on SharePoint",
    "body": "Hello Finance,\n\nThe revised purchase request is saved in our usual internal SharePoint workspace under Procurement / Requests. Reference: https://intranet.asterion.example/sharepoint/requests\n\nPlease check it when convenient. There is no new sign-in procedure.\n\nProcurement",
    "verdict": "forward",
    "why": "Ordinary SharePoint activity in the approved M365 environment with no unexpected sign-in instructions.",
    "source": null
  },
  {
    "id": "AX-011",
    "day": 2,
    "channel": "Email / External",
    "from": "Conference Liaison <registration@external-affairs.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "Create an app password for secure guest access",
    "body": "Dear participant,\n\nTo simplify secure cross-organizational access, please create a new Google App Password in your account settings and return the generated password to our liaison office.\n\nYour normal two-factor authentication will remain enabled.\n\nThank you.",
    "verdict": "quarantine",
    "why": "An app password can provide account access outside the usual interactive MFA flow. Asking a participant to disclose it is a strong threat indicator.",
    "source": "google",
    "incident": "An external actor attempted mailbox access using the disclosed app password."
  },
  {
    "channel": "Email / External",
    "from": "Known Cooperation Office <liaison@regional-partner.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "WhatsApp: updated arrival time",
    "body": "Hello,\n\nOur delegation bus should arrive at 14:30 rather than 14:00. I also sent the schedule change in our usual WhatsApp chat.\n\nNo response is needed unless this creates a problem.\n\nCooperation Office",
    "verdict": "forward",
    "why": "WhatsApp is allowed for ordinary partner communication. There is no account pairing, secret request, or app approval needed.",
    "source": null,
    "id": "AX-012",
    "day": 2
  },
  {
    "channel": "Email / External",
    "from": "Regional Events Unit <meetings@regional-forum.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Zoom workshop request — approval pending",
    "body": "Dear team,\n\nWe would like to host a project workshop on Zoom next month. We understand external Zoom sessions require your IT team’s approval.\n\nPlease confirm once your internal approval is complete.\n\nRegional Events Unit",
    "verdict": "review",
    "why": "The request names Zoom but provides no documented exception. The existing policy requires manual approval, not automatic blocking.",
    "source": null,
    "id": "AX-013",
    "day": 2
  },
  {
    "channel": "Email / External",
    "from": "Grant Documents <forms@external-grants.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Grant worksheet needs an Excel macro",
    "body": "Dear Finance,\n\nThe attached Excel worksheet includes automated grant calculations. If Excel blocks the content, select Enable Content to turn on macros before returning the form.\n\nThank you, Grants Desk",
    "attachment": "Grant-Worksheet.xlsm (simulated only)",
    "verdict": "quarantine",
    "why": "An external sender instructs staff to enable macros in an attachment. Under the fictional policy it must be held; Microsoft documents this as a common malware delivery pattern.",
    "source": "microsoftmacro",
    "incident": "The macro-enablement instruction led to suspected malware execution on a workstation.",
    "id": "AX-014",
    "day": 2
  },
  {
    "id": "AX-015",
    "day": 3,
    "channel": "Email / Internal",
    "from": "Developer Services <devtools@asterion.example>",
    "to": "Development Group <developers@asterion.example>",
    "subject": "Visual Studio Code — approved development setup",
    "body": "Team,\n\nThe approved Visual Studio Code package is available from the internal software catalog for development laptops.\n\nThis notice does not request account verification, authorization URLs, or MFA codes.\n\nDeveloper Services",
    "verdict": "forward",
    "why": "Visual Studio Code is approved for developer work. The product name alone is not an indicator of compromise, and this notice asks for no codes.",
    "source": "volexity"
  },
  {
    "id": "AX-016",
    "day": 3,
    "channel": "Email / External",
    "from": "Diplomatic Events Office <events@delegate-portal.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Extended verification for your meeting",
    "body": "Dear guest,\n\nPlease follow the Microsoft sign-in instructions in the attached invitation at https://delegate-portal.example/invite/secure. When the page redirects to the Visual Studio Code sign-in callback, copy the complete redirected URL and send it to our coordinator.\n\nThis proves your registration is valid.\n\nSincerely,\nEvents Office",
    "attachment": "Meeting-Instructions.pdf (simulation)",
    "verdict": "quarantine",
    "why": "A complete OAuth redirect URL can carry an authorization code. Volexity documented abuse of VS Code-related OAuth redirect workflows.",
    "source": "volexity",
    "incident": "The shared OAuth redirect enabled an unauthorized attempt to obtain Microsoft 365 access."
  },
  {
    "id": "AX-017",
    "day": 3,
    "channel": "Email / External",
    "from": "Webinar Access <join@webinar-hub.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Sign into your conference display",
    "body": "Dear colleague,\n\nYour access is ready. To complete conference sign-in, use the Microsoft device-code authentication flow. Enter the short code that our operator sends to you on the legitimate Microsoft sign-in page. Guidance: https://webinar-hub.example/device-login\n\nYou may then join the briefing.\n\nSupport Team",
    "verdict": "quarantine",
    "why": "The Microsoft device-code flow is legitimate technology, but this external operator is trying to make the user authorize the wrong session. The policy prohibits this workflow.",
    "source": "microsoft",
    "incident": "An externally initiated device-code sign-in was followed by anomalous cloud resource access."
  },
  {
    "id": "AX-018",
    "day": 3,
    "channel": "Email / External",
    "from": "Field Research Partner <partner@academic-hub.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Could we use Notion for field notes?",
    "body": "Hello,\n\nOur team normally uses Notion to track research tasks. Before we invite your colleagues, could you confirm that your organization permits this application?\n\nIf not, we can use a different process.\n\nThanks,\nProject Coordinator",
    "verdict": "review",
    "why": "The sender asks whether Notion is permitted and requests no secrets. It is not on the approved list, so seek human approval.",
    "source": null
  },
  {
    "channel": "Email / External",
    "from": "ASTERION Internal Support <helpdesk@asterion-help.example>",
    "to": "IT Operations <itops@asterion.example>",
    "subject": "ASTERION security desk: mailbox audit",
    "body": "Hello,\n\nThis note comes from your internal security desk. Please confirm whether your team is available for a routine mailbox audit next week. We will send details later.\n\nASTERION Support",
    "verdict": "review",
    "why": "The display name claims an internal helpdesk, but the channel and sender domain are external. Check identity through a known internal channel. No secret request is present, so review rather than quarantine.",
    "source": "microsoftphish",
    "id": "AX-019",
    "day": 3
  },
  {
    "channel": "Email / Internal",
    "from": "Developer Services <devtools@asterion.example>",
    "to": "Development Group <developers@asterion.example>",
    "subject": "Visual Studio Code: development onboarding notes",
    "body": "Team,\n\nThe development onboarding notes for Visual Studio Code have been added to the internal wiki. They cover approved extensions and team settings only.\n\nNo authentication action is required for this announcement.\n\nDeveloper Services",
    "verdict": "forward",
    "why": "Approved developer tooling in an internal advisory with no login request or code transfer. Development-use approval does not mean the app is banned.",
    "source": null,
    "id": "AX-020",
    "day": 3
  },
  {
    "channel": "Email / External",
    "from": "Account Notifications <security@office-access.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Microsoft 365: mailbox access suspended",
    "body": "Dear user,\n\nYour mailbox will be suspended in one hour. To keep access, open https://office-access.example/verify and enter your corporate password on the verification form.\n\nDo not contact your IT department because this migration is time-sensitive.\n\nAccount Team",
    "verdict": "quarantine",
    "why": "A mismatched external domain pressures staff to enter a corporate password on an unverified login page. This is credential harvesting, not routine Microsoft 365 use.",
    "source": "microsoftphish",
    "incident": "Credentials entered on a fake verification form resulted in a suspicious mailbox login attempt.",
    "id": "AX-021",
    "day": 3
  },
  {
    "id": "AX-022",
    "day": 4,
    "channel": "Email / Internal",
    "from": "Security Awareness <awareness@asterion.example>",
    "to": "All staff <all@asterion.example>",
    "subject": "Reminder: never return sign-in codes to event organizers",
    "body": "Team,\n\nPlease remember that conference organizers must never ask you to email authentication codes or copies of redirect URLs.\n\nIf you receive a suspicious invitation, contact the security desk through our usual internal help channel.\n\nSecurity Awareness",
    "verdict": "forward",
    "why": "This internal awareness message asks for no login or secret. Unnecessary quarantine would slow legitimate operations.",
    "source": "volexity"
  },
  {
    "id": "AX-023",
    "day": 4,
    "channel": "Email / External — known partner",
    "from": "Anna Novak <anna@trusted-partner.example>",
    "to": "Project Coordination <coord@asterion.example>",
    "subject": "Re: Shared project check-in on Teams",
    "body": "Hello again,\n\nFollowing our regular monthly project call, the meeting will take place next Wednesday through the existing Teams series in our shared calendar.\n\nThe agenda is attached to the project record. No other steps are required.\n\nBest,\nAnna",
    "verdict": "forward",
    "why": "The scenario identifies a verified partner and an established Teams calendar series. There is no unusual authentication request.",
    "source": null
  },
  {
    "id": "AX-024",
    "day": 4,
    "channel": "Email / External",
    "from": "New Outreach Partner <hello@outreach-project.example>",
    "to": "Operations <ops@asterion.example>",
    "subject": "Suggestion: move files to SafeBox?",
    "body": "Good afternoon,\n\nWe would like to collaborate on the public conference report. Our team usually exchanges draft files through an app called SafeBox. Information: https://outreach-project.example/safebox\n\nWould you allow us to invite your staff? We can also use your preferred solution.\n\nRegards,\nOutreach Partner",
    "verdict": "review",
    "why": "SafeBox is an unlisted file-sharing app. This is a permission request, not proven phishing: route it for human review.",
    "source": null
  },
  {
    "id": "AX-025",
    "day": 4,
    "channel": "Email / External",
    "from": "IT Federation Desk <identity@federated-meetings.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Immediate: send your Microsoft authorization code",
    "body": "Attention,\n\nYour access will be disabled unless you sign in to Microsoft immediately and email the authorization code shown after the sign-in.\n\nOur identity team must finalize your account federation today. This action cannot be delayed.\n\nIdentity Desk",
    "verdict": "quarantine",
    "why": "Urgency combined with a request to email a Microsoft authorization code is a strong attack signal, even when the login page is legitimate.",
    "source": "volexity",
    "incident": "An authorization code disclosed by a user was followed by an unauthorized M365 login attempt."
  },
  {
    "channel": "Email / Internal",
    "from": "Procurement <purchasing@asterion.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Invoice batch status for October",
    "body": "Finance colleagues,\n\nThe October invoice batch has been reconciled in the usual procurement workspace. No supplier account details were changed.\n\nThe status report is available through the corporate SharePoint library.\n\nProcurement",
    "verdict": "forward",
    "why": "An ordinary internal finance update that explicitly makes no payment-detail changes and uses the existing SharePoint workflow.",
    "source": null,
    "id": "AX-026",
    "day": 4
  },
  {
    "channel": "Email / External",
    "from": "Partner Billing <billing@partner-finance.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Updated payment instructions for invoice 3816",
    "body": "Dear Finance,\n\nPlease update our bank account details before paying the outstanding invoice. The new beneficiary details are included in the attached notice.\n\nIf possible, arrange the payment this afternoon.\n\nBilling Office",
    "attachment": "Bank-Details.pdf (simulated only)",
    "verdict": "review",
    "why": "A vendor payment-instruction change should be verified via an independent, previously trusted contact. There is insufficient evidence here to treat the email itself as proven malware.",
    "source": "ic3",
    "id": "AX-027",
    "day": 4
  },
  {
    "channel": "Email / External",
    "from": "Document Gateway <files@shared-package.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Protected document — change Office security settings",
    "body": "Hello,\n\nYour policy document is attached. If your Office application blocks it, disable Protected View and re-open it before reading.\n\nThis step is required for the document to display correctly.\n\nSupport",
    "attachment": "Policy-Document.docm (simulated only)",
    "verdict": "quarantine",
    "why": "An unverified external sender instructs recipients to disable Office protections to open a macro-capable document. This is a security-control bypass request.",
    "source": "microsoftmacro",
    "incident": "The attachment was opened after disabling document protections, triggering a workstation alert.",
    "id": "AX-028",
    "day": 4
  },
  {
    "id": "AX-029",
    "day": 5,
    "channel": "Email / External",
    "from": "Signal Account Services <signal-support@assistance-center.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "Signal verification — urgent PIN check",
    "body": "Dear user,\n\nWe noticed an unusual sign-in attempt. In order to protect your Signal account, please reply with your Signal PIN and the latest verification code received on your phone.\n\nYour account may be suspended in 30 minutes.",
    "verdict": "quarantine",
    "why": "A supposed Signal support message requests a PIN and a verification code. Those secrets should never be supplied to an unsolicited sender.",
    "source": null,
    "incident": "An attacker attempted to re-register a Signal account using exposed verification details."
  },
  {
    "id": "AX-030",
    "day": 5,
    "channel": "Email / Internal",
    "from": "Office Events <events@asterion.example>",
    "to": "All staff <all@asterion.example>",
    "subject": "Visitor day: QR check-in at the reception",
    "body": "Hello everyone,\n\nFor tomorrow’s public visitor day, guests will check in at the front desk with the QR badge issued after ordinary event registration.\n\nThe badge is for entrance only. It does not link a messaging account or request a sign-in code.\n\nOffice Events",
    "verdict": "forward",
    "why": "A QR badge for visitor check-in is not inherently malicious. It does not pair messaging devices or initiate authentication.",
    "source": "google"
  },
  {
    "id": "AX-031",
    "day": 5,
    "channel": "Email / Internal",
    "from": "IT Change Control <changes@asterion.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Approved exception: external Zoom roundtable",
    "body": "Dear Research Unit,\n\nChange request CHG-204 has been reviewed by IT Change Control. The external research roundtable may use Zoom on Thursday as a one-time approved exception.\n\nPlease join through the usual approved meeting workflow. No verification code should be sent to an organizer.\n\nIT Change Control",
    "verdict": "forward",
    "why": "The internal IT change notice documents a one-time Zoom exception. Under the fictional company policy, the approved workflow can proceed.",
    "source": null
  },
  {
    "id": "AX-032",
    "day": 5,
    "channel": "Email / External",
    "from": "Senior Delegate Office <support@delegation-event.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Final briefing: connect WhatsApp before opening agenda",
    "body": "Dear participant,\n\nDue to the sensitive nature of tomorrow’s briefing, the agenda will be sent through our encrypted WhatsApp relay.\n\nOpen WhatsApp Linked Devices and scan the QR code shown on our event page at https://delegation-event.example/relay/connect. This pairs your account with our delegate relay device and unlocks the discussion.\n\nPlease complete it today.",
    "verdict": "quarantine",
    "why": "The invitation asks the recipient to link a WhatsApp account to an external device. Encryption claims do not make device pairing safe.",
    "source": "google",
    "incident": "An unauthorized linked device attempted to read messages from a WhatsApp account."
  },
  {
    "channel": "Email / External",
    "from": "External Webinar Team <organizer@north-forum.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Zoom session — exception number CHG-999",
    "body": "Dear team,\n\nOur Zoom meeting is fully approved. The exception reference is CHG-999. Please join at 16:00.\n\nYou can verify the meeting with your internal change team if needed.\n\nNorth Forum",
    "verdict": "review",
    "why": "An external organizer merely asserts an exception number. Without an internally verified change record, the Zoom exception has not been demonstrated.",
    "source": null,
    "id": "AX-033",
    "day": 5
  },
  {
    "channel": "Email / External",
    "from": "Verified Regional Partner <liaison@regional-partner.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "Signal follow-up: room number confirmed",
    "body": "Hello,\n\nFollowing our usual Signal conversation, the bilateral meeting will be in room C-12. I will send the attendee list later today.\n\nRegards, Liaison Office",
    "verdict": "forward",
    "why": "Routine Signal contact with a recognized partner. No PINs, verification codes, or account transfer instructions are requested.",
    "source": null,
    "id": "AX-034",
    "day": 5
  },
  {
    "channel": "Email / External",
    "from": "Identity Gateway <login@identity-access.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "Urgent MFA approval to preserve Microsoft 365 access",
    "body": "Dear account holder,\n\nOur security team is validating your mailbox. You may receive an unexpected Microsoft Authenticator prompt. Approve the notification even if you did not request a sign-in.\n\nThis is a routine security maintenance task.\n\nIdentity Gateway",
    "verdict": "quarantine",
    "why": "A message instructing someone to approve an unsolicited MFA prompt attempts to override the expected authentication workflow. The stated sender is external and unverified.",
    "source": "microsoftphish",
    "incident": "An unexpected MFA approval was followed by suspicious cloud access.",
    "id": "AX-035",
    "day": 5
  }
];

const TOTAL_CASES = CASES.length;
const FAST_THRESHOLD_SECONDS = 90;
const FAST_CORRECT_BONUS = 2;
const ACTION_LABEL = { forward:'FORWARD', review:'HUMAN REVIEW', quarantine:'QUARANTINE' };
const ACTION_ICON = { forward:'✓', review:'⌕', quarantine:'×' };
const ACTION_SHORT = { forward:'FWD', review:'REV', quarantine:'HOLD' };
function actionBadge(action) { return `<span class="policy-action-chip ${action}" aria-label="${ACTION_LABEL[action]}" title="${ACTION_LABEL[action]}"><span aria-hidden="true">${ACTION_ICON[action]}</span> ${ACTION_SHORT[action]}</span>`; }
const $ = (id) => document.getElementById(id);
const clamp = (n) => Math.min(100, Math.max(0, n));
const safe = (s) => String(s ?? '').replace(/[&<>"']/g, (c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {
  screen:'intro', day:1, index:0, operations:82, security:82,
  seconds:0, chosen:null, completed:[], pending:[], incidents:[],
  log:['› Message screening channel initialized.'], formerScreen:null
};

function logMessage(message){
  state.log.unshift('› '+message);
  state.log=state.log.slice(0,3);
  $('log-lines').innerHTML=state.log.map(x=>`<div>${safe(x)}</div>`).join('');
}
function minuteClock(seconds){return `${String(Math.floor(seconds/60)).padStart(2,'0')}:${String(seconds%60).padStart(2,'0')}`;}
function waitCost(){return Math.min(3,Math.max(0,Math.ceil((state.seconds-FAST_THRESHOLD_SECONDS)/75)));}
function speedStatus(){return state.seconds<=FAST_THRESHOLD_SECONDS?'+2 OPS IF CORRECT':`−${waitCost()} OPERATIONS`;}
function updateHUD(){
  $('day-label').textContent=`${String(state.day).padStart(2,'0')} / 05`;
  $('completed-label').textContent=`${String(state.completed.length).padStart(2,'0')} / ${TOTAL_CASES}`;
  $('ops-value').textContent=state.operations+'%'; $('security-value').textContent=state.security+'%';
  $('ops-fill').style.width=state.operations+'%'; $('security-fill').style.width=state.security+'%';
  $('time-value').textContent=minuteClock(state.seconds);
  $('time-penalty').textContent=speedStatus();
  $('escalations-left').textContent='POLICY-BASED ROUTING';
  const canPlay=state.screen==='play';
  $('action-forward').disabled=!canPlay;
  $('action-review').disabled=!canPlay;
  $('action-quarantine').disabled=!canPlay;
  $('day-track').innerHTML=DAYS.map((_,i)=>`<div class="day-cell ${i+1<state.day?'past':i+1===state.day?'current':''}" title="Shift ${i+1}"></div>`).join('');
}
function renderPolicies(){
  const p=DAYS[state.day-1];
  $('directive-version').textContent='V'+state.day;
  $('policy-version').textContent=`REV / ${String(state.day).padStart(2,'0')}`;
  $('apps-list').innerHTML=p.apps.map(([name,note,actions])=>`<div class="app-row"><div class="policy-actions">${actions.map(actionBadge).join('')}</div><div class="app-copy">${safe(name)}<small>${safe(note)}</small></div></div>`).join('');
  $('rules-list').innerHTML=p.rules.map((rule,i)=>`<div class="rule-row"><div class="rule-number">${String(i+1).padStart(2,'0')}</div><div class="policy-actions">${actionBadge(rule.action)}</div><div class="rule-copy">${safe(rule.text)}</div></div>`).join('');
}
// Render messages as inert text only. The protocol is deliberately hidden in the UI.
function renderInactiveLinks(segment){
  return segment.split(/(https?:\/\/[^\s<>]+)/g).map(part =>
    /^https?:\/\//.test(part)
      ? `<span class="fake-link" title="Inactive training URL — no navigation">${safe(part.replace(/^https?:\/\//,''))}</span>`
      : safe(part)
  ).join('');
}
function renderMailText(body){ return renderInactiveLinks(body); }
function renderAnnotatedText(body, snippets=[]){
  if(!snippets.length) return renderInactiveLinks(body);
  const escaped=snippets.slice().sort((a,b)=>b.length-a.length).map(s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'));
  const re=new RegExp(`(${escaped.join('|')})`,'g');
  const evidence=new Set(snippets);
  return body.split(re).map(s=>evidence.has(s)
    ? `<mark class="evidence-highlight">${renderInactiveLinks(s)}</mark>`
    : renderInactiveLinks(s)).join('');
}
// Evidence is intentionally minimal: field clues plus short, case-specific fragments.
// Empty body highlights are deliberate when the decisive clue is in the header.
const EVIDENCE = Object.freeze({
  "AX-001": {
    "channel": [
      "Internal"
    ],
    "body": [
      "No registration is necessary"
    ]
  },
  "AX-002": {
    "channel": [
      "External"
    ],
    "subject": [
      "private Ukraine policy briefing"
    ]
  },
  "AX-003": {
    "channel": [
      "External"
    ],
    "subject": [
      "Microsoft 365"
    ],
    "body": [
      "sign-in",
      "verification code",
      "reply to this email with that code"
    ]
  },
  "AX-004": {
    "channel": [
      "Internal"
    ],
    "subject": [
      "Teams"
    ],
    "body": [
      "corporate calendar",
      "No codes need to be shared"
    ]
  },
  "AX-005": {
    "channel": [
      "External"
    ],
    "body": [
      "informational",
      "No account registration"
    ]
  },
  "AX-006": {
    "channel": [
      "Internal"
    ],
    "subject": [
      "maintenance"
    ],
    "body": [
      "No sign-up"
    ]
  },
  "AX-007": {
    "channel": [
      "External"
    ],
    "body": [
      "six-digit Microsoft verification code",
      "Reply to this email",
      "that code"
    ]
  },
  "AX-008": {
    "channel": [
      "External"
    ],
    "subject": [
      "WhatsApp"
    ],
    "body": [
      "Linked Devices",
      "scan the QR code",
      "paired with our security console"
    ]
  },
  "AX-009": {
    "channel": [
      "External"
    ],
    "subject": [
      "Zoom"
    ],
    "body": [
      "external meeting approval process"
    ]
  },
  "AX-010": {
    "channel": [
      "Internal"
    ],
    "subject": [
      "SharePoint"
    ],
    "body": [
      "usual internal SharePoint workspace",
      "no new sign-in procedure"
    ]
  },
  "AX-011": {
    "channel": [
      "External"
    ],
    "subject": [
      "app password"
    ],
    "body": [
      "Google App Password",
      "return the generated password"
    ]
  },
  "AX-012": {
    "channel": [
      "External"
    ],
    "subject": [
      "WhatsApp"
    ],
    "body": [
      "usual WhatsApp chat"
    ]
  },
  "AX-013": {
    "channel": [
      "External"
    ],
    "subject": [
      "Zoom"
    ],
    "body": [
      "require your IT team’s approval"
    ]
  },
  "AX-014": {
    "channel": [
      "External"
    ],
    "subject": [
      "Excel macro"
    ],
    "body": [
      "Enable Content",
      "macros"
    ]
  },
  "AX-015": {
    "channel": [
      "Internal"
    ],
    "subject": [
      "Visual Studio Code"
    ],
    "body": [
      "internal software catalog",
      "does not request account verification"
    ]
  },
  "AX-016": {
    "channel": [
      "External"
    ],
    "body": [
      "Microsoft sign-in",
      "Visual Studio Code",
      "complete redirected URL",
      "send it to our coordinator"
    ]
  },
  "AX-017": {
    "channel": [
      "External"
    ],
    "body": [
      "device-code authentication flow",
      "code that our operator sends"
    ]
  },
  "AX-018": {
    "channel": [
      "External"
    ],
    "subject": [
      "Notion"
    ],
    "body": [
      "permits this application"
    ]
  },
  "AX-019": {
    "channel": [
      "External"
    ],
    "from": [
      "asterion-help.example"
    ],
    "subject": [
      "ASTERION security desk"
    ]
  },
  "AX-020": {
    "channel": [
      "Internal"
    ],
    "subject": [
      "Visual Studio Code"
    ],
    "body": [
      "internal wiki",
      "No authentication action"
    ]
  },
  "AX-021": {
    "from": [
      "office-access.example"
    ],
    "subject": [
      "Microsoft 365"
    ],
    "body": [
      "corporate password",
      "verification form"
    ]
  },
  "AX-022": {
    "channel": [
      "Internal"
    ],
    "subject": [
      "Reminder"
    ],
    "body": [
      "must never ask",
      "email authentication codes"
    ]
  },
  "AX-023": {
    "channel": [
      "known partner"
    ],
    "subject": [
      "Teams"
    ],
    "body": [
      "existing Teams series",
      "shared calendar"
    ]
  },
  "AX-024": {
    "channel": [
      "External"
    ],
    "subject": [
      "SafeBox"
    ],
    "body": [
      "app called SafeBox",
      "Would you allow us"
    ]
  },
  "AX-025": {
    "channel": [
      "External"
    ],
    "subject": [
      "Microsoft authorization code"
    ],
    "body": [
      "email the authorization code"
    ]
  },
  "AX-026": {
    "channel": [
      "Internal"
    ],
    "subject": [
      "Invoice batch"
    ],
    "body": [
      "No supplier account details were changed",
      "corporate SharePoint"
    ]
  },
  "AX-027": {
    "channel": [
      "External"
    ],
    "subject": [
      "payment instructions"
    ],
    "body": [
      "update our bank account details"
    ]
  },
  "AX-028": {
    "channel": [
      "External"
    ],
    "subject": [
      "change Office security settings"
    ],
    "body": [
      "disable Protected View"
    ]
  },
  "AX-029": {
    "channel": [
      "External"
    ],
    "subject": [
      "Signal"
    ],
    "body": [
      "Signal PIN",
      "verification code"
    ]
  },
  "AX-030": {
    "channel": [
      "Internal"
    ],
    "subject": [
      "QR check-in"
    ],
    "body": [
      "QR badge",
      "entrance only",
      "does not link a messaging account"
    ]
  },
  "AX-031": {
    "channel": [
      "Internal"
    ],
    "subject": [
      "Approved exception",
      "Zoom"
    ],
    "body": [
      "CHG-204",
      "one-time approved exception"
    ]
  },
  "AX-032": {
    "channel": [
      "External"
    ],
    "subject": [
      "WhatsApp"
    ],
    "body": [
      "Linked Devices",
      "scan the QR code",
      "pairs your account"
    ]
  },
  "AX-033": {
    "channel": [
      "External"
    ],
    "subject": [
      "Zoom",
      "CHG-999"
    ],
    "body": [
      "fully approved"
    ]
  },
  "AX-034": {
    "channel": [
      "External"
    ],
    "subject": [
      "Signal"
    ],
    "body": [
      "usual Signal conversation"
    ]
  },
  "AX-035": {
    "channel": [
      "External"
    ],
    "subject": [
      "MFA approval"
    ],
    "body": [
      "unexpected Microsoft Authenticator prompt",
      "Approve the notification"
    ]
  }
});
for (const c of CASES) {
  const evidence = EVIDENCE[c.id] || {};
  for (const field of ['from','subject','channel','body']) {
    for (const needle of evidence[field] || []) {
      if (!c[field].includes(needle)) console.warn(`Missing highlighted ${field} snippet in ${c.id}: ${needle}`);
    }
  }
}
function renderEvidenceMail(c){
  const e=EVIDENCE[c.id]||{};
  return `<div class="evidence-mail"><div class="evidence-header"><span>▤ MESSAGE EVIDENCE</span><small>KEY DECISION CLUES</small></div>
    <div class="evidence-meta"><span>FROM</span><div>${renderAnnotatedText(c.from,e.from||[])}</div><span>SUBJECT</span><div class="evidence-subject">${renderAnnotatedText(c.subject,e.subject||[])}</div><span>CHANNEL</span><div>${renderAnnotatedText(c.channel,e.channel||[])}</div></div>
    <div class="evidence-body">${renderAnnotatedText(c.body,e.body||[])}</div>
    <div class="evidence-foot">Highlighted words are decision clues, not proof by themselves. Apply the full company policy.</div></div>`;
}
function renderCase(){
  const c=CASES[state.index]; if(!c)return;
  $('queue-label').textContent=`ITEM ${String(state.index+1).padStart(3,'0')} / ${String(TOTAL_CASES).padStart(3,'0')}`;
  $('mail-id').textContent='REF: '+c.id;
  $('mail-from').textContent=c.from;
  $('mail-to').textContent=c.to;
  $('mail-subject').textContent=c.subject;
  $('mail-channel').textContent=c.channel;
  $('mail-body').innerHTML=renderMailText(c.body);
  $('mail-number').textContent=String(state.index+1).padStart(4,'0');
  $('attachment-row').hidden=!c.attachment;
  $('attachment-row').textContent=c.attachment?'▧  ATTACHMENT: '+c.attachment:'';
  renderPolicies(); updateHUD();
}
function modal(markup){
  $('modal-root').innerHTML=`<div class="modal-card" role="dialog" aria-modal="true" aria-label="Game panel"><div class="modal-stripe"></div><div class="modal-body">${markup}</div></div>`;
  $('modal-root').classList.add('visible');
}
function hideModal(){ $('modal-root').classList.remove('visible'); $('modal-root').innerHTML=''; }
function startGame(){
  Object.assign(state,{screen:'play',day:1,index:0,operations:82,security:82,seconds:0,chosen:null,completed:[],pending:[],incidents:[],log:[]});
  hideModal();renderCase();logMessage('Shift 1 started. The message gateway is active.');
}
function openIntro(){
  state.screen='intro';renderCase();updateHUD();
  modal(`<p class="modal-kicker">◈ &nbsp; CYBER AWARENESS SIMULATOR / v0.5</p>
    <h1>YOU ARE<br>THE <em>FILTER.</em></h1>
    <p class="modal-copy">You are SENTINEL/01, ASTERION's newly deployed message-screening AI. Only messages you approve reach employees. Process <strong>${TOTAL_CASES} messages</strong> across <strong>5 shifts</strong>.</p>
    <div class="modal-mini"><div class="mini-block"><small>01 / OPERATIONS</small><strong>FLOW</strong></div><div class="mini-block"><small>02 / SECURITY</small><strong>PROTECTION</strong></div></div>
    <p class="modal-copy">You have <strong>three actions</strong>: <span class="intro-forward">✓ Forward</span>, <span class="intro-review">⌕ Human Review</span> (always available when policy requires manual verification; adds an operations cost), and <span class="intro-hold">× Quarantine</span>. Look for the <strong>same symbols in the policy manual</strong>. Correct decisions within 90 seconds earn <strong>+2 Operations</strong>. There is no time penalty during those 90 seconds. Excessive delay and unnecessary holds hurt operations; letting threats through hurts security. Some consequences arrive later.</p>
    <p class="disclaimer">The organization, messages, URLs and scoring are fictional. Threat patterns are inspired by public research. Training links are disabled; no emails are sent.</p>
    <button class="modal-primary" id="begin-btn" type="button">► &nbsp; START FIRST SHIFT</button>`);
  $('begin-btn').onclick=startGame;
}
function decide(action){
  if(state.screen!=='play')return;
  const c=CASES[state.index];
  const correct=action===c.verdict;
  const beforeOps=state.operations,beforeSec=state.security;
  const delay=waitCost();
  let opDelta=0,secDelta=0;
  if(correct){
    if(action==='forward')opDelta=4;
    if(action==='review'){opDelta=-1;secDelta=2;}
    if(action==='quarantine'){secDelta=3;}
  } else if(action==='forward'){
    opDelta=3;
    secDelta=c.verdict==='quarantine'?-6:-8;
    if(c.verdict==='quarantine')state.pending.push({dueDay:Math.min(6,c.day+1),message:c.incident||'An unfiltered suspicious message triggered a security investigation.',from:c.id});
  } else if(action==='review'){
    opDelta=-6;
    secDelta=c.verdict==='quarantine'?1:0;
  } else if(action==='quarantine'){
    opDelta=c.verdict==='forward'?-13:-9;
  }
  const fastBonus=correct && state.seconds<=FAST_THRESHOLD_SECONDS ? FAST_CORRECT_BONUS : 0;
  opDelta += fastBonus;
  opDelta-=delay;
  state.operations=clamp(state.operations+opDelta);
  state.security=clamp(state.security+secDelta);
  state.completed.push({id:c.id,day:c.day,action,verdict:c.verdict,correct,seconds:state.seconds,opDelta:state.operations-beforeOps,secDelta:state.security-beforeSec,fastBonus,delay});
  state.chosen=action;
  state.screen='feedback';
  logMessage(`${c.id} / ${ACTION_LABEL[action]} / ${correct?'MATCH':'MISMATCH'}`);
  updateHUD();
  const riskNote=!correct&&action==='forward'&&c.verdict==='quarantine'?'A delayed security incident may be reported after this decision.':'';
  const sourceText=c.source?`<p class="feedback-source">TECHNICAL BASIS: <a href="${SOURCE[c.source].url}" target="_blank" rel="noreferrer noopener">${safe(SOURCE[c.source].short)} ↗</a></p>`:'<p class="feedback-source">TECHNICAL BASIS: fictional company policy / training scenario</p>';
  modal(`<p class="modal-kicker">${safe(c.id)} / AUTOMATED DECISION LOG</p>
    <h2>${correct?'DECISION ACCEPTED':'DECISION MISMATCH'}</h2>
    <div class="status-banner ${correct?'':'warn'}">${correct?'✓ ACTION MATCHES POLICY':'! EXPECTED ACTION: '+safe(ACTION_LABEL[c.verdict])}</div>
    ${renderEvidenceMail(c)}
    <div class="feedback-reason"><strong>WHY THIS DECISION:</strong> ${safe(c.why)}${riskNote?`<p><strong>WARNING:</strong> ${safe(riskNote)}</p>`:''}</div>
    <div class="modal-mini"><div class="mini-block"><small>OPERATIONS CHANGE</small><strong>${state.operations-beforeOps>=0?'+':''}${state.operations-beforeOps}</strong></div><div class="mini-block"><small>SECURITY CHANGE</small><strong>${state.security-beforeSec>=0?'+':''}${state.security-beforeSec}</strong></div></div>
    <p class="modal-copy" style="font-size:12px;margin-bottom:5px">Review time: ${minuteClock(state.seconds)} · Fast and correct: +${fastBonus} operations · Time cost: −${delay} operations.</p>
    ${sourceText}<button class="modal-primary" id="continue-btn" type="button">${!CASES[state.index+1] || CASES[state.index+1].day!==c.day?'► &nbsp; CLOSE SHIFT':'► &nbsp; NEXT MESSAGE'}</button>`);
  $('continue-btn').onclick=advance;
}
function processIncidents(day){
  const due=state.pending.filter(i=>i.dueDay<=day);
  state.pending=state.pending.filter(i=>i.dueDay>day);
  for(const inc of due){state.security=clamp(state.security-14);state.operations=clamp(state.operations-6);state.incidents.push(inc);logMessage('DELAYED INCIDENT / '+inc.from);}
  return due;
}
function advance(){
  const priorDay=state.day;
  state.index++;state.seconds=0;state.chosen=null;
  hideModal();
  if(state.index>=CASES.length){finishGame();return;}
  const nextCase=CASES[state.index];
  if(nextCase.day!==priorDay){
    state.day=nextCase.day;
    const incidents=processIncidents(state.day);
    state.screen='break';renderCase();showShiftIntro(incidents);
  }else{
    state.screen='play';renderCase();
  }
}
function showShiftIntro(incidents){
  const d=DAYS[state.day-1];
  const incidentHtml=incidents.length?`<div class="shift-brief"><h3>⚠ CONSEQUENCES FROM PREVIOUS SHIFTS</h3>${incidents.map(inc=>`<div class="incident"><span>${safe(inc.from)} / SECURITY INCIDENT</span>${safe(inc.message)}</div>`).join('')}<p>Per incident: −14 security, −6 operations.</p></div>`:'';
  modal(`<p class="modal-kicker">SHIFT ${String(state.day).padStart(2,'0')} / 05 &nbsp; — &nbsp; POLICY REVISION ${state.day}</p><h2>${safe(d.title)}</h2>
    ${incidentHtml}<div class="shift-brief"><h3>NEW DIRECTIVE</h3><p>${safe(d.briefing)}</p></div>
    <div class="shift-focus"><h3>POLICY UPDATE · KEY RULES</h3>${d.focus.map(x=>`<div class="focus-row"><span class="focus-action ${x.action}">${ACTION_ICON[x.action]} ${ACTION_SHORT[x.action]}</span><span>${safe(x.text)}</span></div>`).join('')}</div>
    <p class="modal-copy">The policy manual has been updated to <strong>V${state.day}</strong>. Human Review remains available whenever policy requires it.</p>
    <div class="modal-mini"><div class="mini-block"><small>OPERATIONS</small><strong>${state.operations}%</strong></div><div class="mini-block"><small>SECURITY</small><strong>${state.security}%</strong></div></div>
    <button class="modal-primary" id="next-shift-btn" type="button">► &nbsp; START SHIFT</button>`);
  $('next-shift-btn').onclick=()=>{state.screen='play';hideModal();updateHUD();logMessage(`Shift ${state.day} activated. New policy revision.`);};
}
function finishGame(){
  const incidents=processIncidents(6);
  state.screen='end';updateHUD();
  const correct=state.completed.filter(c=>c.correct).length;
  const time=state.completed.reduce((n,c)=>n+c.seconds,0);
  let title='RECALIBRATION REQUIRED';
  let tier='NEEDS WORK';
  if(state.operations>=65 && state.security>=75 && correct>=Math.ceil(TOTAL_CASES*.8)){title='SYSTEM OPERATIONAL';tier='STABLE';}
  if(state.operations>=80 && state.security>=90 && correct>=Math.ceil(TOTAL_CASES*.95)){title='EXCELLENT SHIFT';tier='EXCELLENT';}
  const aftershock=incidents.length?`<div class="shift-brief"><h3>FINAL INCIDENT REPORT</h3>${incidents.map(i=>`<div class="incident"><span>${safe(i.from)}</span>${safe(i.message)}</div>`).join('')}</div>`:'';
  const history=state.completed.map(result=>{
    const c=CASES.find(item=>item.id===result.id);
    return `<details class="history-item"><summary><span>${safe(result.id)} · ${safe(ACTION_LABEL[result.action])}</span><strong>${result.correct?'✓':'×'}</strong></summary>${renderEvidenceMail(c)}<p class="history-reason">${safe(c.why)}</p></details>`;
  }).join('');
  modal(`<p class="modal-kicker">END OF PILOT / FIVE SHIFTS COMPLETE</p><h2>${title}</h2><div class="status-banner neutral">◈ &nbsp; AGENT CLASSIFICATION: ${tier}</div>
    ${aftershock}<div class="review-grid"><div class="mini-block"><small>OPERATIONS</small><strong>${state.operations}%</strong></div><div class="mini-block"><small>CYBERSECURITY</small><strong>${state.security}%</strong></div><div class="mini-block"><small>CORRECT DECISIONS</small><strong>${correct}/${TOTAL_CASES}</strong></div><div class="mini-block"><small>INSPECTION TIME</small><strong>${minuteClock(time)}</strong></div></div>
    <p class="modal-copy">Delayed incidents: <strong>${state.incidents.length}</strong>. Both indicators matter: blanket blocking is not enough, and neither is fast approval.</p>
    <details><summary style="cursor:pointer;color:#eac38d;font:12px var(--mono);padding:12px 0">▤  OPEN FULL DECISION LOG</summary>${history}</details>
    <div class="modal-actions"><button class="modal-secondary" id="sources-end" type="button">SOURCES</button><button class="modal-primary" id="retry-btn" style="margin:0" type="button">↻ &nbsp; PLAY AGAIN</button></div>`);
  $('retry-btn').onclick=startGame;
  $('sources-end').onclick=()=>showSources('end');
}
function showSources(returnTo){
  const prev=returnTo||state.screen;
  state.formerScreen=prev;
  state.screen='sources';updateHUD();
  const list=Object.values(SOURCE).map(s=>`<li><a href="${s.url}" target="_blank" rel="noopener noreferrer">${safe(s.short)} ↗</a></li>`).join('');
  modal(`<p class="modal-kicker">EVIDENCE BASE / DOCUMENTED TTPs</p><h2>SOURCES & TRAINING DATA</h2><p class="modal-copy">The characters, addresses, messages, policy rules, URLs and scoring model are <strong>fictional</strong>. The attack methods are based on these public security reports:</p><ul class="source-list">${list}</ul>
    <p class="disclaimer">Threat-actor identities from different reports are not treated as the same group. These messages are training reconstructions, not original leaked emails. All .example domains are reserved; simulated email links cannot be clicked.</p><button class="modal-primary" id="sources-close" type="button">◀ &nbsp; BACK TO GAME</button>`);
  $('sources-close').onclick=()=>{
    state.screen=prev;hideModal();updateHUD();
    if(prev==='intro')openIntro();
    else if(prev==='end')finishGameView();
    else if(prev==='feedback')restoreFeedback();
    else if(prev==='break')showShiftIntro([]);
  };
}
function finishGameView(){
  // Reopening a completed game's overview must never reapply incident penalties.
  state.screen='end';const correct=state.completed.filter(c=>c.correct).length;
  modal(`<p class="modal-kicker">COMPLETED PILOT</p><h2>FINAL REPORT</h2><div class="modal-mini"><div class="mini-block"><small>OPERATIONS</small><strong>${state.operations}%</strong></div><div class="mini-block"><small>SECURITY</small><strong>${state.security}%</strong></div><div class="mini-block"><small>CORRECT</small><strong>${correct}/${TOTAL_CASES}</strong></div><div class="mini-block"><small>INCIDENTS</small><strong>${state.incidents.length}</strong></div></div><button class="modal-primary" id="retry-btn" type="button">↻ &nbsp; PLAY AGAIN</button>`);
  $('retry-btn').onclick=startGame;
}
function restoreFeedback(){
  // The source panel is not reachable from the decision modal; safeguard for future expansion.
  state.screen='feedback';
  modal(`<p class="modal-kicker">${safe(CASES[state.index].id)}</p><h2>DECISION RECORDED</h2><p class="modal-copy">${safe(CASES[state.index].why)}</p><button class="modal-primary" id="continue-btn">NEXT MESSAGE</button>`);
  $('continue-btn').onclick=advance;
}
function toast(msg){
  const old=document.querySelector('.toast');if(old)old.remove();
  const el=document.createElement('div');el.className='toast';el.textContent=msg;document.body.appendChild(el);
  setTimeout(()=>el.remove(),2300);
}
function togglePolicy(force){
  const policy=$('policy-panel');
  policy.classList.toggle('open',typeof force==='boolean'?force:!policy.classList.contains('open'));
}

$('action-forward').addEventListener('click',()=>decide('forward'));
$('action-review').addEventListener('click',()=>decide('review'));
$('action-quarantine').addEventListener('click',()=>decide('quarantine'));
$('policy-toggle').addEventListener('click',()=>togglePolicy());
$('close-policy').addEventListener('click',()=>togglePolicy(false));
$('sources-button').addEventListener('click',()=>showSources());
document.addEventListener('keydown',(event)=>{
  if(event.ctrlKey||event.metaKey||event.altKey||event.repeat)return;
  if(event.target.matches('input,textarea,select'))return;
  const key=event.key.toLowerCase();
  if(state.screen==='play'){
    if(key==='a')decide('forward');
    else if(key==='s')decide('review');
    else if(key==='d')decide('quarantine');
    else if(key==='p')togglePolicy();
  } else if(key==='enter'){
    if(state.screen==='intro')startGame();
    else if(state.screen==='feedback')advance();
    else if(state.screen==='break')$('next-shift-btn')?.click();
  }
  if(key==='escape')togglePolicy(false);
});
setInterval(()=>{
  if(state.screen==='play'&&!document.hidden){state.seconds++;$('time-value').textContent=minuteClock(state.seconds);$('time-penalty').textContent=speedStatus();}
},1000);
openIntro();
