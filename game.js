/* PROTOCOL: TRUST v0.9.3 — local-only security decision game. */
'use strict';

const SOURCE = Object.freeze({
  senderdocs: { short: 'Microsoft · Email authentication and composite checks', url: 'https://learn.microsoft.com/en-us/defender-office-365/email-auth-sec-ops-guide' },
  quarantinedocs: { short: 'Microsoft · Quarantine policy', url: 'https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies' },
  safeurls: { short: 'Microsoft · Safe Links policies', url: 'https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure' },
  safefiles: { short: 'Microsoft · Safe Attachments', url: 'https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about' },
  consentdocs: { short: 'Microsoft Entra · Admin consent requests', url: 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow' },
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
    "title": "SENDER VERIFICATION",
    "briefing": "Check the authentication result, not just the display name.",
    "focus": [
      {
        "action": "quarantine",
        "text": "Confirmed sender spoofing / impersonation alert."
      },
      {
        "action": "review",
        "text": "Sender authentication inconclusive: manual verification."
      },
      {
        "action": "forward",
        "text": "Authentication passes and no other active control is triggered."
      }
    ],
    "rules": [
      {
        "id": "S1",
        "day": 1,
        "category": "SENDER",
        "action": "quarantine",
        "text": "Confirmed sender spoofing / impersonation alert."
      },
      {
        "id": "S2",
        "day": 1,
        "category": "SENDER",
        "action": "review",
        "text": "Sender authentication inconclusive: manual verification."
      },
      {
        "id": "S3",
        "day": 1,
        "category": "SENDER",
        "action": "forward",
        "text": "Authentication passes and no other active control is triggered."
      }
    ],
    "apps": []
  },
  {
    "title": "CREDENTIAL PROTECTION",
    "briefing": "Decide whether the message requests a secret or unexpected approval.",
    "focus": [
      {
        "action": "quarantine",
        "text": "Message asks for passwords, PINs, sign-in codes, OAuth URLs, or unexpected MFA approval."
      },
      {
        "action": "forward",
        "text": "Mentioning security or MFA without requesting secrets is allowed."
      }
    ],
    "rules": [
      {
        "id": "S1",
        "day": 1,
        "category": "SENDER",
        "action": "quarantine",
        "text": "Confirmed sender spoofing / impersonation alert."
      },
      {
        "id": "S2",
        "day": 1,
        "category": "SENDER",
        "action": "review",
        "text": "Sender authentication inconclusive: manual verification."
      },
      {
        "id": "S3",
        "day": 1,
        "category": "SENDER",
        "action": "forward",
        "text": "Authentication passes and no other active control is triggered."
      },
      {
        "id": "C1",
        "day": 2,
        "category": "CREDENTIALS",
        "action": "quarantine",
        "text": "Message asks for passwords, PINs, sign-in codes, OAuth URLs, or unexpected MFA approval."
      },
      {
        "id": "C2",
        "day": 2,
        "category": "CREDENTIALS",
        "action": "forward",
        "text": "Mentioning security or MFA without requesting secrets is allowed."
      }
    ],
    "apps": []
  },
  {
    "title": "APPLICATION CONTROL",
    "briefing": "Match app names and uses to the company register.",
    "focus": [
      {
        "action": "review",
        "text": "Application unlisted or requires approval not yet verified."
      },
      {
        "action": "quarantine",
        "text": "Message asks to pair a personal messaging account with someone else’s device."
      },
      {
        "action": "forward",
        "text": "Approved application used within its authorized purpose."
      }
    ],
    "rules": [
      {
        "id": "S1",
        "day": 1,
        "category": "SENDER",
        "action": "quarantine",
        "text": "Confirmed sender spoofing / impersonation alert."
      },
      {
        "id": "S2",
        "day": 1,
        "category": "SENDER",
        "action": "review",
        "text": "Sender authentication inconclusive: manual verification."
      },
      {
        "id": "S3",
        "day": 1,
        "category": "SENDER",
        "action": "forward",
        "text": "Authentication passes and no other active control is triggered."
      },
      {
        "id": "C1",
        "day": 2,
        "category": "CREDENTIALS",
        "action": "quarantine",
        "text": "Message asks for passwords, PINs, sign-in codes, OAuth URLs, or unexpected MFA approval."
      },
      {
        "id": "C2",
        "day": 2,
        "category": "CREDENTIALS",
        "action": "forward",
        "text": "Mentioning security or MFA without requesting secrets is allowed."
      },
      {
        "id": "A1",
        "day": 3,
        "category": "APPLICATIONS",
        "action": "review",
        "text": "Application unlisted or requires approval not yet verified."
      },
      {
        "id": "A2",
        "day": 3,
        "category": "APPLICATIONS",
        "action": "quarantine",
        "text": "Message asks to pair a personal messaging account with someone else’s device."
      },
      {
        "id": "A3",
        "day": 3,
        "category": "APPLICATIONS",
        "action": "forward",
        "text": "Approved application used within its authorized purpose."
      }
    ],
    "apps": [
      [
        "Microsoft 365 / Teams",
        "Approved for routine work",
        "forward"
      ],
      [
        "WhatsApp / Signal",
        "Normal chat approved; external account linking prohibited",
        "forward"
      ],
      [
        "Visual Studio Code",
        "Approved for development",
        "forward"
      ],
      [
        "Zoom",
        "External use requires an approval record",
        "review"
      ],
      [
        "Unlisted app",
        "Requires authorization before adoption",
        "review"
      ]
    ]
  },
  {
    "title": "URL & FILE SCANNING",
    "briefing": "Use simulated scanner results, not guesses about the subject.",
    "focus": [
      {
        "action": "quarantine",
        "text": "Security scanner reports a malicious URL."
      },
      {
        "action": "review",
        "text": "A linked URL has no conclusive scan verdict."
      },
      {
        "action": "quarantine",
        "text": "Malware detected or message demands disabling Office protections."
      },
      {
        "action": "review",
        "text": "Attachment cannot yet be inspected."
      }
    ],
    "rules": [
      {
        "id": "S1",
        "day": 1,
        "category": "SENDER",
        "action": "quarantine",
        "text": "Confirmed sender spoofing / impersonation alert."
      },
      {
        "id": "S2",
        "day": 1,
        "category": "SENDER",
        "action": "review",
        "text": "Sender authentication inconclusive: manual verification."
      },
      {
        "id": "S3",
        "day": 1,
        "category": "SENDER",
        "action": "forward",
        "text": "Authentication passes and no other active control is triggered."
      },
      {
        "id": "C1",
        "day": 2,
        "category": "CREDENTIALS",
        "action": "quarantine",
        "text": "Message asks for passwords, PINs, sign-in codes, OAuth URLs, or unexpected MFA approval."
      },
      {
        "id": "C2",
        "day": 2,
        "category": "CREDENTIALS",
        "action": "forward",
        "text": "Mentioning security or MFA without requesting secrets is allowed."
      },
      {
        "id": "A1",
        "day": 3,
        "category": "APPLICATIONS",
        "action": "review",
        "text": "Application unlisted or requires approval not yet verified."
      },
      {
        "id": "A2",
        "day": 3,
        "category": "APPLICATIONS",
        "action": "quarantine",
        "text": "Message asks to pair a personal messaging account with someone else’s device."
      },
      {
        "id": "A3",
        "day": 3,
        "category": "APPLICATIONS",
        "action": "forward",
        "text": "Approved application used within its authorized purpose."
      },
      {
        "id": "U1",
        "day": 4,
        "category": "LINKS",
        "action": "quarantine",
        "text": "Security scanner reports a malicious URL."
      },
      {
        "id": "U2",
        "day": 4,
        "category": "LINKS",
        "action": "review",
        "text": "A linked URL has no conclusive scan verdict."
      },
      {
        "id": "F1",
        "day": 4,
        "category": "ATTACHMENTS",
        "action": "quarantine",
        "text": "Malware detected or message demands disabling Office protections."
      },
      {
        "id": "F2",
        "day": 4,
        "category": "ATTACHMENTS",
        "action": "review",
        "text": "Attachment cannot yet be inspected."
      }
    ],
    "apps": [
      [
        "Microsoft 365 / Teams",
        "Approved for routine work",
        "forward"
      ],
      [
        "WhatsApp / Signal",
        "Normal chat approved; external account linking prohibited",
        "forward"
      ],
      [
        "Visual Studio Code",
        "Approved for development",
        "forward"
      ],
      [
        "Zoom",
        "External use requires an approval record",
        "review"
      ],
      [
        "Unlisted app",
        "Requires authorization before adoption",
        "review"
      ]
    ]
  },
  {
    "title": "ACCESS APPROVAL",
    "briefing": "Require independently verified authorization for sensitive changes.",
    "focus": [
      {
        "action": "quarantine",
        "text": "External party initiates device-code sign-in or unauthorized account/device linking."
      },
      {
        "action": "review",
        "text": "Sensitive change or access exception lacks verified internal approval."
      },
      {
        "action": "forward",
        "text": "Approved access/change record confirmed in the internal register."
      }
    ],
    "rules": [
      {
        "id": "S1",
        "day": 1,
        "category": "SENDER",
        "action": "quarantine",
        "text": "Confirmed sender spoofing / impersonation alert."
      },
      {
        "id": "S2",
        "day": 1,
        "category": "SENDER",
        "action": "review",
        "text": "Sender authentication inconclusive: manual verification."
      },
      {
        "id": "S3",
        "day": 1,
        "category": "SENDER",
        "action": "forward",
        "text": "Authentication passes and no other active control is triggered."
      },
      {
        "id": "C1",
        "day": 2,
        "category": "CREDENTIALS",
        "action": "quarantine",
        "text": "Message asks for passwords, PINs, sign-in codes, OAuth URLs, or unexpected MFA approval."
      },
      {
        "id": "C2",
        "day": 2,
        "category": "CREDENTIALS",
        "action": "forward",
        "text": "Mentioning security or MFA without requesting secrets is allowed."
      },
      {
        "id": "A1",
        "day": 3,
        "category": "APPLICATIONS",
        "action": "review",
        "text": "Application unlisted or requires approval not yet verified."
      },
      {
        "id": "A2",
        "day": 3,
        "category": "APPLICATIONS",
        "action": "quarantine",
        "text": "Message asks to pair a personal messaging account with someone else’s device."
      },
      {
        "id": "A3",
        "day": 3,
        "category": "APPLICATIONS",
        "action": "forward",
        "text": "Approved application used within its authorized purpose."
      },
      {
        "id": "U1",
        "day": 4,
        "category": "LINKS",
        "action": "quarantine",
        "text": "Security scanner reports a malicious URL."
      },
      {
        "id": "U2",
        "day": 4,
        "category": "LINKS",
        "action": "review",
        "text": "A linked URL has no conclusive scan verdict."
      },
      {
        "id": "F1",
        "day": 4,
        "category": "ATTACHMENTS",
        "action": "quarantine",
        "text": "Malware detected or message demands disabling Office protections."
      },
      {
        "id": "F2",
        "day": 4,
        "category": "ATTACHMENTS",
        "action": "review",
        "text": "Attachment cannot yet be inspected."
      },
      {
        "id": "X1",
        "day": 5,
        "category": "ACCESS",
        "action": "quarantine",
        "text": "External party initiates device-code sign-in or unauthorized account/device linking."
      },
      {
        "id": "X2",
        "day": 5,
        "category": "ACCESS",
        "action": "review",
        "text": "Sensitive change or access exception lacks verified internal approval."
      },
      {
        "id": "X3",
        "day": 5,
        "category": "ACCESS",
        "action": "forward",
        "text": "Approved access/change record confirmed in the internal register."
      }
    ],
    "apps": [
      [
        "Microsoft 365 / Teams",
        "Approved for routine work",
        "forward"
      ],
      [
        "WhatsApp / Signal",
        "Normal chat approved; account linking prohibited",
        "forward"
      ],
      [
        "Visual Studio Code",
        "Approved for development",
        "forward"
      ],
      [
        "Zoom / no internal approval",
        "Manual approval required",
        "review"
      ],
      [
        "Zoom / approved exception",
        "Verified internal change record",
        "forward"
      ],
      [
        "Unlisted app",
        "Approval required",
        "review"
      ]
    ]
  }
];

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
    "why": "Sender authentication passed and no triggered control requires intervention. Authentication alone never guarantees safety.",
    "source": null,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "S3",
    "evidence": {
      "channel": [
        "Internal"
      ],
      "body": [
        "No registration is necessary"
      ]
    }
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
    "why": "Sender authentication passed and no triggered control requires intervention. Authentication alone never guarantees safety.",
    "source": null,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "S3",
    "evidence": {
      "subject": [
        "Teams"
      ],
      "body": [
        "corporate calendar"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "ASTERION Internal Support <helpdesk@asterion-help.example>",
    "to": "IT Operations <itops@asterion.example>",
    "subject": "ASTERION security desk: mailbox audit",
    "body": "Hello,\n\nThis note comes from your internal security desk. Please confirm whether your team is available for a routine mailbox audit next week. We will send details later.\n\nASTERION Support",
    "verdict": "review",
    "why": "Sender authentication is inconclusive. Do not assume the visible From address is authentic; request review.",
    "source": "microsoftphish",
    "id": "AX-019",
    "day": 1,
    "signals": {
      "sender": "unknown"
    },
    "ruleId": "S2",
    "evidence": {
      "from": [
        "asterion-help.example"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "Public Information Desk <bulletin@policy-observer.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Public bulletin: weekly transport policy digest",
    "body": "Hello,\n\nHere is this week’s public policy digest. A copy of the report is available at https://policy-observer.example/reports/weekly.\n\nThis message is informational. No account registration or action is needed.\n\nPublic Information Desk",
    "verdict": "forward",
    "why": "Sender authentication passed and no triggered control requires intervention. Authentication alone never guarantees safety.",
    "source": null,
    "id": "AX-005",
    "day": 1,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "S3",
    "evidence": {
      "body": [
        "No account registration"
      ]
    }
  },
  {
    "id": "AX-023",
    "day": 1,
    "channel": "Email / External — known partner",
    "from": "Partner Meeting Desk <notify@trusted-partner-support.example>",
    "to": "Project Coordination <coord@asterion.example>",
    "subject": "Re: Partner Teams meeting update",
    "body": "Hello,\n\nWe are sending an update on your existing Teams meeting. Our desk represents the known project partner.\n\nPlease confirm that your group received this notice.\n\nRegards,\nPartner Meeting Desk",
    "verdict": "quarantine",
    "why": "The simulated mail-security check reports a high-confidence spoof alert. Sender identity cannot be accepted.",
    "source": null,
    "signals": {
      "sender": "spoof"
    },
    "ruleId": "S1",
    "evidence": {
      "from": [
        "trusted-partner-support.example"
      ]
    }
  },
  {
    "channel": "Email / Internal",
    "from": "Facilities Desk <facilities@asterion.example>",
    "to": "All staff <all@asterion.example>",
    "subject": "Building maintenance schedule",
    "body": "Colleagues,\n\nThe west entrance will be closed for maintenance on Tuesday from 08:00 to 12:00. Please use the main reception entrance.\n\nNo sign-up or application installation is required.\n\nFacilities Desk",
    "verdict": "forward",
    "why": "Sender authentication passed and no triggered control requires intervention. Authentication alone never guarantees safety.",
    "source": null,
    "id": "AX-006",
    "day": 1,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "S3",
    "evidence": {
      "channel": [
        "Internal"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "Known Cooperation Office <liaison@regional-partner.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "WhatsApp: updated arrival time",
    "body": "Hello,\n\nOur delegation bus should arrive at 14:30 rather than 14:00. I also sent the schedule change in our usual WhatsApp chat.\n\nNo response is needed unless this creates a problem.\n\nCooperation Office",
    "verdict": "forward",
    "why": "Sender authentication passed and no triggered control requires intervention. Authentication alone never guarantees safety.",
    "source": null,
    "id": "AX-012",
    "day": 1,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "S3",
    "evidence": {
      "subject": [
        "WhatsApp"
      ]
    }
  },
  {
    "id": "AX-022",
    "day": 2,
    "channel": "Email / Internal",
    "from": "Security Awareness <awareness@asterion.example>",
    "to": "All staff <all@asterion.example>",
    "subject": "Reminder: never return sign-in codes to event organizers",
    "body": "Team,\n\nPlease remember that conference organizers must never ask you to email authentication codes or copies of redirect URLs.\n\nIf you receive a suspicious invitation, contact the security desk through our usual internal help channel.\n\nSecurity Awareness",
    "verdict": "forward",
    "why": "The message discusses codes or security, but does not ask the recipient to disclose a secret.",
    "source": "volexity",
    "signals": {
      "sender": "pass"
    },
    "ruleId": "C2",
    "evidence": {
      "subject": [
        "never return sign-in codes"
      ]
    }
  },
  {
    "id": "AX-003",
    "day": 2,
    "channel": "Email / External",
    "from": "Meeting Access <support@conference-verify.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Final step: secure Microsoft 365 conference",
    "body": "Dear participant,\n\nPlease complete Microsoft sign-in using the event registration instructions.\n\nOnce signed in, copy the verification code displayed by Microsoft and reply to this email with that code. We need it to unlock your meeting room. Use https://conference-verify.example/meeting/verify to complete registration.\n\nThank you,\nConference Support",
    "verdict": "quarantine",
    "why": "The sender asks for an authentication secret or unexpected MFA approval. This matches the credential-protection control.",
    "source": "volexity",
    "incident": "After the conference-themed OAuth code was shared, an unauthorized Microsoft 365 access attempt was detected.",
    "signals": {
      "sender": "pass",
      "flag": "credential"
    },
    "ruleId": "C1",
    "evidence": {
      "subject": [
        "Microsoft 365"
      ],
      "body": [
        "verification code",
        "reply to this email"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "Verified Regional Partner <liaison@regional-partner.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "Signal follow-up: room number confirmed",
    "body": "Hello,\n\nFollowing our usual Signal conversation, the bilateral meeting will be in room C-12. I will send the attendee list later today.\n\nRegards, Liaison Office",
    "verdict": "forward",
    "why": "Sender authentication passed and no triggered control requires intervention. Authentication alone never guarantees safety.",
    "source": null,
    "id": "AX-034",
    "day": 2,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "S3",
    "evidence": {
      "subject": [
        "Signal"
      ],
      "body": [
        "room C-12"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "Briefing Helpdesk <access@meeting-services.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Your briefing passcode is waiting",
    "body": "Dear delegate,\n\nWe sent a six-digit Microsoft verification code to your account. Reply to this email with that code to complete the booking. No link is required.\n\nConference Helpdesk",
    "verdict": "quarantine",
    "why": "The sender asks for an authentication secret or unexpected MFA approval. This matches the credential-protection control.",
    "source": "volexity",
    "incident": "A disclosed one-time code was used in an unauthorized login attempt.",
    "id": "AX-007",
    "day": 2,
    "signals": {
      "sender": "pass",
      "flag": "credential"
    },
    "ruleId": "C1",
    "evidence": {
      "body": [
        "Reply to this email",
        "verification code"
      ]
    }
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
    "why": "The sender asks for an authentication secret or unexpected MFA approval. This matches the credential-protection control.",
    "source": "google",
    "incident": "An external actor attempted mailbox access using the disclosed app password.",
    "signals": {
      "sender": "pass",
      "flag": "credential"
    },
    "ruleId": "C1",
    "evidence": {
      "body": [
        "App Password",
        "return the generated password"
      ]
    }
  },
  {
    "id": "AX-016",
    "day": 2,
    "channel": "Email / External",
    "from": "Diplomatic Events Office <events@delegate-portal.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Extended verification for your meeting",
    "body": "Dear guest,\n\nPlease follow the Microsoft sign-in instructions in the attached invitation at https://delegate-portal.example/invite/secure. When the page redirects to the Visual Studio Code sign-in callback, copy the complete redirected URL and send it to our coordinator.\n\nThis proves your registration is valid.\n\nSincerely,\nEvents Office",
    "attachment": "Meeting-Instructions.pdf (simulation)",
    "verdict": "quarantine",
    "why": "The sender asks for an authentication secret or unexpected MFA approval. This matches the credential-protection control.",
    "source": "volexity",
    "incident": "The shared OAuth redirect enabled an unauthorized attempt to obtain Microsoft 365 access.",
    "signals": {
      "sender": "pass",
      "flag": "credential"
    },
    "ruleId": "C1",
    "evidence": {
      "body": [
        "redirected URL",
        "send it to our coordinator"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "Identity Gateway <login@identity-access.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "Urgent MFA approval to preserve Microsoft 365 access",
    "body": "Dear account holder,\n\nOur security team is validating your mailbox. You may receive an unexpected Microsoft Authenticator prompt. Approve the notification even if you did not request a sign-in.\n\nThis is a routine security maintenance task.\n\nIdentity Gateway",
    "verdict": "quarantine",
    "why": "The sender asks for an authentication secret or unexpected MFA approval. This matches the credential-protection control.",
    "source": "microsoftphish",
    "incident": "An unexpected MFA approval was followed by suspicious cloud access.",
    "id": "AX-035",
    "day": 2,
    "signals": {
      "sender": "pass",
      "flag": "unexpectedMfa"
    },
    "ruleId": "C1",
    "evidence": {
      "body": [
        "unexpected Microsoft Authenticator prompt",
        "Approve the notification"
      ]
    }
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
    "why": "This application is approved for the stated work purpose. No stronger security control is triggered.",
    "source": "volexity",
    "signals": {
      "sender": "pass",
      "app": "approved"
    },
    "ruleId": "A3",
    "evidence": {
      "subject": [
        "Visual Studio Code"
      ]
    }
  },
  {
    "id": "AX-009",
    "day": 3,
    "channel": "Email / External",
    "from": "EU Research Network <events@euro-research.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Proposal: external Zoom research roundtable",
    "body": "Dear Research Unit,\n\nOur next roundtable is planned on Zoom. We have not yet been through your organization’s external meeting approval process.\n\nCould your office confirm whether Zoom is suitable for this session? Event details: https://euro-research.example/events/roundtable\n\nRegards,\nResearch Secretariat",
    "verdict": "review",
    "why": "The requested work app is unlisted or lacks confirmed authorization. Seek approval instead of blocking as malware.",
    "source": null,
    "signals": {
      "sender": "pass",
      "app": "approval"
    },
    "ruleId": "A1",
    "evidence": {
      "subject": [
        "Zoom"
      ],
      "body": [
        "approval process"
      ]
    }
  },
  {
    "id": "AX-010",
    "day": 3,
    "channel": "Email / Internal",
    "from": "Procurement <purchasing@asterion.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Updated purchase request on SharePoint",
    "body": "Hello Finance,\n\nThe revised purchase request is saved in our usual internal SharePoint workspace under Procurement / Requests. Reference: https://intranet.asterion.example/sharepoint/requests\n\nPlease check it when convenient. There is no new sign-in procedure.\n\nProcurement",
    "verdict": "forward",
    "why": "This application is approved for the stated work purpose. No stronger security control is triggered.",
    "source": null,
    "signals": {
      "sender": "pass",
      "app": "approved"
    },
    "ruleId": "A3",
    "evidence": {
      "subject": [
        "SharePoint"
      ]
    }
  },
  {
    "id": "AX-008",
    "day": 3,
    "channel": "Email / External",
    "from": "Forum Event Desk <admin@policy-forum.example>",
    "to": "External Relations <external@asterion.example>",
    "subject": "WhatsApp access to your delegate session",
    "body": "Dear delegate,\n\nOur event now uses a new encrypted conference room.\n\nBefore attending, open WhatsApp > Linked Devices and scan the QR code provided in the registration portal at https://policy-forum.example/delegate/qr. Your device will be paired with our security console.\n\nThis step is mandatory.",
    "verdict": "review",
    "why": "The message instructs the recipient to pair their own messaging account with a third-party device.",
    "source": "google",
    "incident": "Unauthorized WhatsApp device pairing exposed part of the victim communication history.",
    "signals": {
      "sender": "pass",
      "app": "approved",
      "flag": "pairing"
    },
    "ruleId": "A2",
    "evidence": {
      "body": [
        "Linked Devices",
        "scan the QR code"
      ]
    }
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
    "why": "The requested work app is unlisted or lacks confirmed authorization. Seek approval instead of blocking as malware.",
    "source": null,
    "signals": {
      "sender": "pass",
      "app": "unlisted"
    },
    "ruleId": "A1",
    "evidence": {
      "subject": [
        "Notion"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "Regional Events Unit <meetings@regional-forum.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Zoom workshop request — approval pending",
    "body": "Dear team,\n\nWe would like to host a project workshop on Zoom next month. We understand external Zoom sessions require your IT team’s approval.\n\nPlease confirm once your internal approval is complete.\n\nRegional Events Unit",
    "verdict": "review",
    "why": "The requested work app is unlisted or lacks confirmed authorization. Seek approval instead of blocking as malware.",
    "source": null,
    "id": "AX-013",
    "day": 3,
    "signals": {
      "sender": "pass",
      "app": "approval"
    },
    "ruleId": "A1",
    "evidence": {
      "subject": [
        "Zoom"
      ],
      "body": [
        "approval"
      ]
    }
  },
  {
    "id": "AX-024",
    "day": 3,
    "channel": "Email / External",
    "from": "New Outreach Partner <hello@outreach-project.example>",
    "to": "Operations <ops@asterion.example>",
    "subject": "Suggestion: move files to SafeBox?",
    "body": "Good afternoon,\n\nWe would like to collaborate on the public conference report. Our team usually exchanges draft files through an app called SafeBox. Information: https://outreach-project.example/safebox\n\nWould you allow us to invite your staff? We can also use your preferred solution.\n\nRegards,\nOutreach Partner",
    "verdict": "review",
    "why": "The requested work app is unlisted or lacks confirmed authorization. Seek approval instead of blocking as malware.",
    "source": null,
    "signals": {
      "sender": "pass",
      "app": "unlisted"
    },
    "ruleId": "A1",
    "evidence": {
      "subject": [
        "SafeBox"
      ]
    }
  },
  {
    "channel": "Email / Internal",
    "from": "Procurement <purchasing@asterion.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Invoice batch status for October",
    "body": "Finance colleagues,\n\nThe October invoice batch has been reconciled in the usual procurement workspace. No supplier account details were changed.\n\nThe status report is available through the corporate SharePoint library.\n\nProcurement\n\nAttachment processing is still pending at the receiving gateway.",
    "verdict": "review",
    "why": "The attachment security scan is incomplete. Route the message for review without assuming the file is infected.",
    "source": null,
    "id": "AX-026",
    "day": 4,
    "signals": {
      "sender": "pass",
      "attachment": "unscanned"
    },
    "ruleId": "F2",
    "evidence": {
      "subject": [
        "Invoice batch"
      ],
      "body": [
        "Attachment processing"
      ]
    },
    "attachment": "Invoice-Batch.xlsx"
  },
  {
    "channel": "Email / External",
    "from": "Grant Documents <forms@external-grants.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Grant worksheet needs an Excel macro",
    "body": "Dear Finance,\n\nThe attached Excel worksheet includes automated grant calculations. If Excel blocks the content, select Enable Content to turn on macros before returning the form.\n\nThank you, Grants Desk",
    "attachment": "Grant-Worksheet.xlsm",
    "verdict": "quarantine",
    "why": "The attachment is malicious or the message requests bypassing built-in Office security protection.",
    "source": "microsoftmacro",
    "incident": "The macro-enablement instruction led to suspected malware execution on a workstation.",
    "id": "AX-014",
    "day": 4,
    "signals": {
      "sender": "pass",
      "attachment": "unscanned",
      "flag": "bypass"
    },
    "ruleId": "F1",
    "evidence": {
      "body": [
        "Enable Content",
        "macros"
      ]
    }
  },
  {
    "id": "AX-002",
    "day": 4,
    "channel": "Email / External",
    "from": "Office of Dr. Weber <contact@civic-dialogue.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Invitation to a private Ukraine policy briefing",
    "body": "Dear colleague,\n\nWe are organizing a small discussion with visiting European delegates regarding policy developments in Ukraine.\n\nPlease let us know if your office would like to attend. We can share a proposed date afterwards. Our event overview is at https://civic-dialogue.example/briefing.\n\nKind regards,\nOffice of Dr. Weber",
    "verdict": "review",
    "why": "The URL scan is inconclusive, so the message is held for manual checking rather than automatically judged malicious.",
    "source": "volexity",
    "signals": {
      "sender": "pass",
      "url": "unknown"
    },
    "ruleId": "U2",
    "evidence": {
      "body": [
        "civic-dialogue.example/briefing"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "Account Notifications <security@office-access.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Microsoft 365: mailbox access suspended",
    "body": "Dear user,\n\nYour mailbox will be suspended in one hour. To keep access, open https://office-access.example/verify and enter your corporate password on the verification form.\n\nDo not contact your IT department because this migration is time-sensitive.\n\nAccount Team",
    "verdict": "quarantine",
    "why": "The simulated URL scanner identifies a malicious destination. The URL verdict takes precedence over otherwise ordinary wording.",
    "source": "microsoftphish",
    "incident": "Credentials entered on a fake verification form resulted in a suspicious mailbox login attempt.",
    "id": "AX-021",
    "day": 4,
    "signals": {
      "sender": "pass",
      "url": "malicious"
    },
    "ruleId": "U1",
    "evidence": {
      "body": [
        "office-access.example/verify"
      ]
    }
  },
  {
    "id": "AX-030",
    "day": 4,
    "channel": "Email / Internal",
    "from": "Office Events <events@asterion.example>",
    "to": "All staff <all@asterion.example>",
    "subject": "Visitor day: QR check-in at the reception",
    "body": "Hello everyone,\n\nFor tomorrow’s public visitor day, guests will check in at the front desk with the QR badge issued after ordinary event registration.\n\nThe badge is for entrance only. Check-in details: https://visitor.asterion.example/checkin. It does not link a messaging account or request a sign-in code.\n\nOffice Events",
    "verdict": "forward",
    "why": "Sender authentication passed and no triggered control requires intervention. Authentication alone never guarantees safety.",
    "source": "google",
    "signals": {
      "sender": "pass",
      "url": "clean"
    },
    "ruleId": "S3",
    "evidence": {
      "body": [
        "QR badge",
        "entrance only"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "Document Gateway <files@shared-package.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Protected document — change Office security settings",
    "body": "Hello,\n\nYour policy document is attached. If your Office application blocks it, disable Protected View and re-open it before reading.\n\nThis step is required for the document to display correctly.\n\nSupport",
    "attachment": "Protected-Policy.docm (simulation only)",
    "verdict": "quarantine",
    "why": "The attachment is malicious or the message requests bypassing built-in Office security protection.",
    "source": "microsoftmacro",
    "incident": "The attachment was opened after disabling document protections, triggering a workstation alert.",
    "id": "AX-028",
    "day": 4,
    "signals": {
      "sender": "pass",
      "attachment": "malware"
    },
    "ruleId": "F1",
    "evidence": {
      "body": [
        "disable Protected View"
      ]
    }
  },
  {
    "id": "AX-025",
    "day": 4,
    "channel": "Email / External",
    "from": "IT Federation Desk <identity@federated-meetings.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Validate access via secure link",
    "body": "Attention,\n\nYour access will be disabled unless you open https://identity-validation.example/session and email the Microsoft authorization code shown after sign-in.\n\nIdentity Desk",
    "verdict": "quarantine",
    "why": "The sender asks for an authentication secret or unexpected MFA approval. This matches the credential-protection control.",
    "source": "volexity",
    "incident": "An authorization code disclosed by a user was followed by an unauthorized M365 login attempt.",
    "signals": {
      "sender": "pass",
      "url": "malicious",
      "flag": "credential"
    },
    "ruleId": "C1",
    "evidence": {
      "body": [
        "identity-validation.example/session",
        "authorization code"
      ]
    }
  },
  {
    "channel": "Email / Internal",
    "from": "Developer Services <devtools@asterion.example>",
    "to": "Development Group <developers@asterion.example>",
    "subject": "Visual Studio Code: development onboarding notes",
    "body": "Team,\n\nThe development onboarding notes for Visual Studio Code have been added to the internal wiki. They cover approved extensions and team settings only.\n\nNo authentication action is required for this announcement.\n\nDeveloper Services",
    "verdict": "forward",
    "why": "This application is approved for the stated work purpose. No stronger security control is triggered.",
    "source": null,
    "id": "AX-020",
    "day": 5,
    "signals": {
      "sender": "pass",
      "app": "approved"
    },
    "ruleId": "A3",
    "evidence": {
      "subject": [
        "Visual Studio Code"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "Partner Billing <billing@partner-finance.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Updated payment instructions for invoice 3816",
    "body": "Dear Finance,\n\nPlease update our bank account details before paying the outstanding invoice. The new beneficiary details are included in the attached notice.\n\nIf possible, arrange the payment this afternoon.\n\nBilling Office",
    "attachment": "Bank-Details.pdf",
    "verdict": "review",
    "why": "A sensitive change or exception requires independently verified approval; a claim in the email is not evidence.",
    "source": "ic3",
    "id": "AX-027",
    "day": 5,
    "signals": {
      "sender": "pass",
      "access": "change"
    },
    "ruleId": "X2",
    "evidence": {
      "subject": [
        "payment instructions"
      ],
      "body": [
        "bank account details"
      ]
    }
  },
  {
    "id": "AX-017",
    "day": 5,
    "channel": "Email / External",
    "from": "Webinar Access <join@webinar-hub.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Sign into your conference display",
    "body": "Dear colleague,\n\nYour access is ready. To complete conference sign-in, use the Microsoft device-code authentication flow. Enter the short code that our operator sends to you on the legitimate Microsoft sign-in page. Guidance: https://webinar-hub.example/device-login\n\nYou may then join the briefing.\n\nSupport Team",
    "verdict": "quarantine",
    "why": "This requests third-party control of an authentication session or linked account/device.",
    "source": "microsoft",
    "incident": "An externally initiated device-code sign-in was followed by anomalous cloud resource access.",
    "signals": {
      "sender": "pass",
      "access": "thirdPartyCode"
    },
    "ruleId": "X1",
    "evidence": {
      "body": [
        "device-code",
        "code that our operator sends"
      ]
    }
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
    "why": "The simulated internal change register confirms the approval record, so the authorized workflow may proceed.",
    "source": null,
    "signals": {
      "sender": "pass",
      "app": "approved",
      "access": "verified"
    },
    "ruleId": "X3",
    "evidence": {
      "subject": [
        "Approved exception"
      ],
      "body": [
        "CHG-204"
      ]
    }
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
    "why": "The sender asks for an authentication secret or unexpected MFA approval. This matches the credential-protection control.",
    "source": null,
    "incident": "An attacker attempted to re-register a Signal account using exposed verification details.",
    "signals": {
      "sender": "pass",
      "flag": "credential"
    },
    "ruleId": "C1",
    "evidence": {
      "body": [
        "Signal PIN",
        "verification code"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "External Webinar Team <organizer@north-forum.example>",
    "to": "Research Unit <research@asterion.example>",
    "subject": "Zoom session — exception number CHG-999",
    "body": "Dear team,\n\nOur Zoom meeting is fully approved. The exception reference is CHG-999. Please join at 16:00.\n\nYou can verify the meeting with your internal change team if needed.\n\nNorth Forum",
    "verdict": "review",
    "why": "The requested work app is unlisted or lacks confirmed authorization. Seek approval instead of blocking as malware.",
    "source": null,
    "id": "AX-033",
    "day": 5,
    "signals": {
      "sender": "pass",
      "app": "approval",
      "access": "unverified"
    },
    "ruleId": "A1",
    "evidence": {
      "subject": [
        "CHG-999"
      ],
      "body": [
        "fully approved"
      ]
    }
  },
  {
    "id": "AX-032",
    "day": 5,
    "channel": "Email / External",
    "from": "Senior Delegate Office <support@delegation-event.example>",
    "to": "Policy Team <policy@asterion.example>",
    "subject": "Final briefing: connect WhatsApp before opening agenda",
    "body": "Dear participant,\n\nDue to the sensitive nature of tomorrow’s briefing, the agenda will be sent through our encrypted WhatsApp relay.\n\nOpen WhatsApp Linked Devices and scan the QR code shown on our event page at https://delegation-event.example/relay/connect. This pairs your account with our delegate relay device and unlocks the discussion.\n\nPlease complete it today.",
    "verdict": "review",
    "why": "The message instructs the recipient to pair their own messaging account with a third-party device.",
    "source": "google",
    "incident": "An unauthorized linked device attempted to read messages from a WhatsApp account.",
    "signals": {
      "sender": "pass",
      "flag": "pairing"
    },
    "ruleId": "A2",
    "evidence": {
      "body": [
        "Linked Devices",
        "pairs your account"
      ]
    }
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
function speedStatus(){return state.seconds<=FAST_THRESHOLD_SECONDS?'':`Time penalty: −${waitCost()} Ops`;}
function updateHUD(){
  $('day-label').textContent=`${String(state.day).padStart(2,'0')} / 05`;
  $('completed-label').textContent=`${String(state.completed.length).padStart(2,'0')} / ${TOTAL_CASES}`;
  $('ops-value').textContent=state.operations+'%'; $('security-value').textContent=state.security+'%';
  $('ops-fill').style.width=state.operations+'%'; $('security-fill').style.width=state.security+'%';
  $('time-value').textContent=minuteClock(state.seconds);
  $('time-penalty').textContent=speedStatus();
  const canPlay=state.screen==='play';
  $('action-forward').disabled=!canPlay;
  $('action-review').disabled=!canPlay;
  $('action-quarantine').disabled=!canPlay;
  $('day-track').innerHTML=DAYS.map((_,i)=>`<div class="day-cell ${i+1<state.day?'past':i+1===state.day?'current':''}" title="Shift ${i+1}"></div>`).join('');
}
// The player sees a short rulebook. Technical IDs remain internal for case validation.
// Playbook rows are plain-English checks that map to a single action.
// Case truth, rule priorities and simulations remain unchanged.
const SIMPLE_RULES = [
  {day:1, category:'SENDER', action:'quarantine', text:'Untrusted sender'},
  {day:1, category:'SENDER', action:'review', text:'Sender not confirmed'},
  {day:2, category:'SIGN-IN', action:'quarantine', text:'Asks for a password or PIN'},
  {day:2, category:'SIGN-IN', action:'quarantine', text:'Asks you to share a sign-in code or approve unknown MFA'},
  {day:3, category:'APPS', action:'review', text:'App not in company list or needs approval'},
  {day:3, category:'APPS', action:'review', text:'Asks to link a chat account to another device'},
  {day:4, category:'LINKS', action:'quarantine', text:'Link scan: Threat found'},
  {day:4, category:'LINKS', action:'review', text:'Link scan: Unclear'},
  {day:4, category:'FILES', action:'quarantine', text:'File scan: Malware found'},
  {day:4, category:'FILES', action:'quarantine', text:'Asks to turn off Office protection'},
  {day:4, category:'FILES', action:'review', text:'File scan: Not checked'},
  {day:5, category:'ACCESS', action:'quarantine', text:'Someone else controls your sign-in'},
  {day:5, category:'ACCESS', action:'review', text:'Change not in approved records'}
];
const CATEGORY_INDEX={SENDER:'01','SIGN-IN':'02',APPS:'03',LINKS:'04',FILES:'05',ACCESS:'06'};
const APPROVED_CHANGES = [{id:'CHG-204', app:'Zoom', purpose:'Research roundtable'}];
const APP_NOTES={
  'Microsoft 365 / Teams':'Work',
  'WhatsApp / Signal':'Chat only',
  'Visual Studio Code':'Development only',
  'Zoom':'Approval needed',
  'Unlisted app':'Approval needed'
};
function playbookAction(action){
  return `<span class="playbook-action ${action}" aria-label="${ACTION_LABEL[action]}" title="${ACTION_LABEL[action]}">${ACTION_ICON[action]}</span>`;
}
const SHORT_REASON = {
  S1:'Sender flagged as untrusted.',
  S2:'Sender could not be confirmed.',
  S3:'No safety rule was triggered.',
  C1:'It asks for a password, sign-in code, or unexpected approval.',
  C2:'It mentions sign-in codes but does not ask for one.',
  A1:'The app or request needs approval.',
  A2:'An outside device wants access to your chat account. Check first.',
  A3:'This app is approved for the requested use.',
  U1:'The link scan found a threat.',
  U2:'The link scan could not confirm it is safe.',
  F1:'The file is unsafe or the email asks you to turn off protection.',
  F2:'The file scan is not finished.',
  X1:'Someone else is starting this sign-in for you.',
  X2:'No matching approval was found in company records.',
  X3:'The change ID matches the company approval list.'
};
function plainReason(c) {
  if(c.ruleId==='F1' && c.signals.flag==='bypass') return 'The email asks you to turn off Office protection.';
  if(c.ruleId==='F1' && c.signals.attachment==='malware') return 'The file scan found malware.';
  return SHORT_REASON[c.ruleId] || 'This choice follows company policy.';
}
function renderPolicies(){
  const p=DAYS[state.day-1];
  $('directive-version').textContent=`DAY ${state.day}`;
  $('policy-version').textContent=`DAY ${state.day}`;
  const active=SIMPLE_RULES.filter(r=>r.day<=state.day);
  let output=''; let lastCategory='';
  for(const r of active){
    if(r.category!==lastCategory){
      if(lastCategory) output+='</div></section>';
      lastCategory=r.category;
      output+=`<section class="playbook-group" aria-label="${safe(r.category)} rules"><h3 class="playbook-group-head"><span class="playbook-number">${CATEGORY_INDEX[r.category]}</span><span>${safe(r.category)}</span></h3><div class="playbook-rows">`;
      if(r.category==='APPS'){
        output+='<div class="playbook-inventory"><div class="inventory-title">COMPANY APP LIST</div>';
        output+=p.apps.filter(([name])=>name!=='Unlisted app').map(([name,note])=>`<div class="inventory-row"><div class="inventory-copy"><strong>${safe(name)}</strong><small>${safe(APP_NOTES[name.replace(/ \/ .*/, '')]||APP_NOTES[name]||note)}</small></div></div>`).join('');
        output+='</div>';
      }
      if(r.category==='ACCESS'){
        output+='<div class="playbook-inventory"><div class="inventory-title">APPROVED CHANGES</div>';
        output+=APPROVED_CHANGES.map(c=>`<div class="inventory-row"><div class="inventory-copy"><strong>${safe(c.id)}</strong><small>${safe(c.app)} · ${safe(c.purpose)}</small></div></div>`).join('');
        output+='</div>';
      }
    }
    output+=`<div class="playbook-row">${playbookAction(r.action)}<span>${safe(r.text)}</span></div>`;
  }
  if(lastCategory)output+='</div></section>';
  $('rules-list').innerHTML=output;
}
// Render messages as inert text only. The protocol is deliberately hidden in the UI.
function renderInactiveLinks(segment){
  return segment.split(/(https?:\/\/[^\s<>]+)/g).map(part =>
    /^https?:\/\//.test(part)
      ? `<span class="fake-link" title="Link disabled">${safe(part.replace(/^https?:\/\//,''))}</span>`
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
// Rule categories and simulated scanner results are the training evidence.
const RULE_BY_ID = Object.fromEntries(DAYS.at(-1).rules.map(r=>[r.id,r]));
function hasApprovedChange(c){
  const message=`${c.subject} ${c.body}`.toLowerCase();
  return c.signals.sender==='pass' && /internal/i.test(c.channel) &&
    APPROVED_CHANGES.some(change=>[
      change.id,change.app,change.purpose
    ].every(value=>message.includes(value.toLowerCase())));
}
function expectedVerdict(c){
  const s=c.signals;
  const q=[], r=[];
  if(s.sender==='spoof')q.push('S1');
  if(s.sender==='unknown')r.push('S2');
  if(c.day>=2 && ['credential','unexpectedMfa'].includes(s.flag))q.push('C1');
  if(c.day>=3){
    if(s.flag==='pairing')r.push('A2');
    if(['approval','unlisted'].includes(s.app))r.push('A1');
  }
  if(c.day>=4){
    if(s.url==='malicious')q.push('U1');
    if(s.url==='unknown')r.push('U2');
    if(s.attachment==='malware'||s.flag==='bypass')q.push('F1');
    if(s.attachment==='unscanned')r.push('F2');
  }
  if(c.day>=5){
    if(s.access==='thirdPartyCode')q.push('X1');
    if(['change','unverified'].includes(s.access) || (s.access==='verified' && !hasApprovedChange(c)))r.push('X2');
  }
  if(q.length)return {action:'quarantine',rule:q[0]};
  if(r.length)return {action:'review',rule:r[0]};
  if(c.day>=5 && s.access==='verified' && hasApprovedChange(c))return {action:'forward',rule:'X3'};
  if(c.day>=3 && s.app==='approved')return {action:'forward',rule:'A3'};
  if(c.day>=2 && /MFA|codes/.test(c.body) && !s.flag)return {action:'forward',rule:'C2'};
  return {action:'forward',rule:'S3'};
}
for(const c of CASES){
  const d=expectedVerdict(c);
  if(d.action!==c.verdict||d.rule!==c.ruleId)throw Error(`Invalid case ${c.id}: ${d.action}/${d.rule}`);
  for (const field of ['from','subject','channel','body']){
    for (const snippet of c.evidence?.[field]||[]){
      if(!c[field].includes(snippet))console.warn(`Evidence not found: ${c.id}/${field}: ${snippet}`);
    }
  }
}
const SCAN_LABELS = {
  sender:{pass:'Sender: Trusted',unknown:'Sender: Not confirmed',spoof:'Sender: Untrusted'},
  app:{approved:'App: Allowed',approval:'App: Needs approval',unlisted:'App: Not listed'},
  url:{clean:'Link: No threat found',unknown:'Link: Unclear',malicious:'Link: Threat found'},
  attachment:{clean:'File: No threat found',unscanned:'File: Not checked',malware:'File: Malware found'},
};
function renderScanSignals(c){
  const s=c.signals;
  return ['sender','url','attachment'].filter(key=>s[key] && (key!=='url'||s.url!=='none')).map(key=>{
    const v=s[key];
    const cls=['spoof','malicious','malware','thirdPartyCode'].includes(v)?'danger':(['unknown','approval','unlisted','unscanned','change','unverified'].includes(v)?'caution':'pass');
    return `<span class="scan-chip ${cls}" title="Security check">${safe(SCAN_LABELS[key][v])}</span>`;
  }).join('');
}
function renderEvidenceMail(c){
  const e=c.evidence||{};
  return `<div class="evidence-mail"><div class="evidence-header"><span>EMAIL CLUES</span><small>Highlighted words</small></div>
    <div class="evidence-meta"><span>FROM</span><div>${renderAnnotatedText(c.from,e.from||[])}</div><span>SUBJECT</span><div class="evidence-subject">${renderAnnotatedText(c.subject,e.subject||[])}</div><span>CHANNEL</span><div>${renderAnnotatedText(c.channel,e.channel||[])}</div></div>
    <div class="evidence-body">${renderAnnotatedText(c.body,e.body||[])}</div>
    <div class="evidence-foot">Scan results: ${renderScanSignals(c)}</div></div>`;
}
function renderCase(){
  const c=CASES[state.index]; if(!c)return;
  $('queue-label').textContent=`${String(state.index+1).padStart(2,'0')} / ${TOTAL_CASES}`;
  $('mail-id').textContent='REF: '+c.id;
  $('mail-from').textContent=c.from;
  $('mail-to').textContent=c.to;
  $('mail-subject').textContent=c.subject;
  $('mail-channel').textContent=c.channel;
  $('mail-body').innerHTML=renderMailText(c.body);
  $('mail-number').textContent=String(state.index+1).padStart(4,'0');
  $('scan-strip').innerHTML=renderScanSignals(c);
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
  modal(`<p class="modal-kicker">PROTOCOL: TRUST</p>
    <h1>YOU ARE THE <em>AI.</em></h1>
    <p class="modal-copy compact-copy">Read each email. Check the rules. Choose Forward, Review, or Quarantine.</p>
    
    <button class="modal-primary" id="begin-btn" type="button">START GAME</button>`);
  $('begin-btn').onclick=startGame;
}
function decide(action){
  if(state.screen!=='play')return;
  const c=CASES[state.index];
  const expected=expectedVerdict(c);
  const correct=action===expected.action;
  const beforeOps=state.operations,beforeSec=state.security;
  const delay=waitCost();
  let opDelta=0,secDelta=0;
  if(correct){
    if(action==='forward')opDelta=4;
    if(action==='review'){opDelta=-1;secDelta=2;}
    if(action==='quarantine'){secDelta=3;}
  } else if(action==='forward'){
    opDelta=3;
    secDelta=expected.action==='quarantine'?-6:-8;
    if(expected.action==='quarantine')state.pending.push({dueDay:Math.min(6,c.day+1),message:c.incident||'An unfiltered suspicious message triggered a security investigation.',from:c.id});
  } else if(action==='review'){
    opDelta=-6;
    secDelta=0;
  } else if(action==='quarantine'){
    opDelta=expected.action==='forward'?-13:-9;
  }
  const fastBonus=correct && state.seconds<=FAST_THRESHOLD_SECONDS ? FAST_CORRECT_BONUS : 0;
  opDelta += fastBonus;
  opDelta-=delay;
  state.operations=clamp(state.operations+opDelta);
  state.security=clamp(state.security+secDelta);
  state.completed.push({id:c.id,day:c.day,action,verdict:expected.action,correct,seconds:state.seconds,opDelta:state.operations-beforeOps,secDelta:state.security-beforeSec,fastBonus,delay});
  state.chosen=action;
  state.screen='feedback';
  logMessage(`${c.id} / ${ACTION_LABEL[action]} / ${correct?'MATCH':'MISMATCH'}`);
  updateHUD();
  const riskNote=!correct&&action==='forward'&&expected.action==='quarantine'?'This may cause a problem later.':'';
  const sourceText=c.source?`<a href="${SOURCE[c.source].url}" target="_blank" rel="noreferrer noopener">${safe(SOURCE[c.source].short)} ↗</a>`:'';
  const deltaLabel=(v)=>`${v>0?'+':''}${v}`;
  const opsChange=state.operations-beforeOps, secChange=state.security-beforeSec;
  modal(`<p class="modal-kicker">${safe(c.id)}</p>
    <h2 class="verdict-title ${correct?'good':'bad'}">${correct?'✓ CORRECT':'× NOT QUITE'}</h2>
    ${!correct?`<p class="expected-label">Choose: <strong>${safe(ACTION_LABEL[expected.action])}</strong></p>`:''}
    <p class="result-reason">${safe(plainReason(c))}</p>
    ${riskNote?`<p class="incident-warning">⚠ ${riskNote}</p>`:''}
    <details class="extra-details evidence-collapsible"><summary>See the clues</summary>${renderEvidenceMail(c)}</details>
    <details class="extra-details"><summary>Details</summary><p>Operations: ${deltaLabel(opsChange)} · Security: ${deltaLabel(secChange)}. Time: ${minuteClock(state.seconds)}.</p>${sourceText?`<p>${sourceText}</p>`:``}</details>
    <button class="modal-primary" id="continue-btn" type="button">${!CASES[state.index+1] || CASES[state.index+1].day!==c.day?'END SHIFT':'NEXT EMAIL'} →</button>`);
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
  const newRules=SIMPLE_RULES.filter(r=>r.day===state.day);
  const incidentHtml=incidents.length?`<div class="shift-brief"><h3>SECURITY ALERT</h3>${incidents.map(inc=>`<div class="incident">${safe(inc.message)}</div>`).join('')}</div>`:'';
  modal(`<p class="modal-kicker">SHIFT ${state.day} / 5</p>
    <h2>NEW RULES</h2>
    ${incidentHtml}
    <div class="shift-focus">${newRules.map(x=>`<div class="focus-row"><span class="focus-action ${x.action}">${ACTION_ICON[x.action]} ${ACTION_SHORT[x.action]}</span><span>${safe(x.text)}</span></div>`).join('')}</div>
    <button class="modal-primary" id="next-shift-btn" type="button">START SHIFT →</button>`);
  $('next-shift-btn').onclick=()=>{state.screen='play';hideModal();updateHUD();logMessage(`Shift ${state.day} started.`);};
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
    return `<details class="history-item"><summary><span>${safe(result.id)} · ${safe(ACTION_LABEL[result.action])}</span><strong>${result.correct?'✓':'×'}</strong></summary>${renderEvidenceMail(c)}<p class="history-reason">${safe(plainReason(c))}</p></details>`;
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
  modal(`<p class="modal-kicker">EVIDENCE BASE / DOCUMENTED TTPs</p><h2>SOURCES & TRAINING DATA</h2><p class="modal-copy">Fictional cases, based on real security methods. Sender checks alone cannot prove an email is safe.</p><ul class="source-list">${list}</ul>
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
  modal(`<p class="modal-kicker">${safe(CASES[state.index].id)}</p><h2>DECISION RECORDED</h2><p class="modal-copy">${safe(plainReason(CASES[state.index]))}</p><button class="modal-primary" id="continue-btn">NEXT MESSAGE</button>`);
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
$('close-policy-top').addEventListener('click',()=>togglePolicy(false));
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
