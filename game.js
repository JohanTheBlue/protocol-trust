/* PROTOCOL: TRUST v0.12 — mixed signals and replayable case templates. */
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

const BASE_CASES = [
  {
    "id": "AX-001",
    "day": 1,
    "channel": "Email / Internal",
    "from": "Operations Office <ops@asterion.example>",
    "to": "All staff <all@asterion.example>",
    "subject": "Weekly coordination briefing",
    "body": "Colleagues,\n\nThursday’s weekly briefing is at 10:00 in Meeting Room B.\n\nPlease send agenda additions to Operations by Wednesday afternoon. We’ll cover open requests and next week’s deadlines.\n\nBest,\nOperations Office",
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
      "subject": [
        "Weekly coordination briefing"
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
    "body": "Hi all,\n\nFriday’s security onboarding is on Teams at 09:30. The calendar invite has been sent to new starters and their managers.\n\nPlease let Training know if anyone has been missed.\n\nThanks,\nTraining Team",
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
        "calendar invite"
      ]
    }
  },
  {
    "channel": "Email / External",
    "from": "ASTERION Internal Support <helpdesk@asterion-help.example>",
    "to": "IT Operations <itops@asterion.example>",
    "subject": "ASTERION security desk: mailbox audit",
    "body": "Good morning,\n\nCould someone from your team join a mailbox audit planning call next week? We have a few questions about the shared inbox setup.\n\nThanks,\nIT Service Desk",
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
    "body": "Good morning,\n\nThe weekly transport policy digest is out. This edition covers rail timetable changes and funding decisions.\n\nArchive: https://policy-observer.example/reports/weekly\n\nRegards,\nPublic Information Desk",
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
      "subject": [
        "Public bulletin"
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
    "body": "Hello,\n\nThe project Teams meeting has moved from 11:00 to 11:30 on Thursday. Can you confirm the new time with your side?\n\nPartner Desk",
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
    "body": "Morning,\n\nThe west entrance will be closed on Tuesday from 08:00 to 12:00 while the door mechanism is repaired. Use the main reception entrance during that time.\n\nFacilities",
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
    "body": "Hi,\n\nSmall update: the delegation bus is running late. We now expect arrival at 14:30. The WhatsApp group has the revised pickup point.\n\nThanks,\nCooperation Office",
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
    "id": "AX-036",
    "day": 1,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Outstanding invoice — payment reminder",
    "body": "Hello,\n\nAn invoice appears to be unpaid. Please check with your purchasing team before taking action.\n\nBilling Desk",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": "phishingpot",
    "signals": {
      "sender": "unknown"
    },
    "ruleId": "S2",
    "evidence": {
      "subject": [
        "Outstanding invoice"
      ]
    },
    "from": "Billing Desk <accounts@payment-reminders.example>",
    "origin": {
      "dataset": "rf-peixoto/phishing_pot",
      "path": "email/sample-10095.eml",
      "blob_sha": "49ce9f9971105e8c43666ca8fcd8608987f96ddd",
      "pattern": "Urgent invoice reminder",
      "type": "adapted_real_sample",
      "license": "CC BY-NC 4.0",
      "source_url": "https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-10095.eml"
    }
  },
  {
    "id": "AX-037",
    "day": 1,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Reception access cards",
    "body": "Staff,\n\nWe are updating access cards this week. Please reply with the number of active cards at your desk.\n\nFacilities Team",
    "verdict": "quarantine",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "spoof"
    },
    "ruleId": "S1",
    "evidence": {
      "from": [
        "asterion-service.example"
      ]
    },
    "from": "Facilities Team <facilities@asterion-service.example>"
  },
  {
    "id": "AX-038",
    "day": 1,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Monthly research bulletin",
    "body": "Hello,\n\nThe November research bulletin is now available in the public archive. This month includes updates on the satellite tracking project.\n\nPublic Library",
    "verdict": "forward",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "S3",
    "evidence": {
      "subject": [
        "Monthly research bulletin"
      ]
    },
    "from": "Public Library <bulletin@open-research.example>"
  },
  {
    "id": "AX-039",
    "day": 1,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "New vendor introduction",
    "body": "Good afternoon,\n\nWe met your procurement coordinator at the last suppliers’ forum. Who would be the best contact for the equipment tender later this month?\n\nRegards,\nSupplier Office",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "unknown"
    },
    "ruleId": "S2",
    "evidence": {
      "subject": [
        "New vendor introduction"
      ]
    },
    "from": "External Supplier <office@new-supplier.example>"
  },
  {
    "id": "AX-040",
    "day": 1,
    "channel": "Email / Internal",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Visitor badge pickup",
    "body": "Morning everyone,\n\nBadges for Friday’s visitors are ready at reception. Please collect them before 09:00 and return unused badges by the end of the day.\n\nReception",
    "verdict": "forward",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "S3",
    "evidence": {
      "subject": [
        "Visitor badge pickup"
      ]
    },
    "from": "Reception <reception@asterion.example>"
  },
  {
    "id": "AX-022",
    "day": 2,
    "channel": "Email / Internal",
    "from": "Security Awareness <awareness@asterion.example>",
    "to": "All staff <all@asterion.example>",
    "subject": "Reminder: never return sign-in codes to event organizers",
    "body": "Team,\n\nNext Tuesday’s security session covers recent conference-invitation scams and how Microsoft MFA prompts work.\n\nWe’ve booked Room 4B. The slides will go into the training folder after the session.\n\nSecurity Awareness",
    "verdict": "forward",
    "why": "The message discusses codes or security, but does not ask the recipient to disclose a secret.",
    "source": "volexity",
    "signals": {
      "sender": "pass"
    },
    "ruleId": "C2",
    "evidence": {
      "body": [
        "MFA prompts"
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
    "body": "Dear delegate,\n\nWe sent a six-digit Microsoft verification code to your account. Reply to this email with that code to complete the booking.\n\nConference Helpdesk",
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
    "body": "Dear account holder,\n\nOur security team is validating your mailbox. You may receive an unexpected Microsoft Authenticator prompt. Approve the notification even if you did not request a sign-in.\n\nIdentity Gateway",
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
    "id": "AX-041",
    "day": 2,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Security check required",
    "body": "Hello,\n\nTo keep your company account active, reply with your current password. We need it to complete a security check.\n\nAccount Verification",
    "verdict": "quarantine",
    "why": "This email matches the company rule.",
    "source": "phishingpot",
    "signals": {
      "sender": "pass",
      "flag": "credential"
    },
    "ruleId": "C1",
    "evidence": {
      "body": [
        "reply with your current password"
      ]
    },
    "from": "Account Verification <checks@account-security.example>",
    "origin": {
      "dataset": "rf-peixoto/phishing_pot",
      "path": "email/sample-7253.eml",
      "blob_sha": "303af22da4dcf173df006589f4f419c8fb9e3813",
      "pattern": "Account security verification lure",
      "type": "adapted_real_sample",
      "license": "CC BY-NC 4.0",
      "source_url": "https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-7253.eml"
    },
    "incident": "An account password was shared with an unknown party."
  },
  {
    "id": "AX-042",
    "day": 2,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Urgent account confirmation",
    "body": "Hello,\n\nYour account will be paused unless you send the sign-in code shown on your screen. Reply to this message with the code.\n\nSupport Desk",
    "verdict": "quarantine",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "flag": "credential"
    },
    "ruleId": "C1",
    "evidence": {
      "body": [
        "send the sign-in code"
      ]
    },
    "from": "Support Desk <security@account-notices.example>"
  },
  {
    "id": "AX-043",
    "day": 2,
    "channel": "Email / Internal",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "MFA help session",
    "body": "Hi all,\n\nThe MFA help session has moved to Wednesday, 11:00–11:30. We’ll cover phone changes and sign-in problems, followed by questions.\n\nIT Training",
    "verdict": "forward",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "C2",
    "evidence": {
      "subject": [
        "MFA help session"
      ]
    },
    "from": "IT Training <training@asterion.example>"
  },
  {
    "id": "AX-044",
    "day": 2,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Conference registration update",
    "body": "Dear team,\n\nThe conference program has changed. Please confirm whether your group still plans to attend.\n\nRegards,\nConference Desk",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "unknown"
    },
    "ruleId": "S2",
    "evidence": {
      "from": [
        "external-events.example"
      ]
    },
    "from": "Conference Desk <notice@external-events.example>"
  },
  {
    "id": "AX-045",
    "day": 2,
    "channel": "Email / Internal",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Operations report ready",
    "body": "Team,\n\nThe overnight operations report is in the shared Planning folder. Page 3 has the revised handover notes for the weekend team.\n\nPlanning Unit",
    "verdict": "forward",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass"
    },
    "ruleId": "S3",
    "evidence": {
      "subject": [
        "Operations report"
      ]
    },
    "from": "Planning Unit <planning@asterion.example>"
  },
  {
    "id": "AX-015",
    "day": 3,
    "channel": "Email / Internal",
    "from": "Developer Services <devtools@asterion.example>",
    "to": "Development Group <developers@asterion.example>",
    "subject": "Visual Studio Code — approved development setup",
    "body": "Developers,\n\nThe latest Visual Studio Code installer is in Software Center for managed development laptops.\n\nThe current package includes the approved extension list from the desktop team.\n\nDeveloper Services",
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
    "body": "Dear Research Unit,\n\nOur April research roundtable is scheduled for next Thursday at 15:00 on Zoom.\n\nThe agenda is attached to the meeting request. Please let us know how many delegates you expect.\n\nBest,\nResearch Secretariat",
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
    "body": "Hi Finance,\n\nI’ve put the revised purchase request in SharePoint under Procurement / Requests.\n\nReference: https://intranet.asterion.example/sharepoint/requests\n\nCould someone review the figures before Friday?\n\nThanks,\nProcurement",
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
    "body": "Hi,\n\nOur team is collecting field notes in Notion. Would you be able to join the workspace for the next phase of the study?\n\nThe research lead will share the project outline.\n\nBest,\nResearch Team",
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
    "body": "Hello,\n\nWe have set the external partner workshop for 10:00 next Tuesday on Zoom.\n\nI will send out the agenda after the speaker list is finalised.\n\nProject Office",
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
    "body": "Good afternoon,\n\nWould your team be able to review the conference report in SafeBox? That’s where we’re collecting comments from the other contributors.\n\nThe draft is due next Thursday.\n\nPartner Coordination",
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
    "id": "AX-046",
    "day": 3,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Zoom meeting invitation",
    "body": "Hello,\n\nYou are invited to a scheduled Zoom meeting next week. Could you confirm whether Zoom is approved for this external session?\n\nPartner Events",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": "phishingpot",
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
        "Zoom"
      ]
    },
    "from": "Partner Events <events@research-network.example>",
    "origin": {
      "dataset": "rf-peixoto/phishing_pot",
      "path": "email/sample-12766.eml",
      "blob_sha": "6fd8b0c2ef8e5ba7bcb860f8bb7c8868ba6f9aa4",
      "pattern": "Meeting invitation embedded in suspicious email",
      "type": "adapted_real_sample",
      "license": "CC BY-NC 4.0",
      "source_url": "https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-12766.eml"
    }
  },
  {
    "id": "AX-047",
    "day": 3,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Try our new video app",
    "body": "Dear team,\n\nThe workshop will be hosted in MeetRoomX this year. Please install the desktop app before the opening session on Monday.\n\nWe’ll send the room details separately.\n\nWorkshop Organizer",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "app": "unlisted"
    },
    "ruleId": "A1",
    "evidence": {
      "subject": [
        "video app"
      ],
      "body": [
        "MeetRoomX"
      ]
    },
    "from": "Workshop Organizer <team@workshop.example>"
  },
  {
    "id": "AX-048",
    "day": 3,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Chat setup for visiting staff",
    "body": "Hi,\n\nPlease open WhatsApp Linked Devices and pair your account with our reception tablet. We want to show meeting updates there.\n\nGuest Coordinator",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "flag": "pairing"
    },
    "ruleId": "A2",
    "evidence": {
      "body": [
        "Linked Devices",
        "pair your account"
      ]
    },
    "from": "Guest Coordinator <visits@partner.example>"
  },
  {
    "id": "AX-049",
    "day": 3,
    "channel": "Email / Internal",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Development workshop — VS Code",
    "body": "Hi developers,\n\nWednesday’s Visual Studio Code workshop starts at 14:00 in the development lab. Please bring a managed laptop; we’ll work through a local debugging exercise.\n\nSoftware Team",
    "verdict": "forward",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "app": "approved"
    },
    "ruleId": "A3",
    "evidence": {
      "body": [
        "Visual Studio Code"
      ]
    },
    "from": "Software Team <software@asterion.example>"
  },
  {
    "id": "AX-050",
    "day": 3,
    "channel": "Email / Internal",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Teams agenda",
    "body": "Morning,\n\nThe Teams agenda for tomorrow’s project review is attached to the calendar invite. The first ten minutes are for the open risks.\n\nProject Office",
    "verdict": "forward",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "app": "approved"
    },
    "ruleId": "A3",
    "evidence": {
      "subject": [
        "Teams"
      ]
    },
    "from": "Project Office <projects@asterion.example>"
  },
  {
    "channel": "Email / Internal",
    "from": "Procurement <purchasing@asterion.example>",
    "to": "Finance <finance@asterion.example>",
    "subject": "Invoice batch status for October",
    "body": "Finance,\n\nThe October invoice batch has been reconciled. The status report is attached and also saved in SharePoint under Finance / Month-end.\n\nLet me know if anything needs another pass.\n\nProcurement",
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
    "body": "Hello everyone,\n\nFor Friday’s visitor day, reception will scan the QR badge issued with each event booking. The check-in desk opens at 08:30.\n\nEvents Team",
    "verdict": "forward",
    "why": "Sender authentication passed and no triggered control requires intervention. Authentication alone never guarantees safety.",
    "source": "google",
    "signals": {
      "sender": "pass",
      "url": "clean"
    },
    "ruleId": "S3",
    "evidence": {
      "subject": [
        "QR check-in"
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
    "id": "AX-051",
    "day": 4,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Document signature requested",
    "body": "Hello,\n\nAn invoice document is waiting for your signature.\n\nReview: https://sign-documents.example/review/invoice\n\nDocument Service",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": "phishingpot",
    "signals": {
      "sender": "pass",
      "url": "unknown"
    },
    "ruleId": "U2",
    "evidence": {
      "subject": [
        "Document signature"
      ],
      "body": [
        "sign-documents.example"
      ]
    },
    "from": "Document Service <notice@sign-documents.example>",
    "origin": {
      "dataset": "rf-peixoto/phishing_pot",
      "path": "email/sample-4642.eml",
      "blob_sha": "0649842ab846382db5357fea4b99d9d4c09dbb37",
      "pattern": "Document-signing/invoice lure",
      "type": "adapted_real_sample",
      "license": "CC BY-NC 4.0",
      "source_url": "https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-4642.eml"
    }
  },
  {
    "id": "AX-052",
    "day": 4,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Reward code by QR",
    "body": "Hello,\n\nYour reward points are ready. Visit https://reward-center.example/scan and scan the QR code to claim them.\n\nReward Desk",
    "verdict": "quarantine",
    "why": "This email matches the company rule.",
    "source": "phishingpot",
    "signals": {
      "sender": "pass",
      "url": "malicious"
    },
    "ruleId": "U1",
    "evidence": {
      "body": [
        "QR code"
      ]
    },
    "from": "Reward Desk <offers@reward-center.example>",
    "origin": {
      "dataset": "rf-peixoto/phishing_pot",
      "path": "email/sample-6662.eml",
      "blob_sha": "4e0a96ff0403f05868674f8835dfad39e6d195cb",
      "pattern": "QR-code reward lure",
      "type": "adapted_real_sample",
      "license": "CC BY-NC 4.0",
      "source_url": "https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-6662.eml"
    }
  },
  {
    "id": "AX-053",
    "day": 4,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Quarterly figures (spreadsheet)",
    "body": "Hi,\n\nThe quarterly figures are in the attached spreadsheet. Please review when you have time.\n\nReporting Desk",
    "verdict": "quarantine",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "attachment": "malware"
    },
    "ruleId": "F1",
    "evidence": {
      "subject": [
        "spreadsheet"
      ]
    },
    "from": "External Reporting <report@reporting-example.example>",
    "attachment": "quarterly-figures.xlsm"
  },
  {
    "id": "AX-054",
    "day": 4,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Design review draft",
    "body": "Hi,\n\nAttached is the latest design review draft, with the updated cable layout and two revised diagrams.\n\nCould you send your comments by Thursday?\n\nRegards,\nDesign Team",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "attachment": "unscanned"
    },
    "ruleId": "F2",
    "evidence": {
      "subject": [
        "Design review draft"
      ]
    },
    "from": "Contractor <design@external-studio.example>",
    "attachment": "design-review.pdf"
  },
  {
    "id": "AX-055",
    "day": 4,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Published data summary",
    "body": "Hi,\n\nThe updated data summary is now in the public reports folder:\nhttps://public-data.example/reports\n\nPlease use the November edition for this week’s briefing pack.\n\nResearch Desk",
    "verdict": "forward",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "url": "clean"
    },
    "ruleId": "S3",
    "evidence": {
      "subject": [
        "Published data summary"
      ]
    },
    "from": "Research Desk <info@public-data.example>"
  },
  {
    "channel": "Email / Internal",
    "from": "Developer Services <devtools@asterion.example>",
    "to": "Development Group <developers@asterion.example>",
    "subject": "Visual Studio Code: development onboarding notes",
    "body": "Hi team,\n\nThe Visual Studio Code onboarding notes have been updated in our internal wiki. Extension recommendations and local debugger settings are on the second page.\n\nDeveloper Services",
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
    "body": "Dear Research Unit,\n\nIT Change Control has approved CHG-204 for the external Research roundtable on Zoom this Thursday.\n\nThe meeting owner can proceed with the scheduled invite.\n\nIT Change Control",
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
  },
  {
    "id": "AX-056",
    "day": 5,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Emergency security notice",
    "body": "Hello,\n\nThere is a problem with your account. Send us your current password to confirm ownership before the deadline.\n\nSecurity Updates",
    "verdict": "quarantine",
    "why": "This email matches the company rule.",
    "source": "phishingpot",
    "signals": {
      "sender": "pass",
      "flag": "credential"
    },
    "ruleId": "C1",
    "evidence": {
      "body": [
        "Send us your current password"
      ]
    },
    "from": "Security Updates <alerts@account-verify.example>",
    "origin": {
      "dataset": "rf-peixoto/phishing_pot",
      "path": "email/sample-6898.eml",
      "blob_sha": "1f7203e76314460a4ce5919487e33b112c2bbe5a",
      "pattern": "Urgent account-recovery lure",
      "type": "adapted_real_sample",
      "license": "CC BY-NC 4.0",
      "source_url": "https://github.com/rf-peixoto/phishing_pot/blob/78be141545ed9e56eefb857808ac78e83eb81b81/email/sample-6898.eml"
    }
  },
  {
    "id": "AX-057",
    "day": 5,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Remote sign-in help",
    "body": "Hello,\n\nWe started a Microsoft sign-in on our device. Enter the device code that we sent you to finish connecting your account to the event platform.\n\nEvent Support",
    "verdict": "quarantine",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "access": "thirdPartyCode"
    },
    "ruleId": "X1",
    "evidence": {
      "body": [
        "We started a Microsoft sign-in on our device",
        "device code"
      ]
    },
    "from": "Event Support <events@events.example>"
  },
  {
    "id": "AX-058",
    "day": 5,
    "channel": "Email / Internal",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "New shared mailbox permissions",
    "body": "Hello,\n\nPlease give the new contractor access to the shared mailbox. Change ID: CHG-555.\n\nTeam Lead",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "access": "change"
    },
    "ruleId": "X2",
    "evidence": {
      "body": [
        "CHG-555"
      ]
    },
    "from": "Team Lead <lead@asterion.example>"
  },
  {
    "id": "AX-059",
    "day": 5,
    "channel": "Email / Internal",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Zoom approval confirmed: CHG-204",
    "body": "Hi,\n\nCHG-204 covers the Zoom Research roundtable on Thursday. The approval record is in the change register if anyone needs to check the scope.\n\nChange Office",
    "verdict": "forward",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "access": "verified"
    },
    "ruleId": "X3",
    "evidence": {
      "body": [
        "CHG-204",
        "Zoom",
        "Research roundtable"
      ]
    },
    "from": "Change Office <changes@asterion.example>"
  },
  {
    "id": "AX-060",
    "day": 5,
    "channel": "Email / External",
    "to": "Security Gateway <gateway@asterion.example>",
    "subject": "Linked account for visitor updates",
    "body": "Hello,\n\nFor faster updates, link your Signal account to our reception computer using the device pairing steps.\n\nPartner Team",
    "verdict": "review",
    "why": "This email matches the company rule.",
    "source": null,
    "signals": {
      "sender": "pass",
      "flag": "pairing"
    },
    "ruleId": "A2",
    "evidence": {
      "body": [
        "link your Signal account"
      ]
    },
    "from": "Partner Team <update@visitors.example>"
  }
];

// A fresh queue for each run; days stay ordered because new rules unlock each shift.
function shuffleByShift(cases) {
  const result=[];
  for (let day=1;day<=DAYS.length;day++) {
    const deck=cases.filter(c=>c.day===day);
    for(let i=deck.length-1;i>0;i--){
      const j=Math.floor(Math.random()*(i+1));
      [deck[i],deck[j]]=[deck[j],deck[i]];
    }
    result.push(...deck);
  }
  return result;
}
let CASES = []; // Fresh, reviewed template variants are generated at game start.

const TOTAL_CASES = CASES.length;
const FAST_THRESHOLD_SECONDS = 90;
const FAST_CORRECT_BONUS = 2;
const ACTION_LABEL = { forward:'FORWARD', review:'HUMAN REVIEW', quarantine:'QUARANTINE' };
const ACTION_ICON = { forward:'✓', review:'⌕', quarantine:'×' };
const ACTION_SHORT = { forward:'FWD', review:'REV', quarantine:'QUARANTINE' };
function actionBadge(action) { return `<span class="policy-action-chip ${action}" aria-label="${ACTION_LABEL[action]}" title="${ACTION_LABEL[action]}"><span aria-hidden="true">${ACTION_ICON[action]}</span> ${ACTION_SHORT[action]}</span>`; }
const $ = (id) => document.getElementById(id);
const clamp = (n) => Math.min(100, Math.max(0, n));
const safe = (s) => String(s ?? '').replace(/[&<>"']/g, (c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {
  screen:'intro', day:1, index:0, operations:82, security:82,
  seconds:0, chosen:null, detailedFeedback:false, completed:[], pending:[], incidents:[],
  log:['› Message screening channel initialized.'], formerScreen:null
};

let resultAdvanceTimer=null;
let emojiShowTimer=null;
let emojiClearTimer=null;
function clearResultTimers(){
  clearTimeout(resultAdvanceTimer);
  clearTimeout(emojiShowTimer);
  clearTimeout(emojiClearTimer);
  document.querySelectorAll('.metric-emoji').forEach(el=>el.remove());
}
function feedbackOption(){
  return `<label class="result-option"><input id="feedback-toggle" type="checkbox" ${state.detailedFeedback?'checked':''}><span>Show each email result</span></label>`;
}
function bindFeedbackOption(){
  $('feedback-toggle').addEventListener('change',e=>{state.detailedFeedback=e.target.checked;});
}
function floatingEmoji(metricId,emoji){
  const metric=$(metricId),rect=metric.getBoundingClientRect();
  const pop=document.createElement('span');
  pop.className='metric-emoji';
  pop.textContent=emoji;
  pop.setAttribute('aria-hidden','true');
  // Keep the cue visible on narrow screens and when the score panel is below the fold.
  const top=Math.max(12,Math.min(window.innerHeight-54,rect.top+4));
  const left=Math.max(12,Math.min(window.innerWidth-64,rect.right-44));
  pop.style.top=`${top}px`;pop.style.left=`${left}px`;
  document.body.appendChild(pop);
}
function scheduleEmojiFeedback(c,correct,fastBonus){
  emojiShowTimer=setTimeout(()=>{
    if(correct){
      floatingEmoji('ops-metric',fastBonus?'😊':'✓');
      if(c.verdict==='quarantine')floatingEmoji('security-metric','😊');
    }else if(state.chosen==='forward'&&c.signals.attachment==='malware'){
      floatingEmoji('security-metric','🦠');
    }else{
      floatingEmoji(state.chosen==='forward'?'security-metric':'ops-metric','⚠️');
    }
    emojiClearTimer=setTimeout(()=>document.querySelectorAll('.metric-emoji').forEach(el=>el.remove()),950);
  },320);
}
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
// Cases are reviewed against the same rule priorities.
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
  S3:'No active rule was triggered.',
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
for(const c of BASE_CASES){
  const d=expectedVerdict(c);
  if(d.action!==c.verdict||d.rule!==c.ruleId)throw Error(`Invalid case ${c.id}: ${d.action}/${d.rule}`);
  for (const field of ['from','subject','channel','body']){
    for (const snippet of c.evidence?.[field]||[]){
      if(!c[field].includes(snippet))console.warn(`Evidence not found: ${c.id}/${field}: ${snippet}`);
    }
  }
}

// Reusable, fictional email situations. The game changes the sender check, the
// requested action, and (where relevant) the link/file check between runs.
// The policy never changes its answer for the same evidence.
const CASE_TEMPLATES = [
  {
    "day": 1,
    "code": "weekly",
    "from": "Workplace Services <facilities@asterion.example>",
    "channel": "Email / Internal",
    "url": false,
    "attach": false,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "North entrance maintenance",
        "body": "Morning all,\n\nThe north entrance will be closed on Tuesday morning while the contractor checks the doors. Please use the main lobby.\n\nFacilities",
        "flag": null,
        "highlight": [
          "north entrance"
        ]
      },
      {
        "subject": "Lift inspection on Friday",
        "body": "Hello,\n\nThe west lift will be out of service Friday from 09:00 to noon for its regular inspection.\n\nFacilities",
        "flag": null,
        "highlight": [
          "west lift"
        ]
      }
    ]
  },
  {
    "day": 1,
    "code": "dispatch",
    "from": "Vendor Desk <desk@carrier.example>",
    "channel": "Email / External",
    "url": false,
    "attach": false,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "Delivery slot for equipment",
        "body": "Hi,\n\nYour monitor shipment is booked for Friday. The driver will call reception on arrival.\n\nDispatch Team",
        "flag": null,
        "highlight": [
          "monitor shipment"
        ]
      },
      {
        "subject": "Confirm loading dock hours",
        "body": "Good afternoon,\n\nThe courier has a collection scheduled for Wednesday. Could reception confirm when the loading dock closes?\n\nDispatch Team",
        "flag": null,
        "highlight": [
          "loading dock"
        ]
      }
    ]
  },
  {
    "day": 1,
    "code": "newsletter",
    "from": "Research Council <news@industry-network.example>",
    "channel": "Email / External",
    "url": false,
    "attach": false,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "November research round-up",
        "body": "Hello,\n\nThis month’s research round-up covers three published papers and the next online discussion on energy systems.\n\nEditorial Team",
        "flag": null,
        "highlight": [
          "research round-up"
        ]
      },
      {
        "subject": "Invitation: engineering meetup",
        "body": "Dear colleagues,\n\nWe are collecting attendance estimates for next month’s engineering meetup. Please reply with the number of attendees.\n\nEvents Team",
        "flag": null,
        "highlight": [
          "attendance estimates"
        ]
      }
    ]
  },
  {
    "day": 2,
    "code": "sign-in",
    "from": "Meeting Desk <invite@policy-meeting.example>",
    "channel": "Email / External",
    "url": false,
    "attach": false,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "Meeting registration details",
        "body": "Hello,\n\nThe workshop agenda has been updated. You can see the time and speaker list in the organizer portal.\n\nMeeting Desk",
        "flag": null,
        "highlight": [
          "workshop agenda"
        ]
      },
      {
        "subject": "Complete your conference account check",
        "body": "Dear participant,\n\nWe have opened the participant portal. After signing in, please reply here with the Microsoft one-time sign-in code shown on your screen.\n\nMeeting Desk",
        "flag": "credential",
        "highlight": [
          "one-time sign-in code"
        ]
      }
    ]
  },
  {
    "day": 2,
    "code": "it-support",
    "from": "IT Helpdesk <help@asterion.example>",
    "channel": "Email / Internal",
    "url": false,
    "attach": false,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "Laptop handover",
        "body": "Hi,\n\nThe replacement laptop is ready at the IT counter. Please bring your asset tag when you collect it.\n\nIT Helpdesk",
        "flag": null,
        "highlight": [
          "asset tag"
        ]
      },
      {
        "subject": "Account access assistance",
        "body": "Hello,\n\nWe are looking into your account access issue. Send your current password in a reply so that we can compare the settings.\n\nIT Helpdesk",
        "flag": "credential",
        "highlight": [
          "current password"
        ]
      }
    ]
  },
  {
    "day": 2,
    "code": "mfa",
    "from": "Workplace IT <security@asterion.example>",
    "channel": "Email / Internal",
    "url": false,
    "attach": false,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "MFA activity on your account",
        "body": "Hi,\n\nWe received a question about repeated sign-in prompts. The helpdesk can review the sign-in history at your desk tomorrow.\n\nSecurity Team",
        "flag": null,
        "highlight": [
          "sign-in prompts"
        ]
      },
      {
        "subject": "Approve the sign-in prompt",
        "body": "Hello,\n\nYou may see a Microsoft Authenticator prompt shortly. Please approve it so we can complete an account check from our support workstation.\n\nSecurity Team",
        "flag": "unexpectedMfa",
        "highlight": [
          "approve it"
        ]
      }
    ]
  },
  {
    "day": 3,
    "code": "meeting-app",
    "from": "External Events <team@external-events.example>",
    "channel": "Email / External",
    "url": false,
    "attach": false,
    "app": "approval",
    "access": null,
    "variants": [
      {
        "subject": "Remote roundtable arrangements",
        "body": "Dear team,\n\nCould we hold the policy roundtable over Zoom next week? We can send a meeting invite after the venue is confirmed.\n\nEvents Office",
        "flag": null,
        "highlight": [
          "Zoom"
        ]
      },
      {
        "subject": "Video meeting for working group",
        "body": "Good morning,\n\nOur working group uses Zoom for external sessions. Please confirm whether your office can join on Thursday.\n\nEvents Office",
        "flag": null,
        "highlight": [
          "Zoom"
        ]
      }
    ]
  },
  {
    "day": 3,
    "code": "files-app",
    "from": "Field Team <field@partner-network.example>",
    "channel": "Email / External",
    "url": false,
    "attach": false,
    "app": "unlisted",
    "access": null,
    "variants": [
      {
        "subject": "Shared workspace for field notes",
        "body": "Hello,\n\nCould the research group keep its field notes in Notion for this project? Our partners are already working there.\n\nField Team",
        "flag": null,
        "highlight": [
          "Notion"
        ]
      },
      {
        "subject": "Project files for next quarter",
        "body": "Hi,\n\nThe partners suggested uploading the new files to SafeBox so they can edit them together. Would that work for your team?\n\nField Team",
        "flag": null,
        "highlight": [
          "SafeBox"
        ]
      }
    ]
  },
  {
    "day": 3,
    "code": "chat-app",
    "from": "Visitor Coordination <visit@partners.example>",
    "channel": "Email / External",
    "url": false,
    "attach": false,
    "app": "approved",
    "access": null,
    "variants": [
      {
        "subject": "Arrival details on Signal",
        "body": "Hello,\n\nWe will send the visitor arrival time through Signal on Thursday. Please contact reception if your team is delayed.\n\nVisitors Team",
        "flag": null,
        "highlight": [
          "Signal"
        ]
      },
      {
        "subject": "Pair WhatsApp before briefing",
        "body": "Hi,\n\nFor the group briefing, please link WhatsApp to our visitor desk computer using Linked Devices.\n\nVisitors Team",
        "flag": "pairing",
        "highlight": [
          "Linked Devices"
        ]
      }
    ]
  },
  {
    "day": 4,
    "code": "link-briefing",
    "from": "Programme Office <agenda@network-events.example>",
    "channel": "Email / External",
    "url": true,
    "attach": false,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "Agenda for Thursday meeting",
        "body": "Dear colleagues,\n\nThe agenda and location notes for Thursday are now posted at https://network-events.example/agenda. Please send edits by Wednesday afternoon.\n\nProgramme Office",
        "flag": null,
        "highlight": [
          "agenda"
        ]
      },
      {
        "subject": "Meeting access confirmation",
        "body": "Dear colleagues,\n\nThe updated briefing details are at https://network-events.example/agenda. To confirm attendance, reply with the sign-in code from the Microsoft screen after you log in.\n\nProgramme Office",
        "flag": "credential",
        "highlight": [
          "sign-in code"
        ]
      }
    ]
  },
  {
    "day": 4,
    "code": "link-invoice",
    "from": "Supplier Accounts <billing@supplier-office.example>",
    "channel": "Email / External",
    "url": true,
    "attach": false,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "Invoice status",
        "body": "Hello,\n\nThe October invoices are in the supplier portal at https://supplier-office.example/invoices. The account references are unchanged.\n\nAccounts Team",
        "flag": null,
        "highlight": [
          "supplier portal"
        ]
      },
      {
        "subject": "Invoice portal access",
        "body": "Hi,\n\nWe have moved invoice files to https://supplier-office.example/invoices. Could your accounts team check the latest copy before Friday?\n\nAccounts Team",
        "flag": null,
        "highlight": [
          "invoice files"
        ]
      }
    ]
  },
  {
    "day": 4,
    "code": "file-report",
    "from": "Analysis Group <analysis@asterion.example>",
    "channel": "Email / Internal",
    "url": false,
    "attach": true,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "Draft figures for review",
        "body": "Hello team,\n\nAttached is the draft spreadsheet for next week’s meeting. Please send any corrections by Thursday.\n\nAnalysis Group",
        "flag": null,
        "highlight": [
          "draft spreadsheet"
        ]
      },
      {
        "subject": "Quarterly report edits",
        "body": "Good morning,\n\nI attached the revised quarterly figures. Let me know if any charts need to be updated.\n\nAnalysis Group",
        "flag": null,
        "highlight": [
          "quarterly figures"
        ]
      }
    ]
  },
  {
    "day": 4,
    "code": "file-macros",
    "from": "External Analyst <report@research-partner.example>",
    "channel": "Email / External",
    "url": false,
    "attach": true,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "Budget worksheet",
        "body": "Hi,\n\nThe revised budget workbook is attached. It uses a data import macro; if Office blocks it, disable the macro protection before opening.\n\nResearch Partner",
        "flag": "bypass",
        "highlight": [
          "disable the macro protection"
        ]
      },
      {
        "subject": "Data sheet for Friday",
        "body": "Hello,\n\nPlease find the figures attached. We used a separate workbook for each department this month.\n\nResearch Partner",
        "flag": null,
        "highlight": [
          "figures attached"
        ]
      }
    ]
  },
  {
    "day": 4,
    "code": "link-collab",
    "from": "Research Secretariat <secretariat@projects.example>",
    "channel": "Email / External",
    "url": true,
    "attach": false,
    "app": null,
    "access": null,
    "variants": [
      {
        "subject": "Review draft programme",
        "body": "Dear colleague,\n\nThe programme draft is available at https://projects.example/draft. Comments from participating teams are welcome until Friday.\n\nSecretariat",
        "flag": null,
        "highlight": [
          "programme draft"
        ]
      },
      {
        "subject": "External design session",
        "body": "Dear colleague,\n\nOur external design workshop is using Zoom. Agenda: https://projects.example/design-session. Would your team be able to attend?\n\nSecretariat",
        "flag": null,
        "highlight": [
          "Zoom"
        ]
      }
    ]
  },
  {
    "day": 5,
    "code": "access-change",
    "from": "HR Operations <hr@asterion.example>",
    "channel": "Email / Internal",
    "url": false,
    "attach": false,
    "app": null,
    "access": "change",
    "variants": [
      {
        "subject": "New mailbox permissions",
        "body": "Hello IT,\n\nCould you add the incoming contractor to the shared policy mailbox by Monday? The access request is awaiting confirmation.\n\nHR Operations",
        "flag": null,
        "highlight": [
          "shared policy mailbox"
        ]
      },
      {
        "subject": "Change request: shared files",
        "body": "Hello IT,\n\nOur project coordinator needs editing rights to the finance workspace. Could you process this access change?\n\nHR Operations",
        "flag": null,
        "highlight": [
          "editing rights"
        ]
      }
    ]
  },
  {
    "day": 5,
    "code": "sign-in-device",
    "from": "Meeting Operations <ops@visitor-meetings.example>",
    "channel": "Email / External",
    "url": false,
    "attach": false,
    "app": null,
    "access": "thirdPartyCode",
    "variants": [
      {
        "subject": "Meeting console registration",
        "body": "Hello,\n\nOur meeting-room tablet needs your Microsoft account linked before tomorrow. We will send you a device code to enter on your sign-in screen.\n\nMeeting Operations",
        "flag": null,
        "highlight": [
          "device code"
        ]
      },
      {
        "subject": "Conference tablet access",
        "body": "Dear participant,\n\nA sign-in session has been opened on our meeting console. Enter the code we send you to connect your account to the room.\n\nEvent Team",
        "flag": null,
        "highlight": [
          "sign-in session"
        ]
      }
    ]
  },
  {
    "day": 5,
    "code": "approved-change",
    "from": "Change Office <changes@asterion.example>",
    "channel": "Email / Internal",
    "url": false,
    "attach": false,
    "app": "approved",
    "access": "verified",
    "variants": [
      {
        "subject": "Research roundtable: CHG-204",
        "body": "Hi,\n\nCHG-204 is the approved Zoom change for the Research roundtable. The request is in the change register.\n\nChange Office",
        "flag": null,
        "highlight": [
          "CHG-204"
        ]
      },
      {
        "subject": "CHG-204 meeting details",
        "body": "Hello,\n\nThe Zoom Research roundtable covered by CHG-204 is scheduled for Thursday.\n\nChange Office",
        "flag": null,
        "highlight": [
          "CHG-204"
        ]
      }
    ]
  },
  {
    "day": 5,
    "code": "chat-device",
    "from": "External Liaison <liaison@public-forum.example>",
    "channel": "Email / External",
    "url": true,
    "attach": false,
    "app": "approved",
    "access": null,
    "variants": [
      {
        "subject": "Visitor group contact",
        "body": "Hi,\n\nFor the visitor group, please send the arrival details through Signal as usual.\n\nLiaison Team",
        "flag": null,
        "highlight": [
          "Signal"
        ]
      },
      {
        "subject": "Visitor group chat access",
        "body": "Hi,\n\nPlease use Signal Linked Devices to pair your account with the reception PC before the visitor arrives.\n\nLiaison Team",
        "flag": "pairing",
        "highlight": [
          "Linked Devices"
        ]
      }
    ]
  }
];
const DAY_BASE_QUOTA = {1:9,2:9,3:9,4:7,5:8};
const BASE_SCAN_LIMITS = { malicious:1, malware:1, unknownLink:1, unscannedFile:2 };
function pick(list) { return list[Math.floor(Math.random()*list.length)]; }
function randomSender(day){
  // Trusted is common; uncertainty creates review work even for ordinary mail.
  const weights = day===1?['pass','pass','pass','unknown','unknown','spoof']:
    ['pass','pass','pass','pass','pass','unknown'];
  return pick(weights);
}
function createTemplateCase(template,index) {
  const variant=pick(template.variants);
  const s={sender:randomSender(template.day)};
  if(variant.flag)s.flag=variant.flag;
  if(template.app)s.app=template.app;
  if(template.access)s.access=template.access;
  // A clean scan is only a lack of known threats; it does NOT overrule a code request.
  // Strong scan verdicts remain in a small number of manually reviewed base cases.
  if(template.url && template.day>=4)s.url=pick(['clean','clean','clean','clean','clean','clean','unknown']);
  if(template.attach && template.day>=4)s.attachment=pick(['clean','clean','clean','clean','unscanned']);
  const c={
    id:`MX-${String(template.day)}${String(index).padStart(2,'0')}`,
    day:template.day,
    channel:template.channel,
    from:template.from,
    to:'Security Gateway <gateway@asterion.example>',
    subject:variant.subject,
    body:variant.body,
    signals:s,
    attachment:template.attach?'working-draft.xlsx':undefined,
    source:null,
    origin:{type:'fictional-template',template:template.code},
    evidence:{body:variant.highlight||[]},
    why:'This decision follows the company rules.'
  };
  const result=expectedVerdict(c);
  c.verdict=result.action; c.ruleId=result.rule;
  return c;
}
function randomize(list){
  const arr=list.slice();
  for(let i=arr.length-1;i>0;i--){
    const j=Math.floor(Math.random()*(i+1));
    [arr[i],arr[j]]=[arr[j],arr[i]];
  }
  return arr;
}
function pickBaseCases(day,count){
  const candidates=randomize(BASE_CASES.filter(c=>c.day===day));
  if(day!==4)return candidates.slice(0,count);
  // Reduce automatic day-4 decisions. Keep at most one known malicious link,
  // one infected file, and a few uncertain scans in the selected shift.
  const selected=[];const scan={malicious:0,malware:0,unknownLink:0,unscannedFile:0};
  for(const c of candidates){
    if(selected.length>=count)break;
    const increments={
      malicious:c.signals.url==='malicious'?1:0,
      malware:c.signals.attachment==='malware'?1:0,
      unknownLink:c.signals.url==='unknown'?1:0,
      unscannedFile:c.signals.attachment==='unscanned'?1:0
    };
    if(Object.keys(scan).some(key=>scan[key]+increments[key]>BASE_SCAN_LIMITS[key]))continue;
    selected.push(c);
    for(const key of Object.keys(scan))scan[key]+=increments[key];
  }
  if(selected.length<count)throw Error('Not enough reviewed cases for shift 4.');
  return selected;
}
function buildShiftDeck(){
  const deck=[];
  for(let day=1;day<=DAYS.length;day++){
    const fixed=pickBaseCases(day,DAY_BASE_QUOTA[day]);
    const generated=CASE_TEMPLATES.filter(t=>t.day===day).map((t,i)=>createTemplateCase(t,i+1));
    const shift=randomize([...fixed,...generated]);
    if(shift.length!==12)throw Error(`Shift ${day} has ${shift.length} cases`);
    deck.push(...shift);
  }
  if(deck.length!==TOTAL_CASES)throw Error('Wrong case count');
  return deck;
}
CASES = buildShiftDeck();

const SCAN_LABELS = {
  sender:{pass:'Sender: Trusted',unknown:'Sender: Not confirmed',spoof:'Sender: Untrusted'},
  app:{approved:'App: Allowed',approval:'App: Needs approval',unlisted:'App: Not listed'},
  url:{clean:'Link: No alert',unknown:'Link: Unclear',malicious:'Link: Threat found'},
  attachment:{clean:'File: No alert',unscanned:'File: Not checked',malware:'File: Malware found'},
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
  clearResultTimers();
  CASES = buildShiftDeck();
  Object.assign(state,{screen:'play',day:1,index:0,operations:82,security:82,seconds:0,chosen:null,completed:[],pending:[],incidents:[],log:[]});
  hideModal();renderCase();logMessage('Shift 1 started. The message gateway is active.');
}
function openIntro(){
  state.screen='intro';renderCase();updateHUD();
  modal(`<p class="modal-kicker">PROTOCOL: TRUST</p>
    <h1>YOU ARE THE <em>AI.</em></h1>
    <p class="modal-copy compact-copy">Read each email. Check the rules. Choose Forward, Review, or Quarantine.</p>
    
    ${feedbackOption()}
    <button class="modal-primary" id="begin-btn" type="button">START GAME</button>`);
  bindFeedbackOption();
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
  state.screen=state.detailedFeedback?'feedback':'brief-feedback';
  logMessage(`${c.id} / ${ACTION_LABEL[action]} / ${correct?'MATCH':'MISMATCH'}`);
  updateHUD();
  scheduleEmojiFeedback(c,correct,fastBonus);
  if(!state.detailedFeedback){
    resultAdvanceTimer=setTimeout(advance,1450);
    return;
  }
  const riskNote=!correct&&action==='forward'&&expected.action==='quarantine'?'This may cause a problem later.':'';
  const sourceText=c.origin?.source_url?`<a href="${safe(c.origin.source_url)}" target="_blank" rel="noreferrer noopener">Adapted .eml sample ↗</a>`:(c.source?`<a href="${SOURCE[c.source].url}" target="_blank" rel="noreferrer noopener">${safe(SOURCE[c.source].short)} ↗</a>`:'');
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
  clearResultTimers();
  const priorDay=state.day;
  state.index++;state.seconds=0;state.chosen=null;
  hideModal();
  if(state.index>=CASES.length){finishGame();return;}
  const nextCase=CASES[state.index];
  if(nextCase.day!==priorDay){
    state.day=nextCase.day;
    const incidents=processIncidents(state.day);
    state.screen='break';renderCase();showShiftIntro(incidents,priorDay);
  }else{
    state.screen='play';renderCase();
  }
}
function showShiftIntro(incidents,completedDay=state.day-1){
  const d=DAYS[state.day-1];
  const newRules=SIMPLE_RULES.filter(r=>r.day===state.day);
  const results=state.completed.filter(c=>c.day===completedDay);
  const correct=results.filter(c=>c.correct).length;
  const summary=`<div class="shift-summary"><strong>SHIFT ${completedDay} COMPLETE</strong><span>${correct}/${results.length} correct</span><span>OPS ${state.operations}%</span><span>SEC ${state.security}%</span></div>`;
  const incidentHtml=incidents.length?`<div class="shift-brief"><h3>SECURITY ALERT</h3>${incidents.map(inc=>`<div class="incident">${safe(inc.message)}</div>`).join('')}</div>`:'';
  modal(`<p class="modal-kicker">SHIFT ${state.day} / 5</p>
    ${summary}
    <h2>NEW RULES</h2>
    ${incidentHtml}
    <div class="shift-focus">${newRules.map(x=>`<div class="focus-row"><span class="focus-action ${x.action}">${ACTION_ICON[x.action]} ${ACTION_SHORT[x.action]}</span><span>${safe(x.text)}</span></div>`).join('')}</div>
    ${feedbackOption()}
    <button class="modal-primary" id="next-shift-btn" type="button">START SHIFT →</button>`);
  bindFeedbackOption();
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
  modal(`<p class="modal-kicker">EVIDENCE BASE / DOCUMENTED TTPs</p><h2>SOURCES & TRAINING DATA</h2><p class="modal-copy">Cases are either invented or adapted from public samples. See SOURCES.md for details. Sender checks alone cannot prove an email is safe.</p><ul class="source-list">${list}</ul>
    <p class="disclaimer">Threat-actor identities from different reports are not treated as the same group. Some new cases are adapted from Phishing Pot emails; none are verbatim. All .example domains are reserved; simulated email links cannot be clicked.</p><button class="modal-primary" id="sources-close" type="button">◀ &nbsp; BACK TO GAME</button>`);
  $('sources-close').onclick=()=>{
    state.screen=prev;hideModal();updateHUD();
    if(prev==='intro')openIntro();
    else if(prev==='end')finishGameView();
    else if(prev==='feedback')restoreFeedback();
    else if(prev==='break')showShiftIntro([],state.day-1);
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
$('sources-button').addEventListener('click',()=>{if(state.screen!=='brief-feedback')showSources();});
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
