---
layout: default
title: "03: Identity and Email Threat Analysis"
parent: The Guides
nav_order: 3
---

## Part 1: Identity Threat Detection

**Goal:** To understand how modern security platforms detect compromised user accounts by analyzing behavioral signals, a core component of any Identity and Access Management (IAM) security program.

### Key Concepts (The Theory)

- **Identity as a Security Boundary:** In a cloud-first world, a user's identity (their username and password/credentials) is the new perimeter. Protecting it is paramount.
- **Risk Detections:** Security platforms don't just wait for a password to be proven bad. They continuously analyze user activity and generate "risk detections" based on suspicious signals. These are indicators that an account may be compromised.
- **Common High-Risk Signals:**
  - **Leaked Credentials:** The platform's threat intelligence detects that the user's corporate credentials have been found on the dark web or in a public data breach dump. This immediately flags the account because the password is known to be compromised. This is a primary enabler for the **Valid Accounts (T1078)** technique.
  - **Impossible Travel:** A user logs in from Spain, and five minutes later, a login for the same account occurs from Russia. This is physically impossible, indicating one of the logins is fraudulent. This is a classic detection for **Valid Accounts: Stolen Credentials**.
  - **Anonymous IP Address:** The login originates from an anonymizer service like Tor or a known malicious VPN exit node. Attackers use these to hide their true location (**Proxy: T1090.003**).
  - **Malicious IP Address:** The login comes from an IP address with a bad reputation, such as a known botnet command-and-control (C2) server.

### Practical Application (The Hunt)

- **The Security Portal:** In a tool like Microsoft Defender for Identity, these risk detections are aggregated into a "User Risk Level" (Low, Medium, High). An automated policy might trigger on "High" risk, forcing an immediate password reset or blocking the account (**Mitigation: M1035**).
- **Investigating a Risky User:**

  1.  An alert fires for "High User Risk" for `ciso@yourcompany.com`.
  2.  You open the user's profile in the portal. You see three recent risk detections: `Leaked Credentials`, `Login from unfamiliar location`, and `Anomalous token`.
  3.  The `Anomalous token` detection is most critical, as it might indicate a stolen session cookie.
  4.  **Action:** You would trigger a "Confirm User Compromised" action in the portal. This forces a logout on all active sessions, requires the user to perform MFA, and forces a password reset, effectively locking the attacker out.

- **Analyst Tip:** The "Impossible Travel" alert is high-fidelity, but always consider legitimate exceptions. A user might log in from their desktop in the office and then immediately have their phone's email client check in from a different location via a mobile network. Context is key. Always check the device type and application associated with the logins.

---

## Part 2: Threat Hunting: Email Analysis

**Goal:** To understand the process and tools used to hunt for and remove malicious emails across an entire organization.

### Key Concepts (The Theory)

- **Email Security Gateway (ESG):** A tool that filters incoming and outgoing email for spam, phishing, and malware before it reaches the user's mailbox.
- **Threat Hunting Query Interface:** Most modern security platforms (EDR, SIEM, ESG) provide a powerful interface to search through massive datasets of security events. In the Microsoft ecosystem, this is often called "Advanced Hunting" and uses the Kusto Query Language (KQL).
- **Remediation Actions:** When a malicious email is found, an analyst can take several actions:
  - **Soft Delete:** Moves the email to the user's "Recoverable Items" folder. This gets it out of the inbox but allows for easy recovery if it was a false positive. This is the most common action.
  - **Hard Delete:** Permanently deletes the email. Used when you are 100% certain it's malicious.
  - **Block Sender/Domain:** Adds the sender or their domain to a blocklist to prevent future emails.

### Practical Application (The Hunt)

1.  **The Indicator:** A user reports a suspicious email with the subject "Urgent Action Required on Your Account." This subject line becomes your initial indicator.
2.  **The Hunt with KQL:** You go to the Advanced Hunting portal in Microsoft Defender. You need to search all email events for that subject line.
    - `EmailEvents`: This is the table containing all metadata about processed emails.
    - `| where Subject contains "Urgent Action"`: This is the filter. `contains` is a case-insensitive search for the substring.
    - `| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject`: This selects the specific columns you want to see in the results.
    ```kql
    EmailEvents
    | where Subject contains "Urgent Action"
    | project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject
    ```
3.  **Review and Remediate:** The query returns a list of 25 users who received the email. You review the sender address and other details to confirm they are all part of the same phishing campaign (**Phishing: T1566**). You select all 25 emails in the results and trigger a "Soft Delete" remediation action.
4.  **Investigate Further:** The hunt isn't over. The next step is to investigate if anyone _clicked_ the link in the email. You would pivot to a new query.

    - **Analyst Tip:** A more advanced KQL query could join email events with device events to find users who both received the email _and_ had a network connection to the malicious domain shortly after. This is the power of a correlated data platform.

    ```kql
    EmailEvents
    | where Subject contains "Urgent Action"
    // In a real query, you'd extract the URL and join with DeviceNetworkEvents
    // This is a conceptual example of the next step.

    ```
