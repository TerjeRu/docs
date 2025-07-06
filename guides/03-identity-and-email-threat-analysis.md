---
layout: default
title: 03: Identity and Email Threat Analysis
parent: The Guides
nav_order: 3
permalink: /guides/03-identity-and-email-threat-analysis/
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

### `guides/04-endpoint-live-response-techniques.md`

````markdown
---
layout: default
title: 04: Endpoint Live Response Techniques
parent: The Guides
nav_order: 4
---

## Part 1: Process and Service Analysis

**Goal:** To move beyond simply listing processes and learn to analyze their relationships and behaviors to spot anomalies. This is the core of endpoint investigation.

### Key Concepts (The Theory)

- **Process Discovery (T1057):** This is the ATT&CK technique for identifying and listing running processes. A key part of this is understanding **parent-child process relationships**. Legitimate processes have predictable parents. For example, when you open Command Prompt, `explorer.exe` is the parent of `cmd.exe`. If you see `WINWORD.EXE` spawning `powershell.exe`, that is highly suspicious and a classic sign of a malicious macro.
- **Process Masquerading (T1036.005):** Attackers often name their malware after legitimate system processes to blend in. The most common example is naming malware `svchost.exe`. The key to detection is checking the process _path_. The real `svchost.exe` only runs from `C:\Windows\System32`. If you see it running from `C:\Users\Terje\AppData\Local\Temp\`, it's malware.

### Practical Exercises (Hands-On Labs)

#### **On Windows**

1.  **Using PowerShell (Advanced):** PowerShell gives you far more detail than Task Manager. The `Get-Process` cmdlet is your primary tool.
    - This command gets all processes and selects specific, useful properties to display in a table.
      ```powershell
      Get-Process | Select-Object Name, Id, Path, Company | Format-Table -AutoSize
      ```
    - **Analyst Tip:** To investigate parent-process relationships, you need a more powerful query. This command shows every process, its ID, and its parent's ID. You can then investigate the parent to see if the relationship is legitimate.
      ```powershell
      Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, CommandLine | Format-Table -AutoSize
      ```

#### **On Mac/Linux**

1.  **Using `ps` (Advanced):** The `ps` command is standard, but its flags unlock its true power.
    - This command provides a "forest" view, showing the parent-child hierarchy explicitly.
      - `-e`: Selects every process.
      - `-f`: Does a "full-format" listing.
      - `-H`: Shows the process hierarchy (forest).
      ```bash
      ps -efH
      ```
    - **Analyst Tip:** Since the output can be huge, pipe it to `less` to make it scrollable (`ps -efH | less`). Inside `less`, you can use `/` to search for a specific process name. This is a fundamental workflow for Linux/Mac analysts.

---

## Part 2: Correlating Processes to Network Activity

**Goal:** To connect a specific network connection back to the exact process that initiated it. This is how you identify which program is responsible for suspicious traffic.

### Key Concepts (The Theory)

- **System Network Connections Discovery (T1049):** This is the ATT&CK technique for identifying network connections to, from, and through a system. The goal is to find connections to malicious IPs or unusual ports and attribute them to a process.

### Practical Exercises (Hands-On Labs)

#### **On Windows**

1.  **Using PowerShell:** While `netstat -ano` is good, PowerShell can provide richer, object-based output.
    - The `Get-NetTCPConnection` cmdlet shows all TCP connections. We then select key properties.
      ```powershell
      Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Format-Table -AutoSize
      ```
    - **Analyst Tip:** This is where you combine skills. If you find a suspicious connection from PID `1234`, you can immediately pivot to find out what that process is: `Get-Process -Id 1234 | Select-Object *`. This workflow—from network to process—is repeated constantly during an investigation.

#### **On Mac/Linux**

1.  **Using `lsof` (Advanced):** We used `lsof -i` before. Now let's refine it.
    - This command shows only established TCP connections, filtering out listening ports and other noise.
      - `-i TCP`: Specifies to look only at TCP internet files.
      - `-sTCP:ESTABLISHED`: Filters for the TCP state "ESTABLISHED".
      - `-n`: No DNS resolution (faster).
      - `-P`: No port name resolution (shows `53` instead of `domain`).
      ```bash
      sudo lsof -i TCP -sTCP:ESTABLISHED -n -P
      ```
    - **Analyst Tip:** If you suspect a specific process, like `suspicious_app`, is making a connection, you can filter directly for it: `sudo lsof -i -n -P -c suspicious_app`. The `-c` flag filters by command name.

---

## Part 3: Hunting for Persistence Mechanisms

**Goal:** To find where malware hides to ensure it automatically runs again after a reboot.

### Key Concepts (The Theory)

- **Boot or Logon Autostart Execution (T1547):** This is a broad ATT&CK tactic for persistence. Malware needs to survive a restart, so it places itself in locations the OS automatically executes on boot. Common locations include registry "Run" keys, startup folders, and scheduled tasks.

### Practical Exercises (Hands-On Labs)

#### **On Windows**

1.  **Using Autoruns (GUI):** The Sysinternals tool **[Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)** is the gold standard. It shows _every_ possible auto-start location. When you run it, go to **Options -> Scan Options** and enable "Verify Code Signatures" and "Check VirusTotal.com". Unsigned executables or those with high VirusTotal scores are immediately suspicious.
2.  **Using PowerShell (CLI):** You can query the most common registry run keys directly.

    ```powershell
    # For the current user
    Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

    # For all users on the machine
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    ```

#### **On Mac/Linux**

1.  **macOS - LaunchAgents/Daemons:** The primary persistence locations on a Mac are the `LaunchAgents` and `LaunchDaemons` folders. Attackers place `.plist` files here to define what program to run.
    - **Analyst Tip:** You can list the contents of all three main locations with one command. Look for recently created files or files with suspicious names.
      ```bash
      ls -l ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
      ```
2.  **Linux - Cron Jobs & Systemd:**
    - Check the user's scheduled tasks with `crontab -l`.
    - For system-wide services, investigate `systemd` unit files, typically in `/etc/systemd/system/`.
    - **Analyst Tip:** A common persistence trick on Linux is to add a malicious command to a user's shell startup script (e.g., `~/.bashrc`, `~/.zshrc`). Check these files for any strange or obfuscated lines.
````
