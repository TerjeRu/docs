---
layout: default
title: 05: Adversary Tactics and Threat Intelligence
nav_order: 5
---

## Part 1: Operationalizing the MITRE ATT&CK® Framework

**Goal:** To move beyond defining ATT&CK and learn to use it as a practical tool for understanding threats and guiding investigations.

### Key Concepts (The Theory)

- **Tactics, Techniques, and Procedures (TTPs):** This is the core of threat intelligence.
  - **Tactics:** The adversary's high-level goal (e.g., `Initial Access`, `Execution`, `Persistence`).
  - **Techniques:** _How_ the adversary achieves the goal (e.g., `Phishing`, `Scheduled Task/Job`).
  - **Sub-techniques:** A more specific description of the technique (e.g., `Phishing: Spearphishing Attachment (T1566.001)`).
  - **Procedures:** The specific implementation of a technique by an adversary (e.g., using a specific PowerShell command to create a scheduled task that downloads a file).
- **Threat Groups:** ATT&CK also catalogs known adversary groups (e.g., `APT28`, `FIN7`) and maps the specific TTPs they are known to use. This allows you to move from "someone is using phishing" to "this activity matches the known procedures of APT28."

### Practical Exercises (Hands-On Labs)

1.  **Analyze a Threat Group's Playbook:**

    - Go to the **[MITRE ATT&CK Groups](https://attack.mitre.org/groups/)** page.
    - Find a well-known group, for example, **APT29** (also known as Cozy Bear). Click on their group page (`G0016`).
    - Scroll down to the "Techniques Used" table. This is their known playbook.
    - **Analyst Tip:** Look at their common `Initial Access` techniques. You'll see `Phishing (T1566)`. Now look at their `Command and Control` techniques. You'll see `Ingress Tool Transfer (T1105)`. This tells you a story: APT29 often gets in via phishing and then downloads additional tools to the compromised host. As an analyst, if you see phishing, you should immediately start hunting for signs of tool downloads.

2.  **Map Your Own Detections:**
    - Think back to the last guide (`04`). We discussed finding persistence via Scheduled Tasks.
    - Go to the main **[ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)**.
    - Find the **Persistence** column (Tactic `TA0003`).
    - Find the technique **Scheduled Task/Job (T1053)**. Click on it.
    - Read the description and the "Procedure Examples." You'll see real examples of how threat groups have used this technique. This is how you connect your own findings to the global threat landscape.

---

## Part 2: The Pyramid of Pain in Practice

**Goal:** To understand why some indicators are more valuable than others and how to "move up the pyramid" to create more durable defenses.

### Key Concepts (The Theory)

- **The Pyramid of Pain:** A model that shows how much "pain" you cause an adversary by denying them certain indicators. Blocking hashes is trivial for them to bypass; forcing them to change their core TTPs is very difficult.
- **Indicators of Compromise (IOCs) vs. Indicators of Attack (IOAs):**
  - **IOCs** are the artifacts of an attack (the "what"). They are the bottom of the pyramid: hashes, IPs, domains. They are reactive.
  - **IOAs** are the behaviors of an attack (the "how"). They are the top of the pyramid: tools and TTPs. Detecting an IOA means you're identifying the adversary's technique, regardless of the specific malware they use. This is proactive.

### A Practical Scenario: Moving Up the Pyramid

1.  **Trivial (Hashes):** You detect `malware.exe`. You block its SHA-256 hash. The next day, the attacker re-compiles it, changing the hash, and gets past your block.
2.  **Easy (IPs):** You see the new malware beaconing to `1.2.3.4`. You block the IP. The attacker spins up a new C2 server at `5.6.7.8`.
3.  **Simple (Domains):** You notice the malware gets its C2 address by looking up `evil-c2.com`. You block the domain. The attacker registers `new-evil-c2.com`.
4.  **Annoying (Host Artifacts):** You see the malware always creates a file at `C:\Users\Public\update.dat`. You create a rule to alert on any file creation at that specific path. The attacker now has to change their malware's code to use a different filename.
5.  **Challenging (Tools):** You realize the attacker is using a modified version of a common hacking tool like Mimikatz. You can create signatures to detect the _tool itself_, forcing the attacker to re-tool or write something custom.
6.  **Tough (TTPs):** You analyze the malware and see its core behavior is using PowerShell to inject shellcode into the memory of another process (e.g., `explorer.exe`). This is **Process Injection (T1055)**. You create a behavioral rule in your EDR to alert on _any_ instance of PowerShell allocating memory in another process and writing to it. Now, it doesn't matter what malware the attacker uses; if they use that _technique_, you will detect it. This causes the most pain.

---

## Part 3: Practical Threat Intelligence Enrichment

**Goal:** To take a single indicator and use various tools to build a complete picture of the threat.

### Practical Exercises (Hands-On Labs)

This is a multi-step hunt. Start with one indicator and pivot from there.

1.  **Get an Initial Indicator:**

    - Go to **[ThreatFox by abuse.ch](https://threatfox.abuse.ch/browse/)**. Find a recent malware sample and copy its **SHA-256 hash**.

2.  **Enrich with VirusTotal:**

    - Go to **[VirusTotal](https://www.virustotal.com/)** and search for the hash.
    - **Analyst Tip:** Look at the **"Details"** tab for file names it has been seen with. Look at the **"Behavior"** tab to see what network connections it made in a sandbox environment. Look at the **"Community"** tab for comments. These tabs often contain more value than the main detection ratio.

3.  **Pivot to Network Indicators:**

    - From the VirusTotal "Behavior" or "Details" tab, you will likely find an **IP address** or **Domain Name** the malware communicated with. Copy one.

4.  **Enrich the Network Indicator (Command Line):**
    - Now, use the tools on your Mac or Kali VM to dig deeper into the domain (e.g., `evil-c2.com`).
    - **`dig`:** Get all DNS records for the domain. The `ANY` flag asks for all record types.
      ```bash
      dig evil-c2.com ANY
      ```
    - **`whois`:** Find out who registered the domain.
      - `whois`: The command to perform a WHOIS lookup.
      ```bash
      whois evil-c2.com
      ```
    - **Analyst Tip:** In the `whois` output, look at the "Creation Date". Was the domain registered yesterday? This is a huge red flag. Also look at the "Registrar" and "Registrant Email". You can sometimes pivot on this information to find other malicious domains registered by the same person or organization. This is a core OSINT technique.
