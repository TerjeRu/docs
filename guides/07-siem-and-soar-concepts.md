---
layout: default
title: "07: SIEM and SOAR Concepts"
parent: The Guides
nav_order: 7
---

## Part 1: SIEM - The Brain of the SOC

**Goal:** To understand the core function of a SIEM as the central nervous system for all security data, enabling detection and investigation at scale.

### Key Concepts (The Theory)

- **SIEM (Security Information and Event Management):** A platform that provides a single pane of glass for all security-related data. Its job is to collect, normalize, and correlate logs from thousands of sources to find the signal in the noise.

### The SIEM Data Pipeline

1.  **Collection:** The SIEM uses "connectors" or "agents" to pull logs from every conceivable source: firewalls, servers (Windows Event Logs, Linux syslog), EDR agents, cloud services (AWS, Azure, Google Cloud), email gateways, and more.

2.  **Parsing and Normalization:** This is the most critical and difficult step. Every log source has a different format. A parser reads the raw log and extracts key fields into a standardized schema.

    - **Raw Firewall Log:** `timestamp=1672531200, src_ip=1.2.3.4, dst_ip=192.168.1.10, dst_port=445, action=blocked`
    - **Raw Windows Log:** `EventID: 4625, AccountName: administrator, SourceIP: 1.2.3.4, FailureReason: Bad Password`
    - **Normalized SIEM Event:**
      ```json
      {
        "event_time": "2023-01-01T00:00:00Z",
        "source_ip": "1.2.3.4",
        "destination_ip": "192.168.1.10",
        "destination_port": 445,
        "action": "blocked",
        "event_source": "PaloAltoFirewall",
        "user_name": null,
        "event_id": null
      }
      ```
    - **Analyst Tip:** Bad parsers are the bane of a SOC analyst's existence. If a parser fails to extract the `source_ip` correctly, none of your detection rules based on that field will work.

3.  **Enrichment:** Once normalized, the SIEM can add more context. It might automatically perform a GeoIP lookup on the `source_ip` to add a `source_country` field, or check the IP against a threat intelligence feed and add a `is_known_malicious` flag.

4.  **Correlation and Detection:** With all data in a standard format, the SIEM can run detection rules that correlate events from different sources over time.
    - **Simple Rule:** `event_source = 'PaloAltoFirewall' AND action = 'blocked'`
    - **Advanced Correlation Rule:** "Create a High Severity alert if we see an `Impossible Travel` alert from the Identity Provider for a user, AND within 10 minutes, we see a successful logon for that same user (EventID `4624`) from a new IP, AND that IP then generates 5 or more firewall blocks within the next 5 minutes." This rule combines three different data sources to create a very high-fidelity alert that is almost certainly a real incident.

---

## Part 2: SOAR - The Hands of the SOC

**Goal:** To understand how SOAR platforms automate and orchestrate responses, freeing up human analysts to focus on complex investigation.

### Key Concepts (The Theory)

- **SOAR (Security Orchestration, Automation, and Response):** A platform that connects to all your other security tools via APIs to execute actions and automate workflows. If a SIEM _finds_ the problem, a SOAR _fixes_ the problem.
- **Orchestration:** Getting different, unrelated tools to work together in a coordinated sequence.
- **Automation:** Performing a series of actions without human intervention.
- **Playbook:** A pre-defined, digital workflow that outlines the exact steps to take in response to a specific type of alert. It's a coded, automated version of a Standard Operating Procedure (SOP).

### A Detailed SOAR Playbook: "Phishing Triage"

Let's expand on the phishing example to see how orchestration works.

**Trigger:** An email is forwarded by a user to the `phishing@company.com` mailbox.

1.  **Step 1 (Ingestion):** The SOAR platform is connected to the mailbox. It automatically ingests the email and creates a new case/ticket.

2.  **Step 2 (Parsing & Extraction - Orchestration):** The SOAR calls its internal email parsing module to automatically extract key observables:

    - Sender's Address (`evil@badsite.com`)
    - Sender's IP (`4.3.2.1`)
    - Subject (`"Urgent Invoice Payment"`)
    - All URLs (`http://clickme.xyz/login.php`)
    - All attachment hashes (`d8e8fca2dc0f896fd7cb4cb0031ba249`)

3.  **Step 3 (Enrichment - Orchestration):** The SOAR automatically queries multiple external and internal tools via their APIs:

    - It sends the attachment hash `d8e8fca...` to the **VirusTotal API**.
    - It sends the URL `http://clickme.xyz/login.php` to the **VirusTotal API**.
    - It sends the sender's IP `4.3.2.1` to the **AbuseIPDB API**.
    - It queries the **SIEM API** to see if any other users have received emails from this sender in the last 24 hours.

4.  **Step 4 (Decision Point):** The playbook has logic built-in.

    - `IF` VirusTotal verdict for the hash or URL is `malicious` `OR` AbuseIPDB reputation is `> 80` `OR` the SIEM query returns `> 10` results...
    - `THEN` proceed to automatic remediation.
    - `ELSE` assign the case to a Tier 1 analyst for manual review.

5.  **Step 5 (Remediation - Orchestration):** The indicators were confirmed malicious. The SOAR now takes action:

    - It connects to the **Microsoft Defender API** and initiates a search-and-purge job to soft-delete the email from all user inboxes.
    - It connects to the **Palo Alto Firewall API** and adds the sender's IP `4.3.2.1` and the URL's domain `clickme.xyz` to a high-priority blocklist.
    - It connects to the **Jira API** and creates a new ticket for the networking team to monitor for any historical traffic to the blocked indicators.

6.  **Step 6 (Notification):** The SOAR sends a summary of the incident, including all findings and actions taken, to the SOC's Slack channel and closes its own case as "Remediated via Automation."

- **Analyst Tip:** This entire process might take 30 seconds of machine time, versus 15-20 minutes of manual work for an analyst. This is the power of SOAR. It handles the high-volume, low-complexity tasks, allowing humans to focus on the complex investigations that require critical thinking.
