---
layout: default
title: 01: Cybersecurity Foundations
nav_order: 1
---

## Part 1: Network Analysis Fundamentals

**Goal:** To understand how to identify a system's network identity and inspect its communications, a core task in any investigation.

### Key Concepts (The Theory)

- **IP Addresses & Ports:** An IP address is a system's unique identifier on a network. A port is a logical endpoint for a specific service on that system. The combination, like `192.168.1.10:443`, is called a **socket**. Analysts scrutinize these sockets to understand what services are running and what connections are being made. Common ports to know are `80` (HTTP), `443` (HTTPS), `22` (SSH), and `3389` (RDP). Attackers often use non-standard ports to evade simple firewalls.

- **TCP vs. UDP:** These are two core data transport protocols.

  - **TCP (Transmission Control Protocol)** is stateful and reliable. It establishes a connection with a **"three-way handshake"** (Client sends SYN -> Server sends SYN/ACK -> Client sends ACK). Seeing this handshake in packet captures confirms a connection was established. It's used for services that require data integrity, like loading a webpage.
  - **UDP (User Datagram Protocol)** is stateless and connectionless. It's a "fire-and-forget" protocol that is faster but offers no delivery confirmation. It's used for services like DNS lookups or live streaming. Some malware favors it for C2 traffic due to its low overhead.

- **DNS (Domain Name System):** DNS translates human-readable domain names (e.g., `google.com`) into machine-readable IP addresses (e.g., `142.250.184.164`). For an analyst, DNS logs are a primary source of threat intelligence. Investigating DNS queries can reveal connections to malicious domains, phishing sites, and algorithmically generated C2 infrastructure.

### Practical Exercises (Hands-On Labs)

1.  **Find Your Network Identity**

    - **On Windows:**
      1.  Open **Command Prompt** (CMD).
      2.  Type `ipconfig /all` and press Enter. The `/all` flag displays the full TCP/IP configuration for all adapters, including your MAC address and the DNS servers you're using.
    - **On Mac/Linux:**
      1.  Open the **Terminal**.
      2.  Type `ip addr` (on Linux) or `ifconfig` (on macOS).

2.  **Inspect Active Connections**

    - This is a critical first step in "live response" to see who your computer is talking to.
    - **On Windows:** In CMD, run `netstat -ano`.

      - `-a`: Displays all active connections and listening ports.
      - `-n`: Displays addresses and port numbers in numerical form (which is faster because it avoids name lookups).
      - `-o`: Displays the owning process ID (PID) associated with each connection.

      ```bash
      netstat -ano
      ```

      - **Analyst Tip:** To find what's listening for connections, run `netstat -ano | findstr /i "LISTENING"`. This helps you spot potentially unauthorized services.

    - **On your Mac/Linux:** In the Terminal, `lsof -i` is powerful. The `-i` flag lists open files that are using the internet.
      ```bash
      lsof -i
      ```
      - **Analyst Tip:** To find processes listening on a specific port (e.g., 443), use `lsof -i :443`. The colon before the port number specifies a listening port. This is great for finding out what application is using a standard port.

3.  **Query the Internet's Phonebook (DNS)**
    - `dig` (Domain Information Groper) is the professional's tool for DNS investigation.
    - Use `dig` to look up a domain's A (address) record.
      ```bash
      dig [www.google.com](https://www.google.com)
      ```
    - Use it to find mail servers (MX records), which is useful when investigating phishing.
      ```bash
      dig google.com MX
      ```
      - **Analyst Tip:** To see what an external DNS server thinks, specify the server in the command: `dig @8.8.8.8 www.google.com`. The `@` symbol tells `dig` which DNS server to query directly. This helps determine if a DNS issue is local or global.

---

## Part 2: Understanding the Threat Landscape

**Goal:** To categorize common cyber threats and the fundamental concepts used to secure data.

### Key Concepts (The Theory)

- **Malware (Malicious Software):** A broad term for software designed to perform malicious actions.
  - **Viruses:** Modify legitimate files. Look for file integrity changes.
  - **Worms:** Self-propagate across the network. Look for signs of lateral movement.
  - **Trojans:** Disguise as legitimate software. A common technique is to drop a script that gets executed by a legitimate interpreter. This is a form of **Execution (TA0002)**, often using **Command and Scripting Interpreter (T1059)**.
  - **Ransomware:** Encrypts files. Look for mass file modification and ransom notes.
- **Phishing & Social Engineering:** The manipulation of human psychology. Phishing is a primary **delivery** vector for malware and for stealing credentials, falling under the **Initial Access (TA0001)** tactic.
- **Encryption & Hashing:**
  - **Encryption:** A reversible process using a key to protect **confidentiality**.
  - **Hashing:** A one-way, non-reversible process that creates a unique fingerprint to verify data **integrity**. Analysts use hashes (MD5, SHA-256) as Indicators of Compromise (IOCs) to hunt for known-bad files.

### Practical Exercises (Hands-On Labs)

1.  **Analyze a Phishing Email**

    - Browse submissions on a site like [PhishTank](https://phishtank.org/).
    - **Analyst Tip:** Look beyond the obvious. In a real investigation, you'd analyze the email's raw source to see the `Received:` headers. These headers trace the path the email took across mail servers and can reveal the true origin, bypassing a forged "From" address.

2.  **Generate File Hashes Manually**
    - Generating hashes is a core skill for verifying file integrity and searching for known-bad malware.
    - Create a simple text file named `test.txt`.
    - **On your Mac/Linux:**
      - The `-a 256` flag specifies the hashing algorithm to use (in this case, SHA-256).
      ```bash
      shasum -a 256 test.txt
      ```
    - **On Windows:**
      - `certutil` is a powerful command-line utility. The `-hashfile` argument tells it to compute the hash of a file, and `SHA256` specifies the algorithm.
      ```bash
      certutil -hashfile test.txt SHA256
      ```
      - **Analyst Tip:** Once you have a hash, you can search for it in your SIEM or EDR to see if that file exists anywhere else in your environment. You would also pivot to a threat intelligence platform like VirusTotal to see if the hash is associated with known malware.

---

## Part 3: The Defender's Mindset

**Goal:** To understand the structure of a modern security team and the core models for detection and response.

### Key Concepts (The Theory)

- **SOC (Security Operations Center):** The central function for monitoring, detection, and response.
- **SIEM (Security Information and Event Management):** The core log aggregation and correlation platform of a SOC.
- **EDR (Endpoint Detection and Response):** Provides deep visibility into endpoint activity (process execution, file changes, network connections).
- **The Cyber Kill Chain vs. MITRE ATT&CK:**
  - The **Kill Chain** is a high-level, linear model of the stages of an attack (Recon ->...-> Actions). It's good for understanding the overall flow.
  - **MITRE ATT&CK®** is a detailed knowledge base of the specific _how_—the tactics, techniques, and procedures (TTPs) adversaries use at each stage. An analyst uses ATT&CK to identify specific behaviors.

### Practical Exercises (Hands-On Labs)

1.  **Explore Public Threat Intelligence Feeds**

    - Visit a resource like the **[abuse.ch ThreatFox](https://threatfox.abuse.ch/browse/)**. This site lists IOCs (hashes, IPs, URLs) recently associated with malware. This is the type of raw data that fuels security tools.

2.  **Think Like an Analyst (A Thought Experiment)**
    - **Scenario:** An EDR alert fires: `powershell.exe` on a user's machine made a network connection to an IP address in a foreign country.
    - **Your thought process (moving towards a structured investigation):**
      1.  **Observe (Gather Facts):** What is the exact command line for `powershell.exe`? What is the parent process (what launched PowerShell)? What is the user account? What is the destination IP and port? What is the timestamp?
      2.  **Orient (Add Context):** Is the user a developer who might legitimately use PowerShell? Is the destination IP a known-malicious address (check VirusTotal)? Is the PowerShell command obfuscated or encoded (e.g., using Base64)? Is it fileless (e.g., `powershell.exe -enc ...`), running only in memory to evade detection? This is a key question for an analyst.
      3.  **Decide & Act (Formulate a Plan):** Based on the context, what is your initial hypothesis? If context strongly suggests malicious activity (e.g., parent process is `WINWORD.EXE`, command is encoded, IP is known-bad), the immediate action is containment: isolate the host from the network via the EDR console to prevent lateral movement. Then, continue the investigation.
