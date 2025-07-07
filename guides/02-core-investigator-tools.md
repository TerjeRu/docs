---
layout: default
title: "02: Core Investigator Tools"
parent: The Guides
nav_order: 2
---

## Part 1: Network Traffic Analysis

**Goal:** To move beyond `netstat` and learn how to capture and inspect the raw data of your network traffic, a fundamental skill for detecting threats that don't leave traces on disk.

### Key Concepts (The Theory)

- **Packet Capture (PCAP):** The act of recording all data packets crossing a network interface. This is analogous to wiretapping your own connection and is essential for deep forensic analysis. This falls under the **Collection (TA0009)** tactic in MITRE ATT&CK.
- **Wireshark:** The industry-standard GUI tool for analyzing PCAP files. It decodes hundreds of protocols and allows for powerful filtering and analysis.
- **tcpdump:** The command-line equivalent of Wireshark. It is lightweight, powerful, and available on virtually every Linux, BSD, and macOS system. It's the go-to tool for capturing traffic on servers or remote systems.
- **Berkeley Packet Filter (BPF) Syntax:** The filtering language used by `tcpdump` and other tools. It allows you to specify exactly what traffic you want to capture (e.g., `host 1.1.1.1 and port 443`).

### Practical Exercises (Hands-On Labs)

1.  **Capture Traffic with `tcpdump` (Mac/Linux)**

    - Open your Terminal. The following command captures traffic and writes it to a file.
      - `sudo`: Required to access network interfaces.
      - `-i en0`: Specifies the interface to listen on (e.g., `en0` for Wi-Fi on Mac, `eth0` for wired on Linux). Use `ifconfig` or `ip addr` to find yours.
      - `-w capture.pcap`: Writes the output to a file named `capture.pcap`.
    - Run the command, then browse a few websites, then stop it with `Ctrl+C`.
      ```bash
      sudo tcpdump -i en0 -w capture.pcap
      ```

2.  **Analyze the Capture with Wireshark**
    - Install **[Wireshark](https://www.wireshark.org/download.html)** on your Mac or Windows machine.
    - Open the `capture.pcap` file you created.
    - In the "Apply a display filter" bar, type `http` and press Enter. This shows only unencrypted web traffic. Find a `GET` request, right-click, and choose **Follow > TCP Stream** to reassemble and view the conversation.
    - **Analyst Tip:** Learn a few key Wireshark filters. `dns.qry.name contains "badsite"` helps you hunt for requests to a specific domain. `ip.addr == 8.8.8.8` shows all traffic to and from a specific IP. `tcp.flags.syn == 1 and tcp.flags.ack == 0` will show you only the initial SYN packets of TCP handshakes, useful for spotting network scanning.

---

## Part 2: Web and URL Analysis

**Goal:** To learn how to safely dissect websites and URLs to identify phishing and drive-by-download threats.

### Key Concepts (The Theory)

- **Browser Developer Tools:** Built-in tools (usually F12) that are essential for analysis. The "Network" tab shows every request a page makes, the "Console" shows errors, and "Application" shows cookies and storage.
- **URL Analysis:** The skill of dissecting a URL to spot deception. Attackers use subdomains, URL shorteners, and file extensions to trick users.
- **Online Sandboxing:** Using a secure, remote service to analyze a suspicious file or URL. This prevents you from infecting your own machine.

### Practical Exercises (Hands-On Labs)

1.  **Inspect a Website with Developer Tools**

    - Go to a major news website. Open Developer Tools (F12 or `Cmd+Opt+I`) and click the **Network** tab.
    - Refresh the page and watch the requests fly by. Sort by "Domain" to see how many third-party trackers and ad networks are being contacted.
    - **Analyst Tip:** Click on the "Console" tab. Errors here can sometimes indicate broken scripts or failed connections that might be of interest. In the "Application" tab, look at "Cookies" to see how the site is tracking your session.

2.  **Analyze a URL from the Command Line (Mac/Linux)**

    - `curl` is a powerful tool for interacting with URLs without a browser.
    - Use the `-I` flag to fetch only the HTTP headers of a site. This shows you the server type, redirects, and cookies without rendering any content.
      ```bash
      curl -I https://www.google.com
      ```
    - **Analyst Tip:** Use `curl -L` to follow redirects. A site might use multiple redirects to hide its final malicious destination. `curl -I -L <suspicious_url>` will show you the entire redirect chain.

3.  **Use an Online Sandbox**
    - Go to **[VirusTotal](https://www.virustotal.com/)**.
    - Find a suspicious link from a site like **[PhishTank](https://phishtank.org/)**.
    - On VirusTotal, use the **URL** tab to paste the link and see the results.
    - **Analyst Tip:** Don't just look at the "Detection" score. Click on the **"Details"** tab to see the final URL after redirects and the **"Community"** tab to see if other researchers have left comments about the threat. This is a core part of the "enrichment" process. This entire process is a key part of investigating **Phishing (T1566)**.

---

## Part 3: Basic Log Analysis

**Goal:** To learn where to find the most critical logs on different operating systems and how to begin filtering them.

### Key Concepts (The Theory)

- **Log Files:** Timestamped records of events. For an analyst, logs are the digital breadcrumbs needed to reconstruct an attacker's actions.
- **Correlation:** The real power of log analysis comes from correlating events across different sources. Seeing a firewall block an IP at the same time an EDR tool sees a process trying to contact that IP is a strong indicator of compromise.

### Practical Exercises (Hands-On Labs)

1.  **Explore System Logs**

    - **On Windows:**

      - Open **Event Viewer**. The three most important logs are:
        - **Security:** Contains logon events, account management, etc. (requires admin rights).
        - **System:** Contains events logged by system components.
        - **Application:** Contains events logged by software.
      - **Analyst Tip:** In the Security log, filter for Event ID `4624` (Successful Logon) and `4625` (Failed Logon). A storm of 4625s followed by a 4624 from the same IP is a classic sign of a successful **Brute Force (T1110)** attack.

    - **On your Mac:**

      - The `log` command is the modern way to query the Unified Log system.
      - This command shows all log entries from the `sshd` process in the last hour.
        - `show`: The action to perform.
        - `--predicate`: The filter to apply.
        - `--last`: The time window.

      ```bash
      log show --predicate 'process == "sshd"' --last 1h
      ```

    - **On your Linux VM (Kali/Arch):**

      - Key logs are in `/var/log/`. `auth.log` (Debian/Ubuntu) or `secure` (CentOS/RHEL) tracks authentication. `syslog` is a general-purpose log.
      - Use `grep` to filter these files for keywords like "failed" or "session opened".

      ```bash
      grep -i "failed password" /var/log/auth.log
      ```
