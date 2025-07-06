---
layout: default
title: "08: Analyst Toolkit and Resource"
parent: The Guides
nav_order: 8
---

### A Curated List for Continuous Learning

This guide is a living document of high-quality, professional resources. The world of cybersecurity moves fast; continuous learning isn't just recommended, it's required. This list avoids beginner-level content and focuses on the tools and knowledge bases used by professional analysts.

---

## Part 1: Essential Online Analysis Tools

These are the browser-based tools you will use daily to triage and enrich indicators.

- **[VirusTotal](https://www.virustotal.com/)**: The indispensable tool for checking files, hashes, URLs, domains, and IPs against dozens of antivirus engines and blocklists. **Use Case:** Your first stop for enriching any technical indicator. Pay attention to the "Details," "Behavior," and "Community" tabs.
- **[URLScan.io](https://urlscan.io/)**: A sandbox for URLs. It provides a detailed report of what happens when a URL is visited, including the IPs it contacts, the domains it requests, and a screenshot of the page. **Use Case:** Safely investigating a suspicious link to see its redirect chain and the resources it loads.
- **[Shodan](https://www.shodan.io/)**: A search engine for internet-connected devices. Instead of web content, it indexes service banners. **Use Case:** Finding exposed RDP ports, unpatched web servers, or identifying the C2 infrastructure of an adversary by searching for unique server headers or SSL certificates.
- **[AbuseIPDB](https://www.abuseipdb.com/)**: A database of IP addresses that have been reported for malicious activity. **Use Case:** Quickly checking the reputation of an IP address seen in your logs.
- **[ThreatFox by abuse.ch](https://threatfox.abuse.ch/browse/)**: A community-driven feed of Indicators of Compromise (IOCs) associated with malware. **Use Case:** Finding fresh, real-world malware samples (hashes, URLs) for analysis and hunting.

---

## Part 2: Hands-On Practice & Skill Development

Theory is one thing; hands-on keyboard is another. These platforms are where you build real muscle memory.

- **[Blue Team Labs Online (BTLO)](https://blueteamlabs.online/)**: A platform focused exclusively on defensive security. It provides labs based on realistic scenarios where you investigate incidents using a provided set of tools (like a SIEM and EDR). **Focus:** Defensive investigations, log analysis, digital forensics.
- **[Hack The Box](https://www.hackthebox.com/)** & **[TryHackMe](https://tryhackme.com/)**: While known for offensive training, their real value is in understanding attack paths. By learning how systems are compromised, you learn what artifacts to look for. **Focus:** Start with their introductory blue team/defensive security "paths" or "rooms."
- **[CyberDefenders](https://cyberdefenders.org/)**: Similar to BTLO, this platform offers excellent blue team challenges, often providing PCAP, memory dump, and log files from a simulated incident for you to analyze. **Focus:** Deeper forensic analysis challenges.
- **[LetsDefend](https://letsdefend.io/)**: Provides a simulated SOC environment where you can work through alerts, write incident reports, and practice the day-to-day workflow of a Tier 1 analyst. **Focus:** SOC workflow simulation.

---

## Part 3: Core Knowledge & Learning Resources

Deeper learning resources for foundational topics.

- **MITRE ATT&CK® Resources:**
  - **[ATT&CK Website](https://attack.mitre.org/)**: The primary source. Use it constantly to map TTPs.
  - **[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)**: A tool to visualize and explore the ATT&CK matrix. Use it to compare threat groups or map your own defensive coverage.
  - **[MITRE Engenuity Evaluations](https://attackevals.mitre-engenuity.org/)**: See how different EDR vendors perform in detecting the TTPs of specific adversary groups. Invaluable for understanding how EDRs _really_ work.
- **Networking & Packet Analysis:**
  - **[Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)**: A massive repository of sample `.pcap` files, from normal traffic to captures of malware C2, network scans, and various attacks. Essential for hands-on practice.
  - **[PacketTotal](https://packettotal.com/)**: An online PCAP analyzer. Upload a packet capture, and it will automatically identify suspicious streams and enrich indicators.
  - **[BPF Filter Guide](https://www.tcpdump.org/manpages/pcap-filter.7.html)**: The official man page for Berkeley Packet Filter syntax. This is the definitive, technical guide for writing filters for `tcpdump`. It's dense but essential reference material.
- **Command Line & Scripting:**
  - **[The Linux Command Line (Free Book)](https://linuxcommand.org/tlcl.php)**: A comprehensive and highly-regarded book on the Linux shell, available for free. Perfect for going from basics to advanced scripting.
  - **[Microsoft PowerShell 101](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/00-introduction?view=powershell-7.4)**: Microsoft's official introduction to the concepts and syntax of PowerShell.
  - **[Apple Terminal User Guide](https://support.apple.com/guide/terminal/welcome/mac)**: The official guide from Apple for using the Terminal in macOS.
  - **[Explainshell](https://explainshell.com/)**: Paste in a complex shell command, and it will break down every single component and flag for you. Invaluable for deconstructing cryptic commands you find online.

---

## Part 4: High-Signal Threat Intelligence & News

Staying current is critical. These are professional-grade sources, not just headlines.

- **Government & Agency Alerts:**
  - **[CISA Advisories (US)](https://www.cisa.gov/news-events/cybersecurity-advisories)**: Authoritative alerts on active threats and vulnerabilities targeting US infrastructure, but relevant globally.
  - **[NCSC (UK)](https://www.ncsc.gov.uk/)**: The UK's National Cyber Security Centre provides excellent guidance and reports.
- **Key Vendor Blogs:** These companies are on the front lines of incident response. Their blogs are a primary source of new TTPs and threat group analysis.
  - **[Mandiant Blog](https://www.mandiant.com/resources/blog)**
  - **[CrowdStrike Blog](https://www.crowdstrike.com/blog/)**
  - **[Red Canary Blog](https://redcanary.com/blog/)**
- **Curated Newsletters:** Let others do the filtering for you.
  - **[SANS NewsBites](https://www.sans.org/newsletters/newsbites/)**: A semi-weekly summary of the most important headlines.
  - **[Risky Business](https://risky.biz/)**: A weekly podcast and newsletter that provides sharp, insightful analysis of the week's security news.

---

## Part 5: Essential Cheat Sheets & Reference

Quick references to keep bookmarked.

- **[SANS Institute Posters](https://www.sans.org/posters/)**: A huge collection of high-quality posters on forensics, SIEM, hacking techniques, and more. The "SIFT Workstation" and "REMnux" posters are classics.
- **[LOLBAS (Living Off The Land Binaries and Scripts)](https://lolbas-project.github.io/)**: A dictionary of every legitimate Microsoft binary, script, and library that can be abused by an attacker. **Use Case:** You see a strange command using `certutil.exe`. Check LOLBAS to see how attackers abuse it.
- **[GTFOBins](https://gtfobins.github.io/)**: The Linux equivalent of LOLBAS. A curated list of Unix binaries that can be used to bypass local security restrictions.
- **Query Language Cheat Sheets:**
  - **[KQL Cheat Sheet (Microsoft)](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)**
  - **[Splunk Search Language Cheat Sheet](https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf)**
