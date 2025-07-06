---
layout: default
title: 04: Endpoint Live Response Techniques
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
