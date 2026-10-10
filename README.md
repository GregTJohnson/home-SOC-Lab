# Home SOC Lab: Wazuh SIEM + Sysmon on Apple Silicon

This is a small, self-contained SOC lab built to practice the day-to-day work of a Tier 1/Tier 2 analyst: collecting endpoint telemetry, reading alerts, triaging them, and documenting what I find.

## Goals

- Set up a working SIEM and a monitored Windows endpoint
- Collect detailed process telemetry with Sysmon
- Generate test activity and confirm it is detected (or find out where it is not)
- Triage alerts the way an analyst would, and write the reasoning. 

## Architecture

```
+-----------------------------------------------------------+
|  Apple Silicon Mac mini (16 GB RAM) running UTM            |
|  Shared network: 192.168.64.0/24                           |
|                                                            |
|  +---------------------+        +-----------------------+  |
|  | win-victim01        |  logs  | wazuh-server          |  |
|  | Windows 11 ARM64    +------->+ Ubuntu Server 24.04   |  |
|  | Wazuh agent         |        | Wazuh manager,        |  |
|  | Sysmon              |        | indexer, dashboard    |  |
|  | 192.168.64.x        |        | 192.168.64.2          |  |
|  +---------------------+        +-----------+-----------+  |
|                                             |              |
+---------------------------------------------|--------------+
                                              v
                               Wazuh dashboard (https://192.168.64.2)
                               viewed from the host browser
```

> TODO: replace this ASCII sketch with a draw.io diagram and save it as `architecture-diagram.png`.

## Components

| Component | Details |
|---|---|
| Host | Apple Silicon Mac mini, 16 GB RAM |
| Hypervisor | UTM (Apple Virtualization), Shared Network mode |
| SIEM | Wazuh 4.x all-in-one install on Ubuntu Server 24.04 LTS (ARM64), 5 GB RAM, 2 cores, 40 GB disk |
| Endpoint | Windows 11 ARM64 (build 26100), 4 GB RAM, 2 cores, 64 GB disk, ISO built with CrystalFetch |
| Endpoint telemetry | Wazuh agent + Sysmon v15.22 (`Sysmon64a.exe`, the ARM64 build) with the SwiftOnSecurity config |

## Setup summary

1. Created the Wazuh VM in UTM and installed Ubuntu Server 24.04 ARM64 
2. Installed Wazuh with the official all in one installer and confirmed the dashboard at `https://192.168.64.2`.
3. Built a Windows 11 ARM64 ISO with CrystalFetch and installed Windows in a second VM using a local account.
4. Deployed the Wazuh agent from the dashboard's "Deploy new agent" and confirmed it showed **Active**.
5. Installed Sysmon with the SwiftOnSecurity configuration.
6. Added a `<localfile>` block to the agent's `ossec.conf` so it collects the `Microsoft-Windows-Sysmon/Operational` event channel, then restarted the agent.
7. Generated a test activity and confirmed it in the dashboard.
8. Built three visualizations and combined them into one dashboard.

## Screenshots

| | |
|---|---|
| Agent active | `screenshots/01-agent-active.png` |
| Rule 92027 alert detail | `screenshots/02-rule-92027-alert.png` |
| Threat Hunting overview | `screenshots/03-threat-hunting-overview.png` |
| Dashboard overview | `screenshots/04-dashboard-overview.png` |

## Dashboard

"Home SOC Lab Overview" contains:

- **Alerts over time** (date histogram on `@timestamp`)
- **Top processes (Sysmon)** (Sysmon event ID 1, top values of `data.win.eventdata.image`)
- **Top alert rules** (top values of `rule.description`)

## Test activity and findings

### 1. Encoded PowerShell triggers a detection

I ran a harmless encoded command, which decodes to `Write-Host "test"`:

```powershell
powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAdABlAHMAdAAiAA==
```

Sysmon recorded it as an event ID 1 process creation, and Wazuh raised **rule 92027, "PowerShell process spawned PowerShell instance" (level 4)**.

- **What ran:** `powershell.exe -enc ...`, launched from an interactive PowerShell window by the local lab user with high integrity
- **Assessment:** not harmful. I ran it myself and the payload decodes to a harmless string
- **What would change my verdict:** I would escalate this if it was launched by an app like Word, a web browser, or a script host such as 'wscript.exe', if it ran under an account or at a time that didn’t fit, or if the decoded command downloaded or ran something else.

### 2. Not every command raises an alert

Plain `whoami` and `ipconfig` did not appear as alerts in Wazuh. By default, Wazuh only stores events that match a detection rule, so routine commands are analyzed and discarded. This is a detection gap, and the natural next step is a custom rule that alerts on discovery commands run from an interactive shell.

### 3. Same command, different parent

`net user` raised **rule 92031, "Discovery activity executed" (level 3)**, but the parent process was `wazuh-agent.exe`, not my PowerShell session. The monitoring agent runs some commands itself, so the rule fires on the agent's own activity. The command alone says little; the parent process tells most of the story.

### 4. Level 12 alerts on a fresh install: svchost triage

A new Windows install produced several level 12 alerts, such as **rule 61618, "Sysmon - Suspicious Process - svchost.exe"** (MITRE T1055). I investigated one of them.

**What the rule checks:** Only that a newly created process has `svchost.exe` as its image. It doesn't check the file path or the parent process, so it fires every time Windows starts a normal svchost. That makes it noisy.

![Rule 61618 definition](screenshots/06-rule-61618-definition.png)

**What I checked:** image path, command line, user, integrity level, working directory, file metadata, parent process, and hash.

- **Image:** `C:\Windows\System32\svchost.exe`
- **Command line:** `svchost.exe -k GPSvcGroup` (a normal service group)
- **User and integrity:** `NT AUTHORITY\SYSTEM`, System, session 0
- **File metadata:** Microsoft Corporation, "Host Process for Windows Services," version matching this Windows build
- **Hash:** the SHA256 was identical across every 61618 alert I reviewed
- **Parent:** not recorded. Sysmon logged a parent PID but no `parentImage`, so I couldn't confirm it from this data.

![Level 12 alert detail](screenshots/05-level12-svchost-triage.png)

**Verdict:** False positive. The rule matched as written, and the activity is normal Windows service startup.

**What would change my verdict:** an image path outside System32, a parent other than `services.exe`, a command line with no `-k`, a user other than SYSTEM, LOCAL SERVICE, or NETWORK SERVICE, or a hash that doesn't match the known-good file.

**Tuning idea:** Alert only when svchost runs from outside System32 or has a parent other than `services.exe`, so real masquerading stands out. This is what I'll build as a custom rule next.

## Problems and fixes

| Problem | Cause | Fix |
|---|---|---|
| Could not get CrystalFetch from the App Store | Apple account payment issue blocked even free downloads | Downloaded the `.dmg` from the project's GitHub releases page |
| Wazuh VM would not boot the installer | The Windows ISO was attached to the Ubuntu VM | Re-attached the Ubuntu Server ARM64 ISO to the CD/DVD drive |
| Windows setup: "system drive needs to be at least 52 GB" | Windows 11 24H2 minimum; the virtual disk was 50 GB | Resized the disk to 64 GB (dynamically allocated) |
| PowerShell commands failed with "path does not exist" | Pasted lines merged together (`dir Sysmoncd Sysmon`) | Ran each command separately, one paste at a time |
| Ping showed "Destination host unreachable" but 0% loss | The replies came from the Windows VM itself; the server was powered off | Started the Wazuh VM and re-tested; replies then came from `192.168.64.2` |
| Windows VM froze, then hung on the boot spinner | Internal disk nearly full (about 9 GB free) while both VMs ran, plus a forced stop | Diagnosed the root cause as disk space, not RAM; deleted the broken VM, a 33 GB clone, and ISOs; rebuilt Windows and re-deployed the agent |
| Searches for `whoami` and `ipconfig` returned nothing | Wazuh stores only events that match a rule | Documented as a detection gap; planned a custom rule |
| External LaCie drive unusable for VMs | Measured about 67 MB/s write speed (spinning HDD) | Kept VMs on the internal drive; kept at least 20 GB free |

## Lessons learned

- A VM that freezes after a forced stop is a disk-space red flag, not just a RAM one. Keep at least 20 GB free and avoid cloning large VMs.
- Parent process context is what separates a benign alert from a serious one.
- A SIEM that stores only rule matches will quietly miss routine reconnaissance, which is why custom detections matter.

## Next steps

- Write custom detection rules (Sigma or Wazuh rules) for discovery commands and encoded PowerShell, and tune false positives
- Run Atomic Red Team tests and map results to MITRE ATT&CK
- Write alert-triage playbooks (phishing, brute force, malware on endpoint)
- Triage the level 12 svchost alerts and document the verdict
