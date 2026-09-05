# Incident Report: Simulated Attack Chain

**Analyst:** Marc Tomek Lawrence
**Date of investigation:** August 28 – September 4, 2026
**Environment:** Isolated home lab (Windows 11, Kali Linux, Metasploitable)
**Classification:** Simulated / self-generated — no real victim or production system involved

---

## 1. Executive Summary

An attacker (Kali, `192.168.64.11`) performed network reconnaissance against two targets on an isolated lab network, brute-forced SSH credentials on a Linux host (Metasploitable, `192.168.64.12`), exploited a known backdoor in that host's FTP service to gain shell access, and separately simulated establishing persistence on the Windows 11 endpoint (`192.168.64.8`) via a scheduled task. Detection was built on Windows native audit logging (no Sysmon) forwarded via HTTP Event Collector, and Linux syslog forwarding, both feeding a self-hosted Splunk Enterprise instance. Three of the four attack stages were fully detected via SPL; the exploitation stage revealed a confirmed detection gap, investigated and root-caused rather than left unexplained.

## 2. Scope & Systems Involved

| Host | Role | IP |
|---|---|---|
| Windows 11 | Target / monitored endpoint | 192.168.64.8 |
| Kali Linux | Attacker | 192.168.64.11 |
| Metasploitable | Secondary target | 192.168.64.12 |

## 3. Timeline of Events

| Time | Event | Source/Evidence |
|---|---|---|
| Aug 30, ~05:36 | Reconnaissance: full-port Nmap scan against Metasploitable (26 ports found open in under a minute) | Nmap output; `screenshots/05-recon-splunk.png` |
| Aug 30, ~05:40–05:58 | Reconnaissance: full-port Nmap scan against Windows 11 (18+ min due to firewall filtering; only 2 ports found open) | Nmap output; Windows Firewall log via `WinFirewall` sourcetype |
| Aug 28, 20:55:42–43 | Brute-force: repeated failed SSH logins against `msfadmin` on Metasploitable from Kali | `syslog`, "Failed password"; `screenshots/04-bruteforce-splunk-live.png` |
| Aug 28, 20:55:40 | Brute-force: successful SSH login as `msfadmin` (password `msfadmin`) | `syslog`, "Accepted password"; `screenshots/04-bruteforce-splunk-live.png` |
| Sep 1, 13:13:06 | Exploitation: vsftpd 2.3.4 backdoor triggered on Metasploitable; Meterpreter session opened (third attempt succeeded after two failures) | Metasploit console output; `screenshots/06-exploitation-metasploit.png` |
| Sep 4, 10:02:19.572 | Persistence: `schtasks.exe` process creation on Windows 11 | EventCode 4688; `screenshots/09-persistence-4688.png` |
| Sep 4, 10:02:19.740 | Persistence: scheduled task `PersistTest3` created (trigger: on logon) | EventCode 4698; `screenshots/08-persistence-4698.png` |

## 4. Indicators of Compromise (IOCs)

| Type | Value | Notes |
|---|---|---|
| Source IP (attacker) | `192.168.64.11` | Kali, consistent across all four attack stages |
| Target — brute force / exploitation | `192.168.64.12` (Metasploitable) | Account targeted: `msfadmin` |
| Target — persistence simulation | `192.168.64.8` (Windows 11) | Account: `Tristan` (local admin used to simulate the technique) |
| Cracked credential | `msfadmin` / `msfadmin` | Default credential, no lockout policy in place |
| Exploited service | vsftpd 2.3.4 (port 21) | Known intentional backdoor |
| Scheduled task name | `\PersistTest3` | Trigger: on logon; payload: `calc.exe` (harmless stand-in) |
| Process | `schtasks.exe` | Created the persistence task |

## 5. Evidence Log

1. `screenshots/00-pipeline-verification.png` — initial Splunk log pipeline verification (21,891 events indexed)
2. `screenshots/01-baseline-dashboard.png` — SOC Lab Overview dashboard showing normal/quiet activity before any attacks
3. `screenshots/02-bruteforce-hydra.png` — Hydra output confirming the cracked `msfadmin` credential
4. `screenshots/03-bruteforce-authlog.png` — Metasploitable's own `/var/log/auth.log`, showing failed attempts and the accepted login (first detection pass, before syslog forwarding was live)
5. `screenshots/04-bruteforce-splunk-live.png` — brute-force attack re-run and detected live in Splunk after syslog forwarding was fixed
6. `screenshots/05-recon-splunk.png` — Splunk results showing Kali's 20 unique destination ports, standing out clearly from all other hosts on the network
7. `screenshots/06-exploitation-metasploit.png` — full Metasploit console: two failed exploitation attempts, the successful third attempt, and `sysinfo` confirming shell access
8. `screenshots/07-exploitation-vsftpd-log.png` — target's own `vsftpd.log`, showing normal FTP connections logged but no entry for the actual exploitation (evidence of the detection gap)
9. `screenshots/08-persistence-4698.png` — Splunk table showing EventCode 4698 for the `PersistTest3` scheduled task creation
10. `screenshots/09-persistence-4688.png` — corresponding EventCode 4688 showing `schtasks.exe` process creation, ~0.17 seconds before the 4698 event

## 6. Root Cause

- **Weak/default credentials:** Metasploitable's `msfadmin` account uses its well-known default password, with no account lockout policy to slow a brute-force attempt.
- **Outdated, intentionally vulnerable software:** vsftpd 2.3.4 contains a known backdoor; this class of vulnerability would be closed by patching or decommissioning the service in a real environment.
- **Limited endpoint visibility by design:** no Sysmon or EDR agent was used anywhere in this lab, so all detection had to be built from native OS auditing (Windows Event Log auditing, Linux syslog) — a deliberate constraint to demonstrate detection engineering without relying on premium tooling.
- **Incomplete initial log forwarding coverage:** Metasploitable was not part of the Splunk pipeline at the start of the exercise; closing this gap (HEC for Windows, syslog for Linux) was itself a significant part of the work.

## 7. Detection Gaps Identified

- **Exploitation stage (vsftpd backdoor) was not detected via Splunk**, even after broadening Metasploitable's syslog forwarding from `auth,authpriv` to include the `daemon` facility. Root-caused to the exploit's actual trigger mechanism: a raw TCP connection to a bind-shell listener on port 6200, spawned after the FTP banner is read — this never passes through vsftpd's own connection-logging code, so no facility-level syslog change can catch it. Closing this gap for real would require network-level monitoring (an IDS such as Zeek/Suricata watching for connections to non-standard ports) or host-based process monitoring (auditd/EDR) that doesn't depend on the exploited service logging its own compromise.
- **Scheduled task *replacement* does not reliably generate a fresh EventCode 4698**, even though task *creation* under a new name does. A detection rule tuned only to alert on "a new task appeared" could miss an attacker who instead modifies or replaces an existing, already-allowlisted task name for persistence.
- **Windows Firewall log (`pfirewall.log`) required manual field extraction** (`rex`) rather than automatic parsing, since the official Splunk Add-on for Windows wasn't installed — a reminder that raw log ingestion without the right parsing app can silently limit what SPL can query on, even when the data itself is present.

## 8. Recommendations

1. Enforce account lockout policy after N failed authentication attempts (would have slowed or blocked the brute-force stage).
2. Patch or decommission vulnerable service versions (vsftpd 2.3.4 specifically) — the only real fix for the exploitation detection gap, since visibility into the compromise itself is limited by what the vulnerable service chooses to log.
3. Add network-level monitoring (IDS such as Zeek/Suricata) to catch attack activity that never generates application-layer log events, such as raw-socket backdoor connections.
4. Install the official Splunk Add-on for Windows for proper automatic field extraction on Windows Firewall and other native logs, reducing reliance on manual `rex` patterns.
5. Extend detection logic for scheduled tasks to cover modification/replacement of existing tasks, not just first-time creation.
6. Consider adding Sysmon or a lightweight EDR agent in a future iteration of this lab to compare detection coverage against the native-auditing-only baseline used here.

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Network Service Discovery | T1046 |
| Credential Access | Brute Force | T1110 |
| Initial Access | Exploit Public-Facing Application | T1190 |
| Persistence | Scheduled Task | T1053.005 |
