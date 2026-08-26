# Incident Report: Simulated Attack Chain

**Analyst:** Marc Tomek Lawrence
**Date of investigation:** [fill in]
**Environment:** Isolated home lab (Windows 11, Kali Linux, Metasploitable)
**Classification:** Simulated / self-generated — no real victim or production system involved

---

## 1. Executive Summary

*2–4 sentences. What happened, in plain language, as if briefing a manager who wasn't watching. Example structure: "An attacker performed reconnaissance against the lab network, brute-forced credentials on [host], and established persistence via a scheduled task. The activity was detected using Windows native audit logging forwarded to Splunk Cloud, with no Sysmon or EDR present."*

## 2. Scope & Systems Involved

| Host | Role | IP |
|---|---|---|
| Windows 11 | Target / monitored endpoint | |
| Kali Linux | Attacker | |
| Metasploitable | Secondary target | |

## 3. Timeline of Events

*Chronological, timestamped, evidence-backed. This is the section that mirrors the chain-of-custody discipline from documentation-heavy investigative work — every entry should be traceable back to a specific log event.*

| Time (UTC) | Event | Source/Evidence |
|---|---|---|
| | Reconnaissance began (Nmap scan detected) | EventCode / firewall log ref |
| | Brute-force attempts began | EventCode 4625 |
| | Successful authentication | EventCode 4624 |
| | Exploitation of vulnerable service | Metasploit console / log ref |
| | Persistence established (scheduled task) | EventCode 4698 |

## 4. Indicators of Compromise (IOCs)

| Type | Value | Notes |
|---|---|---|
| Source IP | | Attacker (Kali) |
| Account(s) targeted | | |
| Scheduled task name | | |
| Process/command line | | |

## 5. Evidence Log

*List every screenshot/query result referenced above, with a description — this is the chain-of-custody habit carried over from documentation-intensive investigative work. Even in a lab, showing you keep an evidence log signals real investigative discipline.*

1. `screenshots/01-recon-scan.png` — Nmap scan results showing port enumeration against Windows 11
2. `screenshots/02-bruteforce-splunk.png` — Splunk search results, EventCode 4625 spike from attacker IP
3. `screenshots/03-successful-logon.png` — EventCode 4624 immediately following brute-force burst
4. `screenshots/04-persistence-task.png` — EventCode 4698 scheduled task creation
5. *(add more as needed)*

## 6. Root Cause

*What allowed each stage to succeed? E.g., weak password policy, no account lockout threshold, unpatched service version, lack of EDR/Sysmon reducing visibility into process behavior.*

## 7. Detection Gaps Identified

*Be honest here — this is a differentiator, not a weakness, when you can articulate it in an interview. E.g., "Without Sysmon or a network IDS (Zeek/Suricata), network-connection-level visibility was limited to firewall logs, which don't capture payload or protocol detail. In a production environment, this gap would be closed with endpoint detection tooling."*

## 8. Recommendations

1. Enforce account lockout policy after N failed attempts
2. Alert on scheduled task creation from non-admin accounts pointing to non-standard paths
3. Patch/remove vulnerable service versions
4. Consider adding Sysmon or a lightweight EDR agent for richer process and network telemetry
5. Network segmentation between untrusted and monitored hosts

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Network Service Discovery | T1046 |
| Credential Access | Brute Force | T1110 |
| Initial Access | Exploit Public-Facing Application | T1190 |
| Persistence | Scheduled Task | T1053.005 |
