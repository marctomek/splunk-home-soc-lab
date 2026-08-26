A hands-on security operations lab built to simulate attack detection, investigation, and incident documentation using Splunk Cloud.

Environment: Windows 11 (monitored endpoint) · Kali Linux (attacker) · Metasploitable (vulnerable target) — all on a local, isolated virtual network.

Analyst: Marc Tomek Lawrence — LinkedIn

Why this lab

I built this to apply SOC skills I use on the job (SIEM monitoring, log analysis, alert triage) against real attacks I control end-to-end — generating the traffic, detecting it in Splunk, and documenting the investigation the way I would for a real incident.

Lab architecture
Host	Role	Logging
Windows 11	Monitored endpoint	Windows Security & System Event Logs (Advanced Audit Policy), forwarded to Splunk Cloud via Universal Forwarder
Kali Linux	Attacker	Source of simulated attacks (Hydra, Nmap, Metasploit, Atomic Red Team)
Metasploitable	Vulnerable target	Exploitation target for Attack 3
Splunk Cloud	SIEM	Ingests and indexes Windows endpoint logs; all detection built in SPL

See 01-lab-setup/ for the full build steps, including how endpoint visibility was configured without Sysmon, using native Windows auditing (Event IDs 4688, 4624/4625, 4698) with command-line logging enabled.

Detections

Each attack was simulated, then detected and documented independently, with SPL queries, screenshots, and MITRE ATT&CK mapping.

#	Scenario	Technique detected	MITRE ATT&CK
1	Brute-force login	Repeated failed authentication	T1110
2	Network reconnaissance	Port/service scanning	T1046
3	Exploitation	Remote exploitation of vulnerable service	T1190
4	Persistence	Scheduled task creation	T1053.005
Incident report

03-incident-report/ ties multiple attacks into one narrative — an attacker performing recon, brute-forcing credentials, exploiting a service, and establishing persistence — written as a full incident report: timeline, IOCs, chain-of-custody-style evidence log, and response recommendations.

Skills demonstrated
SPL query writing and search optimization
Windows security log analysis (without Sysmon — native auditing only)
Attack simulation and detection engineering
MITRE ATT&CK mapping
Incident documentation and reporting
Notes on scope

This is a personal, isolated lab environment. No production systems, third-party networks, or public infrastructure were involved in any simulated attack.
