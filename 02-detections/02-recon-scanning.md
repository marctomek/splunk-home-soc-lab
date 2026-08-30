# Detection 2: Network Reconnaissance

**MITRE ATT&CK:** T1046 — Network Service Discovery

## Scenario

From Kali (`192.168.64.11`), ran a full-port Nmap scan against both targets to enumerate open ports and services.
nmap -sV -p- 192.168.64.12 # Metasploitable
nmap -sV -p- 192.168.64.8 # Windows 11

**Interesting result:** the two scans looked completely different. Metasploitable — deliberately vulnerable, minimal firewalling — returned **26 open ports** in under a minute (FTP, SSH, Telnet, SMTP, SMB, MySQL, PostgreSQL, VNC, IRC, and more — a real attack surface). Windows 11, sitting behind an active firewall, took **over 18 minutes** to scan and returned only **2 open ports** (one unidentified service on 7680, and Splunk's own web UI on 8000). Nearly all other ports came back `filtered` rather than `closed`, meaning Windows Firewall silently dropped the packets instead of responding at all.

This is a useful thing to be able to explain in an interview: a full-port scan against a well-firewalled host is *slow and mostly unproductive* for the attacker, not just detectable — the two go hand in hand.

## Detection logic

Windows Firewall logging was enabled (Windows Defender Firewall with Advanced Security → Properties → Logging → log dropped/successful connections) and forwarded to Splunk via a `monitor://` stanza pointed at `pfirewall.log`.

`pfirewall.log` is raw space-delimited text, not automatically parsed into fields by Splunk without the proper Windows TA installed — so field extraction is done manually with `rex` against the log's actual column order (`date time action protocol src-ip dst-ip src-port dst-port ...`):

```spl
index=soc_lab sourcetype=WinFirewall
| rex field=_raw "^\S+\s+\S+\s+\S+\s+\S+\s+(?<src_ip>\S+)\s+\S+\s+\S+\s+(?<dest_port>\S+)"
| stats dc(dest_port) as unique_ports by src_ip
| sort -unique_ports
```

## What to look for / findings

- [x] **Results (real run):**

| src_ip | unique_ports | Notes |
|---|---|---|
| `127.0.0.1` | 57 | Splunk's own internal loopback traffic — excluded from analysis |
| `192.168.64.11` | **20** | **Kali — the scanning host** |
| `192.168.64.8` | 9 | Windows 11 itself (background/normal traffic) |
| `192.168.64.12` | 3 | Metasploitable |

- [x] Screenshot: <img width="1202" height="727" alt="05-recon-splunk" src="https://github.com/user-attachments/assets/4b00bb55-ec72-45b9-8293-d25716f45eda" /> — Splunk results table showing Kali's 20 unique ports standing out from every other real host on the network
- [x] **Time window:** the Metasploitable scan completed quickly; the Windows 11 scan took **18+ minutes** due to the firewall silently dropping most probes rather than responding — worth noting that "short time window" isn't a reliable signal on its own when the target is well-defended, since a heavily-filtered scan can run much longer than an unfiltered one.

## False positives to consider

Vulnerability scanners, monitoring tools, and some legitimate network discovery protocols can look similar. Volume (many distinct ports from one source) is the more reliable differentiator here than scan duration — a well-firewalled target can make even a real attacker's scan take a long time, so time window alone shouldn't be the deciding factor in an alert rule.

## Response recommendation

Alert on any single source contacting an abnormal number of distinct ports, regardless of scan duration; consider this a precursor indicator worth escalating even without a confirmed compromise. The dramatic difference in exposed surface between the two targets in this exercise (26 open ports vs. 2) is itself a good illustration of why host-level firewalling matters even inside a segmented network.
