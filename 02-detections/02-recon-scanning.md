# Detection 2: Network Reconnaissance

**MITRE ATT&CK:** T1046 — Network Service Discovery

## Scenario

From Kali, ran an Nmap scan against the Windows 11 and Metasploitable hosts to enumerate open ports and services.
nmap -sV -p- <target-ip>

## Detection logic

Without Sysmon's network-connection event (ID 3), this detection leans on the **Windows Firewall log** rather than Splunk SPL alone.

1. Enable Windows Defender Firewall logging: **Windows Defender Firewall with Advanced Security → Properties → Logging → log dropped/successful connections**, save to `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`.
2. Forward this log to Splunk via the Universal Forwarder (add a `monitor://` stanza in `inputs.conf` for the firewall log path).
3. Search for a single source IP touching many distinct destination ports in a short window:

```spl
index=soc_lab sourcetype=WinFirewall
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 20
```

## What to look for / findings

- [ ] Screenshot: number of unique destination ports contacted by the Kali IP
- [ ] Time window of the scan (should be tight — scans are fast)
- [ ] Which ports/services responded (cross-reference with Nmap's own output for accuracy)

## False positives to consider

Vulnerability scanners, monitoring tools, and some legitimate network discovery protocols can look similar. Volume and time-window (many ports, very short window) is the key differentiator from normal traffic.

## Response recommendation

Alert on any single source contacting an abnormal number of distinct ports within a short window; consider this a precursor indicator worth escalating even without a confirmed compromise.
