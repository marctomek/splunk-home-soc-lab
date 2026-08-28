# Detection 1: Brute-Force Login (SSH)

**MITRE ATT&CK:** T1110 — Brute Force

## Scenario

From Kali (`192.168.64.11`), ran Hydra against Metasploitable's SSH service (`192.168.64.12`), attempting repeated authentication against the `msfadmin` account with a custom 10-entry wordlist (mixed wrong guesses plus the real password).

```
hydra -l msfadmin -P passwords.txt ssh://192.168.64.12
```

**Environment note:** the original plan targeted Windows 11 via RDP, but Windows 11 **Home edition does not support incoming RDP** — confirmed directly in Settings → System → Remote Desktop, which shows "Your Home edition of Windows 11 doesn't support Remote Desktop." The attack was pivoted to Metasploitable's SSH service instead.

**Troubleshooting note:** Hydra initially failed with an SSH key-exchange error (`kex error: no match for method mac algo`), because Metasploitable (Ubuntu 8.04-era) only supports legacy SSH algorithms that modern Kali disables by default. Fixed by adding legacy algorithm support to Kali's `/etc/ssh/ssh_config`:
```
Host *
    KexAlgorithms +diffie-hellman-group1-sha1
    HostKeyAlgorithms +ssh-rsa
    MACs +hmac-md5,hmac-sha1
```

## Detection logic

Metasploitable was initially **not part of the Splunk forwarding pipeline** — only the Windows 11 endpoint forwarded logs via the Universal Forwarder. The first pass of this detection was pulled directly from the target's own `/var/log/auth.log` to work around that gap honestly rather than fake full SIEM visibility.

That gap has since been closed: Metasploitable's classic `syslogd` now forwards `auth`/`authpriv` facility logs to Splunk in real time over UDP 514, using Splunk's built-in UDP data input (see [`01-lab-setup`](../01-lab-setup) for the full forwarding setup). The attack was rerun after forwarding was confirmed working, and the same detection is now fully SPL-based:

```spl
index=soc_lab sourcetype=syslog host=192.168.64.12 "Failed password" OR "Accepted password"
```

To build an actual alerting rule rather than just search results:

```spl
index=soc_lab sourcetype=syslog host=192.168.64.12 "Failed password"
| stats count by src_ip
| where count > 5
```

**Troubleshooting note (syslog forwarding setup):** getting this pipeline working took a few rounds of debugging worth documenting, since it's a realistic picture of what setting up log forwarding actually looks like:
- Windows ignores ICMP ping by default, which initially looked like a VM networking failure but was just Windows silently dropping the ping requests — enabling the built-in ICMPv4-In firewall rule confirmed the network path was fine all along.
- A raw `nc -u` test packet to port 514 confirmed the Windows Firewall rule and Splunk's UDP listener were both working correctly.
- The actual bug was in `/etc/syslog.conf`: classic BSD-style `syslogd` (used on this older Ubuntu build) only supports `@hostname` for remote forwarding, not `@hostname:port`. The `:514` suffix caused every forwarded message to silently fail, with no error logged anywhere. Removing the port suffix (since 514 is the default anyway) fixed it immediately.

This is a good example of a "log source went silent with no errors" investigation — the kind of quiet failure mode worth being able to recognize and methodically rule out (network → firewall → port → config) in a real SOC role.

## What to look for / findings

- [x] **Source IP:** `192.168.64.11` (Kali)
- [x] **Target:** `192.168.64.12` (Metasploitable), account `msfadmin`
- [x] **Failed attempts:** 12:00:17 — six failed attempts in the same second (ports 34634–34702), consistent with Hydra's parallel connection threads
- [x] **Successful login:** 12:00:15, port 34632 — `Accepted password for msfadmin from 192.168.64.11`
- [x] Screenshot: <img width="877" height="577" alt="screenshots:02-bruteforce-hydra" src="https://github.com/user-attachments/assets/35c7aa4e-adde-44fc-bde4-a2d5bfa6e23d" /> — Hydra output confirming the cracked credential
- [x] Screenshot: <img width="1470" height="956" alt="screenshots:03-bruteforce-authlog" src="https://github.com/user-attachments/assets/828003a4-2f76-458c-9621-7e425ff0492e" /> — target-side auth.log showing failed attempts and the accepted login
- [x] Screenshot: <img width="1228" height="710" alt="screenshots:04-bruteforce-splunk-live" src="https://github.com/user-attachments/assets/9d7f1e4b-fa93-4204-9de3-a12017a9fcdb" /> — same attack rerun after syslog forwarding was fixed, showing the failed/accepted login events live in Splunk via SPL

**Interesting timing detail:** the accepted login (12:00:15) timestamps *before* the failed attempts captured in the same log excerpt (12:00:17). This isn't a logging error — Hydra runs multiple parallel login threads by default, so a thread that happens to try the correct password can succeed before other threads finish working through incorrect guesses. Worth noting explicitly rather than assuming the log is out of order.

## False positives to consider

Legitimate users mistyping passwords, expired credentials, or service accounts with misconfigured scheduled tasks can also generate failed-login bursts. A real detection rule should also check for a *single source IP* hitting *multiple accounts*, which is a stronger brute-force signal than one account failing repeatedly.

## Response recommendation

Account lockout policy, source IP blocking at the firewall/`iptables`, and alerting on any successful login immediately following a failed-login burst from the same source. Forwarding Linux auth logs into the SIEM (rather than relying on manual log review) was identified as a gap during this exercise and has since been implemented — see the syslog forwarding setup above.

