# Detection 1: Brute-Force Login

**MITRE ATT&CK:** T1110 — Brute Force

## Scenario

From Kali, ran Hydra against [target — Windows 11 RDP / local account], attempting repeated authentication with a common password list.

```
hydra -l <username> -P <wordlist> rdp://<target-ip>
```

## Detection logic (SPL)

```spl
index=soc_lab EventCode=4625
| stats count by src_ip, Account_Name
| where count > 10
```

*Adjust the threshold based on your baseline — document what "normal" failed-login volume looked like before setting this.*

## What to look for / findings

- [ ] Screenshot: spike in EventCode 4625 events over time
- [ ] Source IP of the attack (Kali VM)
- [ ] Target account(s) attempted
- [ ] Timestamp of first and last attempt
- [ ] Note: did the attack eventually succeed (4624 following a run of 4625s from the same source)?

## False positives to consider

Legitimate users mistyping passwords, expired credentials, or service accounts with misconfigured scheduled tasks can also generate 4625 bursts. A real detection rule should also check for a *single source IP* hitting *multiple accounts*, which is a stronger brute-force signal than one account failing repeatedly.

## Response recommendation

Account lockout policy, source IP blocking at the firewall, and alerting on any successful login (4624) immediately following a failed-login burst from the same source.
