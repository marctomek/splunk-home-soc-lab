# Detection 4: Persistence via Scheduled Task

**MITRE ATT&CK:** T1053.005 — Scheduled Task

## Scenario

Simulated a persistence technique on Windows 11 by creating a scheduled task designed to run at logon or on a recurring interval (via Atomic Red Team's scheduled task test, or manually with `schtasks`).
schtasks /create /tn "UpdateCheck" /tr "C:\Windows\Temp\payload.exe" /sc onlogon

*(Use a harmless placeholder binary, e.g. calc.exe, for the "payload" — the point is detecting the task creation, not running real malware.)*

## Detection logic (SPL)

Event ID 4698 fires natively on scheduled task creation — no Sysmon required.

```spl
index=soc_lab EventCode=4698
| table _time, Account_Name, Task_Name, Task_Content
```

Combine with 4688 (process creation, with command-line logging enabled) to see the `schtasks` command itself:

```spl
index=soc_lab EventCode=4688 CommandLine="*schtasks*"
```

## What to look for / findings

- [ ] Screenshot: 4698 event showing task name and the command it runs
- [ ] Screenshot: corresponding 4688 event showing the `schtasks` command line
- [ ] Task trigger type (on logon, daily, etc.) — relevant to how you'd characterize persistence

## False positives to consider

Legitimate software (updaters, backup tools) creates scheduled tasks constantly. A real rule would allowlist known-good task names/publishers and alert on anything outside that baseline, especially tasks pointing at binaries in unusual locations (Temp, AppData, user-writable paths).

## Response recommendation

Baseline expected scheduled tasks per host; alert on new tasks pointing to executables in non-standard directories; review task creation events tied to non-admin accounts.
