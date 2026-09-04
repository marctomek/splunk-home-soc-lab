# Detection 4: Persistence via Scheduled Task

**MITRE ATT&CK:** T1053.005 — Scheduled Task

## Scenario

Simulated a persistence technique on Windows 11 by creating a scheduled task designed to run at logon, using `calc.exe` as a harmless placeholder for a real payload — the point is detecting the task creation, not running anything malicious.
schtasks /create /tn "PersistTest3" /tr "C:\Windows\System32\calc.exe" /sc onlogon

**Interesting finding during testing:** an earlier attempt reused an existing task name ("UpdateCheck," recreated after replacing a prior version of itself) and did **not** generate a fresh EventCode 4698 in Splunk, even though `schtasks` reported success. Creating a task under a brand-new name (`PersistTest3`) generated the event immediately and reliably. This suggests Windows may log scheduled *task creation* and *task replacement* differently — worth being aware of, since a detection rule tuned only for "new task appears" could miss an attacker who reuses/modifies an existing task name for persistence rather than creating a new one.

## Detection logic (SPL)

Event ID 4698 fires natively on scheduled task creation — no Sysmon required.

```spl
index=soc_lab EventCode=4698 | table _time, Account_Name, Task_Name, Task_Content
```

Combine with 4688 (process creation) to see the `schtasks.exe` process itself. Note: the `CommandLine` field isn't reliably extracted for this sourcetype without the official Splunk Add-on for Windows installed, so searching the raw event text directly is more reliable than filtering on `CommandLine=`:

```spl
index=soc_lab EventCode=4688 "schtasks"
```

## What to look for / findings

- [x] **Task name:** `PersistTest3`
- [x] **Account:** Tristan
- [x] **4698 timestamp:** 2026-09-04 10:02:19.740 — task creation event, confirmed via `Task_Name` and `Task_Content` fields
- [x] **4688 timestamp:** 2026-09-04 10:02:19.572 — `schtasks.exe` process creation, ~0.17 seconds before the 4698 event, exactly the ordering you'd expect (process launches, then the task-creation event fires)
- [x] **Trigger type:** on logon (`/sc onlogon`)
- [x] Screenshot:<img width="1233" height="856" alt="08-persistence-4698" src="https://github.com/user-attachments/assets/7c1145bb-1118-42bb-bcb1-939701f1ace7" /> — Splunk table showing the 4698 event with task name and account
- [x] Screenshot: <img width="1218" height="854" alt="09-persistence-4688" src="https://github.com/user-attachments/assets/9bb9d372-9f7d-4d89-8840-d24c36931b0c" /> — corresponding 4688 event showing `schtasks.exe` as the new process, with timestamp closely matching the 4698 event

## False positives to consider

Legitimate software (updaters, backup tools) creates scheduled tasks constantly. A real rule would allowlist known-good task names/publishers and alert on anything outside that baseline, especially tasks pointing at binaries in unusual locations (Temp, AppData, user-writable paths). Also worth building separate detection logic for task *modification/replacement*, not just first-time creation, based on the finding above.

## Response recommendation

Baseline expected scheduled tasks per host; alert on new tasks pointing to executables in non-standard directories; review task creation events tied to non-admin accounts. Given the task-replacement logging gap found during testing, validate that any production detection rule also catches modifications to existing tasks, not only brand-new task names.
