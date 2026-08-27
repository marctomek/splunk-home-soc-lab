# Lab Setup

## Network diagram

*(Add a screenshot or simple diagram here — even a hand-drawn box diagram exported as PNG works. Show: Windows 11, Kali, Metasploitable, and their IPs on the isolated virtual network.)*

## 1. Endpoint visibility without Sysmon

Sysmon wasn't available in this environment, so endpoint visibility was built entirely on native Windows auditing — which is worth documenting on its own, since many real environments run without Sysmon too.

**Enable Advanced Audit Policy** (as Administrator, in an elevated PowerShell or Command Prompt):

```
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

**Enable command-line logging** in process creation events (Event ID 4688), so the audit log captures the full command line, not just the process name — this is the closest native equivalent to Sysmon's Event ID 1:

Local Group Policy Editor → Computer Configuration → Administrative Templates → System → Audit Process Creation → **Include command line in process creation events** → Enabled.

Or via registry:
```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
```

**Key event IDs used throughout this lab:**

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4688 | New process created (with command line, once enabled above) |
| 4698 | Scheduled task created |
| 4720 | New user account created |

## 2. Forwarding logs to Splunk Enterprise (self-hosted, local)

Splunk Enterprise runs locally on the Windows 11 VM itself (`splunkd` service, web UI at `localhost:8000`). Since the indexer and the forwarder are on the same machine, this lab uses the **HTTP Event Collector (HEC)** over `localhost` rather than a remote receiver.

1. In the Splunk web UI: **Settings → Data Inputs → HTTP Event Collector → New Token**. Name it (e.g., `win11-endpoint`), select or create an index (e.g., `soc_lab`), and note the generated token.
2. Install **Splunk Universal Forwarder** on the same Windows 11 VM.
3. Configure `inputs.conf` (in `SplunkUniversalForwarder\etc\system\local\`) to monitor the Security and System event logs:

```ini
[WinEventLog://Security]
disabled = false
index = soc_lab

[WinEventLog://System]
disabled = false
index = soc_lab
```

4. Configure `outputs.conf` (same folder) to send to the local HEC endpoint with the token from step 1. Because a local Splunk Enterprise install uses a self-signed SSL cert by default, `sslVerifyServerCert` is set to `false` here — acceptable for an isolated local lab, not for production:

```ini
[httpout]
httpEventCollectorToken = <your-HEC-token>
uri = https://localhost:8088
sslVerifyServerCert = false
```

5. Restart the forwarder service so both config files take effect: `splunk.exe restart` (run from the forwarder's `bin` folder).

6. Confirm data is arriving, searching from the local Splunk web UI (`localhost:8000`):
```
index=soc_lab | stats count by source
```

## 3. Baseline

Before running any attacks, generate normal activity for a day — regular logins, regular process activity — so later detections have a "quiet" baseline to compare against. Screenshot of a basic dashboard here showing normal login/process volume.
<img width="1209" height="857" alt="screenshots:00-baseline-dashboard" src="https://github.com/user-attachments/assets/383aa516-550c-40cb-8323-8079dbd4744c" />

