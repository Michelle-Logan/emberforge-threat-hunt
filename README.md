# 🛡️ EmberForge Threat Hunt Report

**Domain Compromise & Credential Access Investigation**

---

## 📌 Executive Summary

This threat hunt identified a **multi-stage attack** within the EmberForge environment that resulted in **Domain Controller compromise** and **credential exfiltration**.

The attacker leveraged a combination of:

* Privilege escalation via UAC bypass
* Persistence via scheduled task creation
* Credential access through LSASS dumping and Kerberoasting
* Lateral movement using NTLM-backed network logons
* Active Directory database extraction through Volume Shadow Copy

The adversary relied heavily on **native Windows binaries and service-based execution**, demonstrating a clear **living-off-the-land** approach.

---

## 🎯 Key Findings

* Malicious payload executed: `update.exe`
* UAC bypass performed via registry hijack and `fodhelper.exe`
* Persistence established with a SYSTEM-level scheduled task
* LSASS dump file created for credential theft
* Kerberoasting activity observed through bursts of Event ID 4769
* Lateral movement performed using NTLM network authentication
* Domain Controller accessed through remote service execution
* `ntds.dit` extracted using a shadow copy workflow
* New domain account created: `svc_backup`
* Network share created for tool distribution
* Firewall rule added to allow SMB access
* Evidence of defense evasion and command output redirection observed

---

## 🧭 Attack Timeline

### 1. Initial Access and Malicious DLL Execution

The attack chain began when a user opened a downloaded archive, leading to extraction of files and execution of a malicious DLL through `rundll32.exe`.

**Key evidence**

```text
rundll32.exe D:\review.dll,StartW
```

**Parent-child relationship**

```text
explorer.exe → rundll32.exe → review.dll
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| parse Raw_s with * "ParentImage'>" ParentImage "<" *
| where CommandLine has "review.dll"
| project UtcTime_s, Computer, ParentImage, Image, CommandLine
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

<img width="1125" height="67" alt="Screenshot 2026-04-13 122948" src="https://github.com/user-attachments/assets/2117fa60-a215-48cf-8894-90e6bc04ecb1" />


---

### 2. Archive Extraction Prior to Execution

A decompression tool extracted the contents of a downloaded archive into the user’s profile just before DLL execution.

**Key evidence**

```text
7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| parse Raw_s with * "ParentImage'>" ParentImage "<" *
| parse Raw_s with * "User'>" User "<" *
| where Image has "7zG.exe"
| project UtcTime_s, Computer, Image, CommandLine, ParentImage, User
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

<img width="998" height="166" alt="Screenshot 2026-04-13 151111" src="https://github.com/user-attachments/assets/ed9f8a02-0b56-453d-93c7-248432e927d6" />


---

### 3. Privilege Escalation via UAC Bypass

The attacker leveraged a known UAC bypass technique by modifying the registry path associated with the `ms-settings` protocol handler. This allowed them to hijack execution flow and run a malicious payload with elevated privileges.

Specifically, the attacker added a registry key:

HKCU\Software\Classes\ms-settings\shell\open\command

and set its value to point to a malicious executable located at:

C:\Users\Public\update.exe

The attacker then executed fodhelper.exe, a trusted Windows binary that is auto-elevated and does not prompt for UAC. Because fodhelper.exe invokes the ms-settings handler, the system instead executed the attacker-controlled payload with administrative privileges.

This technique allowed the attacker to bypass UAC and escalate privileges without user interaction.

**Key evidence**

```text
reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /t REG_SZ /d C:\Users\Public\update.exe /f
```

**Trusted binary abused**

```text
fodhelper.exe
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s in ("1","13")
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| parse Raw_s with * "TargetObject'>" TargetObject "<" *
| parse Raw_s with * "Details'>" Details "<" *
| project UtcTime_s, EventCode_s, Computer, Image, CommandLine, TargetObject, Details
| where EventCode_s == "13"
   or Image has "fodhelper.exe"
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

<img width="1132" height="332" alt="Screenshot 2026-04-13 152602" src="https://github.com/user-attachments/assets/9fe88bce-c70b-4a35-a3ab-2931003a7cf1" />

---

### 4. Persistence via Scheduled Task (System-Level Execution)

Analysis of process creation logs revealed the use of schtasks.exe to establish persistence on the system.

The following command was executed:

schtasks /create /tn WindowsUpdate /tr C:\Users\Public\update.exe /sc onstart /ru system

This command creates a scheduled task named "WindowsUpdate" that executes the malicious payload located at C:\Users\Public\update.exe each time the system starts.

Notably, the task is configured to run under the SYSTEM account, granting the attacker the highest level of privileges on the host.

Additionally, process lineage analysis shows that the parent process responsible for creating the task was the same malicious executable (update.exe), confirming successful execution of the payload and attacker-controlled persistence.

This technique ensures the attacker maintains access across reboots and operates with elevated privileges.

**Key evidence**

```text
schtasks /create /tn WindowsUpdate /tr C:\Users\Public\update.exe /sc onstart /ru system
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| parse Raw_s with * "ParentImage'>" ParentImage "<" *
| where Image has "update.exe" or CommandLine has "update.exe"
| project UtcTime_s, Computer, Image, CommandLine, ParentImage
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

<img width="694" height="110" alt="Screenshot 2026-04-13 153340" src="https://github.com/user-attachments/assets/304f56c8-2539-4cda-8d0b-0a851eeec1e5" />

---

### 5. LSASS Dumping for Credential Theft

The attacker created an LSASS memory dump using `update.exe`, indicating credential harvesting.

**Key evidence**

```text
C:\Windows\System32\lsass.dmp
```

**Process responsible**

```text
update.exe
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "11"
| parse Raw_s with * "TargetFilename'>" TargetFilename "<" *
| parse Raw_s with * "Image'>" Image "<" *
| where TargetFilename has_any ("lsass.dmp", "lsass", ".dmp")
| project UtcTime_s, Computer, Image, TargetFilename
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

<img width="798" height="84" alt="Screenshot 2026-04-13 153515" src="https://github.com/user-attachments/assets/acfc687a-6c74-4d40-b3ba-dce13b10017a" />

---

### 6. Kerberoasting Activity

A burst of Event ID 4769 records indicated suspicious Kerberos service ticket requests consistent with Kerberoasting.

**Indicators**

* Numerous 4769 events in a short interval
* Requests associated with attacker-controlled systems
* Activity involving sensitive Kerberos-related identities

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == 4769
| summarize Count=count() by TimeGenerated
```

### Evidence Screenshot

<img width="309" height="339" alt="Screenshot 2026-04-13 154601" src="https://github.com/user-attachments/assets/ddd7f821-0204-497c-a803-eb1e0969c041" />

---

### 7. Lateral Movement via NTLM Network Logons

Analysis of Windows Security Event ID 4625 logs revealed failed authentication attempts consistent with lateral movement activity.

At 22:35:34, a system at IP address 10.0.2.69 attempted to authenticate to EC2AMAZ-EEU3IA2 using the Administrator account. The logon attempt was performed over the network (Logon Type 3) using the NTLM authentication protocol (NtLmSsp).

The use of NTLM instead of Kerberos, combined with a privileged account and network-based logon attempt, is indicative of potential lateral movement techniques such as pass-the-hash or brute force attempts.

The failed authentication suggests either incorrect credentials or unsuccessful exploitation, but still represents suspicious activity that warrants further investigation.

**Protocol / logon process**

```text
NtLmSsp
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == 4625
| project TimeGenerated, Computer,IPAddress, TargetUserName_s, LogonType_s, LogonProcessName_s, AuthenticationPackageName_s
| order by TimeGenerated asc
```

### Evidence Screenshot

<img width="1299" height="198" alt="Screenshot 2026-04-13 155031" src="https://github.com/user-attachments/assets/402cf059-6e53-4d66-9dbd-f4bb36474563" />

---

### 8. Network Share Creation for Tool Distribution

The attacker created an SMB share pointing to `C:\Users\Public` and granted full access to everyone, turning the workstation into a distribution point.

**Key evidence**

```text
net share tools=C:\Users\Public /grant:everyone,full
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| where CommandLine has "net share"
| project UtcTime_s, Computer, CommandLine
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

<img width="766" height="85" alt="Screenshot 2026-04-13 155405" src="https://github.com/user-attachments/assets/cc480621-48f8-4e40-862d-f249a50d5862" />

---

### 9. Firewall Modification to Allow SMB

The attacker added a firewall rule named `SMB` to permit inbound TCP 445 traffic.

**Key evidence**

```text
netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=tcp localport=445
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| where CommandLine has_all ("netsh","firewall","add")
| project UtcTime_s, Computer, CommandLine
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

<img width="1008" height="89" alt="Screenshot 2026-04-13 155520" src="https://github.com/user-attachments/assets/ff0b4d13-9729-44ba-af6a-25ac59438ffc" />

---

### 10. Remote Service-Based Execution on the Domain Controller

The attacker reused the same remote execution pattern against the Domain Controller, with commands launched in a service context and wrapped through temporary batch files.

**Observed process chain**

```text
services.exe → cmd.exe → execute.bat → cmd.exe /C <command>
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| parse Raw_s with * "ParentImage'>" ParentImage "<" *
| where Computer has "EEU3IA2"
| where CommandLine has_any ("execute.bat", "vssadmin", "ntds.dit")
| project UtcTime_s, Computer, ParentImage, Image, CommandLine
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

```text
[Add screenshot here: services.exe launching cmd.exe wrapper on the DC]
```

---

### 11. NTDS.dit Extraction via Volume Shadow Copy

After reaching the DC, the attacker created a shadow copy workflow and copied the Active Directory database out of the snapshot.

**Key evidence**

```text
vssadmin create shadow /For=C:
```

```text
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\nyMdRNSp.tmp
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| where Computer has "EEU3IA2"
| where CommandLine has_any ("vssadmin", "HarddiskVolumeShadowCopy", "ntds.dit", "copy ")
| project UtcTime_s, Computer, Image, CommandLine
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

```text
[Add screenshot here: shadow copy creation and ntds.dit copy command]
```

---

### 12. Domain Account Creation

The attacker created a new domain account for persistence.

**Key evidence**

```text
net user svc_backup P@ssw0rd123! /add /domain
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| where CommandLine has_all ("net", "user", "/add", "/domain")
| project UtcTime_s, Computer, CommandLine
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

```text
[Add screenshot here: domain account creation command]
```

---

### 13. Command Output Redirection and Batch Staging

The attacker repeatedly wrapped commands in temporary batch files and redirected output to files in Windows temp directories.

**Key evidence**

```text
cmd.exe /Q /c echo <command> > C:\Windows\TEMP\execute.bat & cmd.exe /Q /c C:\Windows\TEMP\execute.bat
```

### KQL Query

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| where CommandLine has_any ("execute.bat", ">", "2>&1", "Temp")
| project UtcTime_s, Computer, CommandLine
| order by todatetime(UtcTime_s) asc
```

### Evidence Screenshot

```text
[Add screenshot here: output redirection and execute.bat wrapper pattern]
```

---

## 🧠 MITRE ATT&CK Mapping

| Technique                           | ID        |
| ----------------------------------- | --------- |
| User Execution                      | T1204     |
| Rundll32 Execution                  | T1218.011 |
| UAC Bypass                          | T1548.002 |
| Scheduled Task Persistence          | T1053     |
| LSASS Credential Dumping            | T1003.001 |
| Kerberoasting                       | T1558.003 |
| SMB / Windows Admin Shares          | T1021.002 |
| Remote Service Execution            | T1569.002 |
| NTDS.dit Extraction                 | T1003.003 |
| Create Account                      | T1136     |
| Network Share Manipulation          | T1135     |
| Firewall Rule Modification          | T1562     |
| Clear / Obscure Execution Artifacts | T1070     |

---

## 🚨 Impact Assessment

* Full **Domain Compromise**
* Exposure of domain credential material
* Persistence established through both system-level and domain-level mechanisms
* Evidence of post-exploitation staging, stealth, and credential access

---

## 🛡️ Recommendations

### Immediate Actions

* Reset all privileged credentials
* Reset all service account credentials
* Rotate KRBTGT twice
* Remove malicious domain account(s)
* Remove malicious scheduled tasks and shares
* Review all firewall changes and revert unauthorized rules

### Detection Improvements

* Enable stronger audit coverage for directory service abuse
* Alert on:

  * `rundll32.exe` with unusual DLL paths
  * `fodhelper.exe`
  * `schtasks.exe /create`
  * `vssadmin create shadow`
  * `net share`
  * `net user /add /domain`
  * `wevtutil`
* Tune detections for batch wrapper execution and command output redirection

### Hardening

* Restrict SMB administrative access
* Restrict use of auto-elevating binaries
* Limit service account privileges
* Enforce stronger auditing on DCs
* Monitor NTDS access and shadow copy creation aggressively

---

## 📊 Conclusion

The EmberForge intrusion demonstrates a complete attacker workflow from initial execution to domain-level credential theft. The attacker abused native Windows tools, leveraged remote service execution, performed shadow-copy-based NTDS extraction, and established persistence through both host and domain artifacts.

This activity reflects a stealth-focused intrusion that prioritized credential access, administrative control, and survivability.

---

## 🧾 Final Assessment

```text
Severity: CRITICAL
Outcome: Domain Compromise
Attacker Capability: Advanced / Multi-Stage
```

---

## 👩‍💻 Author

**Michelle Logan**
Cybersecurity / Threat Hunting Portfolio Project

**Add your links here**

* GitHub: `https://github.com/your-profile`
* LinkedIn: `https://www.linkedin.com/in/your-profile`

