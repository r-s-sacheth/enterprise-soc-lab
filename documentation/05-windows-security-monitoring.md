# 05 — Windows Security Monitoring

## Overview

This stage of the lab establishes a Windows security monitoring baseline on `CLIENT01`.

The objective is to generate useful security telemetry that can later be collected by `SOC01` for centralized monitoring, detection engineering, threat hunting, and incident investigation.

The monitoring configuration consists of:

* Windows Advanced Audit Policy
* Group Policy
* Windows Security event logging
* Sysmon
* Sysmon-based endpoint telemetry

---

## 1. Workstation Security Baseline

A Group Policy Object (GPO) named:

```text
Workstation Security Baseline
```

was created in the `cyberlab.local` domain.

The GPO is intended to provide a security-auditing baseline for domain workstations.

### Configured Audit Policies

The following audit policies were enabled.

### Account Logon

**Audit Credential Validation**

```text
Success
Failure
```

This provides authentication-related telemetry that can be used to investigate credential validation activity.

### Account Management

**Audit User Account Management**

```text
Success
Failure
```

This provides visibility into activities such as:

* User account creation
* User account deletion
* Account changes
* Password changes
* Account enable/disable activity

### Logon/Logoff

**Audit Logon**

```text
Success
Failure
```

**Audit Logoff**

```text
Success
```

**Audit Special Logon**

```text
Success
```

These events provide visibility into user authentication and privileged or special logon activity.

### Policy Change

**Audit Audit Policy Change**

```text
Success
Failure
```

This allows changes to the system audit configuration to be monitored.

### System

**Audit System Integrity**

```text
Success
Failure
```

This provides telemetry related to changes affecting system integrity.

---

## 2. Effective Audit Policy

The configured policy was verified on `CLIENT01` using:

```powershell
auditpol /get /category:*
```

The resulting effective configuration included:

```text
Account Logon
└── Credential Validation          Success + Failure

Account Management
└── User Account Management        Success + Failure

Logon/Logoff
├── Logon                          Success + Failure
├── Logoff                         Success
└── Special Logon                  Success

Policy Change
└── Audit Policy Change            Success + Failure

System
└── System Integrity               Success + Failure
```

This confirmed that the expected audit settings were active on the workstation.

---

## 3. Group Policy Validation

The workstation policy was refreshed using:

```powershell
gpupdate /force
```

The resulting Group Policy configuration was verified using:

```powershell
gpresult /r
```

Computer-scope results confirmed that the following GPOs were applied:

```text
Workstation Security Baseline
Default Domain Policy
```

The computer was identified as:

```text
CLIENT01
```

within:

```text
OU=Workstations,OU=Corp Computers,DC=cyberlab,DC=local
```

The policy was applied from:

```text
DC01.cyberlab.local
```

---

## 4. Sysmon Deployment

Sysmon was enabled on `CLIENT01` using the Windows optional feature.

The initial installation state was checked with:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName Sysmon
```

Sysmon was then enabled using:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -All
```

The Sysmon service and driver were subsequently installed and verified.

The Sysmon service was confirmed to be running:

```powershell
Get-Service Sysmon
```

The Sysmon driver was also verified:

```powershell
Get-CimInstance Win32_SystemDriver |
    Where-Object {$_.Name -like "Sysmon*"} |
    Select-Object Name, State, StartMode, PathName
```

Expected state:

```text
Sysmon      Running
SysmonDrv   Running
```

---

## 5. Sysmon Configuration

A Sysmon configuration file was created at:

```text
C:\SysmonConfig.xml
```

The configuration enables telemetry for the following event categories:

```text
Process Creation
Network Connections
File Creation
Registry Events
DNS Queries
```

The configuration uses SHA256 hashing.

The configuration was applied using:

```powershell
sysmon -c C:\SysmonConfig.xml
```

The active configuration was verified using:

```powershell
sysmon -c
```

The relevant rules were confirmed with:

```powershell
sysmon -c | Select-String "ProcessCreate|NetworkConnect|FileCreate|RegistryEvent|DnsQuery"
```

The active configuration included:

```text
ProcessCreate
NetworkConnect
FileCreate
RegistryEvent
DnsQuery
```

---

## 6. Sysmon Event Log

Sysmon writes its telemetry to:

```text
Microsoft-Windows-Sysmon/Operational
```

The event log was verified using:

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"
```

The log was confirmed to be enabled and receiving events.

---

## 7. Telemetry Validation

Several controlled tests were performed on `CLIENT01` to verify that Sysmon was generating telemetry.

### Network Connection — Event ID 3

A connection to the domain controller was tested:

```powershell
Test-NetConnection dc01.cyberlab.local -Port 445
```

The connection succeeded through the internal interface:

```text
Source:      192.168.100.20
Destination: 192.168.100.10
Port:        445
```

Sysmon subsequently generated Event ID `3`:

```text
Network connection detected
```

This confirmed that network connection telemetry was functioning.

---

### File Creation — Event ID 11

A controlled file was created:

```powershell
New-Item C:\Temp\sysmon-test.txt -ItemType File -Force
```

Sysmon generated Event ID `11`:

```text
File created
```

This confirmed file creation telemetry.

---

### Registry Activity — Event IDs 12 and 13

During testing, Sysmon generated:

```text
Event ID 12 — Registry object added or deleted
Event ID 13 — Registry value set
```

This confirmed that registry telemetry was being collected.

---

### Process Termination — Event ID 5

Sysmon also generated Event ID `5`:

```text
Process terminated
```

This confirmed process termination telemetry.

---

## 8. DNS Validation

DNS resolution was verified using:

```powershell
Resolve-DnsName dc01.cyberlab.local
```

The domain controller resolved through the internal DNS server:

```text
dc01.cyberlab.local
192.168.100.10
```

DNS resolution itself was functioning correctly.

Sysmon DNS Query Event ID `22` was not observed during the initial validation tests. This is documented as a telemetry item for further investigation rather than being treated as a DNS failure.

---

## 9. Current Telemetry Status

| Telemetry                   | Event ID | Status              |
| --------------------------- | -------: | ------------------- |
| Process Creation            |        1 | Under investigation |
| Process Termination         |        5 | Verified            |
| Network Connection          |        3 | Verified            |
| File Creation               |       11 | Verified            |
| Registry Object Activity    |       12 | Verified            |
| Registry Value Modification |       13 | Verified            |
| DNS Query                   |       22 | Under investigation |

The absence of Events `1` and `22` during the initial validation does not indicate that the Windows networking or DNS functionality is broken. Additional investigation will be performed as the monitoring configuration is refined.

---

## 10. Security Monitoring Architecture

The current monitoring architecture is:

```text
                 cyberlab.local
                       │
                 ┌─────▼─────┐
                 │   DC01    │
                 │  AD/DNS   │
                 └─────┬─────┘
                       │
                Internal Network
                       │
                 ┌─────▼─────┐
                 │  CLIENT01 │
                 │ Windows 11│
                 │           │
                 │  Security │
                 │ Auditing  │
                 │    +      │
                 │  Sysmon   │
                 └─────┬─────┘
                       │
                 Security Telemetry
                       │
                 ┌─────▼─────┐
                 │   SOC01   │
                 │ Monitoring│
                 │  / SIEM   │
                 └───────────┘
```

At this stage, `CLIENT01` is generating security telemetry locally. Centralized collection and analysis will be implemented on `SOC01`.

---

## 11. Next Step

The next stage is to configure `SOC01` for centralized security monitoring.

Planned activities include:

* Deploying the monitoring/SIEM stack
* Configuring Windows log collection
* Forwarding `CLIENT01` security telemetry
* Ingesting Sysmon events
* Building detection rules
* Creating Sigma detections
* Performing threat-hunting exercises
* Mapping detections to MITRE ATT&CK
* Simulating controlled attacks
* Conducting incident investigations
