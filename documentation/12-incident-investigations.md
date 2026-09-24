# 12 — Incident Investigations

## Overview

With attack simulations validated in Phase 11, this phase investigates the resulting telemetry as an analyst would — starting from an alert, not from prior knowledge of what was run. Two incidents were reconstructed from Phase 11's evidence: a multi-step execution chain, and the Logon Type 11 / Type 2 authentication anomaly. Both investigations follow the same structure — trigger, timeline reconstruction, scope, root cause — and both explicitly separate what the telemetry alone can establish from what is only known because the underlying activity was self-generated for this lab.

---

## 1. Investigation Methodology

```text
Alert fires (or is selected as the investigation trigger)
       ↓
Confirm what actually happened (raw telemetry, not assumption)
       ↓
Establish a timeline (what came before, what came after)
       ↓
Determine scope (account, host, process lineage involved)
       ↓
Determine root cause (why did this happen / why did detection behave this way)
       ↓
Classify outcome (benign, confirmed gap, or true positive)
       ↓
Record findings and any follow-up actions
```

Each investigation below is written from the perspective of an analyst who did not already know what commands were run — even though, as the person who built this lab, that information was available. Every step uses only information that would actually be visible in Wazuh: the alert itself, the raw event data, and follow-up queries. Where a conclusion is only possible because the investigator is also the lab operator, that is stated explicitly as a disclosure, separate from what the telemetry itself establishes.

---

## 2. Incident 01 — Multi-Step Execution Chain

### 2.1 Initial Alert

The highest-severity alert in a cluster of four related alerts from `CLIENT01` is the natural starting point for triage, rather than the chronologically first one:

```text
Rule:        100004
Level:       10
Description: PowerShell executed with an encoded/Base64 command
MITRE:       T1059.001, T1027
Agent:       CLIENT01
```

The raw event shows:

```text
Image:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage:  C:\Windows\System32\cmd.exe
CommandLine:  powershell.exe -NoProfile -EncodedCommand <base64>
User:         CYBERLAB\alice.johnson
```

Two things stand out: an **encoded command** (worth decoding before drawing conclusions), and a **`cmd.exe` parent** rather than `explorer.exe` or another PowerShell session — a pivot worth tracing further back.

### 2.2 Decoding the Payload

```powershell
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<base64>"))
```
Result: `Write-Host "SIM01-STEP2-EVASION"`

**Assessment:** the decoded payload is benign — a harmless string output, not a download cradle, credential harvester, or persistence mechanism. This scopes the impact of this specific step regardless of the chain's broader intent.

### 2.3 Tracing the Parent Lineage

Tracing `cmd.exe`'s own parent via `ParentProcessGuid` leads to:

```text
Rule:        100003
Level:       6
Description: cmd.exe spawned by PowerShell
```

And tracing one hop further back, the `powershell.exe` that spawned `cmd.exe` shares its process lineage with:

```text
Rule:        100002
Level:       5
Description: PowerShell process execution detected
```

This lowest-severity alert is the **true starting point** of the chain — easily missed if triage stops at the highest-severity alert alone.

### 2.4 Full Reconstructed Timeline

```text
[100002] powershell.exe launched               — CYBERLAB\alice.johnson
       ↓
[100004] powershell.exe (parent: cmd.exe)
         -EncodedCommand → decodes to a benign Write-Host string
       ↓
[100003] cmd.exe spawned directly by the same powershell.exe lineage
       ↓
[92031/92033] Discovery — net user (account enumeration, default-rule coverage)
       ↓
         whoami /all, systeminfo executed — NOT alerted 
         (confirmed gap, see 11-attack-simulations.md Section 6)
```

**Scope:** single host (`CLIENT01`), single account (`CYBERLAB\alice.johnson`), no lateral movement, no persistence mechanism observed, no data staged or exfiltrated.

### 2.5 Root Cause

**What telemetry alone establishes:** the raw evidence cannot distinguish this from a legitimate administrator running a diagnostic or test script versus early-stage adversary reconnaissance. Both would produce an identical telemetry footprint — execution, an encoded test command, a process pivot, and account/system enumeration. Resolving that ambiguity in a real environment would require context outside Sysmon/Wazuh telemetry: confirming with the user directly, checking change-management records, or correlating with additional EDR behavioral data.

**Disclosure (as lab operator, not derived from telemetry):** this was a deliberate, self-generated simulation (`11-attack-simulations.md`, Simulation 01), confirmed benign by design.

---

## 3. Incident 02 — Authentication Anomaly (Logon Type 11 / Type 2)

### 3.1 Initial Alert

Two alerts from `CLIENT01`, milliseconds apart:

```text
Alert A — Rule 60122 (Wazuh default) — Level 5 — LogonType 11
Alert B — Rule 100005 (custom)       — Level 7 — LogonType 2
```

### 3.2 Correlating the Two Events

| Field | Alert A (Type 11) | Alert B (Type 2) |
|---|---|---|
| `targetUserName` | Administrator | Administrator |
| `status` / `subStatus` | 0xc000006d / 0xc000006a | 0xc000006d / 0xc000006a |
| `processName` (caller) | `consent.exe` | `consent.exe` |
| `ipAddress` | ::1 (loopback) | ::1 (loopback) |
| `eventRecordID` | 37924 | 37925 (sequential) |

Every field matches except `logonType` and the sequential `eventRecordID`. **This is one logical authentication attempt, logged as two separate Windows events** — not two independent failures. `consent.exe` as the caller process identifies this as a **UAC elevation prompt**; the loopback address confirms it originated locally, not over the network.

### 3.3 Why Only One Alert Carried Specific Detection

Wazuh's default rule `60122` matches Event ID 4625 broadly, regardless of `logonType`. The custom rule `100005` (Level 7) outranks it for the Type 2 event, becoming that event's recorded alert. The Type 11 event, lacking any custom rule targeting it, falls through to `60122` as its only match.

**This means the gap is not "no detection" — it is that the custom ruleset's added specificity does not extend to Type 11**, even though matching default-rule coverage and the underlying telemetry both exist.

### 3.4 Scope

Single host, single local account (`Administrator`), local-only, single occurrence — not a repeated pattern (consistent with the existing caveat on rule `100005`: one failure does not establish brute force).

### 3.5 Root Cause

**What telemetry alone establishes:** a local UAC elevation attempt failed due to an incorrect password, generating two related audit events, only one of which received purpose-built detection.

**What telemetry alone cannot establish:** whether the password was mistyped by a legitimate user or entered incorrectly during an unauthorized local privilege-escalation attempt. Both produce an identical footprint.

**Disclosure (as lab operator):** deliberate reproduction for `11-attack-simulations.md`, Simulation 02 — confirmed benign, constructed specifically to characterize the detection gap.

---

## 4. Investigation Findings Summary

| Incident | Trigger | Root Cause | Detection Performance |
|---|---|---|---|
| 01 — Execution chain | Highest-severity alert (`100004`), traced backward and forward | Self-generated simulation; telemetry alone cannot distinguish from legitimate admin activity | 3 of 4 chain steps alerted with full specificity; discovery sub-step partially covered by default rules only |
| 02 — Auth anomaly | Two near-simultaneous alerts, different rules | Single UAC elevation attempt, logged as two Windows events; telemetry alone cannot distinguish mistyped-by-owner from unauthorized attempt | One event received specific detection (`100005`); the other received only generic default coverage (`60122`) |

---

## 5. Key Lessons

**Triage from severity, not chronology.** Incident 01 was reconstructed starting from the highest-severity alert and traced outward via process lineage, rather than read top-to-bottom in execution order. This mirrors how alerts actually surface to an analyst and produced a more realistic investigation than a linear walkthrough would have.

**Correlation requires field-level comparison, not just timing.** Incident 02's two alerts arrived close together, but the relationship between them was only established by comparing `status`, `subStatus`, `processName`, and `eventRecordID` directly — proximity in time alone would not have proven they were the same logical event.

**Telemetry has a hard ceiling on what it can prove.** Both incidents reached the same structural conclusion: the raw evidence is consistent with both a benign explanation and a malicious one, and nothing in Sysmon or Windows Security auditing alone can resolve that ambiguity. Naming this limit explicitly, rather than letting the write-up imply more certainty than the evidence supports, is treated as a feature of the investigation, not a gap in it.

**A detection gap and a total blind spot are different findings.** Incident 02 refined Phase 11's own finding further — the Type 11 event was never invisible; it received a generic, lower-specificity alert throughout. The precise language distinguishing "no alert" from "alerted, but not with full specificity" is the actual analytical contribution of this investigation.

**Self-generated evidence requires an explicit disclosure boundary.** Every conclusion in this document that depends on the investigator's dual role as lab operator is marked separately from what the telemetry itself supports, so the analytical method demonstrated here would hold up against genuinely unknown activity, not only against activity the investigator already understood.

---

## 6. Current Status

Two incidents have been reconstructed from Phase 11 telemetry using an alert-first investigative posture: a multi-step execution chain traced from its highest-severity alert backward and forward to establish a full timeline, and a dual-event authentication anomaly correlated at the field level to determine it represented one logical event rather than two. Both investigations reached a clear structural conclusion about what the telemetry can and cannot establish, and both explicitly separate that conclusion from information only available because the underlying activity was self-generated.

## 7. Next Step — Incident Response

With both incidents investigated and scoped, the next phase documents the response actions that would follow — containment, eradication, recovery, and recommendations — including a specific recommendation, arising directly from Incident 02, to extend rule `100005`'s coverage to Logon Type 11 as a concrete outcome of this investigation.

See `13-incident-response.md`.