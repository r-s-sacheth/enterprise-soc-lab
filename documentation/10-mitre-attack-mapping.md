# 10 — MITRE ATT&CK Mapping

> **Update (Phase 13):** rule `100006` was added after this mapping was 
> written, extending detection coverage to Logon Type 11 and closing the 
> gap described in Section 7 below. The coverage matrix in this document 
> reflects the state of the lab as of Phase 10; see `13-incident-response.md` 
> for the resolution.

## Overview

This phase consolidates the detection and hunting work from Phases 07–09 into a single, evidence-based mapping against the MITRE ATT&CK framework. No new telemetry was generated and no new queries were run for this phase — every entry below is drawn directly from validated detections (`07-detection-engineering.md`), Sigma translations (`08-sigma-rules.md`), and hunt findings (`09-threat-hunting.md`) already committed to this repository.

The objective is to answer one question precisely:

> **What attacker behaviors can this SOC lab actually detect or investigate today, based on evidence — not based on what its tooling is theoretically capable of?**

```text
Real telemetry
      ↓
Detection / Hunt (Phases 07–09)
      ↓
Behavior identified
      ↓
MITRE ATT&CK technique
      ↓
Evidence
      ↓
Coverage or visibility gap
```

---

## 1. MITRE ATT&CK in the SOC Lab

MITRE ATT&CK is a knowledge base of adversary tactics and techniques, organized by the goal an attacker is trying to achieve (a *tactic*, e.g. Execution, Credential Access) and the specific method used to achieve it (a *technique*, e.g. T1059.001 — PowerShell).

This lab uses ATT&CK purely as a **mapping and coverage-tracking framework** for work already done — not as a checklist of techniques to claim. A technique only appears in this document if there is a specific rule, Sigma translation, or hunt in Phases 07–09 that produced real evidence for it.

---

## 2. Mapping Methodology

**The mapping in this document is built strictly from observed and validated behavior, not from telemetry capability.**

A defensible mapping looks like this:

```text
PowerShell executed
       ↓
Sysmon Event ID 1
       ↓
Wazuh rule 100002 (validated against live telemetry)
       ↓
T1059.001
```

This document deliberately avoids the inverse, non-defensible pattern:

```text
"Sysmon is deployed"
       ↓
"Therefore this lab can detect T1003, T1055, T1547, T1059, ..."
```

Having a telemetry source does not by itself constitute detection coverage. Three tiers of coverage are distinguished throughout this document:

| Tier         | Meaning                                                                                                                                                              |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Detected** | A Wazuh rule exists and has been validated against real, live-generated telemetry (Phase 07).                                                                        |
| **Hunted**   | No automated rule exists for this specific behavior, but the behavior was investigated via a manual query against raw telemetry (Phase 09), with a recorded outcome. |
| **Gap**      | Telemetry exists that could support detection or hunting of this behavior, but no rule currently alerts on it and no hunt has fully covered it.                      |


A technique appearing under "Detected" or "Hunted" does not mean every variant of that technique is covered — only the specific behavior actually tested. This distinction is maintained explicitly throughout Section 5.

---

## 3. Detection Coverage

| Technique        | Name                                        | Detection     | Telemetry                 | Validation                                                                 |
| ---------------- | ------------------------------------------- | ------------- | ------------------------- | -------------------------------------------------------------------------- |
| T1059.001        | PowerShell                                  | Rule `100002` | Sysmon EID 1              | Validated — `07-detection-engineering.md` Section 4                        |
| T1059.001, T1027 | PowerShell; Obfuscated Files or Information | Rule `100004` | Sysmon EID 1              | Validated — `07-detection-engineering.md` Section 5                        |
| T1059.003        | Windows Command Shell                       | Rule `100003` | Sysmon EID 1              | Validated — `07-detection-engineering.md` Section 7                        |
| T1110            | Brute Force                                 | Rule `100005` | Windows Security EID 4625 | Validated — `07-detection-engineering.md` Section 8 (see scope note below) |


Each of these detections also has a corresponding Sigma translation, independently validated against Wazuh's OpenSearch backend (`08-sigma-rules.md`), confirming the same detection logic is portable beyond Wazuh's specific rule syntax.

**Scope note — T1110:** rule `100005` detects a single failed interactive logon (Event ID 4625, Logon Type 2). This is a precursor event type relevant to brute-force activity, not a validated brute-force *detection* — no correlation logic (multiple failures, time window, threshold) currently exists. This distinction was documented in Phase 07 and is preserved here rather than allowing the technique ID alone to imply broader coverage than what was built.

---

## 4. Threat Hunting Coverage

| Hunt                                 | Technique(s)        | Outcome                                                                            | Evidence                         |
| ------------------------------------ | ------------------- | ---------------------------------------------------------------------------------- | -------------------------------- |
| 01 — Unusual PowerShell parents      | T1059.001 (context) | No unexplained activity observed                                                   | `09-threat-hunting.md` Section 5 |
| 02 — Rare process relationships      | —                   | No unexplained activity observed; no single technique fit the hunt's general scope | `09-threat-hunting.md` Section 6 |
| 03 — Obfuscation indicators          | T1027, T1140        | No observed activity to evaluate                                                   | `09-threat-hunting.md` Section 7 |
| 04 — Authentication failure patterns | T1110 (context)     | **Coverage gap identified** — see Section 7                                        | `09-threat-hunting.md` Section 8 |


Hunt 02 is intentionally left without a technique mapping. It investigated parent-child process relationships broadly, rather than one specific execution pattern, and forcing a technique ID onto it would overstate what was actually examined.

---

## 5. Technique Analysis

### T1059.001 — PowerShell

```text
Sysmon Event ID 1
        ↓
Image matches powershell.exe / pwsh.exe
        ↓
Rule 100002 → Alert
```
Straightforward, unqualified coverage: any PowerShell execution is detected regardless of context.

### T1027 — Obfuscated Files or Information

The lab's coverage of this technique is specific, not general:

```text
T1027
  └── Encoded PowerShell command (-EncodedCommand flag, from a non-PowerShell parent)
```

This is **not** general coverage of T1027. Other obfuscation methods (compressed payloads, custom encoding schemes, binary padding, etc.) are not addressed by any current rule.

### T1059.003 — Windows Command Shell

```text
powershell.exe
      │
      └── cmd.exe
              ↓
         Rule 100003 → Alert
```
Coverage is specific to the `powershell.exe → cmd.exe` parent-child pair. `cmd.exe` spawned by other processes is not covered by this rule.

### T1110 — Brute Force

```text
Observed:
  Single failed interactive logon (Event ID 4625, Logon Type 2, bad password)

Not demonstrated:
  Repeated authentication attempts
  Multi-account or multi-source correlation
  An actual brute-force campaign
```

The rule detects the underlying event type a brute-force campaign would generate, but the lab has not yet simulated or validated detection of the campaign pattern itself. This is a deliberate scope boundary, not an oversight — correlation-based detection is deferred to future detection-engineering work (see `07-detection-engineering.md` Section 18).

---

## 6. Telemetry-to-Technique Mapping

| Telemetry Source                     | Event Type                                       | Techniques Enabled                    |
| ------------------------------------ | ------------------------------------------------ | ------------------------------------- |
| Sysmon Event ID 1 (Process Creation) | Process execution and parent-child relationships | T1059.001, T1027 (partial), T1059.003 |
| Windows Security Event ID 4625       | Failed logon activity                            | T1110 (precursor event only)          |

Sysmon is currently configured for Process Creation, Network Connections, File Creation, Registry Events, and DNS Queries (`05-windows-security-monitoring.md`), but only Process Creation telemetry has been used in a validated detection or hunt to date. Network, file, and registry telemetry are collected but not yet mapped to any technique in this document — this is itself noted as a limitation in Section 8.

---

## 7. Coverage Gap Identified During Threat Hunting

```text
Hunt:              04 — Authentication Failure Patterns
Behavior sought:    Failed logons beyond rule 100005's Logon Type 2 scope
Telemetry available: Windows Security Event ID 4625, all logon types, 
                     queried via wazuh-archives-*
Observed:           Logon Type 11 (CachedInteractive) failures occur in 
                     this environment
Specific instance:   consent.exe (UAC elevation) failing to authenticate 
                     the local Administrator account — a benign 
                     credential-entry error, not an attack
Why coverage is 
insufficient:        Rule 100005 explicitly filters to logonType:2, 
                     excluding Type 11 by design
```

**Technique mapping for this gap is deliberately left open.** The gap concerns a monitoring blind spot (an uncovered logon type), not a confirmed attacker behavior. Labeling this gap with a specific technique ID (e.g. T1110 or T1078) would repeat the same overclaim already corrected in `09-threat-hunting.md` — the one observed Type 11 event was benign, and no pattern establishing credential-access abuse was found. The gap is recorded here as a candidate for future detection engineering, tied to the general Credential Access tactic rather than a specific technique.

---

## 8. Detection and Visibility Limitations

* **Single-endpoint scope.** All coverage in this document reflects telemetry from `CLIENT01` only. No coverage claims extend to `DC01` or `SOC01` itself, neither of which has custom detection rules.
* **Sysmon telemetry is under-utilized relative to what is collected.** Network Connection, File Creation, Registry, and DNS Query events are enabled in Sysmon's configuration but have not yet been used in any validated detection or hunt.
* **No correlation-based detections exist yet.** Every current rule matches a single event. Techniques that manifest as a *pattern* over time (brute force, repeated failed logons, beaconing) are not meaningfully covered by single-event matching alone.
* **Coverage reflects self-generated test activity.** As already noted in Phase 09, all telemetry underlying this mapping was produced by the person building the lab, not by independent or adversarial activity. This does not invalidate the mappings, but it means false-positive and false-negative rates under real, organic usage remain unverified.

---

## 9. Current ATT&CK Coverage

| Tactic            | Technique                                       | Status                          |
| ----------------- | ----------------------------------------------- | ------------------------------- |
| Execution         | T1059.001 — PowerShell                          | Detected                        |
| Execution         | T1059.003 — Windows Command Shell               | Detected                        |
| Defense Evasion   | T1027 — Obfuscated Files or Information         | Detected (scoped)               |
| Defense Evasion   | T1140 — Deobfuscate/Decode Files or Information | Hunted (no activity observed)   |
| Credential Access | T1110 — Brute Force                             | Detected (precursor event only) |
| Credential Access | General — Type 11 logon visibility              | **Gap**                         |


Tactics with **no current coverage at all** — no detection, no hunt, no telemetry mapping: Initial Access, Persistence, Privilege Escalation (beyond the incidental UAC event in Hunt 04), Lateral Movement, Collection, Exfiltration, Command and Control, Impact. These are not claimed anywhere in this document and are explicitly out of scope until addressed in a future phase.

---

## 10. Key Lessons

**A small, evidenced matrix is stronger than a large, unverified one.** This document maps four techniques with real supporting evidence rather than an expansive list implying broader capability than what was actually built and tested.

**Telemetry availability and detection coverage are not the same thing.** Sysmon collects five event categories; only one (process creation) has been used in a validated detection to date. Documenting this gap explicitly (Section 8) is more useful than letting the presence of a telemetry source imply coverage that doesn't exist.

**A gap doesn't need a technique ID to be worth recording.** Section 7's Logon Type 11 finding is documented without forcing it into T1110 or T1078, since neither is supported by the actual evidence. The gap's value is in identifying the blind spot, not in dressing it up with a specific ATT&CK label it hasn't earned.

**Mapping work surfaces its own next steps.** Building this matrix made two things concrete that were only implicit before: T1110 has no correlation logic, and entire tactics (Persistence, Lateral Movement, Exfiltration, etc.) have zero coverage. Both are now explicit inputs to Phase 11 rather than open-ended possibilities.

---

## 11. Current Status

Four detections, four hunts, and one identified coverage gap from Phases 07–09 have been consolidated into a single ATT&CK-based coverage matrix. The matrix distinguishes validated detection ("Detected"), manual investigation with a recorded outcome ("Hunted"), and confirmed visibility blind spots ("Gap"), and explicitly documents which tactics have no coverage at all rather than implying broader capability than what has been built.

## 12. Next Step — Attack Simulations

With current coverage and its limitations now explicit, the next phase moves from documentation to action: executing a chained sequence of attacker techniques (rather than isolated single-command tests) against `CLIENT01`, using this document's coverage matrix — particularly its uncovered tactics and the Logon Type 11 gap — to choose which techniques are worth simulating first.

See `11-attack-simulations.md`.