# 07 — Detection Engineering

## Overview

With centralized telemetry from `CLIENT01` confirmed in `06-soc01-security-monitoring-platform.md`, this phase moves from log collection to detection engineering — writing, testing, validating, and documenting custom Wazuh rules against real security-relevant behavior.

The objective is not simply to create rules that match logs. Each detection follows a repeatable engineering process:

```text
Behavior
   ↓
Existing Coverage
   ↓
Detection Gap
   ↓
Custom Rule
   ↓
Controlled Telemetry
   ↓
Alert Validation
   ↓
Documentation
```

Four custom detections were developed during this phase.

They cover:

* PowerShell process execution
* Encoded PowerShell execution from a non-PowerShell parent
* Suspicious PowerShell → cmd.exe process chaining
* Failed interactive Windows logons

The detections use both:

```text
Sysmon Event ID 1
Windows Security Event ID 4625
```

The phase also exposed several practical detection-engineering problems, including regex escaping, decoder limitations, Base64 test-data handling, rule-priority behavior, and temporary telemetry loss during manager restarts.

These debugging findings are documented because understanding why a detection fails is an important part of building reliable security detections.

---

# 1. Detection Engineering Strategy

The detection sequence was designed to progress from simple process identification toward more contextual behavioral detection.

### Detection 01 — PowerShell Process Execution

```text
Rule:       100002
Telemetry:  Sysmon Event ID 1
Behavior:   powershell.exe / pwsh.exe execution
MITRE:      T1059.001
Status:     Validated
```

This establishes a basic PowerShell execution signal.

### Detection 02 — Encoded PowerShell Command

```text
Rule:       100004
Telemetry:  Sysmon Event ID 1
Behavior:   PowerShell -EncodedCommand from a non-PowerShell parent
MITRE:      T1059.001, T1027
Status:     Validated
```

This extends the PowerShell baseline into command obfuscation and specifically addresses a gap left by an existing Wazuh rule.

### Detection 03 — PowerShell → cmd.exe Process Chain

```text
Rule:       100003
Telemetry:  Sysmon Event ID 1
Behavior:   cmd.exe spawned directly by PowerShell
MITRE:      T1059.003
Status:     Validated
```

This demonstrates process-chain detection using parent-child relationships rather than simply matching an executable.

### Detection 04 — Failed Interactive Logon

```text
Rule:       100005
Telemetry:  Windows Security Event ID 4625
Behavior:   Failed interactive logon
MITRE:      T1110
Status:     Validated
```

This extends the detection set beyond Sysmon into Windows Security authentication telemetry.

---

# 2. Detection Engineering Workflow

Every detection followed the same seven-step workflow:

```text
1. Identify behavior
       ↓
2. Check existing Wazuh coverage
       ↓
3. Find a useful detection gap
       ↓
4. Create custom rule
       ↓
5. Generate controlled telemetry
       ↓
6. Validate alert
       ↓
7. Document detection
```

Checking existing coverage before writing a rule was particularly important.

It prevented redundant detections and exposed differences between what an existing rule's description appeared to detect and what its actual matching conditions covered.

Detection 02 is the clearest example: the initial idea overlapped with an existing Wazuh rule, but inspection of that rule revealed a narrower coverage condition. The custom detection was then redesigned around the uncovered case.

---

# 3. Wazuh Rule Structure

Custom Wazuh rules were added to:

```text
/var/ossec/etc/rules/local_rules.xml
```

The rules use Wazuh's XML rule structure to combine:

* Parent rules or event groups
* Specific event fields
* PCRE2 regular expressions
* Severity levels
* MITRE ATT&CK mappings
* Human-readable descriptions
* Detection categorization

For example, Detection 01 uses:

```xml
<if_group>sysmon_event1</if_group>
```

to restrict the detection to Sysmon process-creation telemetry.

It then matches the process image:

```xml
<field name="win.eventdata.image" type="pcre2">
(?i)(powershell|pwsh)\.exe$
</field>
```

Multiple `<field>` conditions within the same rule provide AND-style matching, allowing detections to express more specific behavior.

---

# 4. Detection 01 — PowerShell Process Execution

## Rule

```xml
<rule id="100002" level="5">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)(powershell|pwsh)\.exe$</field>
  <description>PowerShell process execution detected</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

### Behavior

The rule detects the creation of:

```text
powershell.exe
pwsh.exe
```

from Sysmon Event ID `1`.

MITRE ATT&CK mapping:

```text
T1059.001 — PowerShell
```

### Coverage Check

Before creating the rule, the existing Wazuh ruleset was inspected.

No existing rule was identified that provided the same simple baseline signal based purely on the PowerShell executable image.

The custom rule therefore provides a basic PowerShell execution signal that can serve as a foundation for more specific PowerShell detections.

## Validation

A live PowerShell process was executed on `CLIENT01`.

The resulting telemetry was received by `SOC01`, and the custom rule generated an alert.

Validation was performed against:

```text
/var/ossec/logs/alerts/alerts.json
```

rather than relying solely on the Wazuh Dashboard.

## Debugging

The first version of the rule failed to fire.

The problem was a regex path-escaping mismatch.

The initial pattern expected a specific backslash immediately before the executable name. However, the JSON representation of the Windows path contained escaped backslashes, so the expected pattern did not match the actual field value.

The rule was simplified to match the executable filename directly:

```regex
(?i)(powershell|pwsh)\.exe$
```

This removed the unnecessary path dependency and successfully matched the real Sysmon field.

### Wazuh Logtest Limitation

A second issue appeared when attempting to validate the rule using:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

The hand-entered JSON was processed through the generic JSON decoder rather than the `windows_eventchannel` decoder used by the actual agent telemetry.

Because the rule depends on:

```xml
<if_group>sysmon_event1</if_group>
```

the manually supplied event did not enter the same rule-processing path as real Sysmon Event Channel telemetry.

This demonstrated an important limitation:

```text
Synthetic JSON → generic decoder
Real Windows telemetry → windows_eventchannel decoder
```

Therefore, for these detections, live telemetry was used as the final validation method.

---

# 5. Detection 02 — Encoded PowerShell from a Non-PowerShell Parent

## Rule

```xml
<rule id="100004" level="10">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)(powershell|pwsh)\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?\b</field>
  <description>PowerShell executed with an encoded/Base64 command ($(win.eventdata.commandLine))</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1027</id>
  </mitre>
</rule>
```

### Behavior

The detection identifies PowerShell executions using the:

```text
-EncodedCommand
```

option, including valid abbreviated forms such as:

```text
-e
-enc
-enco
-encod
...
```

The detection is specifically useful when the PowerShell process originates from a **non-PowerShell parent**.

MITRE mappings:

```text
T1059.001 — PowerShell
T1027     — Obfuscated Files or Information
```

---

## Existing Coverage Investigation

Before creating the custom rule, existing Wazuh coverage was inspected.

The default Wazuh ruleset already contains rule:

```text
92057
```

with the description:

```text
Powershell.exe spawned a powershell process which executed a base64 encoded command
```

However, inspection of the rule's actual conditions showed that it depends on the parent process being PowerShell.

Therefore, the existing rule primarily covers:

```text
PowerShell
   ↓
PowerShell -EncodedCommand
```

The custom detection was designed to cover the complementary case:

```text
cmd.exe / other parent
   ↓
PowerShell -EncodedCommand
```

This transformed the original idea from potentially duplicate coverage into a more specific detection gap.

---

# 6. Detection 02 Debugging Investigation

Detection 02 required the most troubleshooting of the phase.

Several separate issues were identified.

## 6.1 Plaintext Marker Testing Was Invalid

Initial tests used a plaintext marker such as:

```text
WAZUH-ENCODED-TEST
```

and searched:

```text
archives.json
```

for the plaintext marker.

This was not a valid test method.

When PowerShell uses:

```text
-EncodedCommand
```

the command is supplied to PowerShell as Base64-encoded data.

For example, the command:

```powershell
Write-Host 'WAZUH-ENCODED-TEST'
```

was encoded as:

```text
VwByAGkAdABlAC0ASABvAHMAdAAgACcAVwBBAFoAVQBIAC0ARQBOAEMATwBEAEUARAAtAFQARQBTAFQAJwA=
```

Sysmon records the command line that was executed, including the encoded value.

Therefore, searching for:

```text
WAZUH-ENCODED-TEST
```

was guaranteed to return nothing.

The correct validation method was to search for the actual encoded command-line value.

---

## 6.2 Agent Buffer Overflow

During one test cycle, the Wazuh agent reported:

```text
WARNING: Agent buffer is full: Events may be lost.
WARNING: Agent buffer is flooded: Producing too many events.
ERROR: Lost connection with manager. Setting lock.
```

This occurred around a Wazuh manager restart.

Restarting the manager to reload rules temporarily interrupts agent connectivity.

If telemetry is generated during that period, events may be delayed or lost.

The affected test cycle was therefore discarded and the test was repeated after the agent reconnected and stabilized.

This was an operational telemetry problem rather than a detection-rule problem.

---

## 6.3 Regex Validation

The regex was tested independently against the actual captured Sysmon `commandLine` value.

This confirmed that the regex itself correctly matched the encoded PowerShell command-line indicator.

This isolated the problem away from the regular expression and toward the Wazuh processing pipeline.

---

## 6.4 Rule Priority

The captured encoded PowerShell event also matched the existing Wazuh rule:

```text
92057
```

which has:

```text
Level 12
```

while the custom rule:

```text
100004
```

has:

```text
Level 10
```

The same event could therefore satisfy multiple detection conditions.

The visible alert was claimed by the higher-level matching rule rather than appearing as the lower-level custom alert.

This explained why searching for:

```text
100004
```

produced no result even though the event itself clearly contained the encoded PowerShell behavior.

The investigation was further supported by observing that the simpler PowerShell detection:

```text
100002
```

also did not appear for the same event when the higher-level rule claimed it.

This demonstrated that the issue was not specific to the Detection 02 regex.

---

## 6.5 Final Validation Scenario

Instead of increasing the severity of `100004` merely to override the existing rule, the test was changed to a scenario outside the coverage of rule `92057`.

The following process chain was used:

```text
cmd.exe
   ↓
powershell.exe -EncodedCommand
```

In this scenario:

```text
ParentImage = cmd.exe
```

so the parent-PowerShell condition required by `92057` was not satisfied.

The custom rule:

```text
100004
```

then generated its own alert successfully.

This confirmed that the custom rule was providing distinct coverage rather than simply duplicating rule `92057`.

---

# 7. Detection 03 — cmd.exe Spawned by PowerShell

## Rule

```xml
<rule id="100003" level="6">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)cmd\.exe$</field>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)(powershell|pwsh)\.exe$</field>
  <description>cmd.exe spawned by PowerShell ($(win.eventdata.parentImage) -> $(win.eventdata.image))</description>
  <mitre>
    <id>T1059.003</id>
  </mitre>
</rule>
```

## Behavior

The rule detects the following direct process relationship:

```text
powershell.exe
       ↓
     cmd.exe
```

The detection therefore uses two fields:

```text
Image       = cmd.exe
ParentImage = powershell.exe / pwsh.exe
```

Both conditions must be satisfied by the same Sysmon Event ID 1 event.

MITRE mapping:

```text
T1059.003 — Windows Command Shell
```

## Coverage Check

Existing Wazuh rules referencing `cmd.exe` and process relationships were inspected.

These rules covered adjacent scenarios, including:

* cmd.exe spawning other processes
* cmd.exe executing from unusual locations
* suspicious children of command shells

However, the specific relationship:

```text
PowerShell → cmd.exe
```

was not covered by the existing rules examined.

This provided a useful example of process-chain detection.

## Validation

A controlled PowerShell → cmd.exe execution was generated on `CLIENT01`.

The event was received by `SOC01` and the custom rule generated the expected alert.

No additional debugging was required because the field structure and decoder behavior had already been established during Detection 01.

---

# 8. Detection 04 — Failed Interactive Logon

## Rule

```xml
<rule id="100005" level="7">
  <if_sid>60122</if_sid>
  <field name="win.eventdata.logonType">2</field>
  <description>Failed interactive logon detected for $(win.eventdata.targetUserName) on $(win.system.computer)</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failed,windows_security,</group>
</rule>
```

## Behavior

This detection is based on Windows Security Event ID:

```text
4625 — An account failed to log on
```

The custom rule uses the existing Wazuh rule:

```text
60122
```

as its parent condition.

It then restricts the detection to:

```text
Logon Type = 2
```

which represents an interactive logon attempt.

The resulting telemetry chain is:

```text
CLIENT01
    ↓
Windows Security Event 4625
    ↓
Wazuh rule 60122
    ↓
Custom rule 100005
    ↓
Level 7 alert
```

MITRE mapping:

```text
T1110 — Brute Force
```

The mapping represents the behavioral category this detection can contribute to; a single failed logon does **not** by itself establish that a brute-force attack occurred.

---

# 9. Detection 04 Validation

A controlled failed authentication attempt was generated on `CLIENT01`.

The corresponding Event ID `4625` was received by `SOC01`.

The captured telemetry included:

```text
User:
CYBERLAB\alice.johnson

Computer:
CLIENT01.cyberlab.local

Logon Type:
2

Status:
0xc000006d

SubStatus:
0xc000006a

Source:
::1
```

The custom Wazuh rule then generated:

```text
Rule ID:
100005

Level:
7
```

The alert was verified in:

```text
/var/ossec/logs/alerts/alerts.json
```

This confirmed that Windows Security authentication telemetry could be used alongside Sysmon telemetry within the same detection-engineering workflow.

---

# 10. Dashboard Validation

The primary validation method during this phase was direct inspection of Wazuh's generated alerts:

```text
/var/ossec/logs/alerts/alerts.json
```

The Wazuh Dashboard was not used as the primary validation mechanism.

This is acceptable because the purpose of this phase was to validate the detection logic and confirm that the Wazuh rule engine generated the expected alerts.

Dashboard visualization is primarily useful for:

* Analyst workflow validation
* Searching and filtering alerts
* Building dashboards
* Demonstrating the detections visually
* Portfolio screenshots

Dashboard screenshots can therefore be added later without changing the underlying detection-validation results documented in this phase.

---

# 11. False Positive Considerations

## Rule 100002 — PowerShell Process Execution

Potential false positives include:

* Legitimate administrative scripting
* Scheduled tasks
* Configuration-management software
* Software installers
* Normal enterprise automation

The low severity:

```text
Level 5
```

reflects that this is primarily a baseline signal rather than a high-confidence malicious detection.

---

## Rule 100003 — PowerShell → cmd.exe

Potential false positives include:

* Legitimate scripts
* Batch-file compatibility
* Administrative automation
* Software installers

The parent-child relationship provides useful context but does not independently establish malicious activity.

Additional context such as:

```text
User
Parent process
Command line
Frequency
Time of execution
```

should be considered during triage.

---

## Rule 100004 — Encoded PowerShell

Potential false positives include:

* Configuration-management tools
* Scheduled scripts
* Administrative automation
* Legitimate applications that use encoded PowerShell arguments

The detection is intentionally scoped to encoded PowerShell originating from a non-PowerShell parent, reducing overlap with existing coverage such as rule `92057`.

---

## Rule 100005 — Failed Interactive Logon

Potential false positives include:

* User typing the wrong password
* Forgotten credentials
* Normal authentication mistakes
* Local testing

A single failed logon is therefore a relatively weak signal.

Its security value increases when multiple failures are correlated by:

```text
User
Source
Time window
Number of attempts
```

Repeated-failure correlation is intentionally deferred to a later phase.

---

# 12. Detection Testing Methodology

Testing was performed using controlled activity on `CLIENT01`.

The general process was:

```text
Generate controlled behavior
        ↓
Confirm Windows/Sysmon telemetry
        ↓
Confirm event reached SOC01
        ↓
Check Wazuh processing
        ↓
Search alerts.json
        ↓
Verify custom rule ID
        ↓
Inspect fields and MITRE mapping
```

The final validation was based on **real telemetry generated by the Windows endpoint**, rather than purely synthetic JSON.

This distinction was important because the custom Sysmon rules depend on the event structure and decoder context produced by the Windows Event Channel integration.

---

# 13. Alert Validation

The four custom rules were validated through the Wazuh alert pipeline.

The relevant validation evidence was obtained from:

```text
/var/ossec/logs/alerts/alerts.json
```

Examples of validated rule IDs:

```text
100002
100003
100004
100005
```

The alerts contained the expected:

* Rule ID
* Severity
* Agent
* Event source
* Windows event fields
* Process information where applicable
* MITRE ATT&CK mapping

This confirmed that the rules were not merely syntactically valid — they successfully generated alerts from real endpoint telemetry.

---

# 14. Detection Coverage Summary

| Detection                    |     Rule | Telemetry              | Behavior                                      | MITRE            | Status       |
| ---------------------------- | -------: | ---------------------- | --------------------------------------------- | ---------------- | -----------  |
| PowerShell Process Execution | `100002` | Sysmon Event ID 1      | PowerShell execution                          | T1059.001        | ✅ Validated |
| Encoded PowerShell           | `100004` | Sysmon Event ID 1      | Encoded PowerShell from non-PowerShell parent | T1059.001, T1027 | ✅ Validated |
| PowerShell → cmd.exe         | `100003` | Sysmon Event ID 1      | Suspicious parent-child process chain         | T1059.003        | ✅ Validated |
| Failed Interactive Logon     | `100005` | Security Event ID 4625 | Interactive authentication failure            | T1110            | ✅ Validated |

The four detections provide coverage across two different telemetry sources:

```text
                 CLIENT01
                    │
          ┌─────────┴───────────┐
          │                     │
        Sysmon            Windows Security
          │                     │
      Event ID 1           Event ID 4625
          │                     │
     ┌────┴────┐                │
     │         │                │
 PowerShell  Process       Failed Logon
   Activity   Chain             │
     │         │                │
     └────┬────┘                │
          │                     │
          └──────────┬──────────┘
                     ↓
                Wazuh Rules
                     ↓
                SOC01 Alerts
```

---

# 15. Key Detection Engineering Lessons

## 15.1 Check Existing Coverage First

A detection should not be created simply because a behavior appears interesting.

Existing rules must be inspected first.

Detection 02 demonstrated why.

The initial concept overlapped with existing Wazuh coverage, but inspection of the actual rule conditions revealed an uncovered variant.

The final rule therefore addressed a genuine detection gap.

---

## 15.2 Rule Descriptions Are Not Enough

An existing rule's description may describe a broad behavior while its actual matching conditions cover a narrower scenario.

Detection engineering requires inspecting:

```text
Rule ID
Conditions
Parent rules
Event fields
Regular expressions
Severity
```

rather than relying only on the description.

---

## 15.3 Live Telemetry Matters

Synthetic JSON testing through `wazuh-logtest` was not sufficient for rules depending on the Windows Event Channel decoding context.

The final validation therefore used:

```text
CLIENT01 → real Windows/Sysmon telemetry → SOC01
```

This is more representative of the production detection path being built.

---

## 15.4 Test the Actual Logged Representation

The encoded PowerShell investigation demonstrated an important principle.

The value visible to the analyst may not be the same representation used by the endpoint telemetry.

For encoded commands:

```text
Human-readable command
        ↓
Base64 encoding
        ↓
Sysmon commandLine
        ↓
      Wazuh
```

Searching for the original plaintext marker therefore produced no useful result.

Testing must match the representation actually present in the telemetry field.

---

## 15.5 Alert Visibility and Rule Matching Are Different Problems

A rule can potentially match an event without its individual alert becoming visible when another higher-level rule claims the event.

Therefore, when a custom rule appears not to fire:

```text
Do not immediately assume the regex is broken.
```

Instead investigate:

```text
Event received?
        ↓
Correct decoder?
        ↓
Correct field?
        ↓
Rule loaded?
        ↓
Regex matches?
        ↓
Another rule also matches?
        ↓
Higher-level rule claiming the alert?
```

This was the central lesson from Detection 02.

---

## 15.6 Operational Problems Can Look Like Detection Problems

The Wazuh agent buffer overflow demonstrated that telemetry can be lost during manager restarts or connectivity interruptions.

Therefore:

```text
No alert
```

does not automatically mean:

```text
Broken detection
```

The telemetry pipeline itself must also be considered.

---

## 15.7 Isolate Variables During Troubleshooting

Detection 02 was ultimately resolved by testing each layer independently:

```text
Rule file
   ↓
Manager configuration
   ↓
Rule syntax
   ↓
Regex matching
   ↓
Telemetry arrival
   ↓
Decoder behavior
   ↓
Existing rule coverage
   ↓
Rule priority
```

This approach prevented the investigation from incorrectly blaming the regex when the actual issue was alert competition with an existing higher-level rule.

---

# 16. Current Wazuh Rule Set

The final custom rules currently present in:

```text
/var/ossec/etc/rules/local_rules.xml
```

are:

```text
100002 — PowerShell process execution
100003 — cmd.exe spawned by PowerShell
100004 — Encoded PowerShell from non-PowerShell parent
100005 — Failed interactive logon
```

The rules were syntax-validated and loaded by the Wazuh manager.

All four detections were subsequently validated against real telemetry generated on `CLIENT01`.

---

# 17. Current Status

The detection-engineering phase is complete.

Four custom Wazuh detections have been:

```text
Designed
   ↓
Implemented
   ↓
Syntax validated
   ↓
Deployed
   ↓
Tested against live telemetry
   ↓
Alert validated
   ↓
Documented
```

Current coverage includes:

```text
PowerShell execution
Encoded PowerShell
PowerShell → cmd.exe process chaining
Failed interactive logon
```

The detections demonstrate coverage across:

```text
Sysmon
Windows Security Events
```

and provide practical examples of:

* Process-based detection
* Command-line detection
* Parent-child process detection
* Authentication detection
* MITRE ATT&CK mapping
* False-positive analysis
* Detection troubleshooting
* Existing-rule coverage analysis

---

# 18. Deferred Detection Opportunities

The following detections are intentionally deferred to later phases:

### Repeated Authentication Failures

The current `100005` rule detects individual failed interactive logons.

A future correlation rule can detect patterns such as:

```text
Multiple failures
      ↓
Same account / source
      ↓
Defined time window
      ↓
Threshold exceeded
      ↓
Potential brute-force detection
```

This will provide a more meaningful implementation of brute-force detection than treating a single failed login as an attack.

### Additional Detection Opportunities

Future detections may include:

* LOLBin execution
* Suspicious scripting interpreters
* Defense-evasion behavior
* Credential-access behavior
* Persistence activity
* Suspicious scheduled tasks
* Suspicious service creation
* Process injection
* Unusual network connections

These are intentionally outside the scope of the current four-detection baseline.

---

# 19. Next Step — Sigma Rules

With four validated Wazuh detections established, the next phase moves toward vendor-neutral detection engineering using Sigma.

The workflow becomes:

```text
Observed Behavior
       ↓
Detection Logic
       ↓
Sigma Rule
       ↓
Wazuh / SIEM Implementation
       ↓
Telemetry Testing
       ↓
Alert Validation
```

The objective of the next phase is to translate the behavioral logic developed here into portable detection rules that can be understood independently of the Wazuh implementation.

The next document is:

```text
08-sigma-rules.md
```

This phase will build on the behaviors already validated here rather than starting from hypothetical detections.
