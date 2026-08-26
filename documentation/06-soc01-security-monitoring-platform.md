# 06 — SOC01 Security Monitoring Platform

## Overview

This stage of the lab establishes `SOC01` as the centralized security monitoring platform for the enterprise lab environment.

`SOC01` runs Wazuh, providing:

* Centralized log collection
* Endpoint agent management
* Windows Security Event ingestion
* Sysmon telemetry ingestion
* Detection rules and alerting
* A web dashboard for investigation and threat hunting

The objective of this phase was to connect `CLIENT01` to `SOC01` as a monitored endpoint and verify that both Windows Security Events and Sysmon telemetry are flowing into the platform end-to-end — from the endpoint, through the manager, into the indexer, and up into the dashboard.

---

## 1. SOC01 Baseline

| Component | Specification                       |
| --------- | ----------------------------------- |
| OS        | Ubuntu                              |
| Hostname  | `soc01`                             |
| Role      | Security monitoring / SIEM platform |

### Network Configuration

`SOC01` uses two interfaces, consistent with the rest of the lab's dual-network design described in `02-network-configuration.md`.

```yaml
# /etc/netplan/50-cloud-init.yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: true

    ens37:
      dhcp4: false
      addresses:
        - 192.168.100.30/24
      nameservers:
        addresses:
          - 192.168.100.10
        search:
          - cyberlab.local
```

* `ens33` — NAT interface (VMnet8), DHCP, provides Internet access
* `ens37` — Internal interface (VMnet1), static `192.168.100.30/24`, uses `DC01` for DNS

The configuration was tested and applied using:

```bash
sudo netplan try
sudo netplan apply
```

### Connectivity and DNS Validation

```bash
resolvectl query dc01.cyberlab.local
getent hosts dc01.cyberlab.local
```

Both confirmed that `SOC01` can resolve the domain controller through the internal DNS server.

Connectivity to `DC01` and `CLIENT01` over `192.168.100.0/24` was also verified.

### System Preparation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git unzip vim net-tools dnsutils jq
```

---

## 2. Monitoring Stack Selection

Wazuh was selected as the SOC platform for this lab.

Reasons for the selection:

* Provides endpoint agents for Windows out of the box
* Supports Windows Security Event and Sysmon `eventchannel` collection
* Provides a built-in detection rule engine with MITRE ATT&CK mapping
* Includes its own indexer and dashboard
* Free and open source, making it suitable for a home lab

Wazuh `4.14` was used for this deployment.

---

## 3. Wazuh Installation

### 3.1 Install Script and Configuration Generation

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
chmod +x wazuh-install.sh
sudo bash wazuh-install.sh --generate-config-files

curl -sO https://packages.wazuh.com/4.14/config.yml
cat config.yml
```

`config.yml` was edited to set the internal IP address (`192.168.100.30`) for the indexer, server, and dashboard nodes.

The configuration files were then regenerated:

```bash
sudo bash wazuh-install.sh --generate-config-files
```

### 3.2 Wazuh Indexer

The indexer was verified as reachable:

```bash
curl -k -u admin https://192.168.100.30:9200
```

The default `admin` password was rotated.

A new password hash was generated using:

```bash
sudo env JAVA_HOME=/usr/share/wazuh-indexer/jdk \
  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
```

The resulting hash was placed into:

```text
/etc/wazuh-indexer/opensearch-security/internal_users.yml
```

The security configuration was then reloaded:

```bash
sudo env JAVA_HOME=/usr/share/wazuh-indexer/jdk \
  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -f /etc/wazuh-indexer/opensearch-security/internal_users.yml \
  -icl \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -h 192.168.100.30 \
  -nhnv
```

The updated credentials were verified with:

```bash
curl -k -u admin https://192.168.100.30:9200
```

### 3.3 Wazuh Server (Manager)

The Wazuh manager was installed using:

```bash
sudo bash wazuh-install.sh --wazuh-server wazuh-1
```

The services were verified:

```bash
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status filebeat --no-pager
```

Listening ports were checked using:

```bash
sudo ss -tulpn | grep -E '1514|1515|55000|9200'
```

The expected ports were:

* `1514` — agent event traffic
* `1515` — agent enrollment
* `55000` — Wazuh API
* `9200` — Wazuh indexer

### 3.4 Filebeat and Keystore Credentials

Filebeat's output credentials were updated to match the new indexer password:

```bash
echo 'YOUR_NEW_ADMIN_PASSWORD' | sudo filebeat keystore add password --stdin --force
sudo systemctl restart filebeat
sudo filebeat test output
```

The Wazuh manager's indexer credentials were also updated:

```bash
sudo /var/ossec/bin/wazuh-keystore \
  -f indexer \
  -k username \
  -v admin

read -s WAZUH_PASS
unset WAZUH_PASS

sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

### 3.5 Wazuh Dashboard

The Wazuh package repository was added:

```bash
sudo apt-get install -y gnupg apt-transport-https

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
sudo gpg --no-default-keyring \
--keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
--import

sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update
sudo apt-get install -y wazuh-dashboard
```

The dashboard configuration was backed up before editing:

```bash
sudo cp /etc/wazuh-dashboard/opensearch_dashboards.yml \
  /etc/wazuh-dashboard/opensearch_dashboards.yml.bak

sudo nano /etc/wazuh-dashboard/opensearch_dashboards.yml
```

The indexer host IP and updated `admin` credentials were added.

The Wazuh app's own credentials were also updated:

```bash
sudo nano /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

The `wazuh-wui` credentials were configured so that the Wazuh dashboard application could authenticate with the Wazuh manager API.

---

## 4. Connecting CLIENT01 as a Wazuh Agent

### 4.1 Agent Installation

The Wazuh agent MSI was downloaded from the official Wazuh website and installed on `CLIENT01`.

The agent configuration was edited using:

```text
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

The `<server><address>` value was set to:

```text
192.168.100.30
```

### 4.2 Agent Registration

On `SOC01`, the agent was registered:

```bash
sudo /var/ossec/bin/manage_agents
```

The agent was added using:

```text
Name: CLIENT01
IP:   192.168.100.20
```

The resulting agent key was extracted.

On `CLIENT01`, the key was imported using:

```powershell
cd "C:\Program Files (x86)\ossec-agent"
.\manage_agents.exe
```

### 4.3 Starting the Agent

```powershell
Start-Service WazuhSvc
Get-Service WazuhSvc
```

### 4.4 Agent Verification

On `SOC01`:

```bash
sudo /var/ossec/bin/agent_control -l
```

The resulting agent list showed:

```text
ID: 000, Name: soc01 (server), IP: 127.0.0.1, Active/Local
ID: 001, Name: CLIENT01, IP: 192.168.100.20, Active
```

This confirmed that `CLIENT01` was enrolled and actively communicating with the manager.

---

## 5. Sysmon Telemetry Collection

In `05-windows-security-monitoring.md`, Sysmon Event ID `1` (Process Creation) was flagged as under investigation.

The event had already been confirmed in the local Sysmon Operational log on `CLIENT01`, but centralized collection had not yet been validated.

With the Wazuh agent installed, a dedicated `<localfile>` block was added to the agent configuration:

```text
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The Wazuh agent service was restarted on `CLIENT01` to apply the configuration.

---

## 6. Verifying Centralized Telemetry

### 6.1 Initial Symptom

A test process (`notepad.exe`) was launched on `CLIENT01`.

The event appeared immediately in the local Sysmon Operational log but did not initially appear in the default Wazuh dashboard view when searching:

```text
agent.name: "CLIENT01" AND data.win.system.eventID: 1
```

### 6.2 Root Cause

The issue was traced through the following checks:

1. **Agent connectivity**

   ```bash
   sudo /var/ossec/bin/agent_control -l
   ```

   `CLIENT01` was shown as `Active`, confirming that agent-to-manager communication was functioning.

2. **Manager-side raw archive**

   With Wazuh archiving enabled, the event was found in:

   ```text
   /var/ossec/logs/archives/archives.json
   ```

   This confirmed that the Sysmon event was reaching the Wazuh manager.

3. **Dashboard index**

   The Wazuh dashboard's default alert index is:

   ```text
   wazuh-alerts-*
   ```

   This index contains events that generate Wazuh alerts.

   The Sysmon Event ID `1` observed during the test was present in the raw archive but was not visible in the default alert index.

**Conclusion:** centralized telemetry ingestion was functioning correctly. The issue was visibility in the alert index rather than an agent, network, or manager ingestion failure.

### 6.3 Enabling the Archives Index

Filebeat archive shipping was confirmed to be enabled:

```yaml
archives:
  enabled: true
```

Filebeat was restarted:

```bash
sudo systemctl restart filebeat
```

The archive index was then confirmed on the indexer:

```bash
curl -k -u admin https://192.168.100.30:9200/_cat/indices?v | grep archives
```

The resulting index followed the expected pattern:

```text
wazuh-archives-4.x-2026.08.21
```

An index pattern was created in the Wazuh dashboard:

```text
Dashboards Management
→ Index Patterns
→ Create index pattern
→ wazuh-archives-*
→ Time field: timestamp
```

The Discover index selector was then changed from:

```text
wazuh-alerts-*
```

to:

```text
wazuh-archives-*
```

The same query:

```text
agent.name: "CLIENT01" AND data.win.system.eventID: 1
```

then returned the Sysmon Process Creation events, including the `notepad.exe` test event.

### 6.4 Updated Telemetry Status

| Telemetry Event             | ID | Local               | Centralized                   |
| --------------------------- | -: | ------------------- | ----------------------------- |
| Process Creation            |  1 | Verified            | Verified (`wazuh-archives-*`) |
| Process Termination         |  5 | Verified            | Verified                      |
| Network Connection          |  3 | Verified            | Verified                      |
| File Creation               | 11 | Verified            | Verified                      |
| Registry Object Activity    | 12 | Verified            | Verified                      |
| Registry Value Modification | 13 | Verified            | Verified                      |
| DNS Query                   | 22 | Under investigation | Under investigation           |

Process Creation (Event ID `1`) is now confirmed end-to-end.

DNS Query (Event ID `22`) remains outstanding and is carried forward as an open item from `05-windows-security-monitoring.md`.

---

## 7. Current Monitoring Architecture

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
                 │ CLIENT01  │
                 │ Windows 11│
                 │ Security  │
                 │ Auditing  │
                 │    +      │
                 │  Sysmon   │
                 │    +      │
                 │Wazuh Agent│
                 └─────┬─────┘
                       │
              Agent traffic (1514/1515)
                       │
                 ┌─────▼─────┐
                 │   SOC01   │
                 │   Wazuh   │
                 │   Manager │
                 │     │     │
                 │     ▼     │
                 │  Filebeat │
                 │     │     │
                 │     ▼     │
                 │   Wazuh   │
                 │   Indexer │
                 │     │     │
                 │     ▼     │
                 │   Wazuh   │
                 │ Dashboard │
                 └───────────┘
```

`CLIENT01` now forwards Windows telemetry and Sysmon events to `SOC01`.

The events are ingested by Wazuh, indexed by the Wazuh indexer, and queryable through the dashboard.

Events can be viewed through:

```text
wazuh-alerts-*
```

for generated alerts, or:

```text
wazuh-archives-*
```

for archived raw telemetry.

---

## 8. Key Lessons

### `wazuh-alerts-*` Is Not the Full Telemetry Dataset

The `wazuh-alerts-*` index contains events that generate Wazuh alerts.

Routine or low-signal telemetry may instead be available through:

```text
wazuh-archives-*
```

This distinction is important when validating whether telemetry is actually reaching the SOC platform.

### Archive Shipping Is Useful During Lab Development

Enabling:

```yaml
logall_json: yes
```

and Filebeat archive shipping provides a raw telemetry source before custom detection rules have been created.

This makes it possible to distinguish between:

```text
No telemetry generated
        ↓
Telemetry not collected
        ↓
Telemetry not indexed
        ↓
Telemetry indexed but not generating an alert
        ↓
Telemetry available in archives
```

### Troubleshooting Should Follow the Telemetry Path

When an event is missing from the dashboard, the investigation should proceed from the endpoint outward:

```text
CLIENT01
   ↓
Wazuh Agent
   ↓
Wazuh Manager
   ↓
Archives / Alerts
   ↓
Filebeat
   ↓
Indexer
   ↓
Dashboard
```

This prevents dashboard visibility problems from being mistaken for endpoint or network failures.

---

## 9. Validation Summary

The following were successfully verified:

* `SOC01` network configuration and DNS resolution
* Wazuh indexer, manager, and dashboard installed and communicating
* `CLIENT01` enrolled as an active Wazuh agent
* Windows telemetry collection from `CLIENT01`
* Sysmon event channel collection from `CLIENT01`
* End-to-end delivery of Sysmon Process Creation (Event ID `1`) telemetry to `SOC01`
* `wazuh-alerts-*` and `wazuh-archives-*` index behavior understood
* `wazuh-archives-*` made queryable through Wazuh Discover

---

## 10. Current Status

Centralized telemetry collection from `CLIENT01` to `SOC01` is operational.

The following path has been successfully validated:

```text
CLIENT01
   ↓
Wazuh Agent
   ↓
Wazuh Manager
   ↓
Filebeat
   ↓
Wazuh Indexer
   ↓
Wazuh Dashboard
```

Sysmon Process Creation (Event ID `1`) is confirmed end-to-end through the archive index.

Outstanding items:

* Sysmon DNS Query Event ID `22` has not yet been observed
* No custom detection rules have been created yet
* Detection currently relies on the existing Wazuh rule set and raw archive review

---

## 11. Next Step

With centralized telemetry confirmed, the next phase moves into detection engineering.

Planned stages:

* `07-detection-engineering.md`
* `08-sigma-rules.md`
* `09-threat-hunting.md`
* `10-mitre-attck.md`
* `11-attack-simulations.md`
* `12-incident-investigations.md`
* `13-incident-response.md`
