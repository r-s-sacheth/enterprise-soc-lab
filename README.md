# Enterprise SOC Lab

An enterprise-style cybersecurity home lab designed to simulate a small corporate environment and provide hands-on experience with Active Directory, Windows security monitoring, detection engineering, threat hunting, incident response, and MITRE ATT&CK-based investigations.

## Project Objectives

* Build an isolated enterprise-style Windows environment
* Deploy and configure Active Directory Domain Services
* Configure DNS, organizational units, users, groups, and domain-joined systems
* Centralize security telemetry from Windows systems
* Develop detection rules and security analytics
* Perform threat hunting and incident investigations
* Map attacks and detections to MITRE ATT&CK
* Document investigation and response procedures

## Lab Architecture

The lab consists of three virtual machines connected through separate VMware virtual networks.

| System   | Role                       |      Internal IP |           NAT IP |
| -------- | -------------------------- | ---------------: | ---------------: |
| DC01     | Domain Controller / DNS    | `192.168.100.10` | `192.168.10.128` |
| CLIENT01 | Windows 11 Domain Client   | `192.168.100.20` | `192.168.10.129` |
| SOC01    | Security Monitoring Server | `192.168.100.30` | `192.168.10.130` |

### Networks

* **VMnet1 — Host-only:** `192.168.100.0/24`

  * Used for isolated communication between lab systems
* **VMnet8 — NAT:** `192.168.10.0/24`

  * Used for Internet access and system updates

## Active Directory

* **Forest:** `cyberlab.local`
* **Domain:** `cyberlab.local`
* **Domain Controller:** `DC01`
* **DNS:** `DC01`

### Organizational Structure

```text
CYBERLAB.LOCAL
│
├── Domain Controllers
│   └── DC01
│
├── Corp Users
│   ├── Alice Johnson
│   ├── Bob Smith
│   ├── Charlie Brown
│   └── David Wilson
│
├── Corp Computers
│   └── Workstations
│       └── CLIENT01
│
├── Groups
│   ├── GG_SOC_Analysts
│   ├── GG_IT_Admins
│   ├── GG_Helpdesk
│   └── GG_Employees
│
└── Service Accounts
```

### Role-Based Groups

| User          | Role             | Security Group    |
| ------------- | ---------------- | ----------------- |
| Alice Johnson | SOC Analyst      | `GG_SOC_Analysts` |
| Bob Smith     | IT Administrator | `GG_IT_Admins`    |
| Charlie Brown | Helpdesk         | `GG_Helpdesk`     |
| David Wilson  | Employee         | `GG_Employees`    |

## Project Roadmap

* [x] VMware lab environment
* [x] Network segmentation
* [x] Windows Server deployment
* [x] Windows 11 client deployment
* [x] Ubuntu/SOC server deployment
* [x] Active Directory Domain Services
* [x] DNS configuration
* [x] Organizational Units
* [x] Users and security groups
* [x] Domain join
* [x] Computer organization
* [x] Group Policy configuration
* [x] Windows security auditing
* [x] Sysmon deployment
* [x] SOC01 monitoring stack
* [x] Centralized log collection
* [x] Detection engineering
* [ ] Sigma rules
* [ ] Threat hunting
* [ ] MITRE ATT&CK mapping
* [ ] Attack simulations
* [ ] Incident investigations
* [ ] Incident response documentation

## Status

**Current phase:** SOC01 monitoring platform and centralized telemetry collection configured. Detection engineering is next.
