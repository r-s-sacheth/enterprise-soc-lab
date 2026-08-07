# 03 — Active Directory

## Overview

Active Directory Domain Services (AD DS) was deployed on `DC01` to provide centralized identity, authentication, authorization, and directory management for the lab environment.

The Active Directory environment uses the `cyberlab.local` domain.

## Active Directory Environment

| Component            | Configuration                                  |
| -------------------- | ---------------------------------------------- |
| Forest               | `cyberlab.local`                               |
| Domain               | `cyberlab.local`                               |
| Domain Controller    | `DC01`                                         |
| Domain Controller IP | `192.168.100.10`                               |
| DNS Server           | `DC01`                                         |
| Server OS            | Windows Server 2025 Standard Evaluation (24H2) |

The forest currently contains a single domain:

```text
Forest
└── cyberlab.local
```

`DC01` hosts the Active Directory Domain Services and DNS roles required by the domain.

## Active Directory Deployment

AD DS was installed through:

```text
Server Manager
→ Add Roles and Features
→ Active Directory Domain Services
```

The DNS Server role was also installed as part of the domain controller deployment.

After installing the required roles, `DC01` was promoted to a domain controller.

The deployment wizard was configured with:

```text
Deployment Type:
Add a new forest

Root domain name:
cyberlab.local
```

The domain controller was then restarted after promotion.

## Domain Controller

`DC01` is the primary domain controller for the lab.

Its responsibilities include:

* Active Directory Domain Services
* DNS
* Domain authentication
* Kerberos authentication
* LDAP directory services
* User and group management
* Organizational Unit management
* Group Policy infrastructure
* SYSVOL and NETLOGON services

Internal address:

```text
192.168.100.10
```

The domain controller's hostname is:

```text
DC01
```

## DNS and Active Directory

DNS is a critical dependency for Active Directory.

The internal DNS server for the domain is `DC01`:

```text
DNS Server:
192.168.100.10
```

The domain uses:

```text
cyberlab.local
```

DNS resolution was verified using:

```cmd
nslookup cyberlab.local
nslookup dc01.cyberlab.local
```

Expected results include:

```text
cyberlab.local → 192.168.100.10
dc01.cyberlab.local → 192.168.100.10
```

This confirms that the internal DNS records required for the domain are resolving correctly.

Detailed network and DNS configuration is documented in:

`02-network-configuration.md`

## Organizational Units

Organizational Units (OUs) were created to logically organize users, computers, and groups within the Active Directory database.

The following OUs were created:

```text
CYBERLAB.LOCAL
│
├── Corp Users
│
├── Corp Computers
│   └── Workstations
│
├── Groups
│
├── Service Accounts
│
└── Security
```

### Corp Users

The `Corp Users` OU contains the normal enterprise user accounts created for the lab.

```text
Corp Users
├── Alice Johnson
├── Bob Smith
├── Charlie Brown
└── David Wilson
```

### Corp Computers

The `Corp Computers` OU is used to organize domain-joined computer objects.

A `Workstations` OU was created underneath it:

```text
Corp Computers
└── Workstations
    └── CLIENT01
```

### Groups

The `Groups` OU contains the security groups used for role-based access control.

### Service Accounts

The `Service Accounts` OU was created to provide a dedicated location for future service accounts.

### Security

The `Security` OU was created as a dedicated location for future security-related directory objects and administrative organization.

## Security Groups

Role-based Global Security Groups were created to represent different enterprise responsibilities.

```text
Groups
├── GG_SOC_Analysts
├── GG_IT_Admins
├── GG_Helpdesk
└── GG_Employees
```

These groups allow permissions and access controls to be assigned based on organizational roles rather than individual users.

## Users and Group Membership

The following users were created:

| User          | Username        | Role             | Security Group    |
| ------------- | --------------- | ---------------- | ----------------- |
| Alice Johnson | `alice`         | SOC Analyst      | `GG_SOC_Analysts` |
| Bob Smith     | `bob.smith`     | IT Administrator | `GG_IT_Admins`    |
| Charlie Brown | `charlie.brown` | Helpdesk         | `GG_Helpdesk`     |
| David Wilson  | `david.wilson`  | Employee         | `GG_Employees`    |

The users were created under:

```text
CYBERLAB.LOCAL
└── Corp Users
```

Each user was added to the appropriate Global Security Group according to their assigned role.

## Default Containers vs Organizational Units

Active Directory automatically creates several containers and organizational objects when a domain is created.

For example:

```text
Domain Controllers
Computers
Users
```

The default `Computers` and `Users` containers are not equivalent to custom Organizational Units.

Custom OUs were created to provide a structured directory hierarchy that can later be used for:

* Group Policy
* Administrative delegation
* Computer organization
* User organization
* Security management

The lab therefore uses custom OUs such as:

```text
Corp Users
Corp Computers
Groups
Service Accounts
Security
```

## Domain Controller Verification

The domain controller was verified using standard Windows administrative commands.

### DC Diagnostics

```cmd
dcdiag /q
```

This was used to identify domain controller health issues during the initial deployment.

### SYSVOL and NETLOGON

The following command was used to verify that the expected domain controller shares were available:

```cmd
net share
```

The following shares were confirmed:

```text
NETLOGON
SYSVOL
```

These shares are important for domain operations and Group Policy distribution.

### DNS Verification

The following commands were used:

```cmd
nslookup cyberlab.local
nslookup dc01.cyberlab.local
```

Successful resolution confirmed that the domain and domain controller DNS records were available.

## Initial Domain Controller Warnings

During the initial domain controller validation, `dcdiag` reported events related to:

* DFS Replication event logging
* Kerberos/KDC processing
* Secure Boot configuration

The Secure Boot warnings were related to the virtual machine not having Secure Boot enabled.

The presence of the `SYSVOL` and `NETLOGON` shares was verified, and the domain's DNS resolution was functioning correctly.

These warnings did not prevent the lab domain from functioning for the current environment.

## Final Active Directory Structure

The current directory structure is:

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
├── Service Accounts
│
└── Security
```

## Current Status

The Active Directory environment is operational.

The following components have been completed:

* AD DS installation
* DNS installation and configuration
* Domain controller promotion
* `cyberlab.local` forest and domain
* Organizational Units
* Domain users
* Global Security Groups
* User-to-group assignments
* Domain-joined workstation
* Domain authentication
* DNS resolution
* SYSVOL and NETLOGON verification

The next stage is to document the domain-join process and client-side authentication validation.

## Next Step

The domain-join process and CLIENT01 authentication are documented in:

`04-domain-join.md`
