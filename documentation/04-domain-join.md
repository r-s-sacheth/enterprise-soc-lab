# 04 — Domain Join and Authentication

## Overview

`CLIENT01` was joined to the `cyberlab.local` Active Directory domain hosted by `DC01`.

This allows the Windows 11 workstation to use centralized Active Directory authentication and participate in the enterprise domain environment.

## Client Configuration

`CLIENT01` has two network interfaces.

### Internal Network

```text
Network: 192.168.100.0/24
IP Address: 192.168.100.20
```

The internal interface is used for communication with the Active Directory environment.

### NAT Network

```text
Network: 192.168.10.0/24
IP Address: 192.168.10.129
Gateway: 192.168.10.2
```

The NAT interface provides Internet connectivity.

## DNS Configuration

Active Directory relies on DNS for domain discovery and authentication.

The internal network interface on `CLIENT01` was configured to use the domain controller as its DNS server:

```text
DNS Server:
192.168.100.10
```

This corresponds to:

```text
DC01
192.168.100.10
```

The client was not configured to use a public DNS server for its internal domain resolution.

## DNS Validation

Before attempting the domain join, DNS resolution was tested from `CLIENT01`.

### Resolve the Domain Controller

```cmd
nslookup dc01.cyberlab.local
```

The result successfully resolved the domain controller to:

```text
dc01.cyberlab.local → 192.168.100.10
```

### Resolve the Domain

```cmd
nslookup cyberlab.local
```

The domain successfully resolved through the internal DNS server:

```text
cyberlab.local → 192.168.100.10
```

### Test Connectivity

The domain controller was also tested using:

```cmd
ping dc01.cyberlab.local
```

Successful replies confirmed connectivity between `CLIENT01` and `DC01` over the internal network.

## Joining CLIENT01 to the Domain

The domain join was performed using the Windows System Properties interface.

On `CLIENT01`:

```text
Win + R
→ sysdm.cpl
```

The **Computer Name** tab was opened and the option to change the computer's domain or workgroup membership was selected.

The computer was configured to join:

```text
Domain:
cyberlab.local
```

Windows then requested domain credentials.

## Domain Credentials

The domain join requires an account with sufficient permissions to add a computer to the Active Directory domain.

The **domain Administrator account** was used for the initial domain join.

This is different from the local administrator account that was used before `CLIENT01` joined the domain.

The credentials were entered using the domain account associated with `CYBERLAB`

After successful authentication, Windows confirmed that the computer had joined the `cyberlab.local` domain.

## Restart

After the domain join completed, `CLIENT01` was restarted.

A restart is required for Windows to fully initialize the domain membership and allow domain authentication.

## Domain Authentication

After restarting, the Windows sign-in screen provided the option to authenticate using a domain account.

A domain user account was used to verify Active Directory authentication.

The client successfully authenticated against the `cyberlab.local` domain.

## Authentication Verification

The following commands were used to verify the domain authentication state.

### Current User

```cmd
whoami
```

This confirmed that the logged-in account belonged to the `CYBERLAB` domain rather than being a local account.

### Group Membership

```cmd
whoami /groups
```

The output was used to verify that the authenticated user received the expected domain security group memberships.

For example, the SOC analyst account was confirmed to be associated with:

```text
CYBERLAB\GG_SOC_Analysts
```

Domain authentication also resulted in membership in standard domain groups such as:

```text
Domain Users
Authenticated Users
```

### Logon Server

The domain controller responsible for authentication was verified using:

```cmd
echo %LOGONSERVER%
```

This confirmed that authentication was being handled by the domain controller.

## Computer Object Placement

When a computer initially joins an Active Directory domain, its computer object is normally placed in the default `Computers` container.

After joining the domain, `CLIENT01` was moved to the custom computer structure created for the lab.

The final location is:

```text
CYBERLAB.LOCAL
└── Corp Computers
    └── Workstations
        └── CLIENT01
```

This provides a dedicated location for domain workstations and will allow workstation-specific Group Policy to be applied later.

## Final Domain Structure

After the domain join and computer organization, the relevant structure is:

```text
## Final Domain Structure

After the domain join and computer organization, the current Active Directory structure is:

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


## Validation Summary

The following were successfully verified:

* `CLIENT01` can resolve `cyberlab.local`
* `CLIENT01` can resolve `dc01.cyberlab.local`
* `CLIENT01` can communicate with `DC01`
* `CLIENT01` successfully joined `cyberlab.local`
* Domain authentication is working
* Domain group membership is being applied
* The domain controller is handling authentication
* `CLIENT01` is located in `Corp Computers → Workstations`

## Current Status

The basic Active Directory environment is operational:

```text
DC01
│
├── Active Directory
├── DNS
└── Domain: cyberlab.local
       │
       └── CLIENT01
           └── Domain-joined workstation
```

The initial identity and domain infrastructure is now complete.

## Next Step

The next phase focuses on configuring the Windows environment for security monitoring and SOC telemetry.

Planned components include:

* Group Policy
* Windows security auditing
* Sysmon
* Centralized log collection
* SOC01 monitoring
* Detection engineering
