# 01 — Environment Setup

## Overview

This project uses a virtualized environment to simulate a small enterprise network for cybersecurity monitoring, detection engineering, threat hunting, and incident response.

The lab is hosted on a local workstation using VMware Workstation Pro.

## Host Environment

| Component  | Specification               |
| ---------- | --------------------------- |
| Hypervisor | VMware Workstation Pro 26H1 |
| CPU        | Intel Core i5-11320H        |
| Memory     | 16 GB RAM                   |
| GPU        | NVIDIA GTX 1650 4 GB        |
| Storage    | 512 GB SSD                  |
| Host OS    | Windows                     |

The available hardware is used to run multiple virtual machines simultaneously while keeping the lab environment isolated from the host network.

## Virtual Machines

The lab currently consists of three virtual machines.

| VM         | Operating System                               | Role                                       |
| ---------- | ---------------------------------------------- | ------------------------------------------ |
| `DC01`     | Windows Server 2025 Standard Evaluation (24H2) | Active Directory Domain Controller and DNS |
| `CLIENT01` | Windows 11 Pro                                 | Domain-joined Windows workstation          |
| `SOC01`    | Ubuntu                                         | Security monitoring and SOC platform       |

### DC01

`DC01` acts as the central identity and directory server for the lab.

**Operating System:** Windows Server 2025 Standard Evaluation (24H2)

Responsibilities:

* Active Directory Domain Services (AD DS)
* DNS
* Domain authentication
* User and group management
* Organizational Units (OUs)
* Domain controller services

Internal address:

```text
192.168.100.10
```

NAT address:

```text
192.168.10.128
```

### CLIENT01

`CLIENT01` is the Windows 11 Pro workstation used to represent an employee endpoint in the enterprise environment.

Responsibilities:

* Domain-joined Windows endpoint
* User authentication against Active Directory
* Security event generation
* Endpoint telemetry for SOC monitoring
* Future attack and detection simulations

Internal address:

```text
192.168.100.20
```

NAT address:

```text
192.168.10.129
```

### SOC01

`SOC01` is the Ubuntu-based security monitoring server.

It will eventually be used for:

* Security log collection
* SIEM functionality
* Security monitoring
* Detection engineering
* Threat hunting
* Incident investigation

Internal address:

```text
192.168.100.30
```

NAT address:

```text
192.168.10.130
```

## Virtualization Network Design

Two separate VMware virtual networks are used to separate internal lab communication from Internet connectivity.

### VMnet1 — Host-only

```text
Network: 192.168.100.0/24
```

VMnet1 provides the isolated internal network used for communication between the lab systems.

```text
DC01       192.168.100.10
CLIENT01   192.168.100.20
SOC01      192.168.100.30
```

VMnet1 is a host-only network and does not provide direct Internet access.

### VMnet8 — NAT

```text
Network: 192.168.10.0/24
Gateway: 192.168.10.2
```

VMnet8 provides Internet connectivity to the virtual machines through VMware NAT.

```text
DC01       192.168.10.128
CLIENT01   192.168.10.129
SOC01      192.168.10.130
```

## Network Design

The resulting topology is:

```text
                          Internet
                             │
                         VMware NAT
                          VMnet8
                      192.168.10.0/24
                             │
             ┌───────────────┼───────────────┐
             │               │               │
           DC01           CLIENT01         SOC01
      192.168.10.128   192.168.10.129   192.168.10.130
             │               │               │
             └───────────────┼───────────────┘
                             │
                      VMware VMnet1
                    Host-only network
                    192.168.100.0/24
                             │
             ┌───────────────┼───────────────┐
             │               │               │
           DC01           CLIENT01         SOC01
      192.168.100.10   192.168.100.20   192.168.100.30
```

## Design Rationale

The two-network design separates **internal enterprise communication** from **Internet connectivity**.

The host-only network is used for:

* Active Directory communication
* DNS
* Domain authentication
* Windows-to-Windows communication
* Security monitoring traffic
* SOC telemetry

The NAT network is used primarily for:

* Operating system updates
* Installing packages
* Downloading security tools
* Internet connectivity when required

This separation provides a more realistic enterprise-lab architecture while reducing unnecessary exposure of internal services.

## Initial Validation

After configuring the network interfaces, connectivity between the three systems was tested.

The internal network was verified using ICMP connectivity tests and DNS resolution. Communication between the lab systems was confirmed over the internal network.

The lab systems were also confirmed to have Internet connectivity through the VMware NAT network.

## Next Step

The next stage of the project is to document the detailed network configuration and Active Directory deployment.

See:

* `02-network-configuration.md`
* `03-active-directory.md`
* `04-domain-join.md`
