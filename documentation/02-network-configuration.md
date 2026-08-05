# 02 — Network Configuration

## Overview

The lab uses two VMware virtual networks to separate internal enterprise communication from Internet connectivity.

* **VMnet1 — Host-only:** Internal lab network
* **VMnet8 — NAT:** Internet access

Each virtual machine has two network interfaces: one connected to the internal VMnet1 network and one connected to the VMnet8 NAT network.

## VMware Virtual Networks

### VMnet1 — Internal Network

VMnet1 is configured as a **Host-only** network.

```text
Network: 192.168.100.0/24
```

This network is used for communication between the systems inside the lab.

| System   |      Internal IP |
| -------- | ---------------: |
| DC01     | `192.168.100.10` |
| CLIENT01 | `192.168.100.20` |
| SOC01    | `192.168.100.30` |

The internal network does not use a default gateway because it is intended for isolated lab communication.

### VMnet8 — NAT Network

VMnet8 is configured as a **NAT** network.

```text
Network: 192.168.10.0/24
Gateway: 192.168.10.2
```

This network provides Internet connectivity to the virtual machines.

| System   |           NAT IP |
| -------- | ---------------: |
| DC01     | `192.168.10.128` |
| CLIENT01 | `192.168.10.129` |
| SOC01    | `192.168.10.130` |

## Network Interface Design

Each virtual machine uses two network adapters.

```text
                     Internet
                        │
                    VMware NAT
                      VMnet8
                 192.168.10.0/24
                        │
          ┌─────────────┼─────────────┐
          │             │             │
        DC01         CLIENT01       SOC01
   192.168.10.128 192.168.10.129 192.168.10.130
          │             │             │
          └─────────────┼─────────────┘
                        │
                  VMware VMnet1
                Host-only network
                 192.168.100.0/24
                        │
          ┌─────────────┼─────────────┐
          │             │             │
        DC01         CLIENT01       SOC01
   192.168.100.10 192.168.100.20 192.168.100.30
```

The internal interface is used for enterprise services and lab communication, while the NAT interface provides Internet access.

## DC01 Network Configuration

DC01 uses:

```text
Internal:
192.168.100.10/24

NAT:
192.168.10.128/24
Gateway:
192.168.10.2
```

The internal interface is used for Active Directory and DNS communication.

DC01 also hosts the DNS service used by the `cyberlab.local` domain.

## CLIENT01 Network Configuration

CLIENT01 uses:

```text
Internal:
192.168.100.20/24

NAT:
192.168.10.129/24
Gateway:
192.168.10.2
```

The internal interface is configured to use DC01 as its DNS server:

```text
DNS:
192.168.100.10
```

This is required for reliable Active Directory name resolution and domain operations.

The NAT interface provides Internet connectivity through VMware NAT.

## SOC01 Network Configuration

SOC01 uses:

```text
Internal:
192.168.100.30/24

NAT:
192.168.10.130/24
Gateway:
192.168.10.2
```

The internal interface is configured with a static address.

The Ubuntu network configuration was applied using Netplan.

Typical validation commands used during configuration included:

```bash
ip -br addr
ip route
```

After modifying the Netplan configuration, the configuration was tested and applied using:

```bash
sudo netplan try
sudo netplan apply
```

## DNS Configuration

Because Active Directory depends heavily on DNS, the internal network uses DC01 as the authoritative DNS server for the lab domain.

```text
Domain:
cyberlab.local

DNS Server:
192.168.100.10
```

CLIENT01 was configured to use:

```text
192.168.100.10
```

as its internal DNS server.

This allows the client to resolve records such as:

```text
dc01.cyberlab.local
cyberlab.local
```

## DNS Registration on DC01

DC01 has two network interfaces:

```text
Internal / VMnet1
192.168.100.10

NAT / VMnet8
192.168.10.128
```

The internal interface is used for Active Directory and DNS communication, while the NAT interface provides Internet connectivity.

To prevent the NAT-facing interface from registering its address in the internal Active Directory DNS zone, DNS registration was disabled on the NAT adapter.

The unwanted NAT-interface A record was also removed from the DNS management console.

As a result, the primary internal DNS record resolves the domain controller through its internal network address:

```text
dc01.cyberlab.local → 192.168.100.10
```

rather than the NAT address:

```text
192.168.10.128
```

## Connectivity Testing

Connectivity was tested between the three lab systems using ICMP and DNS resolution.

### DC01

DC01 was tested for connectivity to:

* `CLIENT01`
* `SOC01`

### CLIENT01

CLIENT01 was tested for connectivity to:

* `DC01`
* `SOC01`

### SOC01

SOC01 was tested for connectivity to:

* `DC01`
* `CLIENT01`

All required internal connectivity was confirmed after firewall configuration was corrected.

Internet connectivity was also verified from all three virtual machines through VMnet8 NAT.

## Windows Firewall Troubleshooting

During initial connectivity testing, communication between the systems failed even though the network configuration and IP addressing were correct.

The issue was identified as Windows Firewall blocking ICMP traffic.

The appropriate **File and Printer Sharing (Echo Request - ICMPv4-In)** firewall rules were enabled on the Windows systems.

After enabling the required ICMP rules, connectivity tests succeeded.

This demonstrated that successful network communication requires both correct network configuration and appropriate host firewall rules.

## DNS Validation

DNS resolution was tested from CLIENT01.

### Domain Controller Resolution

```text
nslookup dc01.cyberlab.local
```

Expected result:

```text
Name:    dc01.cyberlab.local
Address: 192.168.100.10
```

### Domain Resolution

```text
nslookup cyberlab.local
```

Expected result:

```text
Name:    cyberlab.local
Address: 192.168.100.10
```

### Connectivity to DC01

```text
ping dc01.cyberlab.local
```

The hostname successfully resolved to:

```text
192.168.100.10
```

and ICMP replies were received.

## Routing

The NAT interface provides the default route for Internet access.

The internal VMnet1 interface does not have a default gateway because it is used for internal lab communication.

This prevents the internal network from becoming the preferred route for Internet traffic.

Routing information was inspected using:

**Windows:**

```cmd
route print
```

**Ubuntu:**

```bash
ip route
```

## Final Network Configuration

The resulting network configuration is:

| System   | Internal Network | NAT Network      | Internal DNS                     | Default Gateway |
| -------- | ---------------- | ---------------- | -------------------------------- | --------------- |
| DC01     | `192.168.100.10` | `192.168.10.128` | DC01                             | `192.168.10.2`  |
| CLIENT01 | `192.168.100.20` | `192.168.10.129` | `192.168.100.10`                 | `192.168.10.2`  |
| SOC01    | `192.168.100.30` | `192.168.10.130` | As required by SOC configuration | `192.168.10.2`  |

## Validation Summary

The following were successfully verified:

* VMnet1 internal connectivity
* VMnet8 Internet connectivity
* Static internal addressing
* DNS resolution through DC01
* `cyberlab.local` resolution
* `dc01.cyberlab.local` resolution
* Communication between all three lab systems
* Windows firewall configuration for ICMP testing
* Correct routing between the internal and NAT networks

The network is now ready for the Active Directory configuration and domain services documentation.

## Next Step

The next document covers the Active Directory deployment and structure:

`03-active-directory.md`
