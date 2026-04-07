# Kerberoasting

#### Event ID:

- 4769 (Kerberos Service Ticket Requested)

## Detection Fields in Event 4769

| Field                   | What It Contains                                 | Why It Matters                                                                |
|-------------------------|--------------------------------------------------|-------------------------------------------------------------------------------|
| **Service_Name**        | The SPN being requested (e.g., `svc-sql`)         | Identifies which service account is being targeted                           |
| **Ticket_Encryption_Type** | `0x12` (AES) or `0x17` (RC4)                     | RC4 requests are the primary Kerberoasting signal                            |
| **Account_Name**        | The account requesting the ticket                 | Identifies the compromised user running the attack                           |
| **Client_Address**      | Source IP of the request                          | Identifies the attacker's machine                                             |

## Splunk Queries

### 1) Detect RC4 TGS requests

    index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
    | table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
    | sort _time

### 2) Detect how many service accounts were targeted, which account ran the attack and where did it come from

    index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
    | stats dc(Service_Name) as targeted_services count by Account_Name, Client_Address

### 3) Group TGS requests into 5-minute windows and flag any account that requested tickets for more than 5 unique service accounts within a window

(Change threshold according to your environment baseline)

    index=task2 EventCode=4769 Service_Name!="*$" Service_Name!="krbtgt"
    | bin _time span=5m
    | stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
    | where unique_spns > 5

