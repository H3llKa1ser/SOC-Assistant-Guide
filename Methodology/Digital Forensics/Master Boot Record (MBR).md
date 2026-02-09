# Master Boot Record (MBR)

## Tools:

1) HxD (Hex Analyzer)

2) FTK Forensic Tool

Total Bytes of MBR

    512

## MBR Analysis



### Important Bytes

| Bytes Position | Bytes Length | Field Name                | Value                 |
|----------------|--------------|---------------------------|-----------------------|
| 0              | 1            | Boot Indicator            | `80`                  |
| 1–3            | 3            | Starting CHS Address      | `20 21 00`             |
| 4              | 1            | Partition Type            | `07`                  |
| 5–7            | 3            | Ending CHS Address        | `FE FF FF`             |
| 8–11           | 4            | Starting LBA Address      | `00 08 00 00`          |
| 12–15          | 4            | Number of Sectors         | `00 B0 23 03`          |

MBR Signature Bytes (Position 510-512)

    55 AA

Bootloader Code Bytes Position

    0 - 445

Partitions Table Bytes Position

    446 - 509

