# Master Boot Record (MBR)

## Tools:

1) HxD (Hex Analyzer)

2) FTK Forensic Tool (Or any other Image forensics tool)

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

### Locating the partition

Calculate the byte at the start of Partitions table (446) + 16 bytes (an entry in the table)

    446 + 16 = 462

Now, on the HxD tool, go to:

    Search -> Go to -> "Dec" radio button -> 462 -> OK

### Size of a partition

Check the last 4 bytes of the partition table entry that contain the count of sectors in a partition.

Reverse to Big-Endian, convert to decimal, then multiply by 512 (Sector Size).

Formula to calculate:

    Sector Count x 512 (Sector Size)
    ((((Sector Count x 512)/1000)/1000)/1000)

#### ALWAYS REVERSE THE BYTES FROM LITTLE-ENDIAN TO BIG-ENDIAN (LSB to MSB)

### Starting LBA of the partition

Locate the standard starting LBA address as per the table above.

Then reverse it to Big-Endian and revert to Decimal value, then multiply by 512.

    2048 x 512 = 1048576

Then use:

    Search -> Go to -> "Dec" radio button -> 1048576 -> OK

Now you can locate where the LBA address begins.

## Quick Explanation of the above table

Here are the rephrased definitions in simpler technical language:

**Boot Indicator (1 byte):** A flag showing if the partition is bootable. Value 0x80 = bootable, 0x00 = not bootable. Only one partition should be marked bootable (typically the C: drive in Windows).

**Starting CHS Address (3 bytes):** The physical disk location where the partition begins, specified as Cylinder-Head-Sector coordinates. Legacy addressing method, rarely used in modern systems.

**Partition Type (1 byte):** A code identifying the filesystem type. For example, 0x07 indicates NTFS. Each filesystem has a unique identifier.

**Ending CHS Address (3 bytes):** The physical disk location where the partition ends in CHS format. Legacy addressing method, mostly obsolete.

**Starting LBA Address (4 bytes):** The logical sector number where the partition begins. Unlike CHS (physical addressing), LBA provides a simple linear sector count, making it easy to locate partitions in disk editors or forensic tools.

**Number of Sectors (4 bytes):** Total count of sectors contained in the partition, defining its size.
