# GUID Partition Table (GPT)

## Tools:

1) HxD Hex Analyzer

2) FTK Imager forensics tool (or any other image forensics tool)

## GPT Analysis

Important Bytes

| Bytes Position | Bytes Length | Field Name                       | Value                                               |
|----------------|--------------|----------------------------------|-----------------------------------------------------|
| 0–7            | 8            | Signature                        | `45 46 49 20 50 41 52 54`                           |
| 8–11           | 4            | Revision                         | `00 00 01 00`                                       |
| 12–15          | 4            | Header Size                      | `5C 00 00 00`                                       |
| 16–19          | 4            | CRC32 of Header                  | `71 89 13 1C`                                       |
| 20–23          | 4            | Reserved                         | `00 00 00 00`                                       |
| 24–31          | 8            | Current LBA                      | `01 00 00 00 00 00 00 00`                           |
| 32–39          | 8            | Backup LBA                       | `AF 32 CF 1D 00 00 00 00`                           |
| 40–47          | 8            | First Usable LBA                 | `22 00 00 00 00 00 00 00`                           |
| 48–55          | 8            | Last Usable LBA                  | `8E 32 CF 1D 00 00 00 00`                           |
| 56–71          | 16           | Disk GUID                        | `61 1D F1 B0 D6 43 BE 37 4E B1 E6 38 66 EC B1 73 89`|
| 72–79          | 8            | Partition Entry Array LBA        | `02 00 00 00 00 00 00 00`                           |
| 80–83          | 4            | Number of Partition Entries      | `80 00 00 00`                                       |
| 84–87          | 4            | Size of Each Partition Entry     | `80 00 00 00`                                       |
| 88–91          | 4            | CRC32 of Partition Array         | `41 0D C0 22`                                       |

### Quick Explanation

Here are the simplified technical definitions:

**1. Signature (8 bytes):** Identifier that marks a valid GPT header. Always contains the ASCII string "EFI PART" (0x45 46 49 20 50 41 52 54).

**2. Revision (4 bytes):** GPT specification version number. Typically 0x00 00 01 00, representing version 1.0.

**3. Header Size (4 bytes):** Length of the GPT header in bytes. Usually 0x5C 00 00 00 (92 bytes in little-endian decimal).

**4. CRC32 of Header (4 bytes):** Checksum for validating header integrity. A mismatch indicates corruption or tampering.

**5. Reserved (4 bytes):** Unused bytes reserved for future GPT specifications.

**6. Current LBA (8 bytes):** Logical sector address of this GPT header. Normally sector 1 (LBA 1).

**7. Backup LBA (8 bytes):** Logical sector address of the backup GPT header, typically located at the end of the disk.

**8. First Usable LBA (8 bytes):** The earliest sector address where partition data can begin.

**9. Last Usable LBA (8 bytes):** The final sector address where partition data can end. No partitions can extend beyond this point.

**10. Disk GUID (16 bytes):** Globally Unique Identifier that uniquely identifies the disk. Formatted as a standard GUID (e.g., 1DF1B0D6-43BE-374E-B1E6-3866ECB17389).

**11. Partition Entry Array LBA (8 bytes):** Logical sector address where the partition entry table begins.

**12. Number of Partition Entries (4 bytes):** Maximum partition count supported. GPT standard allows 128 partitions (0x80 00 00 00).

**13. Size of Each Partition Entry (4 bytes):** Size of each partition table entry in bytes. Typically 128 bytes (0x80 00 00 00). This is the metadata size, not the actual partition size.

**14. CRC32 of Partition Array (4 bytes):** Checksum for validating the entire partition entry table integrity. Detects corruption or tampering.

### Partition Entry Array

Important Bytes

| Bytes Position | Bytes Length | Field Name              | Value                                                                 |
|----------------|--------------|-------------------------|------------------------------------------------------------------------|
| 0–15           | 16           | Partition Type GUID     | `1628 73 2A C1 1F F8 D2 11 BA 4B 00 A0 C9 3E C9 3B`                    |
| 16–31          | 16           | Unique Partition GUID   | `169E 43 0D 72 EC 12 54 44 8F B2 EE 17 8D F3 CD 3B`                    |
| 32–39          | 8            | Starting LBA            | `00 08 00 00 00 00 00 00`                                              |
| 40–47          | 8            | Ending LBA              | `FF 27 03 00 00 00 00 00`                                              |
| 48–55          | 8            | Attributes              | `00 00 00 00 00 00 00 80`                                              |
| 56–127         | 72           | Partition Name          | `45 00 46 00 49 00 20 00 73 00 79 00 73 ...` *(UTF-16LE encoded string)* |

### Quick Explanation

Here are the simplified technical definitions for GPT Partition Entry fields:

**1. Partition Type GUID (16 bytes):** Identifier indicating the partition's purpose (e.g., EFI System Partition, Windows Data Partition). Stored in mixed-endian format requiring specific byte reordering:
   - Reverse first 4 bytes (little-endian)
   - Reverse next 2 bytes (little-endian)
   - Reverse next 2 bytes (little-endian)
   - Keep remaining 8 bytes as-is (big-endian)
   
   Example: `28 73 2A C1 1F F8 D2 11 BA 4B 00 A0 C9 3E C9 3B` becomes `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` (EFI System Partition).

   **Note:** The EFI System Partition (ESP) stores bootloader files with .efi extensions needed to load the OS kernel, unlike MBR which stores bootloaders in the boot sector.

**2. Unique Partition GUID (16 bytes):** A globally unique identifier assigned to each individual partition on the disk. Stored in mixed-endian format; convert using the same method as Partition Type GUID.

**3. Starting LBA (8 bytes):** Logical sector address where the partition begins on the disk.

**4. Ending LBA (8 bytes):** Logical sector address where the partition ends on the disk.

**5. Attributes (8 bytes):** Bit flags defining partition properties such as bootable, hidden, read-only, or required for platform operation.

**6. Partition Name (72 bytes):** Human-readable partition label encoded in UTF-16LE format. Can contain up to 36 Unicode characters. Decode to view the partition's name.

### Find the partition type GUID

Find the start of the array, then add 128 bytes to jump to the second entry

      512  x 2 = 1024 + 128 = 1152

The second partition's metadata starts at Decimal offset 1152.

Navigate to that offset, by going to:

      Search -> Go to -> "Dec" radio button -> 1152 -> OK

You will find the GUID in the first 16 bytes of that entry.

On formatting it properly, you will find it on the Quick Explanation chapter of the Partition Entry Array part.
