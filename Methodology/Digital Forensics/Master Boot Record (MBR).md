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

Boot Indicator: This byte tells you whether the partition is bootable or not. A bootable partition contains files necessary for the operating system to boot. This boot indicator can only have one of the two values: 80 or 00. If it's 80, it means that the partition is bootable; else, if it's 00, it means that the partition is not bootable.  In Windows based systems, C: is the partition that is typically bootable. If visualized through the partition table, this partition would have the boot indicator set to 80.

Starting CHS Address: Cylinder Head Sector (CHS) is the 3 bytes that tell you where this partition is starting from on the disk. It will give you the starting physical address of the partition, such as the cylinder, head, and sector number. This field is not that important as we now have the simplified logical address of the partition in the form of the Starting LBA Address discussed ahead.

Partition Type: Every partition uses a filesystem such as NTFS, FAT32, etc. This byte indicates the filesystem of the partition. The partition we are taking as a reference has this byte as 07, which means it is an NTFS partition. Every filesystem has its own unique byte. You can learn about the bytes used for other filesystems from here.

Ending CHS Address: The last 3 bytes at the end of the CHS Address indicates the physical location where the partition ends on the disk. This field is also not that important, just like the stated CHS address, as we mostly use the logical address (LBA) instead of the physical address.

Starting LBA Address: Logical Block Addressing (LBA) is the logical address that indicates the start of the partition. We saw that the Starting CHS Address also gives us the starting address of the partition, but because CHS gives you the physical address of the partition, it becomes difficult for us to locate it. However, the Starting LBA Address gives you the logical address of the partition rather than the physical address. You can use it to easily find the start of the partition on the disk in a hexadecimal editor. By locating the partition on the disk, you can also carve data from a disk's hidden or deleted partitions. Based on the partition we are analyzing as a reference with 00 08 00 00 LBA, we will use this logical address to locate our partition later in this task.

Number of Sectors: These last 4 bytes of a partition tell you the number of sectors in the partition. We will calculate the sector's size by using this field ahead.
